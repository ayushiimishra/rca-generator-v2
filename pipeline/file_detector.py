import os
import re
import csv
import json
from pathlib import Path
from datetime import datetime

EVTX_MAGIC = b"ElfFile\x00"
XLSX_MAGIC  = b"PK\x03\x04"

NGINX_RE = re.compile(
    r'\S+ \S+ \S+ \[[^\]]+\] "[A-Z]+ .+ HTTP/\S+" \d+ \S+'
)

LEVEL_MAP = {
    "critical":      "critical",
    "error":         "high",
    "warning":       "medium",
    "information":   "info",
    "verbose":       "info",
    "audit success": "info",
    "audit failure": "high",
}


def _get_field(row: dict, *keys) -> str:
    for key in keys:
        for k, v in row.items():
            if k and k.lower().strip() == key.lower():
                return str(v or "").strip()
    return ""


def _normalize_ts(timestamp: str) -> str:
    for fmt in [
        "%m/%d/%Y %I:%M:%S %p",
        "%Y-%m-%d %H:%M:%S",
        "%d/%m/%Y %H:%M:%S",
        "%Y-%m-%dT%H:%M:%SZ",
        "%d/%b/%Y:%H:%M:%S %z",
        "%Y-%m-%dT%H:%M:%S",
    ]:
        try:
            dt = datetime.strptime(timestamp.strip(), fmt)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            continue
    return "unknown"


def convert_csv_evtx(filepath: str):
    """
    Generator — yields one event at a time.
    O(1) RAM regardless of file size.
    """
    count = 0
    with open(filepath, "r", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            event_id  = _get_field(row,
                "eventid", "event id", "event_id", "id")
            timestamp = _get_field(row,
                "timecreated", "time created",
                "date and time", "timestamp", "time")
            computer  = _get_field(row,
                "computer", "computername", "machine")
            channel   = _get_field(row,
                "channel", "log", "log name")
            level     = _get_field(row,
                "level", "levelname", "severity")

            severity = LEVEL_MAP.get(level.lower(), "info")
            ts       = _normalize_ts(timestamp)

            yield {
                "ts":         ts,
                "source":     "evtx",
                "event_type": event_id or "unknown",
                "severity":   severity,
                "raw":        json.dumps(dict(row)),
                "metadata": {
                    "EventID":          event_id,
                    "Computer":         computer,
                    "Channel":          channel,
                    "EventData":        dict(row),
                    "suspicious_chain": ""
                }
            }
            count += 1
            if count % 100_000 == 0:
                print(f"  [csv] {count:,} rows streamed...")

    print(f"[file_detector] CSV evtx streamed: {count:,} events")


def convert_csv_waf(filepath: str):
    """
    Generator — yields one event at a time.
    O(1) RAM regardless of file size.
    """
    from pipeline.waf_parser import detect_attack
    from pipeline.waf_parser import _assign_severity

    count = 0
    with open(filepath, "r", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            src_ip     = _get_field(row,
                "src_ip", "source_ip", "clientip",
                "client_ip", "ip", "remote_addr")
            method     = _get_field(row,
                "method", "request_method", "verb")
            uri        = _get_field(row,
                "uri", "url", "path", "request_uri")
            status_str = _get_field(row,
                "status", "status_code", "sc-status")
            ua         = _get_field(row,
                "user_agent", "useragent",
                "cs(user-agent)", "agent")
            timestamp  = _get_field(row,
                "timestamp", "time", "datetime",
                "date", "time_local")
            bytes_str  = _get_field(row,
                "bytes", "size", "sc-bytes")

            ts = _normalize_ts(timestamp)

            try:
                status = int(status_str)
            except Exception:
                status = 0

            try:
                byte_count = int(bytes_str)
            except Exception:
                byte_count = 0

            attack   = detect_attack(method, uri, ua, status)
            severity = _assign_severity(attack, status)

            yield {
                "ts":         ts,
                "source":     "waf",
                "event_type": f"{method} {uri}".strip(),
                "severity":   severity,
                "raw":        json.dumps(dict(row)),
                "metadata": {
                    "src_ip":        src_ip,
                    "method":        method,
                    "uri":           uri,
                    "status":        status,
                    "bytes":         byte_count,
                    "user_agent":    ua,
                    "attack_type":   attack["attack_type"],
                    "attack_found":  attack["attack_found"],
                    "confidence":    attack["confidence"],
                    "attack_detail": attack["attack_detail"],
                }
            }
            count += 1
            if count % 100_000 == 0:
                print(f"  [csv] {count:,} rows streamed...")

    print(f"[file_detector] CSV WAF streamed: {count:,} events")


def detect_file_type(filepath: str) -> dict:
    if not os.path.exists(filepath):
        return {"type": "unknown", "valid": False,
                "reason": "File not found"}

    try:
        with open(filepath, "rb") as f:
            header = f.read(16)
    except Exception as e:
        return {"type": "unknown", "valid": False,
                "reason": str(e)}

    # CHECK 1 — Windows Event Log binary
    if header[:8] == EVTX_MAGIC:
        return {
            "type":   "evtx",
            "format": "windows_event_log_binary",
            "parser": "evtx_parser",
            "valid":  True,
            "action": "parse_directly"
        }

    # CHECK 2 — Excel file
    if header[:4] == XLSX_MAGIC:
        return {
            "type":    "excel",
            "format":  "xlsx",
            "valid":   False,
            "action":  "reject",
            "message": (
                "Excel file detected. Cannot read directly.\n"
                "For Windows logs: export as .evtx from "
                "Event Viewer\n"
                "For web logs: export as plain text .log\n"
                "For CSV: save as .csv and re-upload"
            )
        }

    # CHECK 3 — Try reading as plain text
    try:
        with open(filepath, "r", errors="replace") as f:
            first_line  = f.readline().strip()
            second_line = f.readline().strip()
    except Exception as e:
        return {"type": "unknown", "valid": False,
                "reason": str(e)}

    if not first_line:
        return {"type": "unknown", "valid": False,
                "reason": "File is empty"}

    # CHECK 4 — Nginx/Apache combined log
    if NGINX_RE.match(first_line):
        return {
            "type":   "waf",
            "format": "nginx_apache_combined",
            "parser": "waf_parser",
            "valid":  True,
            "action": "parse_directly"
        }

    # CHECK 4b — DNS log (Windows debug, Pihole, CoreDNS, generic)
    from pipeline.dns_parser import is_dns_log
    if is_dns_log(filepath):
        return {
            "type":   "dns",
            "format": "dns_log",
            "parser": "dns_parser",
            "valid":  True,
            "action": "parse_directly"
        }

    # CHECK 5 — CSV format
    if "," in first_line:
        headers = [
            h.strip().strip('"').lower()
            for h in first_line.split(",")
        ]

        evtx_csv_headers = [
            "eventid", "event id", "event_id",
            "timecreated", "time created",
            "channel", "computer", "level"
        ]
        waf_csv_headers = [
            "src_ip", "source_ip", "clientip",
            "client_ip", "method", "uri", "url",
            "status", "status_code", "bytes"
        ]

        if any(h in headers for h in evtx_csv_headers):
            return {
                "type":     "evtx_csv",
                "format":   "csv_windows_event_log",
                "valid":    True,
                "action":   "use_converted_events",
                "filepath": filepath,
                "message":  "Windows Event CSV detected — will stream"
            }

        if any(h in headers for h in waf_csv_headers):
            return {
                "type":     "waf_csv",
                "format":   "csv_access_log",
                "valid":    True,
                "action":   "use_converted_events",
                "filepath": filepath,
                "message":  "WAF CSV detected — will stream"
            }

        return {
            "type":    "csv_unknown",
            "valid":   False,
            "action":  "reject",
            "message": (
                "CSV detected but columns not recognized.\n"
                "For Windows logs columns needed:\n"
                "  EventID, TimeCreated, Computer, Channel\n"
                "For WAF logs columns needed:\n"
                "  src_ip, method, uri, status"
            )
        }

    # CHECK 6 — JSON log
    try:
        parsed = json.loads(first_line)
        if isinstance(parsed, dict):
            return {
                "type":    "json_log",
                "format":  "json",
                "valid":   False,
                "action":  "reject",
                "message": "JSON logs not supported in v1. Coming in v2."
            }
    except Exception:
        pass

    # CHECK 7 — Unknown
    return {
        "type":   "unknown",
        "valid":  False,
        "action": "reject",
        "reason": (
            f"Cannot detect log format.\n"
            f"First line: {first_line[:100]}\n"
            f"Supported: .evtx binary, "
            f"Nginx/Apache .log, CSV"
        )
    }


def validate_and_route(filepath: str) -> dict:
    result = detect_file_type(filepath)
    result["filepath"] = filepath
    result["filename"] = Path(filepath).name
    try:
        result["size_mb"] = round(
            os.path.getsize(filepath) / (1024 * 1024), 2
        )
    except Exception:
        result["size_mb"] = 0
    return result


def route_uploaded_files(filepaths: list) -> dict:
    """
    Routes uploaded files to correct parsers.
    CSV files return generator references.
    O(1) RAM for all file types.
    """
    files  = {}
    errors = []

    for filepath in filepaths:
        result = validate_and_route(filepath)

        if not result["valid"]:
            errors.append(
                f"{result['filename']}: "
                f"{result.get('message') or result.get('reason','unknown error')}"
            )
            continue

        file_type = result["type"]

        if file_type == "evtx":
            files["evtx"] = filepath

        elif file_type == "waf":
            files["waf"] = filepath

        elif file_type == "dns":
            files["dns"] = filepath

        elif file_type == "evtx_csv":
            files["evtx"] = convert_csv_evtx(
                result["filepath"]
            )

        elif file_type == "waf_csv":
            files["waf"] = convert_csv_waf(
                result["filepath"]
            )

    if errors:
        raise ValueError("\n".join(errors))

    if not files:
        raise ValueError(
            "No valid log files detected.\n"
            "Supported: .evtx binary, "
            "Nginx/Apache .log, DNS debug/query .log, CSV"
        )

    return files


if __name__ == "__main__":
    import sys
    sys.path.insert(
        0, str(Path(__file__).resolve().parents[1])
    )

    print("=== File Detector Test ===\n")

    test_files = [
        "uploads/security.evtx",
        "uploads/sample_waf.log",
    ]

    for filepath in test_files:
        if not os.path.exists(filepath):
            print(f"Skipping (not found): {filepath}\n")
            continue

        result = validate_and_route(filepath)
        print(f"File:    {result['filename']}")
        print(f"Size:    {result['size_mb']} MB")
        print(f"Type:    {result['type']}")
        print(f"Format:  {result.get('format','')}")
        print(f"Valid:   {result['valid']}")
        if result.get('message'):
            print(f"Message: {result['message']}")
        print()

    print("--- Testing route_uploaded_files ---")
    try:
        files = route_uploaded_files([
            "uploads/security.evtx",
            "uploads/sample_waf.log"
        ])
        print(f"Result: {list(files.keys())}")
        for k, v in files.items():
            if type(v).__name__ == "generator":
                print(f"  {k}: [Live Generator Stream Handle]")
            else:
                print(f"  {k}: {v}")
    except ValueError as e:
        print(f"Error: {e}")
