import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

SIMULATED_RULES = {
    "4625": {"rule": "Failed Login",
             "technique": "T1110", "severity": "high"},
    "4648": {"rule": "Explicit Credential Use",
             "technique": "T1078", "severity": "high"},
    "4672": {"rule": "Admin Privilege Assigned",
             "technique": "T1078", "severity": "medium"},
    "7045": {"rule": "New Service Installed",
             "technique": "T1543", "severity": "high"},
    "1102": {"rule": "Security Log Cleared",
             "technique": "T1562", "severity": "critical"},
    "4688": {"rule": "Suspicious Process Creation",
             "technique": "T1059", "severity": "medium"},
    "4698": {"rule": "Scheduled Task Created",
             "technique": "T1053", "severity": "high"},
    "4720": {"rule": "User Account Created",
             "technique": "T1136", "severity": "high"},
    "4904": {"rule": "VSSAudit Security Event Source Registration",
             "technique": "T1003.002", "severity": "info"},
    "4634": {"rule": "User Logoff Event",
             "technique": "T1531", "severity": "info"},
}
_SIM_THRESHOLD = 5

CHANNEL_TO_SIGMA_DIRS = {
    "Security": [
        "./sigma-rules/rules/windows/builtin/security",
    ],
    "System": [
        "./sigma-rules/rules/windows/builtin/system",
    ],
    "Application": [
        "./sigma-rules/rules/windows/builtin/application",
    ],
    "Microsoft-Windows-Sysmon/Operational": [
        "./sigma-rules/rules/windows/process_creation",
        "./sigma-rules/rules/windows/network_connection",
        "./sigma-rules/rules/windows/image_load",
        "./sigma-rules/rules/windows/file",
        "./sigma-rules/rules/windows/registry",
        "./sigma-rules/rules/windows/pipe_created",
        "./sigma-rules/rules/windows/process_access",
        "./sigma-rules/rules/windows/driver_load",
        "./sigma-rules/rules/windows/create_remote_thread",
        "./sigma-rules/rules/windows/raw_access_thread",
        "./sigma-rules/rules/windows/process_tampering",
        "./sigma-rules/rules/windows/create_stream_hash",
    ],
    "Microsoft-Windows-PowerShell/Operational": [
        "./sigma-rules/rules/windows/powershell",
    ],
    "Windows PowerShell": [
        "./sigma-rules/rules/windows/powershell",
    ],
    "Microsoft-Windows-TaskScheduler/Operational": [
        "./sigma-rules/rules/windows/builtin/taskscheduler",
    ],
    "Microsoft-Windows-DNS-Client/Operational": [
        "./sigma-rules/rules/windows/builtin/dns_client",
    ],
    "Microsoft-Windows-Windows Defender/Operational": [
        "./sigma-rules/rules/windows/builtin/windefend",
    ],
    "Microsoft-Windows-Firewall With Advanced Security/Firewall": [
        "./sigma-rules/rules/windows/builtin/firewall_as",
    ],
    "Microsoft-Windows-WMI-Activity/Operational": [
        "./sigma-rules/rules/windows/wmi_event",
    ],
    "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational": [
        "./sigma-rules/rules/windows/builtin/terminalservices",
    ],
    "Microsoft-Windows-SMBServer/Security": [
        "./sigma-rules/rules/windows/builtin/smbserver",
    ],
}

DEFAULT_SIGMA_DIRS = [
    "./sigma-rules/rules/windows/builtin/security",
]


def _severity_key(hit: dict) -> int:
    sev = hit.get("severity", "info").lower()
    try:
        return SEVERITY_ORDER.index(sev)
    except ValueError:
        return len(SEVERITY_ORDER)


def detect_evtx_channels(evtx_path: str) -> list[str]:
    """
    Reads first 500 events to detect
    which Windows channels are in the file.
    Returns list of unique channel names found.
    """
    try:
        import evtx as evtx_lib
        from collections import Counter

        parser   = evtx_lib.PyEvtxParser(evtx_path)
        channels = Counter()
        count    = 0

        for record in parser.records_json():
            try:
                data = json.loads(record["data"])
                ch   = (data.get("Event", {})
                            .get("System", {})
                            .get("Channel", "unknown"))
                channels[ch] += 1
            except Exception:
                continue
            count += 1
            if count >= 500:
                break

        found = [ch for ch, _ in channels.most_common()]
        print(f"[chainsaw] Channels detected: {found}")
        return found

    except Exception as e:
        print(f"[chainsaw] Channel detect failed: {e}")
        return ["Security"]


def get_sigma_dirs_for_channels(
    channels: list[str]
) -> list[str]:
    """
    Returns list of existing sigma rule directories
    appropriate for the detected channels.
    """
    dirs = set()

    for channel in channels:
        mapped = CHANNEL_TO_SIGMA_DIRS.get(channel, [])
        if mapped:
            dirs.update(mapped)
        else:
            print(f"[chainsaw] Unknown channel: {channel}"
                  f" — using Security rules as default")
            dirs.update(DEFAULT_SIGMA_DIRS)

    existing = []
    for d in dirs:
        if d.endswith(".yml"):
            if os.path.isfile(d):
                existing.append(d)
        elif os.path.isdir(d):
            existing.append(d)

    if not existing:
        print(f"[chainsaw] No matching dirs found "
              f"— using default")
        return DEFAULT_SIGMA_DIRS

    print(f"[chainsaw] Sigma dirs: {existing}")
    return existing


def run_chainsaw(
    evtx_path:     str,
    chainsaw_path: str = "./chainsaw/chainsaw",
    sigma_path:    str = "./sigma-rules/rules/windows/",
) -> list[dict]:
    if not os.path.isfile(evtx_path):
        print(f"[chainsaw] evtx not found: {evtx_path}")
        return []

    if not os.path.isfile(chainsaw_path):
        print(f"[chainsaw] binary not found: {chainsaw_path}")
        return []

    # Detect channels in the evtx file
    channels = detect_evtx_channels(evtx_path)

    # Get correct sigma dirs for detected channels
    sigma_dirs = get_sigma_dirs_for_channels(channels)

    all_groups: dict = {}

    for sigma_dir in sigma_dirs:
        print(f"[chainsaw] Scanning with: {sigma_dir}")
        if not os.path.isdir(sigma_dir) and \
           not os.path.isfile(sigma_dir):
            print(f"[chainsaw] Skipping — not found: {sigma_dir}")
            continue

        output_path = os.path.join(
            tempfile.gettempdir(),
            f"chainsaw_{os.path.basename(sigma_dir)}.json"
        )
        if os.path.exists(output_path):
            try:
                os.remove(output_path)
            except Exception:
                pass

        cmd = [
            chainsaw_path,
            "hunt",
            "--sigma", sigma_dir,
            "--mapping",
            "./chainsaw/mappings/sigma-event-logs-all.yml",
            "--output", output_path,
            "--json",
            evtx_path,
        ]

        try:
            result = subprocess.run(
                cmd,
                timeout=120,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            if result.returncode != 0:
                print(f"[chainsaw] exit {result.returncode}"
                      f" on {sigma_dir}")
                continue
        except subprocess.TimeoutExpired:
            print(f"[chainsaw] timeout on {sigma_dir}")
            continue
        except Exception as e:
            print(f"[chainsaw] failed on {sigma_dir}: {e}")
            continue

        if not os.path.isfile(output_path):
            continue
        if os.path.getsize(output_path) == 0:
            try:
                os.remove(output_path)
            except Exception:
                pass
            continue

        try:
            with open(output_path, "r",
                      encoding="utf-8",
                      errors="replace") as f:
                raw = json.load(f)
        except Exception as e:
            print(f"[chainsaw] parse error: {e}")
            continue
        finally:
            try:
                os.remove(output_path)
            except Exception:
                pass

        if not raw:
            continue

        for hit in raw:
            try:
                rule_name = hit.get("name", "Unknown")
                severity  = hit.get("level",
                                    "medium").lower()

                technique = "T0000"
                for tag in hit.get("tags", []):
                    if str(tag).lower().startswith(
                            "attack.t"):
                        technique = str(tag).split(
                            ".")[-1].upper()
                        break

                systems    = []
                sample_raw = None
                matched    = hit.get("hits", [hit])

                for m in matched:
                    computer = (
                        m.get("Computer") or
                        m.get("System", {}).get(
                            "Computer") or
                        "unknown"
                    )
                    if computer not in systems:
                        systems.append(computer)
                    if sample_raw is None:
                        sample_raw = json.dumps(m)

                if rule_name not in all_groups:
                    all_groups[rule_name] = {
                        "rule_name":  rule_name,
                        "technique":  technique,
                        "severity":   severity,
                        "count":      0,
                        "systems":    [],
                        "sample_raw": sample_raw,
                    }

                g = all_groups[rule_name]
                g["count"] += len(matched)
                for s in systems:
                    if s not in g["systems"]:
                        g["systems"].append(s)
                if (_severity_key({"severity": severity})
                        < _severity_key(g)):
                    g["severity"] = severity

            except Exception:
                continue

    hits = sorted(all_groups.values(),
                  key=_severity_key)
    total = sum(h["count"] for h in hits)
    print(f"[chainsaw] {len(hits)} rules matched "
          f"{total:,} total hits")

    os.makedirs("uploads", exist_ok=True)
    with open("uploads/sigma_hits.json", "w") as f:
        json.dump(hits, f, indent=2)

    return hits


def simulate_chainsaw(
    evtx_path: str,
    templates: list[dict]
) -> list[dict]:
    groups: dict = {}

    for t in templates:
        tmpl = t.get("template", "")
        if not tmpl.startswith("evtx|"):
            continue

        eid = None
        for part in tmpl.split("|"):
            if part.startswith("EID="):
                eid = part[4:]
                break

        if eid not in SIMULATED_RULES:
            continue

        count = t.get("count", 0)
        if count < _SIM_THRESHOLD:
            continue

        rule_info = SIMULATED_RULES[eid]
        rule_name = rule_info["rule"]

        if rule_name not in groups:
            groups[rule_name] = {
                "rule_name":  rule_name,
                "technique":  rule_info["technique"],
                "severity":   rule_info["severity"],
                "count":      0,
                "systems":    [],
                "sample_raw": t.get("sample_raw", ""),
            }

        g = groups[rule_name]
        g["count"] += count

        computer = (
            t.get("sample_metadata", {})
             .get("Computer", "unknown")
        )
        if computer and computer not in g["systems"]:
            g["systems"].append(computer)

        if _severity_key(rule_info) < _severity_key(g):
            g["severity"] = rule_info["severity"]

    hits = sorted(groups.values(), key=_severity_key)
    total = sum(h["count"] for h in hits)
    print(f"[chainsaw] [SIMULATED] {len(hits)} rules matched, "
          f"{total:,} hits")
    return hits


# Keep run_sigma as alias for compatibility
run_sigma      = run_chainsaw
simulate_sigma = simulate_chainsaw


if __name__ == "__main__":
    sys.path.insert(
        0, str(Path(__file__).resolve().parents[1])
    )

    evtx_path     = "uploads/security.evtx"
    chainsaw_path = "./chainsaw/chainsaw"
    sigma_path    = "./sigma-rules/rules/windows/"

    print("=== Chainsaw Sigma Engine ===\n")

    hits = run_chainsaw(evtx_path, chainsaw_path, sigma_path)

    if not hits:
        print("Chainsaw not available. Using simulation...")
        try:
            with open("uploads/templates.json") as f:
                templates = json.load(f)
            hits = simulate_chainsaw(evtx_path, templates)
        except FileNotFoundError:
            print("Run drain3_engine.py first.")
            hits = []

    print(f"\nTotal rules matched: {len(hits)}")
    for h in hits[:5]:
        print(f"  [{h['severity'].upper():8}] "
              f"{h['technique']:12} "
              f"— {h['rule_name']}: {h['count']} hits")

    print(f"\nSaved to uploads/sigma_hits.json")
