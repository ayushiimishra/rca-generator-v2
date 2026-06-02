import os
import re
import urllib.parse
from datetime import datetime, timezone, timedelta
from typing import Generator
from collections import defaultdict, deque


def _decode_uri(uri: str) -> str:
    """
    Decode URI multiple times to catch double encoding.
    Attackers use %2527 (double encoded ') to bypass filters.
    """
    try:
        decoded = uri
        for _ in range(3):
            new = urllib.parse.unquote(decoded).lower()
            if new == decoded:
                break
            decoded = new
        return decoded
    except Exception:
        return uri.lower()

LOG_RE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<uri>.+?) HTTP/\S+" '
    r'(?P<status>\d+) (?P<bytes>\S+) '
    r'"(?P<referrer>[^"]*)" "(?P<ua>[^"]*)"'
)

IDOR_RE = re.compile(
    r'/(user|account|profile|order|invoice|document|file|download)/\d+',
    re.IGNORECASE
)

_SQL_STRONG = [
    "union select", "union all select", "' or '1'='1",
    "or 1=1", "and 1=1", "drop table", "insert into",
    "delete from", "sleep(", "benchmark(", "xp_cmdshell",
    "waitfor delay", "char(", "convert(", "cast(",
    "information_schema", "0x", "--",
    "exec(", "execute(", "sp_executesql", "declare @",
    "hex(", "unhex(", "load_file(", "into outfile",
    "into dumpfile",
]
_SQL_WEAK = ["select", "from ", "where "]

LEGITIMATE_CONTEXTS = [
    "select-all", "select-option", "select-box",
    "trade-union", "credit-union", "union-find",
    "union-jack", "from-date", "where-clause",
    "newsletter", "selected", "selection",
]
_XSS_PATTERNS = [
    "<script", "</script>", "javascript:", "onerror=",
    "onload=", "onmouseover=", "onfocus=", "onclick=",
    "alert(", "confirm(", "prompt(", "document.cookie",
    "document.write", "window.location", "<iframe",
    "<img src=", "eval(", "string.fromcharcode",
    "%3cscript", "%3e",
    "onmouseout=", "ondblclick=", "onkeypress=", "onsubmit=",
    "vbscript:", "expression(", "<svg", "<math", "&#",
]
_TRAVERSAL_PATTERNS = [
    "../", "..\\", "%2e%2e%2f", "%2e%2e/", "..%2f",
    "%252e%252e", "/etc/passwd", "/etc/shadow",
    "/etc/hosts", "/etc/hostname", "/windows/system32",
    "/windows/win.ini", "boot.ini", "wp-config.php",
    "/proc/self", "/var/log", "../../../../",
]
_CMD_PATTERNS = [
    ";ls", ";cat", ";id", ";whoami", ";pwd",
    "|whoami", "|ls", "&whoami", "&ping", "$(",
    "`", "/bin/sh", "/bin/bash", "/bin/nc", "nc -e",
    "wget http", "curl http", "python -c", "perl -e",
    "ruby -e", "powershell", "cmd.exe", "/c whoami",
]
_SENSITIVE_PATTERNS = [
    "/.env", "/.git", "/.htaccess", "/.htpasswd",
    "/config.php", "/config.yml", "/config.json",
    "/database.yml", "/settings.py", "/wp-config.php",
    "/phpinfo.php", "/info.php", "/server-status",
    "/server-info", "/backup", "/dump.sql", "/backup.sql",
    "/db.sql", "/id_rsa", "/id_dsa", "/.ssh",
    "/passwd", "/shadow",
]
_SCANNER_UAS = [
    "sqlmap", "nikto", "nmap", "masscan", "zgrab",
    "dirbuster", "gobuster", "burpsuite", "burp suite",
    "nuclei", "metasploit", "hydra", "medusa", "nessus",
    "openvas", "acunetix", "w3af", "wfuzz", "ffuf",
    "dirb", "python-requests", "go-http-client",
    "curl/", "wget/",
]
_LFI_PARAMS   = ["include=", "require=", "file=", "page=", "path="]
_LFI_PAYLOADS = [
    "../", "/etc/", "php://", "file://",
    "php://filter", "php://input", "expect://",
    "data://", "zip://",
]
_RFI_PATTERNS = [
    "include=http", "require=http", "file=http",
    "page=http", "url=http", "path=http",
    "=ftp://", "=http://", "=https://",
]
_BRUTE_URIS = ["/login", "/signin", "/auth", "/wp-login", "/admin"]

_ip_windows = defaultdict(deque)
BRUTE_THRESHOLD   = 10
BRUTE_WINDOW_SECS = 60


def _check_brute_force(ip: str, current_ts_str: str) -> tuple:
    if current_ts_str == "unknown":
        return False, 0.0, ""
    try:
        current_dt = datetime.strptime(
            current_ts_str, "%Y-%m-%dT%H:%M:%SZ"
        )
    except ValueError:
        return False, 0.0, ""

    window = _ip_windows[ip]
    window.append(current_dt)

    while window and (current_dt - window[0]).total_seconds() > BRUTE_WINDOW_SECS:
        window.popleft()

    if not window:
        if ip in _ip_windows:
            del _ip_windows[ip]
        return False, 0.0, ""

    count = len(window)
    if count >= BRUTE_THRESHOLD:
        conf   = min(0.95, 0.5 + (count * 0.045))
        detail = (f"True brute force: {count} failed logins "
                  f"from {ip} within 60s sliding window")
        return True, round(conf, 2), detail

    return False, 0.0, ""


def _parse_ts(raw: str) -> str:
    try:
        dt = datetime.strptime(raw, "%d/%b/%Y:%H:%M:%S %z")
        return dt.astimezone(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
    except Exception:
        return "unknown"


def _is_legitimate_context(uri: str) -> bool:
    u = uri.lower()
    return any(ctx in u for ctx in LEGITIMATE_CONTEXTS)


def _first_match(patterns: list, text: str):
    for p in patterns:
        if p in text:
            return p
    return None


def detect_attack(method: str, uri: str, ua: str, status: int) -> dict:
    u = _decode_uri(uri)
    a = ua.lower()

    strong_hits = sum(1 for p in _SQL_STRONG if p in u)
    weak_hits   = sum(1 for p in _SQL_WEAK   if p in u)

    if strong_hits >= 2:
        return {"attack_type": "sql_injection",
                "attack_found": True, "confidence": 0.9,
                "attack_detail": f"{strong_hits} SQL patterns matched"}
    elif strong_hits == 1 and status == 200:
        return {"attack_type": "sql_injection",
                "attack_found": True, "confidence": 0.6,
                "attack_detail": "Single SQL pattern, succeeded"}
    elif strong_hits == 1:
        return {"attack_type": "sql_injection_low",
                "attack_found": False, "confidence": 0.3,
                "attack_detail": "Single SQL pattern, blocked"}
    elif weak_hits >= 1:
        if _is_legitimate_context(uri):
            return {"attack_type": "none",
                    "attack_found": False, "confidence": 0.0,
                    "attack_detail": "Legitimate context detected"}
        return {"attack_type": "sql_injection_low",
                "attack_found": False, "confidence": 0.3,
                "attack_detail": "Weak SQL indicator in URI"}

    hit = _first_match(_XSS_PATTERNS, u)
    if hit:
        return {"attack_type": "xss", "attack_found": True,
                "confidence": 0.85,
                "attack_detail": f"XSS pattern '{hit}' found"}

    hit = _first_match(_TRAVERSAL_PATTERNS, u)
    if hit:
        return {"attack_type": "directory_traversal",
                "attack_found": True, "confidence": 0.80,
                "attack_detail": f"Traversal '{hit}' found"}

    hit = _first_match(_CMD_PATTERNS, u)
    if hit:
        return {"attack_type": "command_injection",
                "attack_found": True, "confidence": 0.90,
                "attack_detail": f"Command injection '{hit}' found"}

    if method in ("GET", "POST") and IDOR_RE.search(uri):
        return {"attack_type": "idor", "attack_found": False,
                "confidence": 0.65,
                "attack_detail": "Direct object reference in URI"}

    hit = _first_match(_SENSITIVE_PATTERNS, u)
    if hit:
        return {"attack_type": "sensitive_file",
                "attack_found": False, "confidence": 0.75,
                "attack_detail": f"Sensitive file '{hit}' accessed"}

    hit = _first_match(_SCANNER_UAS, a)
    if hit:
        return {"attack_type": "scanner", "attack_found": False,
                "confidence": 0.70,
                "attack_detail": f"Scanner '{hit}' in User-Agent"}

    for param in _LFI_PARAMS:
        if param in u:
            payload = _first_match(_LFI_PAYLOADS, u)
            if payload:
                return {"attack_type": "lfi", "attack_found": True,
                        "confidence": 0.85,
                        "attack_detail": f"LFI: {param} + {payload}"}

    hit = _first_match(_RFI_PATTERNS, u)
    if hit:
        return {"attack_type": "rfi", "attack_found": True,
                "confidence": 0.90,
                "attack_detail": f"RFI pattern '{hit}' found"}

    return {"attack_type": "none", "attack_found": False,
            "confidence": 0.0, "attack_detail": ""}


def _assign_severity(attack: dict, status: int) -> str:
    found = attack["attack_found"]
    atype = attack["attack_type"]
    if found and status == 200:           return "critical"
    elif found:                           return "high"
    elif atype == "scanner":             return "high"
    elif atype == "sensitive_file" and status == 200: return "critical"
    elif atype == "sensitive_file":      return "medium"
    elif atype == "brute_force":         return "high"
    elif atype == "idor" and status == 200: return "high"
    elif atype in ("sql_injection_low",) or status in (500, 502, 503, 401, 403):
        return "medium"
    elif status == 404:                  return "low"
    else:                                return "info"


def parse_waf(filepath: str) -> Generator:
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"WAF log file not found: {filepath}")

    count = 0
    with open(filepath, "r", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n")
            m = LOG_RE.match(line)
            if not m:
                continue

            method    = m.group("method")
            uri       = m.group("uri")
            status    = int(m.group("status"))
            bytes_raw = m.group("bytes")
            ua        = m.group("ua")

            try:
                byte_count = 0 if bytes_raw == "-" else int(bytes_raw)
            except ValueError:
                byte_count = 0

            attack   = detect_attack(method, uri, ua, status)
            severity = _assign_severity(attack, status)

            event = {
                "ts":         _parse_ts(m.group("time")),
                "source":     "waf",
                "event_type": f"{method} {uri}",
                "severity":   severity,
                "raw":        line,
                "metadata": {
                    "src_ip":        m.group("ip"),
                    "method":        method,
                    "uri":           uri,
                    "status":        status,
                    "bytes":         byte_count,
                    "user_agent":    ua,
                    "referrer":      m.group("referrer"),
                    "attack_type":   attack["attack_type"],
                    "attack_found":  attack["attack_found"],
                    "confidence":    attack["confidence"],
                    "attack_detail": attack["attack_detail"],
                },
            }

            if status == 401 and any(p in uri.lower() for p in _BRUTE_URIS):
                ip = event["metadata"]["src_ip"]
                ts = event["ts"]
                is_bf, conf, detail = _check_brute_force(ip, ts)

                if is_bf:
                    event["metadata"]["attack_type"]   = "brute_force"
                    event["metadata"]["attack_found"]  = True
                    event["metadata"]["confidence"]    = conf
                    event["metadata"]["attack_detail"] = detail
                    event["severity"] = "high"
                else:
                    event["metadata"]["attack_type"]   = "none"
                    event["metadata"]["attack_found"]  = False
                    event["metadata"]["confidence"]    = 0.0
                    event["metadata"]["attack_detail"] = (
                        "Single failed login - below threshold"
                    )
                    event["severity"] = "low"

            yield event
            count += 1
            if count % 100_000 == 0:
                print(f"  [waf] {count:,} lines streamed...")


if __name__ == "__main__":
    import sys
    from collections import Counter

    if len(sys.argv) < 2:
        print("Usage: python waf_parser.py <file.log>")
        sys.exit(1)

    print("[test] Stream-safe evaluation...")
    stream = parse_waf(sys.argv[1])

    count = 0
    sev_counter = Counter()
    atk_counter = Counter()

    for e in stream:
        count += 1
        sev_counter[e["severity"]] += 1
        atk_counter[e["metadata"]["attack_type"]] += 1

    print(f"\nTotal events parsed: {count:,}")
    print(f"Severities: {dict(sev_counter)}")
    print(f"Attacks:    {dict(atk_counter)}")
