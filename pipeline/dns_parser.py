import re
import math
from datetime import datetime
from collections import defaultdict
from pathlib import Path

# Free/abused TLDs commonly used for C2 and malware hosting
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",
    ".xyz", ".top", ".loan", ".click", ".bid",
    ".zip", ".mov",
}

# Windows DNS Server debug log line
# Format: date time threadid PACKET addr UDP/TCP Rcv/Snd clientip ...
_WINDOWS_DNS_RE = re.compile(
    r'(\d{1,2}/\d{1,2}/\d{4}'
    r'\s+\d{1,2}:\d{2}:\d{2}\s+[AP]M)'
    r'\s+\w+'           # thread id
    r'\s+PACKET\s+\S+'  # PACKET + address
    r'\s+\w+'           # protocol
    r'\s+\w+'           # direction
    r'\s+([\d.]+)',     # client IP
    re.IGNORECASE
)

# Domain encoded as (n)label format in Windows DNS debug log
_WIN_DNS_DOMAIN_RE = re.compile(r'\((\d+)\)([a-zA-Z0-9_-]+)')

# Pihole/dnsmasq query log
# Format: Jan 15 14:23:01 dnsmasq[1234]: query[A] example.com from 192.168.1.100
_PIHOLE_RE = re.compile(
    r'(\w+\s+\d+\s+\d+:\d+:\d+)'
    r'.*?query\[(\w+)\]\s+([\w._-]+)\s+from\s+([\d.]+)',
    re.IGNORECASE
)

# CoreDNS / generic structured log
# Format: [INFO] 192.168.1.100:PORT - "A IN example.com. ...
_COREDNS_RE = re.compile(
    r'\[(?:INFO|WARN)\]\s+([\d.]+):\d+'
    r'\s+-\s+"(\w+)\s+IN\s+([\w._-]+)\.',
    re.IGNORECASE
)

# Generic fallback: timestamp + IP + domain on same line
_GENERIC_RE = re.compile(
    r'(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})'
    r'[^\n]*?([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})'
    r'[^\n]*?((?:[a-zA-Z0-9_-]+\.)+[a-zA-Z]{2,})',
    re.IGNORECASE
)

_TS_FORMATS = [
    "%m/%d/%Y %I:%M:%S %p",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%d %H:%M:%S",
    "%b %d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
]


def _normalize_ts(raw: str) -> str:
    raw = raw.strip()
    for fmt in _TS_FORMATS:
        try:
            return datetime.strptime(raw, fmt).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
        except Exception:
            continue
    return "unknown"


def _entropy(s: str) -> float:
    s = s.lower()
    if not s:
        return 0.0
    freq: dict = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


def _is_dga(domain: str) -> bool:
    """
    Heuristic DGA detection:
    - Long first label (> 12 chars) with high entropy (> 3.5 bits)
    - OR max consonant run >= 5 in the first label
    """
    parts = domain.rstrip(".").split(".")
    if len(parts) < 2:
        return False
    label = parts[0]
    if len(label) > 12 and _entropy(label) > 3.5:
        return True
    vowels = set("aeiou")
    run = 0
    for c in label.lower():
        if c.isalpha() and c not in vowels:
            run += 1
            if run >= 5:
                return True
        else:
            run = 0
    return False


def _dns_tunnel_label(domain: str) -> int:
    """
    Returns the length of the longest subdomain label.
    Labels > 40 chars indicate likely DNS tunneling (iodine, DNScat2).
    """
    parts = domain.rstrip(".").split(".")
    if len(parts) < 3:
        return 0
    return max(len(l) for l in parts[:-2])


def _suspicious_tld(domain: str) -> bool:
    d = domain.lower().rstrip(".")
    return any(d.endswith(t) for t in SUSPICIOUS_TLDS)


def _build_event(ts_raw: str, client_ip: str,
                 domain: str, qtype: str = "A") -> dict:
    domain  = domain.strip(".").lower()
    ts      = _normalize_ts(ts_raw)

    detections: list = []
    tunnel_len = _dns_tunnel_label(domain)
    if tunnel_len > 40:
        detections.append("dns_tunnel")
    if _is_dga(domain):
        detections.append("dga")
    if _suspicious_tld(domain):
        detections.append("suspicious_tld")

    if "dns_tunnel" in detections:
        sev = "critical"
    elif detections:
        sev = "high"
    else:
        sev = "info"

    return {
        "ts":         ts,
        "source":     "dns",
        "event_type": "dns_query",
        "severity":   sev,
        "raw":        f"{ts_raw} {client_ip} {qtype} {domain}",
        "metadata": {
            "client_ip":        client_ip,
            "domain":           domain,
            "query_type":       qtype,
            "detections":       detections,
            "subdomain_length": tunnel_len,
            "entropy":          round(_entropy(domain.split(".")[0]), 2),
        }
    }


def parse_dns(filepath: str):
    """
    Generator — streams normalized events from a DNS log file.

    Supported formats:
      - Windows DNS Server debug log  (date/time PACKET ...)
      - Pihole / dnsmasq query log    (query[A] domain from IP)
      - CoreDNS structured log        ([INFO] IP:PORT - "A IN domain.")
      - Generic syslog DNS lines      (fallback regex)

    Yields events in the same schema as evtx_parser / waf_parser.
    Adds beacon detection: same base domain queried > 20 times
    from the same source IP within the session is flagged as c2_beacon.
    """
    # Beacon detection state
    query_counts: dict = defaultdict(int)
    beacons_flagged: set = set()
    BEACON_THRESHOLD = 20

    count = 0

    try:
        with open(filepath, "r", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                event = None

                # Pihole/dnsmasq
                m = _PIHOLE_RE.search(line)
                if m:
                    event = _build_event(
                        m.group(1), m.group(4),
                        m.group(3), m.group(2)
                    )

                # Windows DNS debug log
                if not event and "PACKET" in line.upper():
                    m = _WINDOWS_DNS_RE.search(line)
                    if m:
                        labels = _WIN_DNS_DOMAIN_RE.findall(line)
                        if labels:
                            domain = ".".join(lbl for _, lbl in labels)
                            event = _build_event(
                                m.group(1), m.group(2), domain
                            )

                # CoreDNS
                if not event:
                    m = _COREDNS_RE.search(line)
                    if m:
                        event = _build_event(
                            "unknown", m.group(1),
                            m.group(3), m.group(2)
                        )

                # Generic fallback
                if not event:
                    m = _GENERIC_RE.search(line)
                    if m:
                        ts_raw = m.group("ts") if "ts" in m.groupdict() else "unknown"
                        event = _build_event(ts_raw, m.group(2), m.group(3))

                if not event:
                    continue

                count += 1

                # Beacon detection: track queries per (client, base_domain)
                meta   = event["metadata"]
                client = meta["client_ip"]
                parts  = meta["domain"].split(".")
                base   = ".".join(parts[-2:]) if len(parts) >= 2 else meta["domain"]
                bkey   = f"{client}|{base}"
                query_counts[bkey] += 1

                if (query_counts[bkey] > BEACON_THRESHOLD
                        and bkey not in beacons_flagged):
                    beacons_flagged.add(bkey)
                    meta["detections"].append("c2_beacon")
                    meta["beacon_count"] = query_counts[bkey]
                    if event["severity"] == "info":
                        event["severity"] = "high"

                if count % 100_000 == 0:
                    print(f"  [dns] {count:,} events streamed...")

                yield event

    except FileNotFoundError:
        print(f"[dns_parser] File not found: {filepath}")
    except Exception as e:
        print(f"[dns_parser] Error: {e}")

    print(f"[dns_parser] Streamed {count:,} DNS events "
          f"({len(beacons_flagged)} beacon patterns detected)")


def is_dns_log(filepath: str) -> bool:
    """
    Peek at the first 20 lines to decide if this is a DNS log.
    Returns True if DNS-specific patterns are found.
    """
    dns_indicators = [
        re.compile(r'query\[', re.IGNORECASE),
        re.compile(r'\bPACKET\b.*UDP', re.IGNORECASE),
        re.compile(r'DNS Server log', re.IGNORECASE),
        re.compile(r'\bA IN\b.*\bNOERROR\b', re.IGNORECASE),
        re.compile(r'dns.*query.*from', re.IGNORECASE),
    ]
    try:
        with open(filepath, "r", errors="replace") as f:
            for i, line in enumerate(f):
                if i > 20:
                    break
                if any(p.search(line) for p in dns_indicators):
                    return True
    except Exception:
        pass
    return False


if __name__ == "__main__":
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

    if len(sys.argv) < 2:
        print("Usage: python dns_parser.py <dns.log>")
        sys.exit(1)

    path = sys.argv[1]
    print(f"Parsing: {path}")
    print(f"Is DNS log: {is_dns_log(path)}\n")

    counts: dict = {}
    for event in parse_dns(path):
        sev = event["severity"]
        counts[sev] = counts.get(sev, 0) + 1
        if event["severity"] in ("critical", "high"):
            m = event["metadata"]
            print(f"  [{sev.upper():8}] {m['client_ip']:15} "
                  f"{m['query_type']:4} {m['domain']} "
                  f"detect={m['detections']}")

    print(f"\nSeverity counts: {counts}")
