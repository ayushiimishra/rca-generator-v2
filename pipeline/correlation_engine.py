"""
correlation_engine.py
─────────────────────
Cross-source correlation. Operates on two data layers:

  Layer A — Sigma hit groups (from sigma_lite_hits.json)
            Each hit now carries: src_ips, host_ips, usernames,
            hostnames, domains, cmdlines.

  Layer B — Raw merged event stream (passed directly at runtime)
            Provides direct access to metadata.src_ip, EventData.IpAddress,
            metadata.client_ip, EventData.SubjectUserName, etc.

Produces:
  uploads/correlation_hits.json   — pivot records linking sources by IOC
  uploads/global_timeline.json    — all events sorted by ts with source labels

Pivot types:
  WEB_TO_HOST     — same IP seen in WAF src_ip AND EVTX IpAddress
  HOST_TO_DNS     — EVTX hostname seen as DNS client_ip origin
  CRED_REUSE      — same username seen across different host systems
  LATERAL_CHAIN   — host A accessed host B (IpAddress in EVTX logon)
  C2_BEACON       — DNS tunnel/DGA from host also has EVTX compromise detections
"""

import os
import json
import re
from pathlib import Path
from datetime import datetime
from collections import defaultdict


# ── Source label for timeline display ───────────────────────────────────────
SOURCE_LABEL = {
    "waf":             "[WAF] ",
    "dns":             "[DNS] ",
    "evtx":            "[EVTX]",
    "sigma_lite":      "[EVTX]",
    "scenario_engine": "[CORR]",
    "chainsaw":        "[EVTX]",
}

_SKIP_IPS   = {"127.0.0.1", "0.0.0.0", "255.255.255.255", "::1",
               "169.254.169.254", ""}
_SKIP_USERS = {"system", "local service", "network service",
               "anonymous logon", "-", "", "null", "none"}


# ────────────────────────────────────────────────────────────────────────────
# IOC extraction helpers
# ────────────────────────────────────────────────────────────────────────────

def _clean_ip(ip: str) -> str:
    ip = str(ip).strip()
    return ip if ip not in _SKIP_IPS and re.match(
        r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip
    ) else ""


def _clean_user(u: str) -> str:
    u = str(u).strip()
    return u if u and not u.endswith("$") and u.lower() not in _SKIP_USERS else ""


def _clean_host(h: str) -> str:
    h = str(h).strip()
    return h if h and h.lower() not in {"unknown", "localhost", "-", "", "null"} else ""


def _iocs_from_raw_event(event: dict) -> dict:
    """
    Extract all IOC-relevant fields from a single raw event
    (as produced by evtx_parser, waf_parser, dns_parser).
    Returns dict with keys: src_ips, host_ips, usernames, hostnames, domains.
    """
    meta    = event.get("metadata", {}) or {}
    edata   = meta.get("EventData", {}) or {}
    source  = event.get("source", "evtx")
    result  = defaultdict(set)

    # WAF: src_ip is the attacker IP
    if source == "waf":
        ip = _clean_ip(meta.get("src_ip", ""))
        if ip:
            result["src_ips"].add(ip)

    # DNS: client_ip is the querying host
    if source == "dns":
        ip = _clean_ip(meta.get("client_ip", ""))
        if ip:
            result["src_ips"].add(ip)
        dom = str(meta.get("domain", "")).strip()
        if dom:
            result["domains"].add(dom)

    # EVTX: IpAddress = logon source (can be attacker IP for network logons)
    ip = _clean_ip(edata.get("IpAddress", ""))
    if ip:
        result["host_ips"].add(ip)

    # Usernames
    for field in ("SubjectUserName", "TargetUserName", "User"):
        u = _clean_user(edata.get(field, ""))
        if u:
            result["usernames"].add(u)

    # Hostnames: Computer, WorkstationName
    for field in ("WorkstationName",):
        h = _clean_host(edata.get(field, ""))
        if h:
            result["hostnames"].add(h)
    comp = _clean_host(meta.get("Computer", ""))
    if comp:
        result["hostnames"].add(comp)

    return {k: list(v) for k, v in result.items()}


def _iocs_from_hit(hit: dict) -> dict:
    """
    Extract IOCs from a sigma_lite hit group (aggregated, not raw).
    Uses the structured fields added by sigma_lite.py IOC harvest patch.
    Falls back to JSON regex scan for backwards compat.
    """
    result = defaultdict(set)

    # Use structured fields if present (new)
    for ip in hit.get("src_ips", []):
        ip = _clean_ip(ip)
        if ip:
            result["src_ips"].add(ip)
    for ip in hit.get("host_ips", []):
        ip = _clean_ip(ip)
        if ip:
            result["host_ips"].add(ip)
    for u in hit.get("usernames", []):
        u = _clean_user(u)
        if u:
            result["usernames"].add(u)
    for h in hit.get("hostnames", []):
        h = _clean_host(h)
        if h:
            result["hostnames"].add(h)
    for d in hit.get("domains", []):
        if d:
            result["domains"].add(d)

    # Fallback: regex scan of sample_raw / systems
    raw = hit.get("sample_raw", "")
    if raw:
        for ip in re.findall(
            r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
            r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b', raw
        ):
            ip = _clean_ip(ip)
            if ip:
                result["host_ips"].add(ip)

    # Systems list → hostnames
    for s in hit.get("systems", []):
        h = _clean_host(s)
        if h:
            result["hostnames"].add(h)

    return {k: list(v) for k, v in result.items()}


# ────────────────────────────────────────────────────────────────────────────
# IOC Registry — maps each value to all hit indices that contain it
# ────────────────────────────────────────────────────────────────────────────

class IOCRegistry:
    def __init__(self):
        # ip_value → {"src": [hit_idx...], "host": [hit_idx...]}
        self.ips:       dict = defaultdict(lambda: {"src": [], "host": []})
        # username → [hit_idx...]
        self.users:     dict = defaultdict(list)
        # hostname → [hit_idx...]
        self.hosts:     dict = defaultdict(list)
        # domain → [hit_idx...]
        self.domains:   dict = defaultdict(list)
        # hit_idx → hit dict
        self.hits:      list = []

    def add_hit(self, hit: dict) -> int:
        idx = len(self.hits)
        self.hits.append(hit)
        iocs = _iocs_from_hit(hit)
        for ip in iocs.get("src_ips", []):
            self.ips[ip]["src"].append(idx)
        for ip in iocs.get("host_ips", []):
            self.ips[ip]["host"].append(idx)
        for u in iocs.get("usernames", []):
            self.users[u.lower()].append(idx)
        for h in iocs.get("hostnames", []):
            self.hosts[h.lower()].append(idx)
        for d in iocs.get("domains", []):
            self.domains[d.lower()].append(idx)
        return idx

    def add_raw_event(self, event: dict):
        """
        Index a raw event's IOCs directly.
        Used to build a richer IP map from the full event stream.
        Returns a lightweight hit-like dict.
        """
        iocs = _iocs_from_raw_event(event)
        source = event.get("source", "evtx")
        ts     = event.get("ts", "")
        meta   = event.get("metadata", {}) or {}
        rule   = event.get("matched_rule", "raw_event")
        hit = {
            "rule_name":  rule,
            "source":     source,
            "ts":         ts,
            "first_seen": ts,
            "systems":    [meta.get("Computer","unknown")],
            "severity":   event.get("severity","info"),
            "confidence": event.get("confidence", 0.5),
            "technique":  "",
            "_raw_event": True,
        }
        hit.update({k: list(v) for k,v in iocs.items()})
        return self.add_hit(hit)


# ────────────────────────────────────────────────────────────────────────────
# Pivot detection
# ────────────────────────────────────────────────────────────────────────────

def _source_of(hit: dict) -> str:
    return hit.get("source", "evtx")


def _sources_of(hit: dict) -> set:
    """Return all log sources that triggered this hit (may be multi-source)."""
    s = set()
    for src in hit.get("event_sources", [hit.get("source","evtx")]):
        s.add(src)
    return s


def _is_waf(hit):  return bool(_sources_of(hit) & {"waf"})
def _is_evtx(hit): return bool(_sources_of(hit) & {"evtx","sigma_lite","chainsaw"})
def _is_dns(hit):  return bool(_sources_of(hit) & {"dns"})


def find_pivots(registry: IOCRegistry) -> list:
    """
    Scan the IOC registry for cross-source relationships.
    Returns list of pivot dicts.
    """
    pivots = []
    seen_pivot_keys = set()

    def _emit(pivot_type, ioc_type, ioc_value, hit_indices, description, extra=None):
        key = f"{pivot_type}:{ioc_type}:{ioc_value}"
        if key in seen_pivot_keys:
            return
        seen_pivot_keys.add(key)

        involved = [registry.hits[i] for i in hit_indices]
        # Skip raw events — only cite named rule hits in the output
        named = [h for h in involved if not h.get("_raw_event")]
        if not named:
            return
        # Use event_sources (actual log sources that fired the rule)
        sources = list({
            s for h in named
            for s in _sources_of(h)
        })
        rule_names = list(dict.fromkeys(
            h.get("rule_name","") for h in named
            if h.get("rule_name")
        ))
        timestamps = sorted(
            h.get("first_seen","") or h.get("ts","")
            for h in named if h.get("first_seen") or h.get("ts")
        )
        p = {
            "pivot_type":  pivot_type,
            "ioc_type":    ioc_type,
            "ioc_value":   ioc_value,
            "sources":     sources,
            "rule_names":  rule_names[:6],
            "hit_count":   len(named),
            "first_seen":  timestamps[0] if timestamps else "",
            "last_seen":   timestamps[-1] if timestamps else "",
            "description": description,
        }
        if extra:
            p.update(extra)
        pivots.append(p)

    # ── WEB_TO_HOST: WAF src_ip == EVTX IpAddress (logon source) ────────────
    # Requires: IP appears in src_ips of a WAF-sourced hit
    #       AND in host_ips of an EVTX-sourced hit
    for ip, buckets in registry.ips.items():
        # src bucket: hits where this IP was captured as attacker src_ip
        src_hits_waf = [i for i in buckets["src"]
                        if not registry.hits[i].get("_raw_event")
                        and _is_waf(registry.hits[i])]
        # host bucket: hits where this IP was an EVTX logon-source IpAddress
        host_hits_evtx = [i for i in buckets["host"]
                          if not registry.hits[i].get("_raw_event")
                          and _is_evtx(registry.hits[i])]

        if src_hits_waf and host_hits_evtx:
            all_idx   = list(dict.fromkeys(src_hits_waf + host_hits_evtx))
            waf_rules  = list(dict.fromkeys(
                registry.hits[i]["rule_name"] for i in src_hits_waf))
            evtx_rules = list(dict.fromkeys(
                registry.hits[i]["rule_name"] for i in host_hits_evtx))
            all_sources = list({
                s for i in all_idx
                for s in _sources_of(registry.hits[i])
            })
            _emit(
                "WEB_TO_HOST", "IP", ip, all_idx,
                description=(
                    f"IP {ip} appeared as WAF attacker source AND as the "
                    f"logon-source IP in Windows host events — the external "
                    f"attacker who exploited the web tier authenticated to "
                    f"internal systems using stolen credentials.\n"
                    f"  WAF detections : {', '.join(waf_rules[:3])}\n"
                    f"  Host detections: {', '.join(evtx_rules[:3])}"
                ),
                extra={"attacker_ip": ip,
                       "waf_rules":   waf_rules,
                       "host_rules":  evtx_rules,
                       "all_sources": all_sources}
            )

    # ── CRED_REUSE: same username on different hostnames ─────────────────────
    for user, hit_indices in registry.users.items():
        if len(hit_indices) < 2:
            continue
        hits_u = [registry.hits[i] for i in hit_indices
                  if not registry.hits[i].get("_raw_event")]
        if len(hits_u) < 2:
            continue
        all_hosts = set()
        for h in hits_u:
            for hn in h.get("hostnames", []):
                all_hosts.add(hn.lower())
        for sys in (hh for h in hits_u for hh in h.get("systems",[])):
            all_hosts.add(sys.lower())
        all_hosts.discard("unknown")
        if len(all_hosts) >= 2:
            all_srcs = list({_source_of(h) for h in hits_u})
            _emit(
                "CRED_REUSE", "USERNAME", user,
                [i for i in hit_indices if not registry.hits[i].get("_raw_event")],
                description=(
                    f"Account '{user}' was seen in detections across multiple "
                    f"systems: {', '.join(sorted(all_hosts))}. "
                    f"This indicates lateral movement using the same credential, "
                    f"or pass-the-hash / pass-the-ticket reuse."
                ),
                extra={"account": user, "systems": sorted(all_hosts)}
            )

    # ── HOST_TO_DNS: EVTX hostname matches DNS client_ip origin ─────────────
    # (Link compromised host to its C2 DNS activity)
    # Build ip→hostname map from host_ips in EVTX hits
    ip_to_evtx_hosts: dict = defaultdict(set)
    for idx, hit in enumerate(registry.hits):
        if _is_evtx(hit) and not hit.get("_raw_event"):
            for ip in hit.get("host_ips", []):
                for h in hit.get("hostnames", []) + hit.get("systems", []):
                    if _clean_host(h):
                        ip_to_evtx_hosts[ip].add(h)

    for ip, buckets in registry.ips.items():
        dns_hits  = [i for i in buckets["src"]
                     if _is_dns(registry.hits[i]) and
                        not registry.hits[i].get("_raw_event")]
        evtx_hits = [i for i in buckets["host"]
                     if _is_evtx(registry.hits[i]) and
                        not registry.hits[i].get("_raw_event")]
        if dns_hits and evtx_hits:
            hosts = sorted(ip_to_evtx_hosts.get(ip, set()))
            _emit(
                "HOST_TO_DNS", "IP", ip,
                list(dict.fromkeys(dns_hits + evtx_hits)),
                description=(
                    f"IP {ip} generated suspicious DNS activity (C2/tunnel) "
                    f"AND appeared in host-level EVTX detections. "
                    f"This host is both compromised and communicating with C2 "
                    f"via DNS. Host(s): {', '.join(hosts) or ip}"
                ),
                extra={"c2_host_ip": ip,
                       "evtx_hosts": hosts}
            )

    # ── LATERAL_CHAIN: IpAddress in one EVTX hit == hostname in another ──────
    # (Host A's IP matches as logon source in events on Host B)
    host_to_ips: dict = defaultdict(set)  # hostname → IPs it appears as
    for idx, hit in enumerate(registry.hits):
        if _is_evtx(hit) and not hit.get("_raw_event"):
            for h in hit.get("hostnames", []) + hit.get("systems", []):
                h = _clean_host(h)
                if h:
                    for ip in hit.get("src_ips", []) + hit.get("host_ips", []):
                        host_to_ips[h.lower()].add(ip)

    # Find IPs that are both a known EVTX hostname's IP AND a host_ip in another hit
    for hostname, known_ips in host_to_ips.items():
        for ip in known_ips:
            if not _clean_ip(ip):
                continue
            victim_hits = [
                i for i in registry.ips[ip]["host"]
                if not registry.hits[i].get("_raw_event")
                and hostname not in {
                    h.lower() for h in
                    registry.hits[i].get("hostnames",[])+registry.hits[i].get("systems",[])
                }
            ]
            if victim_hits:
                source_hits = [
                    i for i in range(len(registry.hits))
                    if not registry.hits[i].get("_raw_event")
                    and hostname in {
                        h.lower() for h in
                        registry.hits[i].get("hostnames",[])+registry.hits[i].get("systems",[])
                    }
                ]
                if source_hits:
                    victim_hosts = list({
                        h for i in victim_hits
                        for h in registry.hits[i].get("hostnames",[])+
                                 registry.hits[i].get("systems",[])
                        if _clean_host(h)
                    })
                    _emit(
                        "LATERAL_CHAIN", "IP", ip,
                        list(dict.fromkeys(source_hits + victim_hits)),
                        description=(
                            f"Host '{hostname}' (IP {ip}) appeared as the "
                            f"logon source IP in detections on "
                            f"{', '.join(victim_hosts) or 'other systems'}. "
                            f"Indicates lateral movement from "
                            f"'{hostname}' → {', '.join(victim_hosts)}."
                        ),
                        extra={"source_host": hostname,
                               "victim_hosts": victim_hosts}
                    )

    # Sort: WEB_TO_HOST first (highest impact), then by hit_count desc
    pivot_order = ["WEB_TO_HOST","CRED_REUSE","LATERAL_CHAIN","HOST_TO_DNS","C2_BEACON"]
    pivots.sort(key=lambda p: (
        pivot_order.index(p["pivot_type"])
        if p["pivot_type"] in pivot_order else 99,
        -p.get("hit_count", 0)
    ))
    return pivots


# ────────────────────────────────────────────────────────────────────────────
# Global Timeline
# ────────────────────────────────────────────────────────────────────────────

def _best_label(hit: dict) -> str:
    """
    Pick the most informative source label for a hit.
    Prefer the actual log source over the engine name.
    event_sources[] carries ["waf"], ["evtx"], ["dns"] etc.
    """
    event_srcs = hit.get("event_sources", [])
    # Priority: waf > dns > evtx > scenario_engine
    for preferred in ("waf", "dns", "evtx"):
        if preferred in event_srcs:
            return SOURCE_LABEL.get(preferred, "[EVTX]")
    # Fall back to the hit's source field
    return SOURCE_LABEL.get(hit.get("source","sigma_lite"), "[EVTX]")


def build_global_timeline(hits: list) -> list:
    """
    Build a sorted, deduplicated timeline from hit groups.
    Uses event_sources[] for accurate [WAF]/[DNS]/[EVTX] labels.
    Excludes raw_event placeholders and scenario_engine entries
    (scenarios appear in §3 alerts, not the per-event timeline).
    """
    seen_keys = set()
    timeline  = []
    for hit in hits:
        if hit.get("_raw_event"):
            continue
        # Exclude scenario correlation entries from timeline
        # (they span multiple events and have no single timestamp)
        if hit.get("source") == "scenario_engine":
            continue

        ts       = hit.get("first_seen") or hit.get("ts") or "unknown"
        label    = _best_label(hit)
        sev      = hit.get("severity","info").upper()
        name     = hit.get("rule_name","")
        tech     = hit.get("technique","")
        conf     = hit.get("confidence",0)
        systems  = [s for s in hit.get("systems",[]) if s and s != "unknown"]
        src      = hit.get("source","sigma_lite")
        esrcs    = hit.get("event_sources",[src])

        # Deduplicate: same rule + same timestamp (same event fired twice)
        dedup_key = f"{name}|{ts}"
        if dedup_key in seen_keys:
            continue
        seen_keys.add(dedup_key)

        try:
            sort_key = datetime.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S").isoformat()
        except Exception:
            sort_key = "9999"

        timeline.append({
            "ts":           ts,
            "sort_key":     sort_key,
            "label":        label,
            "severity":     sev,
            "name":         name,
            "technique":    tech,
            "confidence":   conf,
            "systems":      systems,
            "source":       src,
            "event_sources": esrcs,
        })

    timeline.sort(key=lambda x: x["sort_key"])
    return timeline


# ────────────────────────────────────────────────────────────────────────────
# Main entry point
# ────────────────────────────────────────────────────────────────────────────

def run_correlation(
    sigma_lite_path: str  = "uploads/sigma_lite_hits.json",
    sigma_path:      str  = "uploads/sigma_hits.json",
    waf_hits_path:   str  = None,
    scenario_path:   str  = "uploads/scenario_hits.json",
    corr_output:     str  = "uploads/correlation_hits.json",
    timeline_output: str  = "uploads/global_timeline.json",
    raw_events:      list = None,   # optional: pass merged event stream
) -> tuple:
    """
    Load all hit files, build IOC registry, find cross-source pivots,
    build global timeline. Returns (pivots, timeline).
    raw_events: the merged event stream from evtx+waf+dns parsers.
                If provided, indexes all events for richer IP correlation.
    """
    if waf_hits_path and waf_hits_path != sigma_path:
        sigma_path = waf_hits_path

    registry = IOCRegistry()

    # ── Load sigma_lite hits (carry structured IOC fields) ──────────────────
    for path, default_source in [
        (sigma_lite_path, "sigma_lite"),
        (sigma_path,      "chainsaw"),
        (scenario_path,   "scenario_engine"),
    ]:
        if not os.path.exists(path):
            continue
        with open(path) as f:
            hits = json.load(f)
        n = 0
        for h in hits:
            if "source" not in h:
                h["source"] = default_source
            registry.add_hit(h)
            n += 1
        print(f"[correlation] Indexed {n} hits from {path}")

    # ── Index raw events if provided ─────────────────────────────────────────
    if raw_events:
        n_raw = 0
        for event in raw_events:
            # Only index events that have IP or username content
            meta  = event.get("metadata", {}) or {}
            edata = meta.get("EventData", {}) or {}
            has_ip   = bool(_clean_ip(meta.get("src_ip","")) or
                            _clean_ip(edata.get("IpAddress","")))
            has_user = bool(_clean_user(edata.get("SubjectUserName","")) or
                            _clean_user(edata.get("TargetUserName","")))
            if has_ip or has_user:
                registry.add_raw_event(event)
                n_raw += 1
        print(f"[correlation] Indexed {n_raw} raw events for IP/user cross-ref")

    if not registry.hits:
        print("[correlation] No hits to correlate")
        return [], []

    # ── Find cross-source pivots ─────────────────────────────────────────────
    pivots = find_pivots(registry)

    # Only keep named-rule hits for timeline
    named_hits = [h for h in registry.hits if not h.get("_raw_event")]
    # Deduplicate by rule_name+source for timeline
    seen = {}
    for h in named_hits:
        k = f"{h.get('rule_name','')}|{h.get('source','')}"
        if k not in seen or (h.get("confidence",0) > seen[k].get("confidence",0)):
            seen[k] = h
    timeline = build_global_timeline(list(seen.values()))

    print(f"[correlation] {len(pivots)} cross-source pivots found")
    for p in pivots:
        print(f"  [{p['pivot_type']:16}] {p['ioc_type']}:{p['ioc_value']} "
              f"sources={p['sources']}")
    print(f"[correlation] {len(timeline)} events in global timeline")

    os.makedirs(
        os.path.dirname(corr_output) if os.path.dirname(corr_output) else ".",
        exist_ok=True
    )
    with open(corr_output, "w") as f:
        json.dump(pivots, f, indent=2)
    with open(timeline_output, "w") as f:
        json.dump(timeline, f, indent=2)

    print(f"[correlation] Saved pivots   → {corr_output}")
    print(f"[correlation] Saved timeline → {timeline_output}")
    return pivots, timeline


if __name__ == "__main__":
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    print("=== Correlation Engine ===\n")
    pivots, timeline = run_correlation()
    if pivots:
        print("\nCross-source pivots:")
        for p in pivots:
            print(f"\n  [{p['pivot_type']}] {p['ioc_type']}={p['ioc_value']}")
            print(f"  {p['description']}")
    else:
        print("No cross-source pivots found.")
