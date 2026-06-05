import os
import yaml
import json
from pathlib import Path
from datetime import datetime
from collections import defaultdict

RULES_DIR      = Path(__file__).parent.parent / "rules" / "evtx"
_event_windows = defaultdict(list)

ABSOLUTE_ATTACK_EIDS = {
    "1102",  # security log cleared = always critical
    "4104",  # powershell script block = always high
    "4720",  # new user account = always investigate
    "7045",  # new service = always investigate
    "4698",  # scheduled task = always investigate
    "8",     # Sysmon: create remote thread = always critical
    "10",    # Sysmon: process access (LSASS dump indicator)
    "25",    # Sysmon: process tampering = always critical
}


def load_custom_rules(rules_dir: str = None) -> list[dict]:
    base = Path(rules_dir) if rules_dir else RULES_DIR.parent
    rules = []
    if not base.exists():
        print(f"[sigma_lite] Rules base not found: {base}")
        return []
    # Scan all .yml files recursively under the rules/ directory
    for yml_file in sorted(base.rglob("*.yml")):
        try:
            with open(yml_file, encoding="utf-8") as f:
                rule = yaml.safe_load(f)
            if rule and "event_id" in rule:
                rules.append(rule)
        except Exception as e:
            print(f"[sigma_lite] Failed {yml_file.name}: {e}")
    print(f"[sigma_lite] Loaded {len(rules)} custom rules from {base}")
    return rules


# Field name aliases: Sysmon EID 1 uses Image/ParentImage;
# Security EID 4688 uses NewProcessName/ParentProcessName.
# These aliases allow rules written for Sysmon to also work on
# Security channel process creation events and vice versa.
_FIELD_ALIASES = {
    "image":             ["image", "newprocessname", "processname"],
    "newprocessname":    ["newprocessname", "image", "processname"],
    "parentimage":       ["parentimage", "parentprocessname"],
    "parentprocessname": ["parentprocessname", "parentimage"],
    "targetimage":       ["targetimage", "targetprocessname"],
    "sourceimage":       ["sourceimage", "sourceprocessname"],
}

def _get_field(event_data: dict, field: str) -> str:
    field_lower = field.lower().strip()
    candidates = _FIELD_ALIASES.get(field_lower, [field_lower])
    for candidate in candidates:
        for k, v in event_data.items():
            if k and k.lower().strip() == candidate:
                result = str(v or "").strip()
                if result:
                    return result
    return ""


def _check_condition(cond: dict, event: dict,
                     event_data: dict) -> bool:
    field = cond.get("field", "")

    if field == "count_in_window":
        src   = (event_data.get("IpAddress") or
                 event_data.get("WorkstationName") or "")
        eid   = event.get("event_type", "")
        win   = cond.get("window_seconds", 300)
        thresh = cond.get("greater_than", 10)
        key   = f"{eid}_{src}"
        ts    = event.get("ts", "unknown")
        if ts == "unknown":
            return False
        try:
            dt = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            return False
        times = _event_windows[key]
        times.append(dt)
        cutoff = [t for t in times
                  if (dt - t).total_seconds() <= win]
        _event_windows[key] = cutoff
        return len(cutoff) > thresh

    if field == "hour":
        ts = event.get("ts", "unknown")
        if ts == "unknown":
            return True
        try:
            hour = datetime.strptime(
                ts, "%Y-%m-%dT%H:%M:%SZ"
            ).hour
        except Exception:
            return True
        if cond.get("outside_business_hours"):
            return hour < 8 or hour > 18
        if cond.get("within_business_hours"):
            return 8 <= hour <= 18
        return True

    if field == "suspicious_chain":
        chain = (event.get("metadata", {})
                      .get("suspicious_chain", ""))
        if cond.get("not_empty"):
            return bool(chain and chain.strip())
        return True

    meta_dict = event.get("metadata", {})
    value = (
        _get_field(event_data, field) or
        _get_field(meta_dict, field)
    )
    vl = value.lower()

    if "not_in" in cond:
        if value in cond["not_in"]:
            return False
    if "not_ends_with" in cond:
        if value.endswith(cond["not_ends_with"]):
            return False
    if cond.get("not_empty"):
        if not value or not value.strip():
            return False
    if "contains_any" in cond:
        targets = [str(s).lower() for s in cond["contains_any"]]
        if not any(t in vl for t in targets):
            return False
    if "not_contains_any" in cond:
        targets = [str(s).lower() for s in cond["not_contains_any"]]
        if any(t in vl for t in targets):
            return False
    if "not_starts_with_any" in cond:
        targets = [str(s).lower() for s in cond["not_starts_with_any"]]
        if any(vl.startswith(t) for t in targets):
            return False
    if "equals" in cond:
        if vl != str(cond["equals"]).lower():
            return False
    if "equals_any" in cond:
        targets = [str(v).lower() for v in cond["equals_any"]]
        if vl not in targets:
            return False
    if "contains_all" in cond:
        targets = [str(s).lower() for s in cond["contains_all"]]
        if not all(t in vl for t in targets):
            return False
    if "min_length" in cond:
        if len(value) < int(cond["min_length"]):
            return False
    if "ends_with" in cond:
        if not vl.endswith(str(cond["ends_with"]).lower()):
            return False
    if "ends_with_any" in cond:
        targets = [str(s).lower() for s in cond["ends_with_any"]]
        if not any(vl.endswith(t) for t in targets):
            return False
    if "starts_with_any" in cond:
        targets = [str(s).lower() for s in cond["starts_with_any"]]
        if not any(vl.startswith(t) for t in targets):
            return False
    if "not_equals" in cond:
        if vl == str(cond["not_equals"]).lower():
            return False
    return True


def evaluate_event(event: dict,
                   rules: list[dict]) -> dict:
    event_id   = event.get("event_type", "")
    event_data = (event.get("metadata", {})
                       .get("EventData", {}))
    SEV_ORDER  = ["critical","high","medium","low","info"]
    best       = None

    # Always evaluate ALL rules with their conditions so that
    # more-specific high-severity rules (e.g. rule 15) beat
    # generic lower-severity rules (e.g. rule 05) for the same EID.
    # event_ids list lets one rule cover multiple EIDs (e.g. 4688 + Sysmon 1).
    for rule in rules:
        rule_eid  = rule.get("event_id", "")
        rule_eids = rule.get("event_ids") or []
        matched_eid = (rule_eid == event_id) or (event_id in rule_eids)
        if not matched_eid:
            continue
        conditions = rule.get("conditions", [])
        if not conditions:
            all_pass = True
        else:
            all_pass = all(
                _check_condition(c, event, event_data)
                for c in conditions
            )
        if not all_pass:
            continue
        result = {
            "rule":       rule.get("title", ""),
            "severity":   rule.get("severity", "info"),
            "confidence": rule.get("confidence", 0.5),
            "technique":  rule.get("technique", ""),
            "mitre":      rule.get("mitre", ""),
        }
        if best is None:
            best = result
        else:
            result_sev = SEV_ORDER.index(result["severity"])
            best_sev   = SEV_ORDER.index(best["severity"])
            if result_sev < best_sev:
                # higher severity wins
                best = result
            elif result_sev == best_sev:
                # same severity: higher confidence wins
                if result.get("confidence", 0) > best.get("confidence", 0):
                    best = result

    # For absolute-attack EIDs: if ALL conditions filtered the event out
    # (e.g. account exclusion), still flag with reduced confidence so these
    # events are never silently dropped.
    if best is None and event_id in ABSOLUTE_ATTACK_EIDS:
        for rule in rules:
            rule_eid  = rule.get("event_id", "")
            rule_eids = rule.get("event_ids") or []
            if rule_eid == event_id or event_id in rule_eids:
                return {
                    "rule":       rule.get("title", "Unknown"),
                    "severity":   rule.get("severity", "high"),
                    "confidence": 0.75,
                    "technique":  rule.get("technique", ""),
                    "mitre":      rule.get("mitre", ""),
                }

    return best or {
        "rule":       "no_match",
        "severity":   "info",
        "confidence": 0.0,
        "technique":  "",
        "mitre":      "",
    }


SYSTEM_ACCOUNTS = {
    "system", "local service", "network service",
    "anonymous logon", "iis apppool",
    "window manager", "font driver host",
}

LOTL_BINARIES = {
    "certutil.exe", "mshta.exe", "bitsadmin.exe",
    "installutil.exe", "regasm.exe", "regsvcs.exe",
    "odbcconf.exe", "pcalua.exe", "appsync.exe",
    "xwizard.exe", "syncappvpublishingserver.exe",
}

SUSPICIOUS_CMDLINE_FRAGMENTS = {
    "-enc", "-encodedcommand", "iex ", "invoke-expression",
    "downloadstring", "downloadfile", "delete shadows",
    "-urlcache", "bypass", "-nop ", "-w hidden",
    "net user /add", "sc create", "schtasks /create",
    "/transfer ", "mshta http", "mshta vbscript",
}

SUSPICIOUS_PATH_FRAGMENTS = {
    "\\appdata\\", "\\temp\\", "\\tmp\\",
    "\\users\\public\\", "\\downloads\\",
    "c:\\programdata\\", "c:\\windows\\temp\\",
    "c:\\$recycle.bin\\",
}

ALWAYS_EVALUATE_EIDS = {
    # Sysmon: process access, thread injection, tampering, pipe, DLL load, file
    "8", "10", "11", "17", "25",
    # PowerShell Script Block
    "4104",
    # Security: log cleared, credential, AD events
    "1102",
    "4656", "4657", "4662", "4663",   # object access / DCSync
    "4672",                            # special privileges
    "4698", "4699",                    # scheduled task create/delete
    "4719",                            # audit policy change
    "4720", "4726",                    # account create/delete
    "4728", "4732", "4756",            # group membership
    "5136", "5137", "5141",            # AD object modify/create/delete (DCShadow)
    "5140", "5145",                    # SMB share/pipe access
    "5007",                            # Defender config
    "3002",                            # Defender realtime failure
    "2004",                            # Firewall rule added
    "7045",                            # New service
    "59",  "60",                       # BITS job
    "131",                             # RDP connection attempt
    # WAF and DNS synthetic event types (never have Windows usernames)
    "waf_request", "waf_attack",
    "dns_query",
}


def is_system_activity(event: dict) -> bool:
    """
    Returns True only when the event is unambiguously benign OS noise.
    Never suppresses events with LotL indicators or persistence EIDs —
    SYSTEM/service accounts can and do perform these malicious actions.
    Handles both Security audit (4688/7045) and Sysmon (1/8/10) field names.
    """
    event_id  = event.get("event_type", "")
    metadata  = event.get("metadata", {})
    eventdata = metadata.get("EventData", {})

    raw_username = (
        eventdata.get("SubjectUserName", "") or
        eventdata.get("TargetUserName", "") or
        eventdata.get("User", "") or      # Sysmon uses User field
        metadata.get("SubjectUserName", "") or
        ""
    ).strip()
    # Sysmon User is "DOMAIN\username" — strip domain prefix
    if "\\" in raw_username:
        raw_username = raw_username.split("\\")[-1]
    username = raw_username.lower()

    process = (
        eventdata.get("NewProcessName", "") or
        eventdata.get("ProcessName", "") or
        eventdata.get("Image", "") or     # Sysmon process field
        eventdata.get("ServiceFileName", "") or
        eventdata.get("ImagePath", "") or
        ""
    ).lower().strip()

    cmdline = (eventdata.get("CommandLine", "") or "").lower()

    # Sysmon create remote thread, process access, tampering: never suppress
    if event_id in ALWAYS_EVALUATE_EIDS:
        return False

    # Sysmon process creation (EID 1): same logic as Security 4688
    if event_id == "1":
        if any(lol in process for lol in LOTL_BINARIES):
            return False
        if metadata.get("suspicious_chain"):
            return False
        if any(frag in cmdline for frag in SUSPICIOUS_CMDLINE_FRAGMENTS):
            return False
        if any(sus in process for sus in SUSPICIOUS_PATH_FRAGMENTS):
            return False
        if username.startswith("dwm-") or username.startswith("umfd-"):
            return True
        # Only suppress known system accounts; empty username = evaluate
        if username and username.endswith("$"):
            return True
        if username and any(acct in username for acct in SYSTEM_ACCOUNTS):
            return True
        return False

    # Security process creation: evaluate unless provably benign
    if event_id == "4688":
        # LotL indicators override any account filter — SYSTEM can be hijacked
        if any(lol in process for lol in LOTL_BINARIES):
            return False
        if metadata.get("suspicious_chain"):
            return False
        if any(frag in cmdline for frag in SUSPICIOUS_CMDLINE_FRAGMENTS):
            return False
        # Execution from user-writable path is always suspicious
        if any(sus in process for sus in SUSPICIOUS_PATH_FRAGMENTS):
            return False
        # DWM/UMFD — Windows display manager, genuinely benign
        if username.startswith("dwm-") or username.startswith("umfd-"):
            return True
        # Suppress only confirmed system accounts; empty username = evaluate
        if username and username.endswith("$"):
            return True
        if username and any(acct in username for acct in SYSTEM_ACCOUNTS):
            return True
        # Unknown username or named user — let the rules decide
        return False

    # New service: evaluate if path is in a user-writable location
    # (covers SYSTEM installing malware from AppData/Temp)
    if event_id == "7045":
        if any(sus in process for sus in SUSPICIOUS_PATH_FRAGMENTS):
            return False

    # Scheduled task: DWM/UMFD never create tasks; everything else is suspicious
    if event_id == "4698":
        if username.startswith("dwm-") or username.startswith("umfd-"):
            return True
        return False

    # Logon-related and other events: standard account noise filter
    # WAF and DNS events never have usernames — never suppress them
    source = event.get("source", "evtx")
    if source in ("waf", "dns"):
        return False
    if not username:
        # Unknown/missing username: evaluate rather than suppress
        # (attackers frequently run tools without a traceable username)
        return False
    if username.endswith("$"):
        return True
    if username.startswith("dwm-") or username.startswith("umfd-"):
        return True
    if any(acct in username for acct in SYSTEM_ACCOUNTS):
        return True

    return False


def run_sigma_lite(
    events,
    rules_dir:   str = None,
    output_path: str = "uploads/sigma_lite_hits.json"
) -> list[dict]:
    global _event_windows
    _event_windows = defaultdict(list)

    rules = load_custom_rules(rules_dir)
    if not rules:
        return []

    SEV_ORDER = ["critical","high","medium","low","info"]
    groups    = defaultdict(lambda: {
        "rule_name":     "",
        "technique":     "",
        "severity":      "info",
        "confidence":    0.0,
        "count":         0,
        "systems":       [],
        "sample_raw":    "",
        "source":        "sigma_lite",   # always sigma_lite (engine name)
        "event_sources": [],             # actual log sources that triggered
        "first_seen": "",
        "last_seen":  "",
        "ts":         "",
        # Structured IOC fields for correlation_engine
        "src_ips":    [],   # WAF source IPs (metadata.src_ip)
        "host_ips":   [],   # EVTX logon-source IPs (EventData.IpAddress)
        "usernames":  [],   # non-machine usernames
        "hostnames":  [],   # Computer / WorkstationName
        "domains":    [],   # DNS query domains
        "cmdlines":   [],   # CommandLine snippets (first 200 chars)
    })
    total_checked = 0

    for event in events:
        source = event.get("source", "evtx")
        # DNS events use event_type="dns_query"; WAF use waf prefix
        # Rules match by event_id — cross-source firing is prevented
        # by event_id specificity (numeric EIDs never match "dns_query")
        if is_system_activity(event):
            continue

        result   = evaluate_event(event, rules)
        total_checked += 1
        if result["confidence"] < 0.4:
            continue  # skip low confidence matches
        computer = event.get("metadata", {}).get(
            "Computer", "unknown"
        )
        if result["rule"] != "no_match":
            name = result["rule"]
            g    = groups[name]
            base_conf    = result["confidence"]
            count_so_far = g["count"] + 1

            if count_so_far == 1:
                adjusted_conf = base_conf
            elif count_so_far <= 5:
                adjusted_conf = min(
                    0.99, base_conf + 0.05
                )
            elif count_so_far <= 20:
                adjusted_conf = min(
                    0.99, base_conf + 0.10
                )
            else:
                adjusted_conf = min(
                    0.99, base_conf + 0.15
                )

            g["rule_name"]       = name
            g["technique"]       = result["technique"]
            g["confidence"]      = round(adjusted_conf, 2)
            g["base_confidence"] = base_conf
            g["count"]           += 1
            # Track which log sources triggered this rule
            esrc = event.get("source","evtx")
            if esrc not in g["event_sources"]:
                g["event_sources"].append(esrc)
            g["sample_raw"] = (
                g["sample_raw"] or
                event.get("raw", "")[:300]
            )
            event_ts = event.get("ts", "")
            if event_ts:
                if not g["first_seen"] or event_ts < g["first_seen"]:
                    g["first_seen"] = event_ts
                    g["ts"]         = event_ts
                if not g["last_seen"] or event_ts > g["last_seen"]:
                    g["last_seen"] = event_ts
            if computer not in g["systems"]:
                g["systems"].append(computer)

            # ── Harvest IOCs from the triggering event ──────────────────
            meta    = event.get("metadata", {})
            edata   = meta.get("EventData", {})
            esource = event.get("source", "evtx")

            # WAF: src_ip is in metadata.src_ip
            if esource == "waf":
                _ip = str(meta.get("src_ip", "")).strip()
                if _ip and _ip not in g["src_ips"]:
                    g["src_ips"].append(_ip)

            # EVTX: logon source IP is in EventData.IpAddress
            _logon_ip = str(edata.get("IpAddress", "")).strip()
            if _logon_ip and _logon_ip not in ("-","::1","127.0.0.1","")                     and _logon_ip not in g["host_ips"]:
                g["host_ips"].append(_logon_ip)

            # DNS: client_ip is in metadata.client_ip
            if esource == "dns":
                _dns_ip = str(meta.get("client_ip", "")).strip()
                if _dns_ip and _dns_ip not in g["src_ips"]:
                    g["src_ips"].append(_dns_ip)
                _dom = str(meta.get("domain", "")).strip()
                if _dom and _dom not in g["domains"]:
                    g["domains"].append(_dom)

            # Username from EventData (any source)
            _SKIP_USERS = {"system","local service","network service",
                           "anonymous logon","-","","null","none"}
            for _uf in ("SubjectUserName","TargetUserName","User"):
                _u = str(edata.get(_uf, "")).strip()
                if _u and not _u.endswith("$") and                         _u.lower() not in _SKIP_USERS and                         _u not in g["usernames"]:
                    g["usernames"].append(_u)

            # WorkstationName / Computer as hostnames
            for _hf in ("WorkstationName","Computer"):
                _h = str(edata.get(_hf, "") or meta.get(_hf, "")).strip()
                if _h and _h.lower() not in ("unknown","-","","localhost")                         and _h not in g["hostnames"]:
                    g["hostnames"].append(_h)
            if computer and computer not in ("unknown","")                     and computer not in g["hostnames"]:
                g["hostnames"].append(computer)

            # CommandLine snippet (first 200 chars)
            _cmd = str(edata.get("CommandLine","")).strip()[:200]
            if _cmd and _cmd not in g["cmdlines"]:
                g["cmdlines"].append(_cmd)
            if (SEV_ORDER.index(result["severity"]) <
                    SEV_ORDER.index(g["severity"])):
                g["severity"] = result["severity"]

    hits = sorted(
        groups.values(),
        key=lambda h: SEV_ORDER.index(
            h.get("severity", "info")
        )
    )
    total_hits = sum(h["count"] for h in hits)
    print(f"[sigma_lite] {len(hits)} rules matched, "
          f"{total_hits:,} hits "
          f"({total_checked:,} events checked)")

    os.makedirs(
        os.path.dirname(output_path)
        if os.path.dirname(output_path) else ".",
        exist_ok=True
    )
    with open(output_path, "w") as f:
        json.dump(hits, f, indent=2)
    return hits


if __name__ == "__main__":
    import sys
    import asyncio
    sys.path.insert(
        0, str(Path(__file__).resolve().parents[1])
    )
    from pipeline.router import route

    print("=== Sigma Lite Custom Rules Test ===\n")
    rules = load_custom_rules()
    print(f"Rules loaded: {len(rules)}")
    for r in rules:
        print(f"  [{r.get('severity','').upper():8}] "
              f"EID={r.get('event_id',''):5} "
              f"— {r.get('title','')}")

    print("\nRunning against security.evtx...")

    async def run():
        events = await route(
            {"evtx": "uploads/security.evtx"}
        )
        hits = run_sigma_lite(events)
        print(f"\nResults:")
        if hits:
            for h in hits:
                print(f"  [{h['severity'].upper():8}] "
                      f"conf={h['confidence']:.2f} "
                      f"x{h['count']:>6} "
                      f"— {h['rule_name']}")
        else:
            print("  No matches on clean machine")
            print("  This is correct behaviour")

    asyncio.run(run())
