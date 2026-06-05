"""
triage_agent.py
───────────────
Builds the correlated triage context string passed to the LLM.

Sections (never truncated):
  §0  Cross-source correlation pivots   ← NEW
  §1  Global attack timeline            ← NEW
  §2  Incident overview
  §3  Critical alerts
  §4  WAF / web attack detections
  §5  Confirmed suspicious EVTX events
  §6  Events requiring investigation
  §7  IOC cross-reference table         ← EXPANDED
  §8  Analysis instructions
  §9  Baseline normal activity          ← always last, dropped first if needed
"""

import json
import os
import re
from pathlib import Path

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

# Maps sigma rule names to their primary EID for forensic field extraction
RULE_TO_EID = {
    # Brute force / logon
    "Failed Login":                              "4625",
    "Brute Force Login Attempt":                 "4625",
    "Potential Credential Brute Force":          "4625",
    "Multiple Failed Logins":                    "4625",
    "Explicit Credential Use":                   "4648",
    "Logon Using Explicit Credentials":          "4648",
    "Pass-the-Hash":                             "4624",
    "Pass-the-Hash Lateral Movement":            "4624",
    "Pass-the-Hash - NTLM Logon":                "4624",

    # Privilege / account
    "Admin Privilege Assigned":                  "4672",
    "Dangerous Privilege Assignment":            "4672",
    "Special Privileges Assigned":               "4672",
    "User Added to High-Privilege AD":           "4728",
    "Hidden Backdoor Account":                   "4726",
    "New User Account Created":                  "4720",

    # Process creation (EID 4688 / Sysmon 1)
    "Suspicious Process Creation":               "4688",
    "Office Application Spawning Shell":         "1",
    "Regsvr32 Spawning Suspicious Child":        "4688",
    "Executable Running From User-Writable":     "4688",
    "WMI Remote Process Creation":               "4688",
    "RDP Session Hijack via TSCON":              "4688",
    "WinRS Remote Shell Execution":              "4688",
    "ADFind Execution":                          "4688",
    "SharpHound/BloodHound":                     "4688",
    "nltest Domain Trust":                       "4688",
    "Network Share Discovery":                   "4688",
    "Rclone Data Exfiltration":                  "4688",
    "Certutil Malicious Use":                    "4688",
    "Suspicious Data Archiving":                 "4688",
    "ntdsutil IFM":                              "4688",
    "LSASS Dump via comsvcs.dll":                "4688",
    "Event Log Clearing via wevtutil":           "4688",
    "Shadow Copy Deletion":                      "4688",
    "Windows Defender Disabled via Command":     "4688",
    "Windows Firewall Disabled":                 "4688",
    "Impacket/PSExec Remote Service":            "7045",

    # PowerShell
    "PowerShell Script Block Logged":            "4104",
    "Malicious PowerShell Offensive":            "4104",
    "PowerShell Download Cradle":                "4104",
    "PowerShell AMSI Bypass":                    "4104",
    "PowerShell Mimikatz":                       "4104",
    "PowerShell Large Encoded":                  "4104",
    "PowerShell In-Memory .NET":                 "4104",
    "PowerShell Defender Disable":               "4104",
    "Windows Defender Disabled via Set-Mp":      "4104",
    "PowerShell History Cleared":                "4104",
    "PowerShell Timestomping":                   "4104",

    # AD / Credential
    "DCSync Attack":                             "4662",
    "DCSync Rights Granted":                     "5136",
    "DCShadow":                                  "5137",
    "AS-REP Roasting":                           "4768",
    "Kerberoasting Burst":                       "4769",
    "WDigest Plaintext Credential":              "4657",
    "LSASS Memory Access via Security Audit":    "4656",
    "Sysmon LSASS Memory Access":                "10",

    # Sysmon
    "Sysmon Process Tampering":                  "25",
    "Sysmon Remote Thread Injection":            "8",
    "Sysmon Named Pipe Created":                 "17",
    "Non-Network Process Making Outbound":       "3",
    "Unsigned DLL Loaded":                       "7",
    "Executable Written to Startup":             "11",

    # Persistence / Evasion
    "Scheduled Task with Encoded":               "4698",
    "Scheduled Task Created and Immediately":    "4699",
    "WMI Event Subscription Created":            "19",
    "Registry Run Key Persistence":              "4657",
    "Audit Policy Disabled":                     "4719",
    "Windows Defender Exclusion":                "5007",
    "Windows Defender Real-Time":                "3002",
    "Windows Firewall Any/Any Rule":             "2004",
    "Mimikatz Kernel Driver":                    "7045",

    # SMB / RDP / BITS
    "SMB Admin Share Access":                    "5140",
    "Remote Service/Task Creation via SMB":      "5145",
    "RDP Discovery Scan":                        "131",
    "RDP/Service Tunneling":                     "4688",
    "BITS Job Downloading":                      "59",
    "Bitsadmin Download":                        "4688",
    "Data Exfiltration Tools":                   "4688",

    # Events always suspicious
    "Security Log Cleared":                      "1102",
}


def _sev_score(sev: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(
        sev.lower(), 0
    )


def _extract_eid(template: str) -> str:
    for part in template.split("|"):
        if part.startswith("EID="):
            return part[4:]
    return ""


def _rule_to_eid(rule_name: str) -> str:
    """Fuzzy-match rule name to its EID."""
    for fragment, eid in RULE_TO_EID.items():
        if fragment.lower() in rule_name.lower():
            return eid
    return ""


def _extract_forensic_fields(eid: str, metadata: dict) -> dict:
    ed = metadata.get("EventData", {})

    def g(field):
        v = ed.get(field, "")
        s = str(v).strip() if v is not None else ""
        return s if s not in ("", "-", "null", "None", "%%1796", "%%2304") else ""

    if eid in ("4625",):
        return {k: v for k, v in {
            "Account":     g("TargetUserName"),
            "Source IP":   g("IpAddress"),
            "Workstation": g("WorkstationName"),
            "Logon Type":  g("LogonType"),
            "Failure":     g("SubStatus"),
        }.items() if v}

    if eid in ("4624",):
        return {k: v for k, v in {
            "Account":   g("TargetUserName"),
            "Source IP": g("IpAddress"),
            "Logon Type": g("LogonType"),
            "Auth":      g("AuthenticationPackageName"),
        }.items() if v}

    if eid in ("4648",):
        return {k: v for k, v in {
            "Subject":       g("SubjectUserName"),
            "Target User":   g("TargetUserName"),
            "Target Server": g("TargetServerName"),
        }.items() if v}

    if eid in ("4662", "5136"):
        return {k: v for k, v in {
            "Subject":    g("SubjectUserName"),
            "Object":     g("ObjectName") or g("ObjectDN"),
            "Access":     g("AccessMask"),
            "Properties": g("Properties") or g("AttributeLDAPDisplayName"),
        }.items() if v}

    if eid in ("4688", "1"):
        return {k: v for k, v in {
            "Account":     g("SubjectUserName") or g("User"),
            "Process":     g("NewProcessName") or g("Image"),
            "Parent":      g("ParentProcessName") or g("ParentImage"),
            "CommandLine": g("CommandLine"),
        }.items() if v}

    if eid in ("4672",):
        return {k: v for k, v in {
            "Account":    g("SubjectUserName"),
            "Privileges": g("PrivilegeList"),
        }.items() if v}

    if eid in ("7045",):
        return {k: v for k, v in {
            "Service":  g("ServiceName"),
            "Path":     g("ServiceFileName"),
        }.items() if v}

    if eid in ("4104",):
        script = g("ScriptBlockText")
        return {"Script": script[:400]} if script else {}

    if eid in ("10",):
        return {k: v for k, v in {
            "Source":  g("SourceImage"),
            "Target":  g("TargetImage"),
            "Access":  g("GrantedAccess"),
        }.items() if v}

    if eid in ("3",):
        return {k: v for k, v in {
            "Process":   g("Image"),
            "Dest IP":   g("DestinationIp"),
            "Dest Port": g("DestinationPort"),
        }.items() if v}

    if eid in ("1102",):
        return {k: v for k, v in {
            "Cleared by": g("SubjectUserName"),
        }.items() if v}

    return {}


GENERIC_BENIGN_PATTERNS = {
    "windows update", "microsoft antimalware", "volume shadow audit",
    "application error", "application hang", "windows error reporting",
    "service control manager", "kernel-general", "kernel-power",
    "disk", "ntfs", "user logoff", "account was logged off",
    "account logged off", "logoff event",
}


def is_benign_hit(hit: dict) -> bool:
    return any(p in hit.get("rule_name", "").lower() for p in GENERIC_BENIGN_PATTERNS)


# ────────────────────────────────────────────────────────────────────────────
# SECTION BUILDERS
# ────────────────────────────────────────────────────────────────────────────

def _section_pivots(pivots: list) -> str:
    """§0 — Cross-source correlation pivots."""
    if not pivots:
        return ""
    lines = ["=== §0 CROSS-SOURCE CORRELATIONS (HIGHEST PRIORITY) ===\n\n"]
    lines.append(
        "The following IOCs were observed across MULTIPLE log sources.\n"
        "Each pivot links a web-tier event to a host-tier event — "
        "confirming the attacker moved from one layer to the other.\n\n"
    )
    for p in pivots:
        sources_str = " → ".join(s.upper() for s in p["sources"])
        lines.append(
            f"  PIVOT [{p['pivot_type']}]\n"
            f"    IOC:     {p['ioc_type']} = {p['ioc_value']}\n"
            f"    Sources: {sources_str}\n"
            f"    Rules:   {', '.join(p['rule_names'])}\n"
            f"    Meaning: {p['description']}\n\n"
        )
    return "".join(lines)


def _section_timeline(timeline: list, pivots: list = None) -> str:
    """§1 — Global attack timeline with [WAF]/[EVTX]/[DNS] source labels.

    Each entry is one sigma rule firing, showing:
      [SRC] timestamp  [SEVERITY] conf=N.NN  Rule Name  (MITRE)  — host/IP
    Pivot-linked IOC values are annotated with ★ to highlight chain events.
    """
    if not timeline:
        return ""

    # Build set of pivot IOC values for annotation
    pivot_iocs = set()
    for p in (pivots or []):
        pivot_iocs.add(str(p.get("ioc_value","")).lower())

    lines = ["=== §1 GLOBAL ATTACK TIMELINE ===\n\n"]
    lines.append(
        "  Format: [SOURCE] timestamp  [SEVERITY] conf  Rule Name  (MITRE)  — host\n"
        "  ★ = IOC linked by cross-source pivot (see §0)\n\n"
    )

    high_plus = [e for e in timeline
                 if e.get("severity","").upper() in ("CRITICAL","HIGH")]
    entries = high_plus if high_plus else timeline[:40]

    for e in entries:
        ts      = (e.get("ts") or "unknown")[:19]
        label   = e.get("label","[EVTX]")
        sev     = e.get("severity","?")
        name    = e.get("name","?")
        tech    = e.get("technique","")
        conf    = e.get("confidence", 0)
        systems = [s for s in e.get("systems",[]) if s and s != "unknown"]
        esrcs   = e.get("event_sources", [])

        # Check if any IOC in this hit matches a pivot
        hit_iocs = set()
        # Pull IPs from systems if they look like IPs
        for s in systems:
            if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', s):
                hit_iocs.add(s.lower())
        is_pivot_linked = bool(hit_iocs & pivot_iocs)
        star = " ★" if is_pivot_linked else ""

        conf_str = f"{conf:.2f}" if isinstance(conf, float) else str(conf)
        line = f"  {label} {ts}  [{sev:8}] {conf_str}  {name}{star}"
        if tech:
            line += f"  ({tech})"
        if systems:
            line += f"  — {', '.join(systems[:2])}"
        lines.append(line + "\n")

    lines.append("\n")
    return "".join(lines)


def _section_overview(sigma_hits: list, total_events: int,
                      total_groups: int) -> str:
    """§2 — Incident overview."""
    critical_hits = [h for h in sigma_hits
                     if h.get("severity","").lower() in ("critical","high")]
    source_types = set()
    for h in sigma_hits:
        src = h.get("source","chainsaw")
        if src == "scenario_engine":  source_types.add("behavioral")
        elif src == "sigma_lite":     source_types.add("custom_rule")
        elif src in ("waf","dns"):    source_types.add(src)
        else:                         source_types.add("chainsaw")

    if len(source_types) >= 3:     auto_conf = "CONFIRMED"
    elif len(source_types) == 2:   auto_conf = "PROBABLE"
    elif critical_hits:            auto_conf = "POSSIBLE"
    else:                          auto_conf = "UNKNOWN"

    return (
        "=== §2 INCIDENT OVERVIEW ===\n\n"
        f"  Log events total  : {total_events:,}\n"
        f"  Event patterns    : {total_groups}\n"
        f"  Critical alerts   : {len(critical_hits)}\n"
        f"  Attack confirmed  : {'YES' if critical_hits else 'INVESTIGATE'}\n"
        f"  Detection sources : {len(source_types)} "
        f"({', '.join(sorted(source_types)) or 'none'})\n"
        f"  Auto confidence   : {auto_conf}\n\n"
    )


def _section_critical_alerts(sigma_hits: list) -> str:
    """§3 — Critical and high-severity sigma hits."""
    crit = [h for h in sigma_hits
            if h.get("severity","").lower() in ("critical","high")
            and not is_benign_hit(h)]
    if not crit:
        return ""
    lines = ["=== §3 CRITICAL ALERTS ===\n\n"]
    for h in sorted(crit, key=lambda x: -x.get("confidence", 0)):
        src = h.get("source","unknown")
        src_label = {
            "scenario_engine": "Behavioral Correlation Engine",
            "sigma_lite":      "Custom Detection Rule",
            "waf":             "WAF Detection",
            "dns":             "DNS Detection",
        }.get(src, "Community Sigma Rule")
        conf     = h.get("confidence", 0)
        conf_str = f"{conf:.0%}" if isinstance(conf, float) else "HIGH"
        ms       = h.get("milestones", [])
        lines.append(
            f"  ALERT: {h['rule_name']}\n"
            f"  Severity   : {h['severity'].upper()}\n"
            f"  Confidence : {conf_str}\n"
            f"  Source     : {src_label}\n"
            f"  Technique  : {h.get('technique','Unknown')}\n"
            f"  Systems    : {', '.join(h.get('systems',[]))}\n"
            f"  Hits       : {h.get('count',0)}\n"
        )
        if h.get("description"):
            lines.append(f"  What it means: {h['description']}\n")
        if ms:
            lines.append(f"  Attack stages: {' → '.join(ms)}\n")
        if h.get("time_span"):
            lines.append(f"  Time span  : {h['time_span']}\n")
        lines.append("\n")
    return "".join(lines)


def _section_waf(templates: list) -> str:
    """§4 — WAF attack detections."""
    waf_attacks = []
    for t in templates:
        tmpl = t.get("template","")
        if not tmpl.startswith("waf|"):
            continue
        parts   = {p.split("=")[0]: p.split("=")[1]
                   for p in tmpl.split("|")[1:] if "=" in p}
        attack  = parts.get("ATTACK","none")
        method  = parts.get("METHOD","?")
        status  = parts.get("STATUS","?")
        sev     = t.get("top_severity","info")
        count   = t.get("count",0)
        meta    = t.get("sample_metadata",{}) or {}
        src_ip  = meta.get("src_ip","")
        uri     = meta.get("uri","")[:120]
        first   = t.get("first_seen","?")

        if attack != "none" or sev in ("critical","high","medium"):
            waf_attacks.append(
                f"  ATTACK: {attack.upper()} via {method} → HTTP {status}\n"
                f"  Count  : {count}  First: {first}\n"
                f"  Sev    : {sev.upper()}\n"
                + (f"  Src IP : {src_ip}\n" if src_ip else "")
                + (f"  URI    : {uri}\n" if uri else "")
                + "\n"
            )
    if not waf_attacks:
        return ""
    return "=== §4 WEB ATTACK DETECTIONS ===\n\n" + "".join(waf_attacks)


def _section_confirmed_events(templates: list, sigma_by_eid: dict) -> tuple:
    """§5 — Confirmed suspicious EVTX events (matched by sigma rule)."""
    ABSOLUTE_EIDS = {"1102","4104","4720","7045","4698","4662","5136",
                     "5137","5141","5140","5145","4657","4719","4728",
                     "4732","4756","4726","4699","25","8","10","17"}
    EID_NAMES = {
        "4624":"Successful Logon","4625":"Failed Logon",
        "4648":"Logon with Explicit Credentials",
        "4662":"DS Object Access (DCSync)","4672":"Special Privileges Assigned",
        "4688":"Process Creation","4698":"Scheduled Task Created",
        "4699":"Scheduled Task Deleted","4719":"Audit Policy Changed",
        "4720":"User Account Created","4726":"User Account Deleted",
        "4728":"Member Added to Global Group","4732":"Member Added to Local Group",
        "4756":"Member Added to Universal Group",
        "4657":"Registry Value Modified",
        "4769":"Kerberos Service Ticket","4776":"NTLM Authentication",
        "5007":"Defender Config Changed","5136":"AD Object Modified",
        "5137":"AD Object Created","5140":"Network Share Accessed",
        "5145":"Network Share Object Accessed","7045":"New Service",
        "1102":"Security Audit Log Cleared","4104":"PowerShell Script Block",
        "1":"Sysmon Process Creation","3":"Sysmon Network Connection",
        "7":"Sysmon Image Loaded","8":"Sysmon Remote Thread",
        "10":"Sysmon Process Access","11":"Sysmon File Created",
        "17":"Sysmon Named Pipe","19":"Sysmon WMI Filter",
        "25":"Sysmon Process Tampering","59":"BITS Job","131":"RDP Connection",
    }
    confirmed = []
    investigate = []
    baseline = []

    for t in templates:
        tmpl = t.get("template","")
        if not tmpl.startswith("evtx|"):
            continue
        eid   = _extract_eid(tmpl)
        sev   = t.get("top_severity","info")
        count = t.get("count",0)
        first = t.get("first_seen","?")
        last  = t.get("last_seen","?")
        meta  = t.get("sample_metadata",{}) or {}
        sys   = meta.get("Computer","unknown")
        name  = EID_NAMES.get(eid, f"Event {eid}")
        forensic = _extract_forensic_fields(eid, meta) if meta else {}
        fstr = ""
        if forensic:
            fstr = "  Forensics:\n" + "".join(
                f"    {k}: {v}\n" for k,v in forensic.items()
            )

        if eid in ABSOLUTE_EIDS or eid in sigma_by_eid:
            matched_rule = sigma_by_eid.get(eid,{}).get("rule_name","Always suspicious")
            confirmed.append(
                f"  EVENT: {name} (EID={eid})\n"
                f"  Count : {count}  {first} → {last}\n"
                f"  System: {sys}\n"
                f"  Rule  : {matched_rule}\n"
                f"{fstr}\n"
            )
        elif sev in ("critical","high","medium"):
            investigate.append(
                f"  EVENT: {name} (EID={eid})\n"
                f"  Count : {count}  Sev: {sev.upper()}\n"
                f"  System: {sys}\n"
                f"{fstr}\n"
            )
        else:
            baseline.append(f"  {name} (EID={eid}): {count}x\n")

    out = ""
    if confirmed:
        out += "=== §5 CONFIRMED SUSPICIOUS EVENTS ===\n\n" + "".join(confirmed)
    if investigate:
        out += "=== §6 EVENTS REQUIRING INVESTIGATION ===\n\n" + "".join(investigate)
    return out, baseline


_SKIP_IPS   = {"-","::1","127.0.0.1","0.0.0.0","255.255.255.255","","None","null"}
_SKIP_USERS = {"system","local service","network service","anonymous logon",
               "-","","null","none"}
_IP_RE = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)


def _section_ioc_table(sigma_hits: list, templates: list,
                        pivots: list = None) -> str:
    """§7 — IOC cross-reference table.
    Pulls from:
      1. Sigma hit structured IOC fields (src_ips, host_ips, usernames, hostnames, domains)
      2. Correlation pivot records (attacker IPs with pivot context)
      3. Template EventData fields
    """
    seen: set = set()
    iocs = []

    def _add(ioc_type, value, context, priority=5):
        if not value:
            return
        value = str(value).strip()
        if not value or value in ("-",""):
            return
        if ioc_type == "IP" and value in _SKIP_IPS:
            return
        if ioc_type == "USERNAME":
            if value.endswith("$") or value.lower() in _SKIP_USERS:
                return
        key = f"{ioc_type}:{value.lower()}"
        if key not in seen:
            seen.add(key)
            iocs.append((priority, ioc_type, value, context))

    # ── 1. Correlation pivots (highest priority — rich context) ─────────────
    for p in (pivots or []):
        ptype = p.get("pivot_type","")
        ioval = p.get("ioc_value","")
        iotyp = p.get("ioc_type","IP")
        srcs  = " + ".join(s.upper() for s in p.get("sources",[]))
        rules = ", ".join(p.get("rule_names",[])[:2])
        ctx   = f"{ptype} pivot ({srcs}): {rules}"
        _add(iotyp, ioval, ctx, priority=1)

    # ── 2. Sigma hit structured fields (harvested at rule-fire time) ──────────
    for h in sigma_hits:
        rule = h.get("rule_name","")
        sev  = h.get("severity","").upper()
        tag  = f"{rule} [{sev}]"

        for ip in h.get("src_ips",[]):
            _add("IP", ip, f"WAF attacker — {tag}", priority=2)
        for ip in h.get("host_ips",[]):
            _add("IP", ip, f"Logon source — {tag}", priority=2)
        for u in h.get("usernames",[]):
            # Skip domain-prefixed duplicates if bare name already added
            bare = u.split("\\")[-1] if "\\" in u else u
            _add("USERNAME", bare, tag, priority=2)
        for h_name in h.get("hostnames",[]):
            if h_name.lower() not in ("attacker-pc","unknown"):
                _add("HOSTNAME", h_name, tag, priority=3)
        for dom in h.get("domains",[]):
            _add("DOMAIN", dom, f"DNS query — {tag}", priority=2)
        # CommandLine snippets for key attacker tools
        for cmd in h.get("cmdlines",[]):
            if any(t in cmd.lower() for t in
                   ("rclone","mimikatz","sharphound","ntdsutil","comsvcs",
                    "vssadmin","wevtutil","bloodhound","invoke-")):
                _add("CMDLINE", cmd[:120], tag, priority=4)

    # ── 3. Raw JSON scan of sample_raw (backwards compat) ────────────────────
    for h in sigma_hits:
        raw = h.get("sample_raw","")
        if not raw:
            continue
        rule = h.get("rule_name","")
        for ip in _IP_RE.findall(raw):
            if ip not in _SKIP_IPS:
                _add("IP", ip, rule, priority=4)
        for m in re.finditer(
            r'"(?:SubjectUserName|TargetUserName|User)"\s*:\s*"([^"$]{2,30})"',
            raw, re.IGNORECASE
        ):
            u = m.group(1).strip()
            if u.lower() not in _SKIP_USERS:
                _add("USERNAME", u, rule, priority=4)

    # ── 4. Template EventData fields ──────────────────────────────────────────
    for t in templates:
        meta = t.get("sample_metadata",{}) or {}
        ed   = meta.get("EventData",{}) or {}
        tmpl = t.get("template","")
        eid  = _extract_eid(tmpl)
        src  = meta.get("src_ip","")
        if src: _add("IP", src, f"WAF src_ip (EID={eid})", priority=3)
        for field in ("IpAddress","DestinationIp"):
            ip = str(ed.get(field,"")).strip()
            if ip not in _SKIP_IPS and ip:
                _add("IP", ip, f"EID={eid} logon source", priority=3)
        for field in ("SubjectUserName","TargetUserName","User"):
            u = str(ed.get(field,"")).strip()
            bare = u.split("\\")[-1] if "\\" in u else u
            _add("USERNAME", bare, f"EID={eid}", priority=3)
        host = meta.get("Computer","")
        if host and host.lower() not in ("unknown",""):
            _add("HOSTNAME", host, f"EID={eid}", priority=4)
        for field in ("Image","NewProcessName"):
            img = str(ed.get(field,"")).strip()
            if img and "\\windows\\" not in img.lower():
                _add("FILEPATH", img, f"EID={eid} process", priority=5)

    if not iocs:
        return ""

    # Sort by priority then type order
    type_order = {"IP":0,"USERNAME":1,"HOSTNAME":2,"DOMAIN":3,
                  "CMDLINE":4,"FILEPATH":5}
    iocs.sort(key=lambda x: (x[0], type_order.get(x[1],9), x[2]))
    # Remove priority from output
    iocs = [(t,v,c) for _,t,v,c in iocs]
    # Remove duplicates that might have slipped through with different priorities
    final = []
    final_keys = set()
    for t,v,c in iocs:
        k = f"{t}:{v.lower()}"
        if k not in final_keys:
            final_keys.add(k)
            final.append((t,v,c))

    lines = ["=== §7 IOC CROSS-REFERENCE TABLE ===\n\n"]
    for ioc_type, value, context in final[:40]:
        lines.append(f"  {ioc_type:<12} {value:<45} ({context[:80]})\n")
    lines.append("\n")
    return "".join(lines)


def _section_instructions() -> str:
    """§8 — Analysis instructions for the LLM."""
    return (
        "=== §8 ANALYSIS INSTRUCTIONS ===\n\n"
        "Evidence hierarchy (use in this order):\n"
        "  1. §0 CROSS-SOURCE CORRELATIONS  — highest confidence, confirms pivots\n"
        "  2. §1 GLOBAL TIMELINE            — use for attack narrative order\n"
        "  3. §3 CRITICAL ALERTS            — individual rule detections\n"
        "  4. §5 CONFIRMED SUSPICIOUS EVENTS — supporting evidence\n"
        "  5. §4 WAF DETECTIONS             — web-tier initial access\n\n"
        "Signal interpretation:\n"
        "  DCSync Attack         → attacker extracted ALL AD password hashes\n"
        "  ntdsutil IFM          → AD database copied to disk for offline cracking\n"
        "  comsvcs.dll MiniDump  → LSASS memory dumped without Mimikatz.exe\n"
        "  AMSI Bypass           → PowerShell AV scanning was disabled before execution\n"
        "  Rclone / MEGAsync     → data staged and uploaded to cloud storage\n"
        "  DNS Tunneling/DGA     → C2 communication via DNS to evade firewall\n"
        "  Shadow Copy Deletion  → ransomware removing recovery points\n"
        "  wevtutil cl / EID 1102 → attacker destroying forensic evidence\n"
        "  WEB_TO_HOST pivot     → same IP in WAF + EVTX confirms attacker crossed tiers\n"
        "  Pass-the-Hash         → stolen NTLM hash used from a different machine\n\n"
        "Rules:\n"
        "  - Every claim must cite a specific alert from §3 or event from §5.\n"
        "  - §0 pivots are your strongest evidence of attack chain continuity.\n"
        "  - §1 timeline gives you the sequence — use exact timestamps.\n"
        "  - Never invent IPs, usernames, or commands not present above.\n"
        "  - Remediation must name specific hosts and accounts from §7.\n"
        "  - Machine accounts (ending $) are never attackers.\n"
        "  - 127.0.0.1 as source = RDP tunneling, not a local user.\n\n"
    )


# ────────────────────────────────────────────────────────────────────────────
# MAIN BUILDER
# ────────────────────────────────────────────────────────────────────────────

def build_correlated_context(
    templates:      list,
    sigma_hits:     list,
    past_incidents: list = None,
    pivots:         list = None,
    timeline:       list = None,
) -> str:
    # Build sigma EID lookup for §5
    sigma_by_eid = {}
    for h in sigma_hits:
        eid = _rule_to_eid(h.get("rule_name",""))
        if not eid:
            m = re.search(r'"EventID"\s*:\s*"?(\d+)"?', h.get("sample_raw",""))
            if m:
                eid = m.group(1)
        if eid:
            sigma_by_eid[eid] = h

    total_events = sum(t.get("count",0) for t in templates)
    total_groups = len(templates)

    # Build all sections
    s0 = _section_pivots(pivots or [])
    s1 = _section_timeline(timeline or [], pivots=pivots)
    s2 = _section_overview(sigma_hits, total_events, total_groups)
    s3 = _section_critical_alerts(sigma_hits)
    s4 = _section_waf(templates)
    s5_s6, baseline_lines = _section_confirmed_events(templates, sigma_by_eid)
    s7 = _section_ioc_table(sigma_hits, templates, pivots=pivots)
    s8 = _section_instructions()

    # Never truncate §0-§3 and §7-§8 (cross-source + critical evidence)
    # Baseline (§9) is always last and always dropped first
    NEVER_TRUNCATE = s0 + s1 + s2 + s3 + s7 + s8
    CAN_TRUNCATE   = s4 + s5_s6

    context = NEVER_TRUNCATE + CAN_TRUNCATE

    # Budget: only drop baseline (§9) and then CAN_TRUNCATE tail if needed
    MAX_CHARS = 32_000   # raised from 18k — modern LLMs handle this fine
    if len(context) > MAX_CHARS:
        # Drop baseline first
        context = NEVER_TRUNCATE + CAN_TRUNCATE[:MAX_CHARS - len(NEVER_TRUNCATE)]
        context += "\n  [Some event details trimmed — critical alerts preserved]\n"

    # Append baseline at end if room
    if len(context) < MAX_CHARS - 500 and baseline_lines:
        context += "=== §9 BASELINE NORMAL ACTIVITY ===\n"
        context += "".join(baseline_lines[:5])
        context += "\n"

    return context


def run_triage(
    templates_path:  str = "uploads/templates.json",
    sigma_path:      str = "uploads/sigma_hits.json",
    output_path:     str = "uploads/triage_context.txt",
    corr_path:       str = None,
    timeline_path:   str = None,
    past_incidents:  list = None,
) -> str:
    # Load templates
    try:
        with open(templates_path) as f:
            templates = json.load(f)
    except FileNotFoundError:
        print(f"[triage] templates not found: {templates_path}")
        templates = []

    # Merge all sigma sources — deduplicate by rule_name+source
    sigma_hits_raw = []
    for path in [sigma_path, "uploads/scenario_hits.json",
                 "uploads/sigma_lite_hits.json"]:
        if os.path.exists(path):
            with open(path) as f:
                hits = json.load(f)
            sigma_hits_raw.extend(hits)
            print(f"[triage] Loaded {len(hits)} hits from {path}")

    # Deduplicate: same rule_name + source → keep highest confidence copy
    seen_rules: dict = {}
    for h in sigma_hits_raw:
        key = f"{h.get('rule_name','')}|{h.get('source','')}"
        if key not in seen_rules:
            seen_rules[key] = h
        elif h.get("confidence", 0) > seen_rules[key].get("confidence", 0):
            seen_rules[key] = h
    sigma_hits = list(seen_rules.values())
    print(f"[triage] After dedup: {len(sigma_hits)} unique hits")

    # Load cross-source correlation outputs
    pivots   = []
    timeline = []
    _corr_file     = corr_path or "uploads/correlation_hits.json"
    _timeline_file = timeline_path or "uploads/global_timeline.json"
    if os.path.exists(_corr_file):
        with open(_corr_file) as f:
            pivots = json.load(f)
        print(f"[triage] Loaded {len(pivots)} correlation pivots")
    if os.path.exists(_timeline_file):
        with open(_timeline_file) as f:
            timeline = json.load(f)
        print(f"[triage] Loaded {len(timeline)} timeline entries")

    context = build_correlated_context(
        templates, sigma_hits, past_incidents,
        pivots=pivots, timeline=timeline
    )

    os.makedirs(
        os.path.dirname(output_path) if os.path.dirname(output_path) else ".",
        exist_ok=True
    )
    with open(output_path, "w") as f:
        f.write(context)

    print(f"[triage] {len(context):,} chars built → {output_path}")
    return context


if __name__ == "__main__":
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    context = run_triage()
    print("\n" + "=" * 60)
    print(context[:4000])
    if len(context) > 4000:
        print(f"\n... [{len(context)-4000:,} more chars] ...")
