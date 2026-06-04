import json
import os
import re
from pathlib import Path

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

RULE_TO_EID = {
    "Failed Login":                        "4625",
    "Potential Credential Brute Force":    "4625",
    "Unknown User Name Or Bad Password":   "4625",
    "Multiple Failed Logins":              "4625",

    "Explicit Credential Use":             "4648",
    "Logon Using Explicit Credentials":    "4648",

    "Admin Privilege Assigned":            "4672",
    "Special Privileges Assigned":         "4672",
    "Special Privileges Assigned To New Logon": "4672",

    "New Service Installed":               "7045",
    "A New Service Was Installed":         "7045",

    "Security Log Cleared":                "1102",
    "The Audit Log Was Cleared":           "1102",
    "Event Log Cleared":                   "1102",

    "Suspicious Process Creation":         "4688",
    "Process Creation":                    "4688",
    "Suspicious Commandline":              "4688",

    "User Logoff Event":                   "4634",
    "An Account Was Logged Off":           "4634",

    "VSSAudit Security Event Source Registration": "4904",

    # sigma_lite custom rule names
    "Brute Force Login Attempt":                        "4625",
    "After Hours Admin Privilege Assignment":           "4672",
    "Admin Privilege Assignment During Business Hours": "4672",
    "Security Log Cleared":                            "1102",
    "New Service Installed":                           "7045",
    "Explicit Credential Use":                         "4648",
    "Suspicious Process Chain Detected":               "4688",
    "Scheduled Task Created By User":                  "4698",
    "New User Account Created":                        "4720",
    "PowerShell Script Block Logged":                  "4104",
}


def _sev_score(sev: str) -> int:
    scores = {"critical":4,"high":3,"medium":2,"low":1,"info":0}
    return scores.get(sev.lower(), 0)


def _extract_eid(template: str) -> str:
    for part in template.split("|"):
        if part.startswith("EID="):
            return part[4:]
    return ""


def score_template(template: dict,
                   sigma_lookup: dict) -> int:
    score = 0
    sev   = template.get("top_severity", "info")
    score += _sev_score(sev) * 2

    if template.get("is_anomalous"):
        score += 3

    if template.get("attack_types"):
        score += 3

    eid = _extract_eid(template.get("template", ""))
    if eid and eid in sigma_lookup:
        score += 5

    conf = sigma_lookup.get(
        eid, {}
    ).get("confidence", 0)
    if conf >= 0.9:
        score += 3
    elif conf >= 0.7:
        score += 2
    elif conf >= 0.5:
        score += 1

    z = abs(template.get("z_score", 0))
    if z > 3:
        score += 2
    elif z > 2:
        score += 1

    return score


GENERIC_BENIGN_PATTERNS = {
    "windows update",
    "windows defender",
    "microsoft antimalware",
    "volume shadow",
    "vssaudit",
    "application error",
    "application hang",
    "windows error reporting",
    "service control manager",
    "kernel-general",
    "kernel-power",
    "disk",
    "ntfs",
    "distribuedcom",
    "security-spm",
    "user logoff",
    "account was logged off",
    "account logged off",
    "logoff event",
}


def is_benign_hit(hit: dict) -> bool:
    rule_name = hit.get("rule_name", "").lower()
    return any(
        pattern in rule_name
        for pattern in GENERIC_BENIGN_PATTERNS
    )


def _extract_forensic_fields(eid: str, metadata: dict) -> dict:
    ed = metadata.get("EventData", {})

    def g(field):
        v = ed.get(field, "")
        s = str(v).strip() if v is not None else ""
        return s if s not in ("", "-", "null", "None", "%%1796", "%%2304") else ""

    if eid == "4625":
        return {k: v for k, v in {
            "Account":     g("TargetUserName"),
            "Source IP":   g("IpAddress"),
            "Workstation": g("WorkstationName"),
            "Logon Type":  g("LogonType"),
            "Failure":     g("Status"),
        }.items() if v}

    if eid == "4624":
        return {k: v for k, v in {
            "Account":     g("TargetUserName"),
            "Source IP":   g("IpAddress"),
            "Logon Type":  g("LogonType"),
            "Auth":        g("AuthenticationPackageName"),
        }.items() if v}

    if eid == "4648":
        return {k: v for k, v in {
            "Subject":        g("SubjectUserName"),
            "Target User":    g("TargetUserName"),
            "Target Server":  g("TargetServerName"),
            "Source IP":      g("IpAddress"),
        }.items() if v}

    if eid == "4672":
        return {k: v for k, v in {
            "Account":    g("SubjectUserName"),
            "Privileges": g("PrivilegeList"),
        }.items() if v}

    if eid == "4688":
        return {k: v for k, v in {
            "Account":     g("SubjectUserName"),
            "Process":     g("NewProcessName"),
            "Parent":      g("ParentProcessName"),
            "CommandLine": g("CommandLine"),
        }.items() if v}

    if eid == "7045":
        return {k: v for k, v in {
            "Account":    g("SubjectUserName"),
            "Service":    g("ServiceName"),
            "Path":       g("ServiceFileName"),
            "Start Type": g("StartType"),
        }.items() if v}

    if eid == "4698":
        return {k: v for k, v in {
            "Account":   g("SubjectUserName"),
            "Task Name": g("TaskName"),
        }.items() if v}

    if eid == "4720":
        return {k: v for k, v in {
            "Created By":  g("SubjectUserName"),
            "New Account": g("TargetUserName"),
        }.items() if v}

    if eid == "1102":
        return {k: v for k, v in {
            "Account": g("SubjectUserName"),
            "Domain":  g("SubjectDomainName"),
        }.items() if v}

    if eid == "4104":
        script = g("ScriptBlockText")
        if script:
            return {"Script Preview": script[:300]}

    # Sysmon fields
    if eid == "1":   # Sysmon process creation
        return {k: v for k, v in {
            "User":        g("User"),
            "Process":     g("Image"),
            "Parent":      g("ParentImage"),
            "CommandLine": g("CommandLine"),
        }.items() if v}

    if eid == "3":   # Sysmon network connection
        return {k: v for k, v in {
            "Process":   g("Image"),
            "User":      g("User"),
            "Dest IP":   g("DestinationIp"),
            "Dest Port": g("DestinationPort"),
            "Dest Host": g("DestinationHostname"),
        }.items() if v}

    if eid == "8":   # Sysmon create remote thread
        return {k: v for k, v in {
            "Source Process": g("SourceImage"),
            "Target Process": g("TargetImage"),
        }.items() if v}

    if eid == "10":  # Sysmon process access (LSASS dump)
        return {k: v for k, v in {
            "Accessing Process": g("SourceImage"),
            "Target Process":    g("TargetImage"),
            "Access Rights":     g("GrantedAccess"),
        }.items() if v}

    if eid == "22":  # Sysmon DNS query
        return {k: v for k, v in {
            "Process": g("Image"),
            "Query":   g("QueryName"),
            "Result":  g("QueryResults"),
        }.items() if v}

    return {}


def build_correlated_context(
    templates: list,
    sigma_hits: list,
    past_incidents: list = None
) -> str:

    sigma_by_eid = {}
    for h in sigma_hits:
        eid = RULE_TO_EID.get(h.get("rule_name",""))
        if not eid and h.get("sample_raw"):
            match = re.search(
                r'"EventID":\s*"?(\d+)"?',
                h["sample_raw"]
            )
            if match:
                eid = match.group(1)
        if eid:
            sigma_by_eid[str(eid)] = h

    ABSOLUTE_EIDS = {"1102","4104","4720","7045","4698"}

    total_events = sum(
        t.get("count",0) for t in templates
    )
    total_groups = len(templates)

    critical_hits = [
        h for h in sigma_hits
        if h.get("severity","").lower()
        in ["critical","high"]
    ]

    # Fix 2: multi-source confidence calibration
    source_types = set()
    for h in sigma_hits:
        src = h.get("source", "chainsaw")
        if src == "scenario_engine":
            source_types.add("behavioral")
        elif src == "sigma_lite":
            source_types.add("custom_rule")
        else:
            source_types.add("chainsaw")

    if len(source_types) >= 3:
        auto_confidence = "CONFIRMED"
    elif len(source_types) == 2:
        auto_confidence = "PROBABLE"
    elif len(source_types) == 1 and critical_hits:
        auto_confidence = "POSSIBLE"
    else:
        auto_confidence = "UNKNOWN"

    lines = []
    lines.append("=== SECURITY INCIDENT ANALYSIS ===\n\n")

    lines.append("--- INCIDENT OVERVIEW ---\n")
    lines.append(f"  Log size:         {total_events:,} events\n")
    lines.append(f"  Event patterns:   {total_groups}\n")
    lines.append(f"  Critical alerts:  {len(critical_hits)}\n")
    lines.append(f"  Attack confirmed: {'YES' if critical_hits else 'INVESTIGATE'}\n")
    lines.append(
        f"  Detection sources: {len(source_types)} "
        f"({', '.join(sorted(source_types)) or 'none'})\n"
    )
    lines.append(f"  Auto confidence:  {auto_confidence}\n\n")

    if critical_hits:
        lines.append("--- CRITICAL ALERTS (highest priority) ---\n\n")
        for h in critical_hits:
            src = h.get("source","unknown")
            src_label = (
                "Behavioral Correlation Engine"
                if src == "scenario_engine"
                else "Custom Detection Rule"
                if src == "sigma_lite"
                else "Community Sigma Rule"
            )
            conf = h.get("confidence","")
            conf_str = f"{conf:.0%}" if isinstance(conf, float) else "HIGH"
            lines.append(
                f"  ALERT: {h['rule_name']}\n"
                f"  Severity:   {h['severity'].upper()}\n"
                f"  Confidence: {conf_str}\n"
                f"  Source:     {src_label}\n"
                f"  Technique:  {h.get('technique','Unknown')}\n"
                f"  Systems:    {', '.join(h.get('systems',[]))}\n"
                f"  Count:      {h.get('count',0)} occurrence(s)\n"
            )
            if h.get("description"):
                lines.append(
                    f"  Description: {h['description']}\n"
                )
            if h.get("time_span"):
                lines.append(
                    f"  Time span:  {h['time_span']}\n"
                )
            lines.append("\n")

    confirmed_eids = []
    investigate_eids = []
    baseline_eids = []

    for t in templates:
        tmpl = t.get("template","")
        if not tmpl.startswith("evtx|"):
            continue
        eid = _extract_eid(tmpl)
        sev = t.get("top_severity","info")
        count = t.get("count",0)
        z = t.get("z_score",0.0)
        anomalous = t.get("is_anomalous",False)
        first = t.get("first_seen","unknown")
        last = t.get("last_seen","unknown")
        systems = []
        meta = t.get("sample_metadata",{})
        if meta:
            comp = meta.get("Computer","")
            if comp and comp != "unknown":
                systems.append(comp)

        EID_NAMES = {
            "4624": "Successful Logon",
            "4625": "Failed Logon",
            "4634": "Logoff",
            "4648": "Logon with Explicit Credentials",
            "4672": "Special Privileges Assigned",
            "4688": "Process Creation",
            "4698": "Scheduled Task Created",
            "4720": "User Account Created",
            "4769": "Kerberos Service Ticket Requested",
            "4776": "NTLM Authentication",
            "7045": "New Service Installed",
            "1102": "Security Audit Log Cleared",
            "4104": "PowerShell Script Block",
            "5156": "Network Connection Allowed",
            "5158": "Network Connection Permitted",
            # Sysmon
            "1":  "Sysmon Process Creation",
            "3":  "Sysmon Network Connection",
            "6":  "Sysmon Driver Loaded",
            "7":  "Sysmon Image Loaded",
            "8":  "Sysmon Create Remote Thread",
            "10": "Sysmon Process Access (LSASS)",
            "11": "Sysmon File Created",
            "17": "Sysmon Named Pipe Created",
            "22": "Sysmon DNS Query",
            "25": "Sysmon Process Tampering",
        }
        eid_name = EID_NAMES.get(eid, f"Event {eid}")

        forensic = _extract_forensic_fields(eid, meta) if meta else {}
        forensic_str = ""
        if forensic:
            forensic_str = "  Forensic details:\n"
            for k, v in forensic.items():
                forensic_str += f"    {k}: {v}\n"

        if eid in ABSOLUTE_EIDS:
            confirmed_eids.append(
                f"  EVENT: {eid_name} (EID={eid})\n"
                f"  Count:      {count} occurrence(s)\n"
                f"  First seen: {first}\n"
                f"  Last seen:  {last}\n"
                f"  Systems:    {', '.join(systems) or 'unknown'}\n"
                f"  NOTE: This event is ALWAYS suspicious\n"
                f"{forensic_str}\n"
            )
        elif eid in sigma_by_eid:
            hit = sigma_by_eid[eid]
            confirmed_eids.append(
                f"  EVENT: {eid_name} (EID={eid})\n"
                f"  Count:      {count} occurrence(s)\n"
                f"  First seen: {first}\n"
                f"  Last seen:  {last}\n"
                f"  Systems:    {', '.join(systems) or 'unknown'}\n"
                f"  Confirmed by: {hit['rule_name']}\n"
                f"{forensic_str}\n"
            )
        elif sev in ["critical","high","medium"]:
            investigate_eids.append(
                f"  EVENT: {eid_name} (EID={eid})\n"
                f"  Count:      {count} occurrence(s)\n"
                f"  Severity:   {sev.upper()}\n"
                f"  First seen: {first}\n"
                f"  Systems:    {', '.join(systems) or 'unknown'}\n"
                f"{forensic_str}\n"
            )
        else:
            baseline_eids.append(
                f"  {eid_name} (EID={eid}): "
                f"{count}x — normal activity\n"
            )

    # WAF / web access log templates
    waf_attacks = []
    waf_baseline = []
    for t in templates:
        tmpl = t.get("template", "")
        if not tmpl.startswith("waf|"):
            continue
        parts = {p.split("=")[0]: p.split("=")[1]
                 for p in tmpl.split("|")[1:]
                 if "=" in p}
        attack  = parts.get("ATTACK", "none")
        method  = parts.get("METHOD", "?")
        status  = parts.get("STATUS", "?")
        count   = t.get("count", 0)
        sev     = t.get("top_severity", "info")
        first   = t.get("first_seen", "unknown")
        last    = t.get("last_seen", "unknown")
        anomalous = t.get("is_anomalous", False)
        meta    = t.get("sample_metadata", {}) or {}
        src_ip  = meta.get("src_ip", "")
        uri     = meta.get("uri", "")[:120]

        if attack != "none" or sev in ("critical", "high", "medium") or anomalous:
            waf_attacks.append(
                f"  ATTACK: {attack.upper()} via {method} → HTTP {status}\n"
                f"  Count:      {count} occurrence(s)\n"
                f"  First seen: {first}\n"
                f"  Last seen:  {last}\n"
                f"  Severity:   {sev.upper()}\n"
                + (f"  Source IP:  {src_ip}\n" if src_ip else "")
                + (f"  Sample URI: {uri}\n" if uri else "")
                + ("\n")
            )
        else:
            waf_baseline.append(
                f"  {method} {status}: {count}x — normal\n"
            )

    if waf_attacks:
        lines.append("--- WEB ATTACK DETECTIONS ---\n\n")
        lines.extend(waf_attacks)
    elif waf_baseline:
        lines.append("--- WEB TRAFFIC SUMMARY ---\n")
        total_waf = sum(t.get("count", 0) for t in templates
                        if t.get("template", "").startswith("waf|"))
        lines.append(f"  Total requests: {total_waf:,}\n")
        lines.append(f"  Traffic patterns: {len(waf_baseline)}\n")
        lines.append("  No attack signatures detected in web logs.\n\n")

    if confirmed_eids:
        lines.append("--- CONFIRMED SUSPICIOUS EVENTS ---\n\n")
        lines.extend(confirmed_eids)

    if investigate_eids:
        lines.append("--- EVENTS REQUIRING INVESTIGATION ---\n\n")
        lines.extend(investigate_eids)

    if baseline_eids:
        lines.append("--- BASELINE NORMAL ACTIVITY ---\n")
        lines.extend(baseline_eids[:5])
        lines.append("\n")

    other_hits = [
        h for h in sigma_hits
        if h.get("severity","").lower()
        not in ["critical","high"]
    ]
    if other_hits:
        lines.append("--- OTHER DETECTIONS ---\n")
        for h in other_hits:
            lines.append(
                f"  {h['rule_name']} "
                f"[{h['severity'].upper()}] "
                f"— {h.get('count',0)} hit(s)\n"
            )
        lines.append("\n")

    # Fix 3: pre-extract IOCs from templates so the LLM has concrete values
    extracted_iocs = []
    for t in templates:
        meta  = t.get("sample_metadata", {}) or {}
        edata = meta.get("EventData", {}) or {}
        tmpl  = t.get("template", "")
        eid   = _extract_eid(tmpl)

        ip = edata.get("IpAddress", "")
        if ip and ip not in {"-", "::1", "127.0.0.1", "", "None", "null"}:
            extracted_iocs.append(
                {"type": "IP", "value": ip,
                 "context": f"EID={eid} logon source"}
            )

        user = (
            edata.get("SubjectUserName", "") or
            edata.get("TargetUserName", "") or ""
        )
        if (user and not user.endswith("$")
                and user.upper() not in {
                    "SYSTEM", "LOCAL SERVICE",
                    "NETWORK SERVICE", "-", ""}):
            extracted_iocs.append(
                {"type": "USERNAME", "value": user,
                 "context": f"EID={eid} actor"}
            )

        computer = meta.get("Computer", "")
        if computer and computer not in {"unknown", ""}:
            extracted_iocs.append(
                {"type": "HOSTNAME", "value": computer,
                 "context": f"EID={eid} target system"}
            )

        img = (edata.get("Image", "") or
               edata.get("NewProcessName", ""))
        if img and "windows" not in img.lower():
            extracted_iocs.append(
                {"type": "FILEPATH", "value": img,
                 "context": f"EID={eid} process"}
            )

    seen_iocs: set = set()
    unique_iocs = []
    for ioc in extracted_iocs:
        key = f"{ioc['type']}:{ioc['value']}"
        if key not in seen_iocs and ioc["value"]:
            seen_iocs.add(key)
            unique_iocs.append(ioc)

    if unique_iocs:
        lines.append("--- EXTRACTED INDICATORS ---\n\n")
        for ioc in unique_iocs[:20]:
            lines.append(
                f"  {ioc['type']}: {ioc['value']}"
                f" ({ioc['context']})\n"
            )
        lines.append("\n")

    lines.append("--- ANALYSIS INSTRUCTIONS ---\n")
    lines.append(
        "Base your RCA ONLY on the events above.\n"
        "CRITICAL ALERTS are the most reliable signals.\n"
        "CONFIRMED SUSPICIOUS EVENTS support the alerts.\n"
        "Do NOT use BASELINE events as evidence of attack.\n"
        "If Security Audit Log Cleared (EID=1102) appears\n"
        "  this is ALWAYS defense evasion — never normal.\n"
        "If RDP Login from Localhost appears\n"
        "  this indicates RDP tunneling attack technique.\n"
        "Separate OBSERVED FACTS from HYPOTHESES.\n"
        "Use null for anything you cannot determine.\n"
    )

    context = "".join(lines)

    # Context budget guard — keep LLM prompt manageable
    MAX_CONTEXT_CHARS = 18_000
    if len(context) > MAX_CONTEXT_CHARS:
        # Drop baseline section (least valuable for LLM)
        baseline_marker = "--- BASELINE NORMAL ACTIVITY ---\n"
        if baseline_marker in context:
            start = context.index(baseline_marker)
            # Find next section after baseline
            tail_search = context.find("---", start + len(baseline_marker) + 10)
            if tail_search > 0:
                context = context[:start] + context[tail_search:]
            else:
                context = context[:start]
            context += "\n  [Baseline events omitted — context budget]\n"

    # If still over budget, truncate investigation section to top entries
    if len(context) > MAX_CONTEXT_CHARS:
        # Hard truncate at budget with a clear marker
        context = context[:MAX_CONTEXT_CHARS]
        context += "\n  [Context truncated at budget limit — "
        context += f"{MAX_CONTEXT_CHARS:,} chars]\n"

    return context


def run_triage(
    templates_path: str = "uploads/templates.json",
    sigma_path:     str = "uploads/sigma_hits.json",
    output_path:    str = "uploads/triage_context.txt",
    past_incidents: list = None
) -> str:

    try:
        with open(templates_path) as f:
            templates = json.load(f)
    except FileNotFoundError:
        print(f"[triage] templates not found: {templates_path}")
        templates = []

    try:
        with open(sigma_path) as f:
            sigma_hits = json.load(f)
    except FileNotFoundError:
        print(f"[triage] sigma_hits not found: {sigma_path}")
        sigma_hits = []

    try:
        with open("uploads/scenario_hits.json") as f:
            scenario_hits = json.load(f)
        if scenario_hits:
            sigma_hits = sigma_hits + scenario_hits
            print(f"[triage] Merged {len(scenario_hits)}"
                  f" scenario hits")
    except FileNotFoundError:
        pass

    try:
        with open("uploads/sigma_lite_hits.json") as f:
            lite_hits = json.load(f)
        if lite_hits:
            sigma_hits = sigma_hits + lite_hits
            print(f"[triage] Merged {len(lite_hits)}"
                  f" sigma_lite hits")
    except FileNotFoundError:
        pass

    context = build_correlated_context(
        templates, sigma_hits, past_incidents
    )

    os.makedirs(
        os.path.dirname(output_path)
        if os.path.dirname(output_path) else ".",
        exist_ok=True
    )
    with open(output_path, "w") as f:
        f.write(context)

    print(f"[triage] {len(context):,} chars built")
    print(f"[triage] Saved to {output_path}")
    return context


if __name__ == "__main__":
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    context = run_triage()
    print("\n" + "=" * 55)
    print(context)
