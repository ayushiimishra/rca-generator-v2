import os
import json
import re
import time
from pathlib import Path
from datetime import datetime

GEMINI_MODEL = "gemini-2.5-flash"


def _call_gemini(prompt: str) -> str:
    try:
        from google import genai
        api_keys = [
            os.environ.get("GEMINI_API_KEY", ""),
            os.environ.get("GEMINI_API_KEY_2", ""),
        ]
        api_keys = [k for k in api_keys if k]
        if not api_keys:
            print("[phi4_rca] No GEMINI keys set")
            return ""

        for key_idx, api_key in enumerate(api_keys):
            client = genai.Client(api_key=api_key)
            for attempt in range(3):
                try:
                    print(f"[phi4_rca] Key {key_idx+1} "
                          f"attempt {attempt+1}/3...")
                    response = client.models.generate_content(
                        model=GEMINI_MODEL,
                        contents=prompt
                    )
                    if response.text:
                        print("[phi4_rca] Response received ✅")
                        return response.text
                except Exception as e:
                    err = str(e)
                    if "429" in err or "quota" in err.lower() or "exhausted" in err.lower():
                        print(f"[phi4_rca] Key {key_idx+1} "
                              f"quota exceeded. Trying next...")
                        break
                    elif "503" in err:
                        wait = 30 * (attempt + 1)
                        print(f"[phi4_rca] Overloaded. "
                              f"Waiting {wait}s...")
                        time.sleep(wait)
                    else:
                        print(f"[phi4_rca] Error: {e}")
                        break

        print("[phi4_rca] All keys exhausted")
        return ""

    except Exception as e:
        print(f"[phi4_rca] Fatal error: {e}")
        return ""


def _call_grok(prompt: str) -> str:
    try:
        from openai import OpenAI
        api_key = os.environ.get("XAI_API_KEY", "")
        if not api_key:
            print("[phi4_rca] XAI_API_KEY not set")
            return ""
        client = OpenAI(
            api_key=api_key,
            base_url="https://api.x.ai/v1"
        )
        response = client.chat.completions.create(
            model="grok-3",
            messages=[
                {
                    "role": "system",
                    "content": "You are a Senior SOC Analyst. "
                               "Respond with valid JSON only. "
                               "No markdown. No explanation."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.1,
            max_tokens=4096
        )
        return response.choices[0].message.content
    except Exception as e:
        print(f"[phi4_rca] Grok error: {e}")
        return ""


def enrich_iocs(ioc_list: list) -> list:
    import urllib.request
    import urllib.parse

    vt_key    = os.environ.get("VT_API_KEY", "")
    abuse_key = os.environ.get("ABUSEIPDB_API_KEY", "")

    if not vt_key and not abuse_key:
        print("[phi4_rca] No enrichment keys set — skipping")
        return ioc_list

    enriched = []
    print(f"[phi4_rca] Enriching {len(ioc_list)} IOCs...")

    for ioc in ioc_list:
        ioc_type   = ioc.get("type", "")
        ioc_value  = ioc.get("value", "")
        confidence = ioc.get("confidence", "LOW")
        reputation = []

        # AbuseIPDB — check IP reputation
        if ioc_type == "IP" and abuse_key:
            try:
                url = (
                    "https://api.abuseipdb.com/api/v2/check"
                    f"?ipAddress={urllib.parse.quote(ioc_value)}"
                    f"&maxAgeInDays=90"
                )
                req = urllib.request.Request(url)
                req.add_header("Key", abuse_key)
                req.add_header("Accept", "application/json")
                with urllib.request.urlopen(
                    req, timeout=5
                ) as r:
                    data = json.loads(r.read())
                score   = data["data"]["abuseConfidenceScore"]
                reports = data["data"]["totalReports"]
                country = data["data"].get("countryCode", "?")
                isp     = data["data"].get("isp", "?")
                reputation.append(
                    f"AbuseIPDB: {score}% malicious "
                    f"({reports} reports) "
                    f"country={country} isp={isp}"
                )
                if score > 50:
                    confidence = "HIGH"
                elif score > 10:
                    confidence = "MEDIUM"
                else:
                    confidence = "LOW"
                print(f"  [AbuseIPDB] {ioc_value} → "
                      f"{score}% malicious")
            except Exception as e:
                reputation.append(
                    f"AbuseIPDB: check failed ({e})"
                )

        # VirusTotal — check IP, domain, URL
        if ioc_type in ["IP", "DOMAIN", "URI"] and vt_key:
            try:
                if ioc_type == "IP":
                    endpoint = (
                        f"https://www.virustotal.com/api/v3"
                        f"/ip_addresses/{ioc_value}"
                    )
                elif ioc_type == "DOMAIN":
                    endpoint = (
                        f"https://www.virustotal.com/api/v3"
                        f"/domains/{ioc_value}"
                    )
                else:
                    url_id = urllib.parse.quote(
                        ioc_value, safe=""
                    )
                    endpoint = (
                        f"https://www.virustotal.com/api/v3"
                        f"/urls/{url_id}"
                    )

                req = urllib.request.Request(endpoint)
                req.add_header("x-apikey", vt_key)
                with urllib.request.urlopen(
                    req, timeout=5
                ) as r:
                    data  = json.loads(r.read())
                stats = (
                    data.get("data", {})
                        .get("attributes", {})
                        .get("last_analysis_stats", {})
                )
                malicious  = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                total      = sum(stats.values())
                reputation.append(
                    f"VirusTotal: {malicious} malicious "
                    f"{suspicious} suspicious "
                    f"out of {total} engines"
                )
                if malicious > 5:
                    confidence = "HIGH"
                elif malicious > 0 or suspicious > 3:
                    if confidence != "HIGH":
                        confidence = "MEDIUM"
                print(f"  [VirusTotal] {ioc_value} → "
                      f"{malicious}/{total} malicious")
            except Exception as e:
                reputation.append(
                    f"VirusTotal: check failed ({e})"
                )

        enriched.append({
            "type":       ioc_type,
            "value":      ioc_value,
            "confidence": confidence,
            "reputation": reputation
        })

    return enriched


def _parse_json_response(raw: str) -> dict:
    try:
        clean = re.sub(r"```json|```", "", raw).strip()
        start = clean.find("{")
        end   = clean.rfind("}") + 1
        if start == -1 or end == 0:
            return {"error": "No JSON found",
                    "raw": raw[:500]}
        return json.loads(clean[start:end])
    except json.JSONDecodeError as e:
        return {"error": str(e), "raw": raw[:500]}


def build_prompt(
    triage_context: str,
    past_incidents: list = None
) -> str:
    prompt = f"""You are a Senior SOC Analyst performing a formal Root Cause Analysis.
Analyse the findings below and produce a precise, evidence-anchored report.

ANALYSIS RULES:
- Base every claim on evidence explicitly present in the data below.
  Separate OBSERVED FACTS from HYPOTHESES.
  Use "evidence suggests" / "strongly indicates" for circumstantial findings.
  Never fabricate specific values (usernames, IPs, hashes) not present in the data.
- Living-off-the-Land (LotL) attacks: SYSTEM or service accounts running
  certutil, mshta, bitsadmin, regsvr32, installutil, wscript/cscript with
  suspicious args IS malicious. Do NOT dismiss these as "normal system activity".
- Services installed from AppData, Temp, Downloads, Users, or ProgramData paths
  are ALWAYS suspicious regardless of which account performed the install.
- Scheduled tasks created by SYSTEM with encoded commands or external URLs
  ARE suspicious — this is a common APT persistence technique.
- Security log cleared (EID 1102) is ALWAYS defense evasion — never benign.
- Look for BEHAVIORAL CHAINS — the combination matters more than single events:
    Brute force + successful logon = credential compromise
    Admin logon + log cleared = confirmed attacker presence
    Service install from temp path + PowerShell = malware deployment
    Explicit credential use + lateral movement EIDs = pass-the-hash / lateral movement
- Calibrate severity against log volume:
    847 failed logins in 5 minutes = brute force campaign
    1 failed login in 10,000 events = anomaly worth noting
    Use the LOG STATISTICS section to set context.
- If total events < 200 this is a targeted log sample — weight confirmed findings heavily.
- Never assume initial access vector without direct evidence.
- Never claim full compromise without proof of data access or exfiltration.
- If a finding could be legitimate admin activity, state that explicitly.
- Remediation steps MUST reference the specific hostnames, accounts, and
  timestamps from the evidence — never say "the affected system" or
  "the compromised account". Use the actual values.
  GOOD: "Isolate DC01.corp from the network"
        "Reset password for jdoe@corp.local (last seen at 03:14 UTC)"
        "Review all services installed on WKS01 since 2024-01-15T03:00Z"
  BAD:  "Isolate the affected system"
        "Reset compromised credentials"
        "Review recently installed services"

Respond ONLY with valid JSON. No markdown. No explanation. No trailing commas.

{triage_context}

Return this EXACT JSON structure (use null for unknown fields, empty array [] for none):
{{
  "summary": "3-4 sentence narrative that tells the attack story chronologically using specific timestamps, systems, and usernames from the evidence. Example: At [time] [user] logged in from [ip] to [system]. At [time] [action] was performed on [system]. This sequence indicates [attack technique].",
  "attack_confirmed": true or false,
  "attack_phase": "most specific phase: Reconnaissance/Initial Access/Execution/Persistence/Privilege Escalation/Defense Evasion/Credential Access/Discovery/Lateral Movement/Collection/Exfiltration/Command and Control/Impact",
  "confidence_level": "CONFIRMED if 3+ independent detection sources agree / PROBABLE if 2 sources agree / POSSIBLE if 1 source / UNKNOWN if unclear",
  "attack_narrative": "Step-by-step timeline of what happened using exact timestamps from the evidence. Each step on a new line. Format: [timestamp] - [what happened with specific actor and system]",
  "five_whys": [
    {{"why": "Why did this occur?",
      "answer": "Reference specific events and timestamps from the evidence"}},
    {{"why": "Why was it not detected earlier?",
      "answer": "Reference the detection gap visible in the evidence"}},
    {{"why": "Why did existing controls fail?",
      "answer": "Reference the specific control that was absent or bypassed"}},
    {{"why": "Why did the attacker succeed?",
      "answer": "Reference the specific capability or access that enabled success"}},
    {{"why": "What is the root cause?",
      "answer": "Single sentence root cause grounded in the evidence"}}
  ],
  "ioc_list": [
    {{"type": "IP or USERNAME or DOMAIN or HASH or URI or HOSTNAME",
      "value": "exact value from the evidence",
      "confidence": "HIGH or MEDIUM or LOW",
      "context": "where and how this IOC appeared in the evidence"}}
  ],
  "mitre_attack": ["T1234 - Technique Name"],
  "remediation_plan": {{
    "containment":  ["Specific action referencing exact system names and accounts from evidence"],
    "eradication":  ["..."],
    "recovery":     ["..."]
  }},
  "evidence_gaps": ["Specific thing that could not be determined from available evidence"],
  "severity_overall": "CRITICAL or HIGH or MEDIUM or LOW or INFO"
}}"""
    return prompt


TWO_PASS_THRESHOLD = 14_000  # chars; above this, compress before full RCA


def _compress_context(context: str) -> str:
    """
    First-pass LLM call: compress a large triage context into a concise
    forensic brief (~3000 chars) preserving all specific values
    (IPs, usernames, commands, timestamps). Used when context exceeds
    TWO_PASS_THRESHOLD before the main RCA call.
    """
    compress_prompt = (
        "You are a SOC analyst. Extract ONLY the security-relevant facts "
        "from the context below into a concise forensic brief. "
        "Rules:\n"
        "- Keep ALL specific values: IP addresses, usernames, process names, "
        "command lines, service names, timestamps, event counts.\n"
        "- Remove verbose descriptions, duplicate information, and normal "
        "baseline activity.\n"
        "- Output plain text, no JSON, max 3000 characters.\n"
        "- Lead with the highest-severity findings.\n\n"
        f"{context}"
    )

    gemini_key = os.environ.get("GEMINI_API_KEY", "")
    xai_key    = os.environ.get("XAI_API_KEY", "")

    compressed = ""
    if gemini_key:
        compressed = _call_gemini(compress_prompt)
    elif xai_key:
        compressed = _call_grok(compress_prompt)

    if compressed and len(compressed) < len(context):
        print(f"[phi4_rca] Two-pass compression: "
              f"{len(context):,} → {len(compressed):,} chars")
        return compressed

    # Fallback: strip baseline section without an LLM call
    baseline_marker = "--- BASELINE NORMAL ACTIVITY ---\n"
    if baseline_marker in context:
        start = context.index(baseline_marker)
        tail = context.find("---", start + len(baseline_marker) + 10)
        trimmed = (context[:start] + context[tail:]) if tail > 0 else context[:start]
        trimmed += "\n  [Baseline section removed by context budget]\n"
        if len(trimmed) < len(context):
            print(f"[phi4_rca] Two-pass fallback trim: "
                  f"{len(context):,} → {len(trimmed):,} chars")
            return trimmed

    return context[:TWO_PASS_THRESHOLD] + "\n  [Context hard-truncated]\n"


def generate_rca(
    triage_context_path: str = "uploads/triage_context.txt",
    templates_path:      str = "uploads/templates.json",
    sigma_hits_path:     str = "uploads/sigma_hits.json",
    output_path:         str = "uploads/rca_report.json",
    session_id:          str = None
) -> dict:

    try:
        with open(triage_context_path) as f:
            triage_context = f.read()
    except FileNotFoundError:
        return {"error": "triage_context.txt not found. Run demo.sh first."}

    try:
        with open(templates_path) as f:
            templates = json.load(f)
    except FileNotFoundError:
        templates = []

    try:
        with open(sigma_hits_path) as f:
            sigma_hits = json.load(f)
    except FileNotFoundError:
        sigma_hits = []

    past_incidents = []

    # Two-pass: compress large contexts before the main RCA call
    if len(triage_context) > TWO_PASS_THRESHOLD:
        print(f"[phi4_rca] Context large ({len(triage_context):,} chars) "
              f"— running compression pass...")
        triage_context = _compress_context(triage_context)

    print("[phi4_rca] Building prompt...")
    prompt = build_prompt(triage_context, past_incidents)
    print(f"[phi4_rca] Prompt size: {len(prompt):,} chars")

    raw_response = ""

    gemini_key = os.environ.get("GEMINI_API_KEY", "")
    xai_key    = os.environ.get("XAI_API_KEY", "")

    if gemini_key:
        print("[phi4_rca] Trying Gemini Flash...")
        raw_response = _call_gemini(prompt)

    if not raw_response and xai_key:
        print("[phi4_rca] Trying xAI Grok...")
        raw_response = _call_grok(prompt)

    if not raw_response:
        return {"error": "No LLM response. "
                         "Set GEMINI_API_KEY or XAI_API_KEY."}

    report = _parse_json_response(raw_response)

    # Normalise fields where LLM occasionally returns wrong type
    # attack_narrative: should be a newline-separated string, not a list
    an = report.get("attack_narrative")
    if isinstance(an, list):
        report["attack_narrative"] = "\n".join(
            str(x) for x in an
        ) if an else None
    elif an is not None and not isinstance(an, str):
        report["attack_narrative"] = str(an)

    # attack_confirmed: should be bool, not null
    if report.get("attack_confirmed") is None:
        report["attack_confirmed"] = False

    # summary fallback: use executive_summary if LLM uses old field name
    if not report.get("summary") and report.get("executive_summary"):
        report["summary"] = report["executive_summary"]

    # mitre_attack: normalise objects → "TID - Name" strings
    mitre = report.get("mitre_attack", [])
    if isinstance(mitre, list):
        normalised = []
        for m in mitre:
            if isinstance(m, dict):
                tid  = m.get("technique_id", "")
                name = m.get("technique_name", "")
                normalised.append(
                    f"{tid} - {name}" if tid else name
                )
            elif isinstance(m, str):
                normalised.append(m)
        report["mitre_attack"] = normalised

    if "ioc_list" in report and report["ioc_list"]:
        report["ioc_list"] = enrich_iocs(
            report["ioc_list"]
        )
        enriched_high = sum(
            1 for i in report["ioc_list"]
            if i.get("confidence") == "HIGH"
        )
        print(f"[phi4_rca] IOC enrichment complete: "
              f"{enriched_high} confirmed HIGH confidence")

    report["session_id"]   = (
        session_id or
        datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    )
    report["generated_at"] = datetime.utcnow().isoformat()
    report["model"]        = GEMINI_MODEL

    os.makedirs(
        os.path.dirname(output_path)
        if os.path.dirname(output_path) else ".",
        exist_ok=True
    )
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"[phi4_rca] Report saved: {output_path}")

    return report


if __name__ == "__main__":
    import sys
    sys.path.insert(
        0, str(Path(__file__).resolve().parents[1])
    )

    print("=== phi4_rca — Gemini Flash RCA Generator ===")
    print(f"Model: {GEMINI_MODEL}\n")

    missing = []
    for f in [
        "uploads/triage_context.txt",
        "uploads/templates.json",
        "uploads/sigma_hits.json"
    ]:
        status = "✅" if os.path.exists(f) else "❌ MISSING"
        print(f"  {f}: {status}")
        if "MISSING" in status:
            missing.append(f)

    if missing:
        print("\nMissing files. Run this first:")
        print("  bash demo.sh")
        sys.exit(1)

    api_key = os.environ.get("GEMINI_API_KEY", "")
    if not api_key:
        print("\n  GEMINI_API_KEY: ❌ not set")
        print("\nTo run:")
        print("  export GEMINI_API_KEY=your-key")
        print("  python pipeline/phi4_rca.py")
        print("\nGet free key from:")
        print("  https://aistudio.google.com/apikey")
        sys.exit(1)

    print(f"\n  GEMINI_API_KEY: ✅ set")
    print(f"\nStarting RCA generation...\n")

    report = generate_rca()

    if "error" in report:
        print(f"\n❌ {report['error']}")
        sys.exit(1)

    print(f"\n{'='*55}")
    print(f"RCA REPORT COMPLETE")
    print(f"{'='*55}")
    print(f"\nExecutive Summary:")
    print(f"  {report.get('executive_summary','')}")
    print(f"\nAttack confirmed: {report.get('attack_confirmed','')}")
    print(f"Attack phase:     {report.get('attack_phase','')}")
    print(f"Severity:         {report.get('severity_overall','')}")
    print(f"Confidence:       {report.get('confidence_level','')}")
    print(f"\nAffected Accounts: {', '.join(report.get('affected_accounts',[]) or []) or 'None identified'}")
    print(f"Affected Systems:  {', '.join(report.get('affected_systems',[]) or []) or 'None identified'}")
    print(f"\nRoot Cause:")
    print(f"  {report.get('root_cause','')}")
    print(f"\nEvidence Gaps:")
    for gap in report.get("evidence_gaps", []):
        print(f"  - {gap}")
    print(f"\nForensic Findings:")
    for i, ff in enumerate(report.get("forensic_findings", []), 1):
        print(f"  [{i}] {ff.get('finding','')} ({ff.get('technique','')})")
        print(f"      {ff.get('evidence','')}")
    print(f"\nMITRE ATT&CK:")
    for m in report.get("mitre_attack", []):
        if isinstance(m, dict):
            print(f"  {m.get('technique_id','')} "
                  f"{m.get('technique_name','')} — "
                  f"{m.get('evidence','')}")
        else:
            print(f"  {m}")
    print(f"\nIOCs:")
    for ioc in report.get("ioc_list", []):
        print(f"  [{ioc.get('confidence','?')}] "
              f"{ioc.get('type','?')}: {ioc.get('value','?')}"
              f" — {ioc.get('context','')}")
    print(f"\nRemediation:")
    rem = report.get("remediation_plan", {})
    for phase, steps in rem.items():
        if steps:
            print(f"  {phase.upper()}:")
            for s in steps:
                print(f"    - {s}")
    print(f"\n✅ Full report: uploads/rca_report.json")
