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
                    from google.genai import types as genai_types
                    response = client.models.generate_content(
                        model=GEMINI_MODEL,
                        contents=prompt,
                        config=genai_types.GenerateContentConfig(
                            temperature=0.05,   # near-deterministic for JSON
                            max_output_tokens=16384,
                            response_mime_type="application/json",
                        )
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
    # Strip markdown fences (fix: \s* not \\s*)
    clean = re.sub(r"```(?:json)?\s*", "", raw).strip()
    # Remove any leading prose before the opening brace
    start = clean.find("{")
    if start == -1:
        return {"error": "No JSON object found", "raw": raw[:500]}

    # Find matching closing brace with correct escape handling (fix: "\\" not "\\\\")
    depth  = 0
    end    = -1
    in_str = False
    esc    = False
    for i, c in enumerate(clean[start:], start=start):
        if esc:
            esc = False
            continue
        if c == "\\":
            esc = True
            continue
        if c == '"':
            in_str = not in_str
            continue
        if in_str:
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                end = i + 1
                break

    # Happy path: well-formed JSON
    if end != -1:
        try:
            return json.loads(clean[start:end])
        except json.JSONDecodeError:
            pass

    # Truncated / malformed — try json_repair first (handles complex cases)
    fragment = clean[start:]
    try:
        from json_repair import repair_json
        repaired = repair_json(fragment, return_objects=True)
        if isinstance(repaired, dict) and repaired:
            repaired["_truncated"] = True
            return repaired
    except Exception:
        pass

    # Fallback: naive brace-count repair
    open_count = fragment.count("{") - fragment.count("}")
    naive = fragment + "}" * max(0, open_count)
    try:
        result = json.loads(naive)
        result["_truncated"] = True
        return result
    except json.JSONDecodeError:
        pass

    # Last resort: try the entire cleaned string
    try:
        return json.loads(clean)
    except Exception as e:
        return {"error": str(e), "raw": raw[:500]}


def build_prompt(
    triage_context: str,
    past_incidents: list = None
) -> str:
    """
    Build the full LLM prompt from the triage context.

    The triage context is structured in numbered sections:
      §0  Cross-source correlation pivots (WEB_TO_HOST, CRED_REUSE, HOST_TO_DNS, LATERAL_CHAIN)
      §1  Global attack timeline — [WAF]/[EVTX]/[DNS]/[CORR] labels, timestamped, ★ = pivot-linked
      §2  Incident overview
      §3  Critical alerts (Custom Detection Rules + Behavioral Correlation Engine)
      §4  WAF web attack detections
      §5  Confirmed suspicious EVTX events with forensic fields
      §6  Events requiring investigation
      §7  IOC cross-reference table (IP, USERNAME, HOSTNAME, DOMAIN, CMDLINE, FILEPATH)
      §8  Analysis instructions
    """
    prompt = f"""You are a Senior SOC Analyst performing a formal Root Cause Analysis.
Analyse the findings below and produce a precise, evidence-anchored report.

╔══════════════════════════════════════════════════════════╗
║           HOW TO READ THE TRIAGE CONTEXT BELOW           ║
╚══════════════════════════════════════════════════════════╝

The evidence is organised into sections §0–§8. Work through them in this order:

  §0  CROSS-SOURCE CORRELATIONS  ← START HERE. These are the strongest findings.
      Each PIVOT entry means the same IP/user/host was seen across two log sources.
      Pivot types and what each means:
        WEB_TO_HOST  : Attacker IP from WAF matches logon-source IP in Windows logs.
                       DEFINITIVE proof the web attacker moved to internal systems.
                       The WAF exploited the web server; then used stolen creds on hosts.
        CRED_REUSE   : Same username in detections across multiple systems.
                       The attacker is using one stolen account for lateral movement.
        HOST_TO_DNS  : Same internal IP in Windows logs AND in DNS tunnel/DGA queries.
                       That host is compromised AND beaconing C2 via DNS.
        LATERAL_CHAIN: Known host IP appearing as logon source on a different host.
                       Confirms the attacker moved from host A to host B.

  §1  GLOBAL ATTACK TIMELINE  ← Use this for chronological narrative order.
      Format per line: [SOURCE] timestamp  [SEVERITY] conf  Rule Name  (MITRE)  — host
      Source labels:
        [WAF]  = web application firewall (external attack surface)
        [EVTX] = Windows event log (host, AD, process creation)
        [DNS]  = DNS server/resolver log (C2, tunneling, DGA)
        [CORR] = behavioral correlation scenario (multi-stage chain)
      ★ marker = this event's host/IP is linked to a §0 cross-source pivot.
      The timeline is pre-sorted by timestamp — use it as your attack narrative backbone.

  §2  INCIDENT OVERVIEW  — overall counts and confidence assessment.
      "Auto confidence: CONFIRMED" means 3+ independent detection sources agree.
      "PROBABLE" = 2 sources. "POSSIBLE" = 1 source.

  §3  CRITICAL ALERTS  — two types of alerts appear here:
      "Source: Custom Detection Rule"         = single-event sigma rule fired
      "Source: Behavioral Correlation Engine" = multi-stage behavioral chain
        These show "Attack stages: X → Y → Z" which is the attack kill-chain sequence.
        "Time span: N minutes" = how long the attack stage lasted.

  §5  CONFIRMED SUSPICIOUS EVENTS  — EVTX events with forensic details.
      "Forensics" block contains the exact field values from the event log.
      Use these for specific IOC values (accounts, IPs, access masks).

  §7  IOC CROSS-REFERENCE TABLE  — structured IOCs with context.
      Types: IP, USERNAME, HOSTNAME, DOMAIN, CMDLINE, FILEPATH
      IOCs from §0 pivots appear first with pivot context (highest confidence).
      CMDLINE entries are exact command lines — cite them verbatim in remediation.

╔══════════════════════════════════════════════════════════╗
║                 SIGNAL INTERPRETATION                     ║
╚══════════════════════════════════════════════════════════╝

When you see these alerts in §3, interpret them as follows:

INITIAL ACCESS:
  "SQL Injection Attack - Successful Data Response"
      → SQLi succeeded (HTTP 200 + large response). Data may already be extracted.
        Web tier is compromised. Check §0 for WEB_TO_HOST pivot to confirm host access.
  "Path Traversal Targeting System Files"
      → Server filesystem enumeration confirmed — attacker can read /etc/passwd,
        web.config, wp-config.php etc. Source of credential material.
  "Web Shell Upload - POST to Server-Side Script Returning 200"
      → Backdoor script installed on the web server. Attacker has persistent
        remote code execution on the web tier. This is persistence + initial access.
  "Office Application Spawning Shell Process"
      → Macro inside Word/Excel/Outlook document launched powershell/cmd.
        User opened a phishing attachment. This is the host-side initial access.
  "Exploit Framework or Scanner User-Agent"
      → Active scanning from an automated attack tool (sqlmap, Nikto, Nuclei).
        Context for the attack — reconnaissance before exploitation.

DEFENSE EVASION (always happens BEFORE the main attack actions):
  "PowerShell AMSI Bypass Attempt"
      → Windows Antimalware Scan Interface was patched in memory.
        ALL PowerShell commands after this point ran without AV inspection.
        This is why subsequent PS commands weren't caught by AV.
  "Windows Defender Disabled via Command Line / Set-MpPreference"
      → AV disabled. Any malware dropped after this point is invisible to Defender.
        Ransomware pre-deployment step confirmed.
  "Windows Defender Exclusion Path Added"
      → A folder was whitelisted in Defender. Attacker added their payload folder.
  "Audit Policy Disabled"
      → Windows stopped generating certain event log entries.
        Forensic blind spot created for actions after this timestamp.
  "Event Log Clearing via wevtutil"
      → Attacker erased specific Windows event logs (Security, System, PS logs).
        This targets forensic investigation — more targeted than EID 1102.
  "Security Log Cleared (EID=1102)"
      → The entire Security event log was wiped. Always defense evasion.
        Treat as a termination of the evidence trail at this timestamp.
  "Sysmon Process Tampering (EID=25)"
      → Process hollowing or doppelganging detected. Malware is running inside a
        legitimate process (svchost, explorer). Near-zero false positive rate.

CREDENTIAL ACCESS:
  "DCSync Attack - AD Replication Rights Accessed"
      → Attacker pulled ALL domain password hashes using AD replication protocol.
        No code on the DC needed. Every domain account is now compromised.
        The account named in SubjectUserName/jsmith performed this.
  "ntdsutil IFM - Active Directory Database Dump"
      → NTDS.dit (AD database) copied to disk. Attacker can crack all domain hashes
        offline. Does not require network connectivity after this point.
  "LSASS Dump via comsvcs.dll MiniDump" / "Sysmon LSASS Memory Access"
      → LSASS memory read for credential extraction. Living-off-the-land —
        no Mimikatz.exe binary needed. comsvcs.dll is a built-in Windows DLL.
  "LSASS Memory Access via Security Audit (EID=4656/4663)"
      → LSASS accessed without Sysmon — detected via Security audit.
        Attacker extracted credentials from LSASS even without Sysmon deployed.
  "Malicious PowerShell Offensive Framework Commandlets"
      → Named function from PowerSploit, Mimikatz, BloodHound, Empire, Rubeus etc.
        Zero false positive rate — these names never appear in legitimate scripts.
  "PowerShell Mimikatz Command Strings"
      → Literal Mimikatz module commands (sekurlsa::logonpasswords etc.) in PS.
        Confirms credential extraction was executed via PowerShell.
  "WDigest Plaintext Credential Storage Re-Enabled"
      → Registry change causes Windows to store plaintext creds in memory.
        Next login by any user exposes their cleartext password to the attacker.
  "Kerberoasting Burst" / "AS-REP Roasting"
      → Kerberos tickets requested for offline cracking. Service/user account
        passwords attacked without triggering account lockout.
  "Dangerous Privilege Assignment (EID=4672 + SeDebugPrivilege)"
      → A non-system account was assigned SeDebugPrivilege, needed for LSASS dump.
        Confirms privilege level needed for credential access was achieved.

DISCOVERY:
  "SharpHound/BloodHound AD Attack Path Mapper"
      → Attacker mapped all AD objects and attack paths to Domain Admin.
        They now know every account, group, and delegation in the domain.
        Lateral movement to Domain Admin will follow this event.
  "ADFind Execution"
      → Third-party AD query tool. No legitimate reason on a workstation.
        Used by ransomware affiliates (LockBit, BlackCat) for domain mapping.
  "nltest Domain Trust and DC Enumeration"
      → Domain trust relationships and DC list enumerated.
        Used to identify attack paths to other domains.
  "Discovery Command Burst"
      → 4+ recon commands (whoami, net, ipconfig, systeminfo) in 2 minutes.
        This is an automated post-exploitation recon script, not manual admin work.
  "DNS Tunneling Detected - Long Subdomain Label"
      → DNS queries with 40+ char subdomains. Only DNS tunneling (iodine, DNScat)
        generates this pattern. Host is communicating with C2 via DNS.
  "DGA Domain Query Detected"
      → Domain Generation Algorithm — malware C2 using pseudo-random domains.
        The compromised host is checking in with its C2 infrastructure.

LATERAL MOVEMENT:
  "Pass-the-Hash - NTLM Logon from Different Source Machine"
      → A stolen NTLM hash was used to authenticate from a different machine.
        The account named in TargetUserName was used from the IP in §7.
        No password needed — only the hash.
  "Impacket/PSExec Remote Service Installation (EID=7045)"
      → cmd /Q /c pattern in ServiceFileName. Impacket SMBexec/PSExec signature.
        Remote command execution on the target system via SMB service.
  "WMI Remote Process Creation"
      → wmic /node: used to execute code on a remote host. Fileless lateral movement.
  "RDP Session Hijack via TSCON"
      → tscon.exe hijacked an active RDP session. No password needed with SYSTEM rights.
        Used to silently take over a logged-in user's desktop.
  "WinRS Remote Shell Execution"
      → Windows Remote Shell — WinRM-based lateral movement alternative to PSExec.
  "Remote Service/Task Creation via SMB Named Pipes (svcctl/atsvc)"
      → Impacket-style lateral movement using Service Control Manager or Task
        Scheduler named pipes. Remote code execution via SMB.
  "SMB Admin Share Access (C$/ADMIN$)"
      → Admin share accessed — prerequisite for PSExec-style lateral movement.

EXFILTRATION:
  "Rclone Data Exfiltration to Cloud Storage"
      → rclone.exe with mega:/sftp://gdrive: confirms data uploaded to cloud.
        Exact command in CMDLINE field of §7 shows destination and source path.
        Confirms double-extortion ransomware — data stolen BEFORE encryption.
  "Data Exfiltration Tools Executed (MEGAsync/FileZilla/WinSCP)"
      → Consumer cloud/FTP tool used for exfiltration. Server context = attacker use.
  "Suspicious Data Archiving in Writable Path"
      → 7zip/WinRAR staging archives in Temp/AppData. Data being prepared for upload.
  "Certutil Malicious Use - urlcache"
      → certutil -urlcache -f URL used to download a payload. Built-in Windows binary.

PERSISTENCE:
  "Scheduled Task with Encoded Command or Download Action"
      → Scheduled task contains -enc or IEX+URL. Persistent code execution on trigger.
  "WMI Event Subscription Created (EID=19/20/21)"
      → Fileless persistence via WMI. Executes on startup/login with no disk artifacts.
  "Registry Run Key Persistence"
      → Malware path written to HKCU/HKLM Run key. Executes on every user login.
  "Executable Written to Startup Folder (EID=11)"
      → Binary placed in Startup folder. Executes on login. No registry modification needed.

AD ATTACKS:
  "DCSync Rights Granted (EID=5136)"
      → Replication rights added to an account BEFORE DCSync is run.
        This is the setup step — EID 4662 is the execution step.
  "DCShadow - Rogue Domain Controller Object Created (EID=5137)"
      → Mimikatz dcshadow registered a fake DC to inject arbitrary AD changes.
        Can modify any AD object without standard audit trails.
  "User Added to High-Privilege AD Security Group (EID=4728/4732/4756)"
      → Compromised account added to Domain Admins or equivalent.
        Final privilege escalation step before impact.
  "AS-REP Roasting (EID=4768, PreAuthType=0)"
      → TGT requested for account with no pre-authentication.
        The encrypted TGT is crackable offline.

IMPACT:
  "Shadow Copy Deletion - All Variants (Ransomware Pre-Deployment)"
      → vssadmin/wmic shadowcopy delete destroyed all recovery points.
        This is ransomware pre-deployment — encryption follows this event.
        Without external backups, recovery is impossible.
        Check CMDLINE in §7 for the exact deletion command used.

BEHAVIORAL CHAIN SCENARIOS (Source: Behavioral Correlation Engine):
  "Ransomware_Deployment"
      → DEFENSE_EVASION → CREDENTIAL_DUMP → SHADOW_DELETION confirmed in sequence.
        Classic double-extortion ransomware kill chain detected end-to-end.
  "Full_Attack_Chain"
      → DISCOVERY → CREDENTIAL_DUMP → LATERAL_MOVEMENT confirmed.
        Multi-stage APT-style attack with all major phases detected.
  "DCSync_Attack"
      → AD_COMPROMISE → CREDENTIAL_DUMP confirmed.
        All domain hashes extracted. Treat every account as compromised.
  "Defense_Evasion_Chain"
      → DEFENSE_EVASION → LOG_CLEARED → SHADOW_DELETION confirmed.
        Attacker systematically blinded detection and destroyed recovery options.
  "Macro_Delivery"
      → MACRO_EXEC → DEFENSE_EVASION confirmed.
        Office macro initial access led directly to AV bypass.
  "Data_Exfiltration"
      → DISCOVERY → EXFILTRATION confirmed.
        Attacker enumerated data then uploaded it. Double-extortion confirmed.
  "Pass_The_Hash_Lateral"
      → CREDENTIAL_DUMP → LATERAL_MOVEMENT confirmed.
        Hashes were stolen then immediately reused for lateral movement.

╔══════════════════════════════════════════════════════════╗
║                    ANALYSIS RULES                        ║
╚══════════════════════════════════════════════════════════╝

EVIDENCE HIERARCHY — in order of confidence:
  1. §0 PIVOT entries (cross-source = strongest)
  2. §3 Behavioral Correlation Engine alerts (multi-stage chain = high)
  3. §3 Custom Detection Rule alerts (single-event = medium-high)
  4. §5 Confirmed events with forensic fields (supporting)
  5. §4 WAF detections (web tier context)

BUILDING THE ATTACK NARRATIVE:
  - Start from §0: if WEB_TO_HOST pivot exists, begin with "attacker from IP X
    exploited the web tier, then used those credentials on internal systems"
  - Use §1 timestamp sequence for chronological order
  - Each step in attack_narrative MUST cite: [timestamp] [system] [account] [action]
  - Connect events: "This follows the DCSync at 02:18 which provided the hashes"

IOC RULES:
  - §7 CMDLINE entries: cite them verbatim in remediation actions
    ("Remove rclone job: rclone cC:/Userssers mega:stolen --config .rclone.conf")
  - §7 DOMAIN entries: these are confirmed C2 domains — block at DNS level
  - IPs from WEB_TO_HOST pivot = external attacker IPs (HIGH confidence)
  - IPs from HOST_TO_DNS pivot = compromised internal hosts (HIGH confidence)
  - "Systems: unknown" in §3 = WAF/DNS event without a Windows hostname (normal)
  - Machine accounts ending $ = NEVER attackers; remove from ioc_list

REMEDIATION SPECIFICITY:
  - Every remediation action MUST name the exact hostname, account, or domain
    from §7. NEVER write "the affected system" or "compromised account".
  GOOD: "Isolate WKS01 from network immediately (DCSync source)"
        "Reset password for jsmith across all systems (CRED_REUSE pivot: WKS01, DC01, SRV02)"
        "Block 185.220.101.45 at perimeter firewall (WEB_TO_HOST attacker IP)"
        "Block DNS domains: aGVsbG93b3JsZA.c2.evil.com, xkvplmqrtzwbn.ru"
        "Remove rclone.exe from WKS01, investigate: rclone cC:/Userssers mega:stolen"
  BAD:  "Isolate the affected system"
        "Reset compromised credentials"
        "Block the attacker IP"

STRICT PROHIBITIONS:
  - NEVER mention a hostname, IP, username, or technique not present in the evidence
  - NEVER claim data exfiltration without a "Rclone / exfil tool" or §0 DATA_EXFIL alert
  - NEVER claim full AD compromise without DCSync or ntdsutil IFM evidence
  - If EID 1102 (log cleared) appears: state forensic continuity is broken at that timestamp
  - Machine accounts (ending $) NEVER go in ioc_list
  - 127.0.0.1 as IpAddress = RDP tunneling indicator, NOT an attacker external IP
  - If §0 has no pivots: do NOT invent connections between log sources
  - "evidence suggests" for single-source; "confirmed" only when §0 pivot or behavioral chain exists

Respond ONLY with valid JSON. No markdown. No explanation. No trailing commas.

{triage_context}

Return this EXACT JSON structure (use null for unknown fields, empty array [] for none):
{{
  "executive_summary": "2-3 sentences for a CEO/board. NO EventIDs, NO MITRE codes, NO tool names, NO technical jargon. Plain English: what happened, which systems/data were affected, what the business impact is. Mention the attacker's entry point and how far they got. GOOD: 'An external attacker exploited the company web application, then gained access to internal servers and domain administrator credentials. Sensitive files were uploaded to a cloud storage service and backup recovery points were deleted, indicating imminent ransomware deployment.' BAD: 'EID=4662 DCSync T1003.006 detected on DC01'",
  "attack_confirmed": true,
  "attack_phase": "The LATEST and MOST SEVERE phase reached: Reconnaissance / Initial Access / Execution / Persistence / Privilege Escalation / Defense Evasion / Credential Access / Discovery / Lateral Movement / Collection / Exfiltration / Command and Control / Impact. If shadow copy deletion or ransomware deployment detected = Impact.",
  "severity_overall": "CRITICAL (ransomware, DCSync, or full AD compromise) / HIGH / MEDIUM / LOW / INFO",
  "confidence_level": "CONFIRMED (3+ independent sources agree, or §0 pivot + behavioral chain) / PROBABLE (2 sources) / POSSIBLE (1 source) / UNKNOWN",
  "attack_narrative": "Chronological step-by-step using EXACT timestamps from §1. Each step: [YYYY-MM-DDTHH:MM:SS] [HOST] Account [account] — [what happened] (detected by: [rule name]). Start with the earliest §1 entry. Connect each step to the next causally.",
  "root_cause_analysis": "Full technical narrative covering: initial access vector, privilege escalation path, credential dumping method, lateral movement technique, exfiltration/impact. For each: cite the exact rule name that detected it, the timestamp, the system, and the account. Reference §0 pivot types by name where applicable (e.g. 'The WEB_TO_HOST pivot on IP 185.220.101.45 confirms...'). Include access masks from §5 forensics where available.",
  "mitre_attack": ["T1190 - Exploit Public-Facing Application", "T1003.006 - DCSync"],
  "remediation_plan": {{
    "containment": [
      "Immediate network isolation of [exact hostname from §7]",
      "Block [exact IP from §7 with pivot context] at perimeter firewall",
      "Disable account [exact username from §7 CRED_REUSE pivot] across all systems"
    ],
    "eradication": [
      "Remove persistence mechanisms: [exact CMDLINE or path from §7]",
      "Reset all domain account passwords (DCSync confirmed — all hashes compromised)",
      "Review and remove scheduled tasks and Run keys on [specific hostnames]"
    ],
    "recovery": [
      "Restore from last known-good backup predating the earliest §1 timeline entry",
      "Re-image [specific hostnames from §7] — do not trust in-place recovery",
      "Enable enhanced logging: Sysmon, PowerShell Script Block, WEF forwarding"
    ]
  }},
  "evidence_gaps": [
    "List what could NOT be determined — e.g. 'Initial phishing email subject/sender not in available logs'",
    "If EID 1102 present: 'Forensic evidence destroyed after [timestamp] — log cleared by [account]'"
  ],
  "ioc_list": [
    {{"type": "IP or USERNAME or DOMAIN or HOSTNAME or CMDLINE or FILEPATH",
      "value": "exact value from §7 — never invent",
      "confidence": "HIGH (from §0 pivot or behavioral chain) / MEDIUM (single rule) / LOW (circumstantial)",
      "context": "WHY suspicious — cite the specific §0 pivot type or §3 rule name. For IPs: state whether external attacker or compromised internal host."}}
  ]
}}"""
    return prompt


TWO_PASS_THRESHOLD = 40_000  # raised: modern LLMs handle larger contexts well


def _compress_context(context: str) -> str:
    """
    First-pass LLM call: compress a large triage context into a concise
    forensic brief (~3000 chars) preserving all specific values
    (IPs, usernames, commands, timestamps). Used when context exceeds
    TWO_PASS_THRESHOLD before the main RCA call.
    """
    compress_prompt = (
        "You are a SOC analyst tasked with compressing a security incident "
        "triage context. Preserve the most forensically valuable content.\n\n"
        "COMPRESSION RULES (in priority order):\n"
        "1. ALWAYS copy §0 CROSS-SOURCE CORRELATIONS verbatim — never summarise.\n"
        "2. ALWAYS copy §1 GLOBAL ATTACK TIMELINE verbatim — timestamps matter.\n"
        "3. From §3 CRITICAL ALERTS: keep rule name, severity, confidence, systems, "
        "attack stages, time span. Drop verbose 'What it means' descriptions.\n"
        "4. From §7 IOC TABLE: keep all rows verbatim — IPs, users, hostnames, "
        "domains, cmdlines are primary evidence.\n"
        "5. From §5 CONFIRMED EVENTS: keep EVENT/EID/System/Forensics blocks. "
        "Drop §4 WAF detections if already covered by §0/§3.\n"
        "6. DROP entirely: §2 overview counts, §8 analysis instructions, "
        "§9 baseline, duplicate alert descriptions.\n"
        "7. NEVER paraphrase IP addresses, usernames, timestamps, or command lines. "
        "Keep ALL specific values exactly as written.\n"
        "Output plain text with the section headers (§0, §1, §3, §7, §5) intact. "
        "Maximum 8000 characters.\n\n"
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

    # ── Normalise all report fields ─────────────────────────────────────────

    # attack_narrative: ensure newline-separated string, not a list
    an = report.get("attack_narrative")
    if isinstance(an, list):
        report["attack_narrative"] = "\n".join(str(x) for x in an) if an else None
    elif an is not None and not isinstance(an, str):
        report["attack_narrative"] = str(an)

    # attack_confirmed: ensure bool
    if report.get("attack_confirmed") is None:
        report["attack_confirmed"] = bool(
            report.get("severity_overall","").upper() in ("CRITICAL","HIGH")
        )
    elif isinstance(report["attack_confirmed"], str):
        report["attack_confirmed"] = report["attack_confirmed"].lower() in ("true","yes","1")

    # executive_summary → summary alias (frontend checks both)
    if not report.get("summary") and report.get("executive_summary"):
        report["summary"] = report["executive_summary"]

    # root_cause_analysis → root_cause alias
    if not report.get("root_cause") and report.get("root_cause_analysis"):
        report["root_cause"] = report["root_cause_analysis"]

    # mitre_attack: normalise objects or plain strings → "TID - Name" strings
    mitre = report.get("mitre_attack", [])
    if isinstance(mitre, list):
        normalised = []
        for m in mitre:
            if isinstance(m, dict):
                tid  = m.get("technique_id", m.get("id", ""))
                name = m.get("technique_name", m.get("name", ""))
                normalised.append(f"{tid} - {name}" if tid else name)
            elif isinstance(m, str):
                normalised.append(m)
        report["mitre_attack"] = [x for x in normalised if x]

    # ioc_list: normalise each entry — remove machine accounts, ensure type field
    ioc_list = report.get("ioc_list", [])
    if isinstance(ioc_list, list):
        cleaned_iocs = []
        for ioc in ioc_list:
            if not isinstance(ioc, dict):
                continue
            val = str(ioc.get("value", "")).strip()
            # Strip machine accounts (end in $)
            if val.endswith("$"):
                continue
            # Normalise type
            ioc_type = str(ioc.get("type", "UNKNOWN")).upper()
            ioc["type"] = ioc_type
            ioc["value"] = val
            # Ensure confidence field
            if "confidence" not in ioc or ioc["confidence"] not in ("HIGH","MEDIUM","LOW"):
                ioc["confidence"] = "MEDIUM"
            cleaned_iocs.append(ioc)
        report["ioc_list"] = cleaned_iocs

    # remediation_plan: ensure dict with containment/eradication/recovery keys
    rem = report.get("remediation_plan", {})
    if not isinstance(rem, dict):
        rem = {}
    for phase in ("containment", "eradication", "recovery"):
        if phase not in rem:
            rem[phase] = []
        elif isinstance(rem[phase], str):
            rem[phase] = [rem[phase]]
        elif not isinstance(rem[phase], list):
            rem[phase] = []
    report["remediation_plan"] = rem

    # evidence_gaps: ensure list of strings
    gaps = report.get("evidence_gaps", [])
    if isinstance(gaps, str):
        gaps = [gaps]
    report["evidence_gaps"] = [str(g) for g in gaps if g] if isinstance(gaps, list) else []

    # Derive affected_accounts from ioc_list USERNAME entries
    # (frontend renders r.affected_accounts with || [] fallback)
    if not report.get("affected_accounts"):
        report["affected_accounts"] = list(dict.fromkeys(
            ioc["value"] for ioc in report.get("ioc_list", [])
            if ioc.get("type") == "USERNAME"
            and not ioc["value"].endswith("$")
        ))

    # Derive affected_systems from ioc_list HOSTNAME entries
    if not report.get("affected_systems"):
        report["affected_systems"] = list(dict.fromkeys(
            ioc["value"] for ioc in report.get("ioc_list", [])
            if ioc.get("type") == "HOSTNAME"
        ))

    # forensic_findings: derive from root_cause_analysis if not present
    # (frontend renders with || [] fallback, so empty list is safe)
    if not report.get("forensic_findings"):
        report["forensic_findings"] = []

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
