import os
import json
from pathlib import Path
from collections import defaultdict
from datetime import datetime

# ---------------------------------------------------------------------------
# SCENARIO SIGNATURES
# Each scenario has:
#   milestones   - the sigma rule title fragments that must ALL fire
#   min_confidence - minimum confidence to trigger
#   severity     - CRITICAL / HIGH / MEDIUM
#   description  - human-readable summary
# ---------------------------------------------------------------------------
SCENARIO_SIGNATURES = {

    # ── Full Attack Chains ──────────────────────────────────────────────────
    "Full_APT_Chain": {
        "description": "Web exploitation → credential dumping → AD compromise → exfiltration.",
        "milestones": ["WEB_EXPLOIT", "CREDENTIAL_DUMP", "AD_COMPROMISE", "EXFILTRATION"],
        "min_confidence": 0.97,
        "severity": "critical"
    },
    "Ransomware_Deployment": {
        "description": "Defense evasion (AV/log) → credential access → shadow copy deletion.",
        "milestones": ["DEFENSE_EVASION", "CREDENTIAL_DUMP", "SHADOW_DELETION"],
        "min_confidence": 0.96,
        "severity": "critical"
    },
    "Full_Attack_Chain": {
        "description": "Discovery → credential access → lateral movement → impact.",
        "milestones": ["DISCOVERY", "CREDENTIAL_DUMP", "LATERAL_MOVEMENT"],
        "min_confidence": 0.95,
        "severity": "critical"
    },
    "Web_To_Host_Pivot": {
        "description": "WAF exploitation led directly to host-level credential activity.",
        "milestones": ["WEB_EXPLOIT", "CREDENTIAL_DUMP"],
        "min_confidence": 0.92,
        "severity": "critical"
    },

    # ── Credential-Focused ──────────────────────────────────────────────────
    "DCSync_Attack": {
        "description": "Attacker dumped all AD credentials via DCSync replication abuse.",
        "milestones": ["AD_COMPROMISE", "CREDENTIAL_DUMP"],
        "min_confidence": 0.93,
        "severity": "critical"
    },
    "Credential_Dumping_Prep": {
        "description": "Discovery commands followed by credential dumping activity.",
        "milestones": ["DISCOVERY", "CREDENTIAL_DUMP"],
        "min_confidence": 0.88,
        "severity": "critical"
    },
    "Pass_The_Hash_Lateral": {
        "description": "NTLM credential reuse detected across systems.",
        "milestones": ["CREDENTIAL_DUMP", "LATERAL_MOVEMENT"],
        "min_confidence": 0.87,
        "severity": "critical"
    },

    # ── Defense Evasion ─────────────────────────────────────────────────────
    "Defense_Evasion_Chain": {
        "description": "AV disabled → logs cleared → shadow copies deleted.",
        "milestones": ["DEFENSE_EVASION", "LOG_CLEARED", "SHADOW_DELETION"],
        "min_confidence": 0.95,
        "severity": "critical"
    },
    "Log_Clearing_After_Intrusion": {
        "description": "Credential activity followed by evidence destruction.",
        "milestones": ["CREDENTIAL_DUMP", "LOG_CLEARED"],
        "min_confidence": 0.91,
        "severity": "critical"
    },

    # ── Persistence ─────────────────────────────────────────────────────────
    "Persistence_After_Escalation": {
        "description": "Privilege escalation followed by persistence mechanism installed.",
        "milestones": ["CREDENTIAL_DUMP", "PERSISTENCE"],
        "min_confidence": 0.88,
        "severity": "high"
    },
    "Macro_To_Persistence": {
        "description": "Office macro execution led to persistence installation.",
        "milestones": ["MACRO_EXEC", "PERSISTENCE"],
        "min_confidence": 0.88,
        "severity": "critical"
    },

    # ── Initial Access ──────────────────────────────────────────────────────
    "Macro_Delivery": {
        "description": "Office application spawned a shell — macro-based initial access.",
        "milestones": ["MACRO_EXEC", "DEFENSE_EVASION"],
        "min_confidence": 0.90,
        "severity": "critical"
    },
    "C2_Beacon_Established": {
        "description": "DNS tunneling or DGA domain activity indicates C2 channel.",
        "milestones": ["C2_ACTIVITY", "DEFENSE_EVASION"],
        "min_confidence": 0.85,
        "severity": "high"
    },

    # ── Exfiltration ────────────────────────────────────────────────────────
    "Data_Exfiltration": {
        "description": "Data collection (discovery/staging) followed by exfiltration tool use.",
        "milestones": ["DISCOVERY", "EXFILTRATION"],
        "min_confidence": 0.89,
        "severity": "critical"
    },

    # ── Compromised Admin ───────────────────────────────────────────────────
    "Compromised_Admin_Lateral_Movement": {
        "description": "Legitimate admin credential used for lateral movement to other systems.",
        "milestones": ["LATERAL_MOVEMENT", "DISCOVERY"],
        "min_confidence": 0.85,
        "severity": "high"
    },
}


# ---------------------------------------------------------------------------
# RULE → MILESTONE mapping
# Maps sigma rule title substrings to behavioral milestones.
# Each rule can contribute to multiple milestones.
# ---------------------------------------------------------------------------
RULE_MILESTONE_MAP = {

    # WEB_EXPLOIT
    "SQL Injection Attack":                              ["WEB_EXPLOIT"],
    "Exploit Framework or Scanner User-Agent":          ["WEB_EXPLOIT"],
    "Web Shell Upload":                                  ["WEB_EXPLOIT", "PERSISTENCE"],
    "Path Traversal Targeting System Files":            ["WEB_EXPLOIT"],

    # MACRO_EXEC (spear-phishing document delivery)
    "Office Application Spawning Shell":                ["MACRO_EXEC", "DEFENSE_EVASION"],

    # DEFENSE_EVASION
    "Windows Defender Disabled via Command Line":       ["DEFENSE_EVASION"],
    "Windows Defender Disabled via Set-MpPreference":   ["DEFENSE_EVASION"],
    "Windows Defender Exclusion Path Added":            ["DEFENSE_EVASION"],
    "Windows Defender Real-Time Protection Failure":    ["DEFENSE_EVASION"],
    "Windows Firewall Disabled via netsh":              ["DEFENSE_EVASION"],
    "Windows Firewall Any/Any Rule Created":            ["DEFENSE_EVASION"],
    "Audit Policy Disabled":                            ["DEFENSE_EVASION"],
    "PowerShell AMSI Bypass Attempt":                   ["DEFENSE_EVASION"],
    "Sysmon Process Tampering":                         ["DEFENSE_EVASION"],
    "Regsvr32 Spawning Suspicious Child":               ["DEFENSE_EVASION"],
    "Mshta Suspicious Execution":                       ["DEFENSE_EVASION"],
    "WMI Event Subscription Created":                   ["DEFENSE_EVASION", "PERSISTENCE"],
    "Registry Run Key Persistence":                     ["DEFENSE_EVASION", "PERSISTENCE"],
    "PowerShell History Cleared":                       ["DEFENSE_EVASION"],
    "PowerShell Timestomping":                          ["DEFENSE_EVASION"],

    # LOG_CLEARED
    "Event Log Clearing via wevtutil":                  ["LOG_CLEARED"],
    "Security Log Cleared":                             ["LOG_CLEARED"],

    # SHADOW_DELETION
    "Shadow Copy Deletion":                             ["SHADOW_DELETION"],

    # CREDENTIAL_DUMP
    "DCSync Attack":                                    ["AD_COMPROMISE", "CREDENTIAL_DUMP"],
    "DCSync Rights Granted":                            ["AD_COMPROMISE", "CREDENTIAL_DUMP"],
    "DCShadow":                                         ["AD_COMPROMISE"],
    "LSASS Memory Access via Security Audit":           ["CREDENTIAL_DUMP"],
    "Sysmon LSASS Memory Access":                       ["CREDENTIAL_DUMP"],
    "LSASS Dump via comsvcs.dll MiniDump":              ["CREDENTIAL_DUMP"],
    "ntdsutil IFM":                                     ["AD_COMPROMISE", "CREDENTIAL_DUMP"],
    "Kerberoasting Burst":                              ["CREDENTIAL_DUMP"],
    "AS-REP Roasting":                                  ["CREDENTIAL_DUMP"],
    "WDigest Plaintext Credential Storage":             ["CREDENTIAL_DUMP"],
    "Dangerous Privilege Assignment":                   ["CREDENTIAL_DUMP"],
    "PowerShell Mimikatz Command Strings":              ["CREDENTIAL_DUMP"],
    "Malicious PowerShell Offensive Framework":         ["CREDENTIAL_DUMP", "DEFENSE_EVASION"],
    "PowerShell In-Memory .NET Assembly":               ["CREDENTIAL_DUMP", "DEFENSE_EVASION"],
    "PowerShell Download Cradle":                       ["DEFENSE_EVASION"],
    "PowerShell Large Encoded Command":                 ["DEFENSE_EVASION"],

    # AD_COMPROMISE
    "User Added to High-Privilege AD Security Group":   ["AD_COMPROMISE"],
    "Hidden Backdoor Account":                          ["AD_COMPROMISE", "PERSISTENCE"],

    # LATERAL_MOVEMENT
    "Pass-the-Hash":                                    ["LATERAL_MOVEMENT"],
    "Impacket/PSExec Remote Service Installation":      ["LATERAL_MOVEMENT"],
    "WMI Remote Process Creation":                      ["LATERAL_MOVEMENT"],
    "RDP Session Hijack via TSCON":                     ["LATERAL_MOVEMENT"],
    "WinRS Remote Shell Execution":                     ["LATERAL_MOVEMENT"],
    "SMB Admin Share Access":                           ["LATERAL_MOVEMENT"],
    "Remote Service/Task Creation via SMB Named Pipes": ["LATERAL_MOVEMENT"],
    "RDP/Service Tunneling Tool":                       ["LATERAL_MOVEMENT", "C2_ACTIVITY"],

    # DISCOVERY
    "ADFind Execution":                                 ["DISCOVERY"],
    "SharpHound/BloodHound":                            ["DISCOVERY"],
    "nltest Domain Trust":                              ["DISCOVERY"],
    "Network Share Discovery":                          ["DISCOVERY"],
    "Discovery Command Burst":                          ["DISCOVERY"],
    "RDP Discovery Scan":                               ["DISCOVERY"],
    "DNS Tunneling Detected":                           ["C2_ACTIVITY"],
    "DGA Domain Query":                                 ["C2_ACTIVITY"],
    "C2 DNS Beaconing":                                 ["C2_ACTIVITY"],
    "Sysmon Named Pipe Created Matching C2":            ["C2_ACTIVITY"],
    "Non-Network Process Making Outbound Connection":   ["C2_ACTIVITY"],

    # EXFILTRATION
    "Rclone Data Exfiltration":                         ["EXFILTRATION"],
    "Data Exfiltration Tools Executed":                 ["EXFILTRATION"],
    "BITS Job Downloading from Suspicious Domain":      ["EXFILTRATION"],
    "Bitsadmin Download":                               ["EXFILTRATION"],
    "Certutil Malicious Use":                           ["EXFILTRATION", "DEFENSE_EVASION"],
    "Suspicious Data Archiving":                        ["EXFILTRATION"],

    # PERSISTENCE
    "Executable Written to Startup Folder":             ["PERSISTENCE"],
    "Scheduled Task with Encoded Command":              ["PERSISTENCE"],
    "Scheduled Task Created and Immediately Deleted":   ["PERSISTENCE", "LATERAL_MOVEMENT"],
    "Mimikatz Kernel Driver Service":                   ["CREDENTIAL_DUMP", "PERSISTENCE"],
    "Unsigned DLL Loaded From User-Writable Path":      ["DEFENSE_EVASION", "PERSISTENCE"],
    "Executable Running From User-Writable Path":       ["DEFENSE_EVASION"],

    # LEGACY / original 19 rules
    "Brute Force Login Attempt":                        ["DISCOVERY"],
    "Multiple Failed Logins":                           ["DISCOVERY"],
    "Pass-the-Hash Lateral Movement":                   ["LATERAL_MOVEMENT"],
    "LOLBin Download or Remote Execution":              ["DEFENSE_EVASION"],
    "Impacket Service Install":                         ["LATERAL_MOVEMENT"],
    "Suspicious Process Chain Detected":                ["DEFENSE_EVASION"],
    "New Service From Suspicious Path":                 ["PERSISTENCE"],
}


def _rule_to_milestones(rule_name: str) -> list:
    """Map a sigma rule title to its behavioral milestones."""
    rn = rule_name.lower()
    for fragment, milestones in RULE_MILESTONE_MAP.items():
        if fragment.lower() in rn:
            return milestones
    return []


class BehavioralStateEngine:
    def __init__(self):
        self.asset_states    = defaultdict(set)   # asset → {MILESTONE, ...}
        self.ip_states       = defaultdict(set)   # src_ip → {MILESTONE, ...}
        self.evidence_ledger = defaultdict(list)  # asset → [evidence lines]
        self.milestone_times = defaultdict(dict)  # asset → {milestone → datetime}
        self.ioc_registry    = defaultdict(set)   # ioc_type → {values}
        self.WINDOW_MINUTES  = 60  # widened from 30 to catch slower attacks

    def _record_milestone(self, asset: str, milestone: str, ts: str):
        try:
            dt = datetime.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S")
            if milestone not in self.milestone_times[asset]:
                self.milestone_times[asset][milestone] = dt
        except Exception:
            pass

    def _milestones_in_window(self, asset: str, milestones: list) -> bool:
        times = self.milestone_times.get(asset, {})
        dts = [times[m] for m in milestones if m in times]
        if len(dts) < 2:
            return True
        delta = (max(dts) - min(dts)).total_seconds() / 60
        return delta <= self.WINDOW_MINUTES

    def ingest_sigma_hit(self, hit: dict):
        """
        Ingest a sigma_lite or scenario detection hit and update
        the behavioral state machine for the relevant asset.
        """
        rule_name = hit.get("rule_name", "")
        severity  = hit.get("severity", "info")
        systems   = hit.get("systems", ["unknown"])
        ts        = hit.get("first_seen", hit.get("ts", "unknown"))
        technique = hit.get("technique", "")
        source    = hit.get("source", "sigma_lite")

        milestones = _rule_to_milestones(rule_name)
        if not milestones:
            return

        for asset in systems:
            if not asset or asset == "unknown":
                asset = "unknown_asset"
            for ms in milestones:
                self.asset_states[asset].add(ms)
                self._record_milestone(asset, ms, ts)
                self.evidence_ledger[asset].append(
                    f"[{ts}] {rule_name} → {ms} "
                    f"[{severity.upper()}] {technique}"
                )

    def ingest_waf_hit(self, hit: dict):
        """Ingest a WAF-sourced detection."""
        src_ip    = hit.get("src_ip", "")
        rule_name = hit.get("rule_name", hit.get("attack_type", "WAF_ATTACK"))
        ts        = hit.get("ts", hit.get("first_seen", "unknown"))
        severity  = hit.get("severity", "high")

        if severity in ("critical", "high"):
            asset = src_ip or "waf_unknown"
            self.asset_states[asset].add("WEB_EXPLOIT")
            self._record_milestone(asset, "WEB_EXPLOIT", ts)
            self.evidence_ledger[asset].append(
                f"[{ts}] WAF: {rule_name} from {src_ip} [{severity.upper()}]"
            )
            if src_ip:
                self.ioc_registry["IP"].add(src_ip)

    def ingest_dns_hit(self, hit: dict):
        """Ingest a DNS-sourced detection."""
        rule_name = hit.get("rule_name", "")
        ts        = hit.get("ts", hit.get("first_seen", "unknown"))
        systems   = hit.get("systems", ["unknown"])
        milestones = _rule_to_milestones(rule_name)
        for asset in systems:
            for ms in milestones:
                self.asset_states[asset].add(ms)
                self._record_milestone(asset, ms, ts)
                self.evidence_ledger[asset].append(
                    f"[{ts}] DNS: {rule_name} → {ms}"
                )

    def evaluate_scenarios(self) -> list:
        """
        Check all assets against all scenario signatures.
        Returns list of triggered scenario dicts.
        """
        triggered = []
        seen_names = set()

        # Sort scenarios: most milestones first (prefer full chains)
        sorted_sigs = sorted(
            SCENARIO_SIGNATURES.items(),
            key=lambda kv: -len(kv[1]["milestones"])
        )

        for asset, states in self.asset_states.items():
            for name, sig in sorted_sigs:
                if name in seen_names:
                    continue
                required = sig["milestones"]
                if not all(m in states for m in required):
                    continue
                if not self._milestones_in_window(asset, required):
                    continue

                times = self.milestone_times.get(asset, {})
                dts   = [times[m] for m in required if m in times]
                time_note = (
                    f"Attack spanned {(max(dts)-min(dts)).total_seconds()/60:.0f} minutes"
                    if len(dts) >= 2 else "Timing uncertain"
                )

                # Derive first/last seen from milestone timestamps
                sc_first = min(dts).strftime("%Y-%m-%dT%H:%M:%SZ") if dts else ""
                sc_last  = max(dts).strftime("%Y-%m-%dT%H:%M:%SZ") if dts else ""

                triggered.append({
                    "scenario_triggered": True,
                    "scenario_name":      name,
                    "description":        sig["description"],
                    "asset":              asset,
                    "severity":           sig["severity"],
                    "confidence":         sig["min_confidence"],
                    "milestones_hit":     [m for m in required if m in states],
                    "evidence":           self.evidence_ledger[asset][-10:],
                    "time_span":          time_note,
                    "first_seen":         sc_first,
                    "last_seen":          sc_last,
                    "ts":                 sc_first,
                })
                seen_names.add(name)

        # Sort by severity then confidence
        sev_order = ["critical", "high", "medium", "low"]
        triggered.sort(key=lambda x: (
            sev_order.index(x.get("severity", "low")),
            -x.get("confidence", 0)
        ))
        return triggered


def evaluate_stream_scenarios(
    sigma_hits_path: str = "uploads/sigma_lite_hits.json",
    waf_hits_path:   str = "uploads/sigma_hits.json",
    output_path:     str = "uploads/scenario_hits.json"
) -> list:
    """
    Load sigma rule hits, ingest them into the state machine,
    and evaluate all scenario signatures. Returns triggered scenarios
    in the format expected by triage_agent.py and phi4_rca.py.
    """
    engine = BehavioralStateEngine()

    # ── Load sigma_lite hits (EVTX + DNS rules) ────────────────────────────
    if os.path.exists(sigma_hits_path):
        with open(sigma_hits_path) as f:
            sigma_hits = json.load(f)
        for hit in sigma_hits:
            src = hit.get("source", "sigma_lite")
            if src == "waf":
                engine.ingest_waf_hit(hit)
            elif src == "dns":
                engine.ingest_dns_hit(hit)
            else:
                engine.ingest_sigma_hit(hit)
        print(f"[scenario] Loaded {len(sigma_hits)} sigma_lite hits")

    # ── Load WAF/chainsaw hits ─────────────────────────────────────────────
    waf_hits = []
    if waf_hits_path != sigma_hits_path and os.path.exists(waf_hits_path):
        with open(waf_hits_path) as f:
            waf_hits = json.load(f)
        for hit in waf_hits:
            if hit.get("source") == "waf" or "sql" in hit.get("rule_name","").lower():
                engine.ingest_waf_hit(hit)
            else:
                engine.ingest_sigma_hit(hit)
        print(f"[scenario] Loaded {len(waf_hits)} chainsaw/WAF hits")

    # ── Evaluate all scenarios ─────────────────────────────────────────────
    raw_scenarios = engine.evaluate_scenarios()

    # ── Format as triage_agent-compatible hit objects ──────────────────────
    detected = []
    for sc in raw_scenarios:
        detected.append({
            "rule_name":         sc["scenario_name"],
            "technique":         "BEHAVIORAL_CORRELATION",
            "severity":          sc["severity"],
            "confidence":        sc["confidence"],
            "count":             len(sc.get("milestones_hit", [])),
            "systems":           [sc["asset"]],
            "sample_raw":        json.dumps(sc["evidence"][:3]),
            "description":       sc["description"],
            "milestones":        sc.get("milestones_hit", []),
            "time_span":         sc.get("time_span", "unknown"),
            "first_seen":        sc.get("first_seen", ""),
            "last_seen":         sc.get("last_seen", ""),
            "ts":                sc.get("ts", sc.get("first_seen", "")),
            "source":            "scenario_engine"
        })

    print(f"[scenario] {len(detected)} scenarios triggered")
    for d in detected:
        print(f"  [{d['severity'].upper():8}] conf={d['confidence']:.2f} "
              f"— {d['rule_name']} ({', '.join(d.get('milestones',[]))})")

    os.makedirs(
        os.path.dirname(output_path) if os.path.dirname(output_path) else ".",
        exist_ok=True
    )
    with open(output_path, "w") as f:
        json.dump(detected, f, indent=2)
    print(f"[scenario] Saved to {output_path}")
    return detected


if __name__ == "__main__":
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    print("=== Behavioral Scenario Engine ===\n")
    hits = evaluate_stream_scenarios()
    if not hits:
        print("No scenarios triggered.")
