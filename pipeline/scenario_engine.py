import os
import json
from pathlib import Path
from collections import defaultdict

SCENARIO_SIGNATURES = {
    "Ransomware_Deployment": {
        "description": "Profiling followed by shadow volume deletion.",
        "milestones": ["PROFILING", "SHADOW_DELETION"],
        "min_confidence": 0.95,
        "severity": "critical"
    },
    "Compromised_Admin_Lateral_Movement": {
        "description": "Explicit credentials followed by privilege escalation.",
        "milestones": ["EXPLICIT_CREDENTIALS", "PRIVILEGE_ESCALATION"],
        "min_confidence": 0.90,
        "severity": "high"
    },
    "Credential_Dumping_Prep": {
        "description": "Profiling followed by explicit credential use.",
        "milestones": ["PROFILING", "EXPLICIT_CREDENTIALS"],
        "min_confidence": 0.85,
        "severity": "high"
    },
    "Persistence_After_Escalation": {
        "description": "Privilege escalation followed by persistence.",
        "milestones": ["PRIVILEGE_ESCALATION", "PERSISTENCE"],
        "min_confidence": 0.90,
        "severity": "high"
    },
    "Full_Attack_Chain": {
        "description": "Complete: profiling + credentials + escalation.",
        "milestones": ["PROFILING", "EXPLICIT_CREDENTIALS",
                       "PRIVILEGE_ESCALATION"],
        "min_confidence": 0.95,
        "severity": "critical"
    },
    "Web_To_Host_Pivot": {
        "description": "WAF attack followed by credential activity.",
        "milestones": ["WEB_ATTACK", "EXPLICIT_CREDENTIALS"],
        "min_confidence": 0.90,
        "severity": "critical"
    },
    "Defense_Evasion_Chain": {
        "description": "Privilege escalation followed by log clearing.",
        "milestones": ["PRIVILEGE_ESCALATION", "LOG_CLEARED"],
        "min_confidence": 0.95,
        "severity": "critical"
    }
}


class BehavioralStateEngine:
    def __init__(self):
        self.asset_states    = defaultdict(set)
        self.waf_states      = defaultdict(set)
        self.evidence_ledger = defaultdict(list)
        self.milestone_times = defaultdict(dict)
        self.WINDOW_MINUTES  = 30

    def _record_milestone(
        self,
        asset: str,
        milestone: str,
        ts: str
    ):
        try:
            from datetime import datetime
            dt = datetime.strptime(
                ts, "%Y-%m-%dT%H:%M:%SZ"
            )
            self.milestone_times[asset][milestone] = dt
        except Exception:
            pass

    def _milestones_within_window(
        self,
        asset: str,
        milestones: list
    ) -> bool:
        times = self.milestone_times.get(asset, {})
        dts = [
            times[m] for m in milestones
            if m in times
        ]
        if len(dts) < 2:
            return True
        earliest = min(dts)
        latest   = max(dts)
        delta_minutes = (
            latest - earliest
        ).total_seconds() / 60
        within = delta_minutes <= self.WINDOW_MINUTES
        if not within:
            print(
                f"[scenario] {asset} milestones "
                f"span {delta_minutes:.0f} min "
                f"> {self.WINDOW_MINUTES} min window "
                f"— not correlated"
            )
        return within

    def process_event(self, event: dict) -> dict:
        source   = event.get("source", "")
        tmpl     = event.get("template", "")
        metadata = event.get("sample_metadata",
                             event.get("metadata", {}))

        # Use Computer hostname as primary asset key
        # Never use username as asset identifier
        computer = metadata.get("Computer", "")

        # For WAF events use IP as asset
        if not computer and source == "waf":
            computer = metadata.get("src_ip", "unknown_host")

        # Only fall back to unknown if truly nothing available
        if not computer:
            computer = "unknown_asset"

        event_data = metadata.get("EventData", {})
        username   = str(
            event_data.get("SubjectUserName", "") or
            event_data.get("TargetUserName", "") or ""
        ).strip()
        ts = event.get("ts",
             event.get("first_seen", "unknown"))

        if "EID=4904" in tmpl or \
           "VSSAudit" in str(metadata):
            self.asset_states[computer].add("SHADOW_DELETION")
            self.evidence_ledger[computer].append(
                f"[{ts}] VSS shadow volume change detected"
            )
            self._record_milestone(
                computer, "SHADOW_DELETION", ts
            )

        elif "EID=4688" in tmpl:
            cmd = str(event_data).lower()
            if any(c in cmd for c in [
                "whoami", "net user", "certutil",
                "bitsadmin", "ipconfig", "systeminfo",
                "tasklist", "net localgroup", "nltest"
            ]):
                self.asset_states[computer].add("PROFILING")
                self.evidence_ledger[computer].append(
                    f"[{ts}] Profiling command detected"
                )
                self._record_milestone(
                    computer, "PROFILING", ts
                )

        elif "EID=4648" in tmpl:
            if (not username.endswith("$") and
                username not in [
                    "SYSTEM", "LOCAL SERVICE",
                    "NETWORK SERVICE", ""
                ]):
                self.asset_states[computer].add(
                    "EXPLICIT_CREDENTIALS"
                )
                self.evidence_ledger[computer].append(
                    f"[{ts}] Explicit credentials: {username}"
                )
                self._record_milestone(
                    computer, "EXPLICIT_CREDENTIALS", ts
                )

        elif "EID=4672" in tmpl:
            if (not username.endswith("$") and
                username not in [
                    "SYSTEM", "LOCAL SERVICE",
                    "NETWORK SERVICE", ""
                ]):
                self.asset_states[computer].add(
                    "PRIVILEGE_ESCALATION"
                )
                self.evidence_ledger[computer].append(
                    f"[{ts}] Privilege escalation: {username}"
                )
                self._record_milestone(
                    computer, "PRIVILEGE_ESCALATION", ts
                )

        elif "EID=4698" in tmpl or "EID=7045" in tmpl:
            if (not username.endswith("$") and
                    username not in ["SYSTEM", ""]):
                self.asset_states[computer].add("PERSISTENCE")
                self.evidence_ledger[computer].append(
                    f"[{ts}] Persistence: {username}"
                )
                self._record_milestone(
                    computer, "PERSISTENCE", ts
                )

        elif "EID=1102" in tmpl:
            self.asset_states[computer].add("LOG_CLEARED")
            self.evidence_ledger[computer].append(
                f"[{ts}] Security log cleared"
            )
            self._record_milestone(
                computer, "LOG_CLEARED", ts
            )

        elif source == "waf":
            attacks = event.get("attack_types", [])
            sev     = event.get("top_severity", "")
            if attacks and sev in ["critical", "high"]:
                src_ip = metadata.get("src_ip", computer)
                self.waf_states[src_ip].add("WEB_ATTACK")
                self.asset_states[computer].add("WEB_ATTACK")
                self.evidence_ledger[src_ip].append(
                    f"[{ts}] WAF attack from {src_ip}: {attacks}"
                )
                self._record_milestone(
                    computer, "WEB_ATTACK", ts
                )

        unlocked = self.asset_states[computer]
        for name, ruleset in SCENARIO_SIGNATURES.items():
            required = ruleset["milestones"]
            if all(m in unlocked for m in required):
                times = self.milestone_times.get(
                    computer, {}
                )
                dts = [
                    times[m] for m in required
                    if m in times
                ]
                if len(dts) >= 2:
                    from datetime import datetime
                    delta = (
                        max(dts) - min(dts)
                    ).total_seconds() / 60
                    time_note = (
                        f"Attack spanned {delta:.0f} minutes"
                    )
                else:
                    time_note = "Timing unknown"

                return {
                    "scenario_triggered": True,
                    "scenario_name":      name,
                    "description":        ruleset["description"],
                    "asset":              computer,
                    "severity":           ruleset["severity"],
                    "confidence":         ruleset["min_confidence"],
                    "evidence":           self.evidence_ledger[computer],
                    "time_span":          time_note,
                }

        any_web_attack = any(
            "WEB_ATTACK" in states
            for states in self.waf_states.values()
        )
        if any_web_attack:
            for host, host_states in \
                    self.asset_states.items():
                if "EXPLICIT_CREDENTIALS" in host_states:
                    return {
                        "scenario_triggered": True,
                        "scenario_name":
                            "Web_To_Host_Pivot",
                        "description":
                            "WAF attack followed by "
                            "credential activity on host",
                        "asset": f"WAF→{host}",
                        "severity":   "critical",
                        "confidence": 0.85,
                        "evidence": (
                            list(self.waf_states.keys()) +
                            self.evidence_ledger.get(
                                host, []
                            )
                        )
                    }

        return {"scenario_triggered": False}


def evaluate_stream_scenarios(
    templates_path: str = "uploads/templates.json",
    output_path:    str = "uploads/scenario_hits.json"
) -> list[dict]:
    if not os.path.exists(templates_path):
        print(f"[scenario] templates.json not found")
        return []

    with open(templates_path) as f:
        templates = json.load(f)

    engine   = BehavioralStateEngine()
    detected = []
    seen     = set()

    for t in templates:
        result = engine.process_event(t)
        if result["scenario_triggered"]:
            name = result["scenario_name"]
            if name not in seen:
                seen.add(name)
                detected.append({
                    "rule_name":   name,
                    "technique":   "BEHAVIORAL_CORRELATION",
                    "severity":    result["severity"],
                    "confidence":  result["confidence"],
                    "count":       1,
                    "systems":     [result["asset"]],
                    "sample_raw":  json.dumps(
                        result["evidence"][:3]
                    ),
                    "description": result["description"],
                    "time_span":   result.get(
                        "time_span", "unknown"
                    ),
                    "source":      "scenario_engine"
                })

    print(f"[scenario] {len(detected)} scenarios triggered")
    for d in detected:
        print(f"  [{d['severity'].upper():8}] "
              f"conf={d['confidence']:.2f} "
              f"— {d['rule_name']}")

    os.makedirs(
        os.path.dirname(output_path)
        if os.path.dirname(output_path) else ".",
        exist_ok=True
    )
    with open(output_path, "w") as f:
        json.dump(detected, f, indent=2)
    print(f"[scenario] Saved to {output_path}")
    return detected


if __name__ == "__main__":
    import sys
    sys.path.insert(
        0, str(Path(__file__).resolve().parents[1])
    )

    print("=== Behavioral Scenario Engine Test ===\n")

    if not os.path.exists("uploads/templates.json"):
        print("Run drain3_engine.py first")
        sys.exit(1)

    hits = evaluate_stream_scenarios()
    if not hits:
        print("No scenarios triggered.")
        print("Correct for clean machine.")
        print("On attacked machine would see:")
        for name in SCENARIO_SIGNATURES:
            print(f"  {name}")
