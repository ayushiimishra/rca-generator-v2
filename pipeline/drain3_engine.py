import sys
import os
import json
from pathlib import Path
from collections import defaultdict
import numpy as np

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

SECURITY_SENSITIVE_EIDS = {
    "4625",  # failed login / brute force
    "4648",  # explicit credentials
    "7045",  # new service installed
    "4698",  # scheduled task created
    "1102",  # security log cleared
    "4688",  # process creation
    "4720",  # new user account created
    "4672",  # special privileges assigned
    "4624",  # successful logon
    "4634",  # logoff
    "4104",  # powershell script block
}

def compress(events) -> list[dict]:
    groups = defaultdict(lambda: {
        "count": 0,
        "severities": set(),
        "attack_types": set(),
        "sources": set(),
        "first_seen": None,
        "last_seen": None,
        "sample_raw": None,
        "sample_metadata": None
    })

    total = 0
    for event in events:
        if event["source"] == "evtx":
            key = (
                f"evtx|"
                f"EID={event['event_type']}|"
                f"CHANNEL={event['metadata'].get('Channel','')}"
            )
        else:
            meta = event.get("metadata", {})
            key = (
                f"waf|"
                f"ATTACK={meta.get('attack_type','none')}|"
                f"METHOD={meta.get('method','')}|"
                f"STATUS={meta.get('status','')}"
            )

        g = groups[key]
        g["count"] += 1
        g["sources"].add(event["source"])
        g["severities"].add(event["severity"])
        g["sample_raw"] = g["sample_raw"] or event["raw"]
        g["sample_metadata"] = (
            g["sample_metadata"] or event.get("metadata", {})
        )

        ts = event.get("ts", "unknown")
        if ts != "unknown":
            if g["first_seen"] is None or ts < g["first_seen"]:
                g["first_seen"] = ts
            if g["last_seen"] is None or ts > g["last_seen"]:
                g["last_seen"] = ts

        attack = event.get("metadata", {}).get("attack_type")
        if attack and attack != "none":
            g["attack_types"].add(attack)

        total += 1
        if total % 100_000 == 0:
            print(f"  [compress] {total:,} events → "
                  f"{len(groups)} groups so far...")

    templates = []
    for key, g in groups.items():
        sevs = g["severities"]
        top_sev = next(
            (s for s in SEVERITY_ORDER if s in sevs), "info"
        )
        templates.append({
            "template":        key,
            "count":           g["count"],
            "sources":         list(g["sources"]),
            "severities":      list(g["severities"]),
            "attack_types":    list(g["attack_types"]),
            "first_seen":      g["first_seen"] or "unknown",
            "last_seen":       g["last_seen"] or "unknown",
            "sample_raw":      g["sample_raw"],
            "sample_metadata": g["sample_metadata"],
            "top_severity":    top_sev
        })

    templates.sort(key=lambda x: x["count"], reverse=True)
    templates = add_z_scores(templates)

    print(f"\n[compress] Complete:")
    print(f"  Total events processed: {total:,}")
    print(f"  Groups produced:        {len(templates)}")
    print(f"\nTop 10 groups:")
    for t in templates[:10]:
        print(f"  [{t['count']:>6}x] "
              f"[{t['top_severity'].upper()}] "
              f"{t['template']}")

    baseline = extract_baseline(templates)
    import json as _json
    import os as _os
    _os.makedirs("uploads", exist_ok=True)
    with open("uploads/baseline.json", "w") as f:
        _json.dump(baseline, f, indent=2)
    print(f"\n[baseline] Normal activity learned:")
    print(f"  Total events:    {baseline['total_events']:,}")
    print(f"  Anomalous groups:{baseline['anomalous_groups']}")
    print(f"  Top EventIDs (normal for this client):")
    for e in baseline['top_event_ids'][:3]:
        print(f"    EID={e['eid']}: {e['count']:,} events")

    return templates


def add_z_scores(templates: list[dict]) -> list[dict]:
    MIN_GROUPS_FOR_ZSCORE = 30

    if len(templates) < 2:
        for t in templates:
            t["z_score"]      = 0.0
            t["mean_count"]   = float(t["count"])
            t["std_count"]    = 0.0
            t["is_anomalous"] = False
        return templates

    if len(templates) < MIN_GROUPS_FOR_ZSCORE:
        print(f"[drain3] Only {len(templates)} groups "
              f"— z-score skipped (need {MIN_GROUPS_FOR_ZSCORE}+)")
        for t in templates:
            t["z_score"]      = 0.0
            t["mean_count"]   = 0.0
            t["std_count"]    = 0.0
            t["is_anomalous"] = False
        return templates

    counts = np.array(
        [t["count"] for t in templates], dtype=float
    )
    mean = float(counts.mean())
    std  = float(counts.std())

    for t in templates:
        z = (t["count"] - mean) / std if std > 0 else 0.0
        t["z_score"]      = round(float(z), 2)
        t["mean_count"]   = round(mean, 2)
        t["std_count"]    = round(std, 2)
        t["is_anomalous"] = bool(abs(z) > 2.0)

    return templates


def extract_baseline(
    templates: list[dict]
) -> dict:
    """
    Automatically learns what is normal
    from this specific log file.
    No hardcoding. Works for any client.
    """
    from collections import Counter

    baseline = {
        "top_event_ids":    [],
        "peak_hours":       [],
        "dominant_channels":[],
        "normal_threshold": {},
        "total_events":     0,
        "total_groups":     len(templates),
    }

    # Find most common EventIDs (these are NORMAL)
    event_counts = Counter()
    for t in templates:
        tmpl = t.get("template", "")
        if not tmpl.startswith("evtx|"):
            continue
        for part in tmpl.split("|"):
            if part.startswith("EID="):
                eid = part[4:]
                event_counts[eid] += t.get("count", 0)
                baseline["total_events"] += t.get("count", 0)

    # Top 5 EventIDs = baseline normal activity
    baseline["top_event_ids"] = [
        {"eid": eid, "count": count}
        for eid, count in event_counts.most_common(5)
    ]

    # Calculate normal threshold per EventID
    # Events below this count = rare = suspicious
    # Events above this count = common = normal
    total = baseline["total_events"]
    for eid, count in event_counts.items():
        pct = (count / total * 100) if total > 0 else 0
        is_dominant = (
            pct > 5.0 and
            eid not in SECURITY_SENSITIVE_EIDS
        )
        baseline["normal_threshold"][eid] = {
            "count":       count,
            "percentage":  round(pct, 2),
            "is_dominant": is_dominant
        }

    # Find anomalous groups (these are SUSPICIOUS)
    anomalous = [
        t for t in templates
        if t.get("is_anomalous")
    ]
    baseline["anomalous_groups"] = len(anomalous)

    # WAF attack summary
    waf_attacks = [
        t for t in templates
        if t.get("template","").startswith("waf|")
        and t.get("attack_types")
    ]
    baseline["waf_attack_types"] = list(set(
        attack
        for t in waf_attacks
        for attack in t.get("attack_types", [])
    ))

    return baseline


if __name__ == "__main__":
    import asyncio
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from pipeline.router import route

    files = {}
    for arg in sys.argv[1:]:
        if arg.endswith('.evtx'): files['evtx'] = arg
        if arg.endswith('.log'):  files['waf']  = arg

    if not files:
        print("Usage: python drain3_engine.py <file.evtx> <file.log>")
        sys.exit(1)

    print("Step 1: Routing files...")
    events = asyncio.run(route(files))

    print("\nStep 2: Grouping events...")
    templates = compress(events)

    print("\nStep 3: Saving templates.json...")
    os.makedirs('uploads', exist_ok=True)
    with open('uploads/templates.json', 'w') as f:
        json.dump(templates, f, indent=2)
    print(f"Saved {len(templates)} groups to uploads/templates.json")
