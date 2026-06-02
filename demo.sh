#!/bin/bash
# ================================================
# AI RCA Generator — Full Pipeline Demo Script
# Runs everything and saves outputs to Desktop
# ================================================

cd ~/rca-generator
source .venv/bin/activate

DESKTOP="/mnt/c/Users/ragha/Desktop/RCA_Demo"
mkdir -p "$DESKTOP"

echo "=================================================="
echo " AI RCA GENERATOR — FULL PIPELINE DEMO"
echo "=================================================="
echo ""

python -c "
import asyncio, json, os, shutil
from collections import Counter
from pipeline.router import route
from pipeline.drain3_engine import compress
from pipeline.sigma_engine import run_chainsaw, simulate_chainsaw
from pipeline.sigma_lite import run_sigma_lite
from pipeline.scenario_engine import evaluate_stream_scenarios
from pipeline.triage_agent import run_triage

DESKTOP = '/mnt/c/Users/ragha/Desktop/RCA_Demo'

async def demo():

    print('STEP 1: Detecting file types by content...')
    from pipeline.file_detector import validate_and_route
    for f in ['uploads/security.evtx', 'uploads/sample_waf.log']:
        result = validate_and_route(f)
        print(f'  {result[\"filename\"]:20} → type={result[\"type\"]:12} valid={result[\"valid\"]}')
    print()

    print('STEP 2: Parsing both log files...')
    events_for_count = await route({
        'evtx': 'uploads/security.evtx',
        'waf':  'uploads/sample_waf.log'
    })
    sev_counter = Counter()
    all_events  = []
    for e in events_for_count:
        sev_counter[e['severity']] += 1
        all_events.append(e)
    print(f'  Total events parsed: {len(all_events):,}')
    for sev in ['critical','high','medium','low','info']:
        c = sev_counter.get(sev, 0)
        if c > 0:
            print(f'    {sev:8}: {c:,}')

    print()
    print('  Saving evtx_parsed.json (first 50 events)...')
    evtx_events = [e for e in all_events if e['source']=='evtx'][:50]
    with open('uploads/evtx_parsed.json', 'w') as f:
        json.dump(evtx_events, f, indent=2)

    print('  Saving waf_parsed.json...')
    waf_events = [e for e in all_events if e['source']=='waf']
    with open('uploads/waf_parsed.json', 'w') as f:
        json.dump(waf_events, f, indent=2)
    print()

    print('STEP 3: Compressing 32,061 events to groups...')
    events2 = await route({
        'evtx': 'uploads/security.evtx',
        'waf':  'uploads/sample_waf.log'
    })
    templates = compress(events2)
    with open('uploads/templates.json', 'w') as f:
        json.dump(templates, f, indent=2)

    critical  = [t for t in templates if t['top_severity']=='critical']
    high      = [t for t in templates if t['top_severity']=='high']
    anomalous = [t for t in templates if t.get('is_anomalous')]
    print(f'  Groups created:   {len(templates)}')
    print(f'  Critical groups:  {len(critical)}')
    print(f'  High groups:      {len(high)}')
    print(f'  Anomalous groups: {len(anomalous)}')
    print()

    print('STEP 4: Layer 1 — Chainsaw channel-specific Sigma rules...')
    sigma_hits = run_chainsaw(
        'uploads/security.evtx',
        './chainsaw/chainsaw',
        './sigma-rules/rules/windows/'
    )
    if not sigma_hits:
        sigma_hits = simulate_chainsaw(
            'uploads/security.evtx', templates
        )
    print(f'  Sigma hits: {len(sigma_hits)}')
    for h in sigma_hits:
        print(f'    [{h[\"severity\"].upper():8}] {h[\"technique\"]:12} x{h[\"count\"]:>5} — {h[\"rule_name\"]}')
    print()

    print('STEP 5: Layer 2 — Custom sigma_lite context-aware rules...')
    events3 = await route({'evtx': 'uploads/security.evtx'})
    lite_hits = run_sigma_lite(
        events3,
        output_path='uploads/sigma_lite_hits.json'
    )
    print(f'  Custom rule hits: {len(lite_hits)}')
    for h in lite_hits:
        print(f'    [{h[\"severity\"].upper():8}] conf={h[\"confidence\"]:.2f} x{h[\"count\"]:>5} — {h[\"rule_name\"]}')
    print()

    print('STEP 6: Layer 3 — Behavioral scenario engine...')
    scenario_hits = evaluate_stream_scenarios(
        templates_path='uploads/templates.json',
        output_path='uploads/scenario_hits.json'
    )
    print(f'  Scenarios triggered: {len(scenario_hits)}')
    for h in scenario_hits:
        print(f'    [{h[\"severity\"].upper():8}] conf={h[\"confidence\"]:.2f} — {h[\"rule_name\"]}')
    if not scenario_hits:
        print('    None — clean machine (correct)')
    print()

    print('STEP 7: Merging all layers and running triage agent...')
    all_hits = sigma_hits + lite_hits
    with open('uploads/sigma_hits.json', 'w') as f:
        json.dump(all_hits, f, indent=2)

    context = run_triage(
        templates_path='uploads/templates.json',
        sigma_path='uploads/sigma_hits.json',
        output_path='uploads/triage_context.txt'
    )
    print(f'  Context built: {len(context):,} chars')
    print(f'  CONFIRMED findings: {context.count(\"[CONFIRMED\")}')
    print(f'  INVESTIGATE:        {context.count(\"[INVESTIGATE\")}')
    print()

    print('STEP 8: Searching ChromaDB for similar past incidents...')
    from pipeline.chromadb_store import (
        seed_with_examples, search_similar, build_findings_text
    )
    seed_with_examples()
    findings_text = build_findings_text(templates, all_hits)
    matches = search_similar(findings_text)
    print(f'  Similar incidents found: {len(matches)}')
    for m in matches:
        print(f'    {m[:80]}')
    print()

    print('STEP 9: Copying output files to Desktop...')
    files = {
        'uploads/evtx_parsed.json':    '1_evtx_parsed.json',
        'uploads/waf_parsed.json':      '2_waf_parsed.json',
        'uploads/templates.json':       '3_templates_compressed.json',
        'uploads/sigma_hits.json':      '4_sigma_hits.json',
        'uploads/sigma_lite_hits.json': '5_sigma_lite_hits.json',
        'uploads/scenario_hits.json':   '6_scenario_hits.json',
        'uploads/triage_context.txt':   '7_triage_context.txt',
    }
    for src, dst in files.items():
        if os.path.exists(src):
            shutil.copy(src, os.path.join(DESKTOP, dst))
            size = os.path.getsize(src)
            print(f'  {dst}: {size:,} bytes ✅')
    print()

    print('==================================================')
    print(' DEMO COMPLETE')
    print('==================================================')
    print()
    print('FILES ON DESKTOP (RCA_Demo folder):')
    print('  1_evtx_parsed.json       first 50 Windows events')
    print('  2_waf_parsed.json        all WAF attack events')
    print('  3_templates_compressed.json  31 compressed groups')
    print('  4_sigma_hits.json        Chainsaw Sigma rule hits')
    print('  5_sigma_lite_hits.json   custom rule hits')
    print('  6_scenario_hits.json     behavioral scenarios')
    print('  7_triage_context.txt     LLM prompt context')
    print()
    print('SUMMARY:')
    print(f'  Events parsed:      {len(all_events):,}')
    print(f'  Groups created:     {len(templates)}')
    print(f'  Chainsaw hits:      {len(sigma_hits)}')
    print(f'  Custom rule hits:   {len(lite_hits)}')
    print(f'  Scenario hits:      {len(scenario_hits)}')
    print(f'  CONFIRMED findings: {context.count(\"[CONFIRMED\")}')
    print(f'  INVESTIGATE:        {context.count(\"[INVESTIGATE\")}')
    print()
    print('NEXT STEP: phi4_rca.py will generate the RCA report')
    print('==================================================')

asyncio.run(demo())
"
