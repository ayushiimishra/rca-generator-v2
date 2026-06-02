#!/bin/bash
cd /home/raghav/rca-generator
source .venv/bin/activate

echo "=================================================="
echo " AI RCA GENERATOR - DEMO RUN"
echo "=================================================="
echo ""

python -c "
import asyncio, json, shutil, os
from pipeline.router import route
from pipeline.drain3_engine import compress
from pipeline.sigma_engine import run_chainsaw, simulate_chainsaw
from pipeline.sigma_lite import run_sigma_lite
from pipeline.scenario_engine import evaluate_stream_scenarios
from pipeline.triage_agent import run_triage
from pipeline.phi4_rca import generate_rca

DESKTOP = '/mnt/c/Users/ragha/Desktop/RCA_Demo'

async def run():
    print('STEP 1: Parsing log file...')
    events = await route({'evtx': 'uploads/DE_RDP_Tunnel_5156.evtx'})
    templates = compress(events)
    with open('uploads/templates.json', 'w') as f:
        json.dump(templates, f, indent=2)

    print()
    print('STEP 2: Running detection layers...')
    sigma_hits = run_chainsaw(
        'uploads/DE_RDP_Tunnel_5156.evtx',
        './chainsaw/chainsaw',
        './sigma-rules/rules/windows/'
    )
    if not sigma_hits:
        sigma_hits = simulate_chainsaw(
            'uploads/DE_RDP_Tunnel_5156.evtx', templates
        )
    events2 = await route({'evtx': 'uploads/DE_RDP_Tunnel_5156.evtx'})
    lite_hits = run_sigma_lite(events2)
    scenario_hits = evaluate_stream_scenarios()

    all_hits = sigma_hits + lite_hits
    with open('uploads/sigma_hits.json', 'w') as f:
        json.dump(all_hits, f, indent=2)

    print()
    print('STEP 3: Triage agent...')
    context = run_triage(
        templates_path='uploads/templates.json',
        sigma_path='uploads/sigma_hits.json',
        output_path='uploads/triage_context.txt'
    )

    print()
    print('STEP 4: Generating AI RCA report...')
    report = generate_rca(
        output_path='uploads/rca_report.json',
        session_id='DEMO_RDP_TUNNEL'
    )

    print()
    print('STEP 5: Saving to Desktop...')
    os.makedirs(DESKTOP, exist_ok=True)
    files = {
        'uploads/templates.json':       '3_templates.json',
        'uploads/sigma_hits.json':      '4_sigma_hits.json',
        'uploads/sigma_lite_hits.json': '5_sigma_lite_hits.json',
        'uploads/scenario_hits.json':   '6_scenario_hits.json',
        'uploads/triage_context.txt':   '7_triage_context.txt',
        'uploads/rca_report.json':      '8_rca_report.json',
    }
    for src, dst in files.items():
        if os.path.exists(src):
            shutil.copy(src, f'{DESKTOP}/{dst}')
            print(f'  Saved: {dst}')

    shutil.copy('uploads/rca_report.json', 'uploads/demo_rca_report.json')

    print()
    print('==================================================')
    print(' DEMO COMPLETE')
    print('==================================================')
    print(f'Severity:         {report.get(\"severity_overall\",\"\")}')
    print(f'Attack confirmed: {report.get(\"attack_confirmed\",\"\")}')
    print(f'Confidence:       {report.get(\"confidence_level\",\"\")}')
    print(f'Summary: {report.get(\"summary\",\"\")}')
    print()
    print('MITRE ATT&CK:')
    for m in report.get('mitre_attack', []):
        print(f'  {m}')
    print()
    print('Five Whys:')
    for i, w in enumerate(report.get('five_whys',[]),1):
        print(f'  {i}. Q: {w.get(\"why\",\"\")}')
        print(f'     A: {w.get(\"answer\",\"\")}')
    print()
    print('Files saved to Desktop/RCA_Demo/')

asyncio.run(run())
"
