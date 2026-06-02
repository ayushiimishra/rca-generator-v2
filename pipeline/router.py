import sys
import heapq
import asyncio
from pathlib import Path
from collections import Counter

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pipeline.evtx_parser import parse_evtx
from pipeline.waf_parser  import parse_waf
from pipeline.dns_parser  import parse_dns


def _ts_key(event: dict) -> str:
    ts = event.get("ts", "unknown")
    return ts if ts and ts != "unknown" else "9999-12-31T23:59:59Z"


async def route(files: dict):
    evtx_path = files.get("evtx")
    waf_path  = files.get("waf")
    dns_path  = files.get("dns")

    sources = [k for k, v in files.items() if v]
    print(f"Mode detected: {'+'.join(sources) or 'none'}")

    if not sources:
        raise ValueError("No files provided.")

    streams = []
    if evtx_path:
        streams.append(parse_evtx(evtx_path))
    if waf_path:
        streams.append(parse_waf(waf_path))
    if dns_path:
        streams.append(parse_dns(dns_path))

    if len(streams) == 1:
        return streams[0]

    return heapq.merge(*streams, key=_ts_key)


if __name__ == "__main__":
    files = {}
    for arg in sys.argv[1:]:
        if arg.endswith('.evtx'): files['evtx'] = arg
        if arg.endswith('.log'):  files['waf']  = arg

    if not files:
        print("Usage: python router.py <file.evtx> <file.log>")
        sys.exit(1)

    print("Streaming validation (production safe)...")
    stream = asyncio.run(route(files))

    count = 0
    severities = {}
    sources = {}
    first_event = None

    for event in stream:
        count += 1
        if first_event is None:
            first_event = event
        sev = event['severity']
        src = event['source']
        severities[sev] = severities.get(sev, 0) + 1
        sources[src] = sources.get(src, 0) + 1
        if count % 100_000 == 0:
            print(f"  {count:,} events streamed...")

    print(f"\nTotal events streamed: {count:,}")
    print(f"Sources: {sources}")
    print(f"Severities: {severities}")
    if first_event:
        import json
        print(f"\nFirst event:")
        print(json.dumps(first_event, indent=2))
