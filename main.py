import os
import uuid
import asyncio
import json
import threading
import time as _time
from datetime import datetime
from pathlib import Path
from fastapi import FastAPI, UploadFile, File, BackgroundTasks
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from dotenv import load_dotenv

load_dotenv(dotenv_path=Path(__file__).parent / ".env")

app = FastAPI(title="AI RCA Generator")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount(
    "/static",
    StaticFiles(directory="frontend"),
    name="static"
)

SESSIONS = {}
UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)


def _cleanup_old_sessions():
    while True:
        _time.sleep(3600)
        cutoff = _time.time() - 86400
        to_delete = []
        for sid, s in list(SESSIONS.items()):
            created = s.get("created_at", 0)
            if created and created < cutoff:
                to_delete.append(sid)
                for f in UPLOAD_DIR.glob(f"{sid}_*"):
                    try:
                        f.unlink()
                    except Exception:
                        pass
        for sid in to_delete:
            SESSIONS.pop(sid, None)
        if to_delete:
            print(f"[cleanup] Removed "
                  f"{len(to_delete)} old sessions")


_cleanup_thread = threading.Thread(
    target=_cleanup_old_sessions, daemon=True
)
_cleanup_thread.start()


@app.get("/")
async def root():
    return FileResponse("frontend/index.html")


@app.post("/api/analyze")
async def analyze(
    background_tasks: BackgroundTasks,
    log_files: list[UploadFile] = File(None)
):
    session_id = str(uuid.uuid4())[:8]
    SESSIONS[session_id] = {
        "status":     "starting",
        "progress":   0,
        "message":    "Uploading files...",
        "report":     None,
        "error":      None,
        "created_at": _time.time(),
    }

    evtx_paths = []
    waf_paths  = []
    dns_paths  = []

    if log_files:
        for i, f in enumerate(log_files):
            if not f or not f.filename:
                continue
            content = await f.read()
            if not content:
                continue

            # Save with a generic extension first for detection
            ext = Path(f.filename).suffix.lower() or ".log"
            path = str(UPLOAD_DIR / f"{session_id}_upload_{i}{ext}")
            with open(path, "wb") as out:
                out.write(content)

            file_size_mb = len(content) / (1024 * 1024)
            if file_size_mb > 500:
                os.remove(path)
                return JSONResponse(
                    {"error": f"{f.filename} is too large "
                              f"({file_size_mb:.0f}MB). Max 500MB."},
                    status_code=400
                )

            from pipeline.file_detector import detect_file_type
            result = detect_file_type(path)

            if not result["valid"]:
                os.remove(path)
                return JSONResponse(
                    {"error": f"{f.filename}: "
                              f"{result.get('message') or result.get('reason', 'Unsupported file format')}"},
                    status_code=400
                )

            file_type = result["type"]
            if file_type in ("evtx", "evtx_csv"):
                evtx_paths.append(path)
            elif file_type in ("waf", "waf_csv"):
                waf_paths.append(path)
            elif file_type == "dns":
                dns_paths.append(path)
            else:
                os.remove(path)
                return JSONResponse(
                    {"error": f"{f.filename}: unrecognised log type '{file_type}'. "
                              "Supported: .evtx, Nginx/Apache .log, DNS .log, CSV"},
                    status_code=400
                )

    if not evtx_paths and not waf_paths and not dns_paths:
        return JSONResponse(
            {"error": "No valid files uploaded. "
                      "Supported: .evtx, Nginx/Apache .log, DNS .log, CSV"},
            status_code=400
        )

    background_tasks.add_task(
        run_pipeline,
        session_id,
        evtx_paths,
        waf_paths,
        dns_paths
    )

    return {"session_id": session_id}


RULE_TO_EID_MAP = {
    "log cleared": "1102",
    "rdp login": "4624",
    "admin user remote": "4624",
    "brute force": "4625",
    "explicit credential": "4648",
    "privilege": "4672",
    "process creation": "4688",
    "scheduled task": "4698",
    "new service": "7045",
    "user account created": "4720",
    "powershell": "4104",
    "pass-the-hash": "4624",
    "lsass": "4656",
    "kerberoasting": "4769",
    "dcsync": "4662",
}


async def run_pipeline(
    session_id:  str,
    evtx_paths:  list,
    waf_paths:   list,
    dns_paths:   list = None
):
    def update(progress, message):
        SESSIONS[session_id]["progress"] = progress
        SESSIONS[session_id]["message"]  = message
        SESSIONS[session_id]["status"]   = "running"
        print(f"[{session_id}] {progress}% {message}")

    try:
        from pipeline.router import route
        from pipeline.drain3_engine import compress
        from pipeline.sigma_engine import (
            run_chainsaw, simulate_chainsaw
        )
        from pipeline.sigma_lite import run_sigma_lite
        from pipeline.scenario_engine import (
            evaluate_stream_scenarios
        )
        from pipeline.correlation_engine import run_correlation
        from pipeline.triage_agent import run_triage
        from pipeline.phi4_rca import generate_rca

        import heapq
        from pipeline.evtx_parser import parse_evtx
        from pipeline.waf_parser import parse_waf

        evtx_streams = [
            parse_evtx(p) for p in evtx_paths
        ]
        waf_streams  = [
            parse_waf(p) for p in waf_paths
        ]

        def _ts_key(e):
            ts = e.get("ts", "unknown")
            return ts if ts != "unknown" \
                else "9999-12-31T23:59:59Z"

        dns_paths = dns_paths or []
        from pipeline.dns_parser import parse_dns
        dns_streams = [parse_dns(p) for p in dns_paths]

        all_streams = evtx_streams + waf_streams + dns_streams
        if len(all_streams) == 1:
            merged_events = all_streams[0]
        else:
            merged_events = heapq.merge(
                *all_streams, key=_ts_key
            )

        total_evtx = len(evtx_paths)
        total_waf  = len(waf_paths)
        print(f"[{session_id}] Merging "
              f"{total_evtx} evtx + "
              f"{total_waf} waf files")

        update(10, "Parsing log files...")
        templates = compress(merged_events)

        if len(templates) == 0:
            SESSIONS[session_id]["status"]  = "error"
            SESSIONS[session_id]["error"]   = (
                "No valid log data found in uploaded file. "
                "Please upload a real Windows Event Log (.evtx) "
                "or Nginx/Apache web access log (.log)."
            )
            SESSIONS[session_id]["message"] = "Invalid file"
            return

        templates_path = str(
            UPLOAD_DIR / f"{session_id}_templates.json"
        )
        with open(templates_path, "w") as f:
            json.dump(templates, f)

        update(30, "Running Chainsaw Sigma rules...")
        sigma_hits = []
        try:
            for ep in evtx_paths:
                hits = run_chainsaw(
                    ep,
                    "./chainsaw/chainsaw",
                    "./sigma-rules/rules/windows/"
                )
                sigma_hits.extend(hits)
            if not sigma_hits and evtx_paths:
                sigma_hits = simulate_chainsaw(
                    evtx_paths[0], templates
                )
        except Exception as _ce:
            print(f"[{session_id}] Chainsaw skipped: {_ce}")
            sigma_hits = []

        update(50, "Running custom detection rules...")
        lite_hits = []
        lite_path = str(UPLOAD_DIR / f"{session_id}_sigma_lite.json")

        # Build merged event stream: evtx + waf + dns
        all_rule_streams = []
        if evtx_paths:
            all_rule_streams += [parse_evtx(p) for p in evtx_paths]
        if waf_paths:
            from pipeline.waf_parser import parse_waf as _pw
            all_rule_streams += [_pw(p) for p in waf_paths]
        if dns_paths:
            from pipeline.dns_parser import parse_dns as _pd
            all_rule_streams += [_pd(p) for p in dns_paths]

        if all_rule_streams:
            import heapq as _hq2
            if len(all_rule_streams) == 1:
                all_rule_events = all_rule_streams[0]
            else:
                all_rule_events = _hq2.merge(
                    *all_rule_streams, key=_ts_key
                )
            lite_hits = run_sigma_lite(
                all_rule_events, output_path=lite_path
            )

        # Ensure lite_path file always exists for downstream consumers
        if not os.path.exists(lite_path):
            with open(lite_path, "w") as f:
                json.dump([], f)

        all_hits = sigma_hits + lite_hits
        sigma_path = str(
            UPLOAD_DIR / f"{session_id}_sigma_hits.json"
        )
        with open(sigma_path, "w") as f:
            json.dump(all_hits, f)

        update(60, "Running behavioral scenarios...")
        scenario_path = str(
            UPLOAD_DIR / f"{session_id}_scenario_hits.json"
        )
        try:
            scenario_hits = evaluate_stream_scenarios(
                sigma_hits_path=lite_path if lite_hits else sigma_path,
                waf_hits_path=sigma_path,
                output_path=scenario_path,
            )
        except Exception as _se:
            print(f"[{session_id}] Scenario engine failed: {_se}")
            scenario_hits = []

        # Ensure scenario_path file always exists for run_correlation
        if not os.path.exists(scenario_path):
            with open(scenario_path, "w") as f:
                json.dump([], f)

        update(65, "Correlating cross-source evidence...")
        corr_path     = str(UPLOAD_DIR / f"{session_id}_correlation.json")
        timeline_path = str(UPLOAD_DIR / f"{session_id}_timeline.json")

        # Re-parse log files to pass raw event stream for richer IP correlation
        from pipeline.evtx_parser import parse_evtx as _parse_evtx
        from pipeline.waf_parser  import parse_waf  as _parse_waf
        _raw_events = []
        try:
            for _ep in evtx_paths:
                _raw_events.extend(list(_parse_evtx(_ep)))
            for _wp in waf_paths:
                _raw_events.extend(list(_parse_waf(_wp)))
            from pipeline.dns_parser import parse_dns as _pdns
            for _dp in (dns_paths or []):
                _raw_events.extend(list(_pdns(_dp)))
        except Exception as _e:
            print(f"[{session_id}] Raw event reparse skipped: {_e}")

        try:
            run_correlation(
                sigma_lite_path=lite_path if lite_hits else sigma_path,
                sigma_path=sigma_path,
                waf_hits_path=sigma_path,
                scenario_path=scenario_path,
                corr_output=corr_path,
                timeline_output=timeline_path,
                raw_events=_raw_events or None,
            )
        except Exception as _cre:
            print(f"[{session_id}] Correlation failed: {_cre}")

        update(70, "Running triage agent...")
        triage_path = str(
            UPLOAD_DIR / f"{session_id}_triage.txt"
        )
        try:
            run_triage(
                templates_path=templates_path,
                sigma_path=sigma_path,
                output_path=triage_path,
                corr_path=corr_path,
                timeline_path=timeline_path,
            )
        except Exception as _te:
            print(f"[{session_id}] Triage failed: {_te}")

        # Ensure triage_path file always exists for generate_rca
        if not os.path.exists(triage_path):
            with open(triage_path, "w") as f:
                f.write("Triage unavailable.")

        update(85, "Generating RCA with AI...")
        rca_path = str(
            UPLOAD_DIR / f"{session_id}_rca.json"
        )
        report = generate_rca(
            triage_context_path=triage_path,
            templates_path=templates_path,
            sigma_hits_path=sigma_path,
            output_path=rca_path,
            session_id=session_id
        )

        if "error" in report:
            report["note"]         = "Demo report loaded"
            report["generated_at"] = datetime.utcnow().isoformat()
            report["model"]        = "demo-backup"

        try:
            with open(sigma_path) as f:
                all_sigma = json.load(f)
            enriched_hits = []
            for hit in all_sigma:
                enriched = dict(hit)
                eid = None
                rule_name = hit.get("rule_name", "")
                for k, v in RULE_TO_EID_MAP.items():
                    if k.lower() in rule_name.lower():
                        eid = v
                        break
                if not eid and hit.get("sample_raw"):
                    import re as _re2
                    m = _re2.search(
                        r'"EventID":\s*"?(\d+)"?',
                        hit.get("sample_raw", "")
                    )
                    if m:
                        eid = m.group(1)
                if eid:
                    enriched["event_id"] = eid
                enriched["proof"] = (
                    f"Detected by {hit.get('source', 'unknown')} "
                    f"rule '{rule_name}'. "
                    f"Found {hit.get('count', 0)} occurrence(s) "
                    f"on systems: "
                    f"{', '.join(hit.get('systems', []))}"
                )
                enriched_hits.append(enriched)
            report["detection_hits"] = enriched_hits
        except Exception:
            report["detection_hits"] = []

        try:
            with open(templates_path) as f:
                tmpl = json.load(f)
            critical_events = []
            for t in tmpl:
                sev = t.get("top_severity","")
                if sev in ["critical","high","medium"]:
                    meta = t.get("sample_metadata",{})
                    edata = meta.get("EventData",{}) if meta else {}
                    critical_events.append({
                        "pattern":   t.get("template",""),
                        "count":     t.get("count",0),
                        "severity":  sev,
                        "first_seen": t.get("first_seen","unknown"),
                        "last_seen":  t.get("last_seen","unknown"),
                        "systems":   [meta.get("Computer","unknown")] if meta else [],
                        "z_score":   t.get("z_score",0),
                        "is_anomalous": t.get("is_anomalous",False),
                    })
            print(f"[{session_id}] Timeline: {len(critical_events)} events")
            for ev in critical_events[:3]:
                print(f"  {ev['severity']} {ev['pattern']} {ev['first_seen']}")
            report["event_timeline"] = critical_events[:15]
        except Exception:
            report["event_timeline"] = []

        SESSIONS[session_id]["status"]   = "complete"
        SESSIONS[session_id]["progress"] = 100
        SESSIONS[session_id]["message"]  = "RCA complete"
        SESSIONS[session_id]["report"]   = report
        print(f"[{session_id}] Complete")

    except Exception as e:
        SESSIONS[session_id]["status"]  = "error"
        SESSIONS[session_id]["error"]   = str(e)
        SESSIONS[session_id]["message"] = f"Error: {e}"
        print(f"[{session_id}] Error: {e}")


@app.get("/api/status/{session_id}")
async def get_status(session_id: str):
    if session_id not in SESSIONS:
        return JSONResponse(
            {"error": "Session not found"},
            status_code=404
        )
    s = SESSIONS[session_id]
    return {
        "session_id": session_id,
        "status":     s["status"],
        "progress":   s["progress"],
        "message":    s["message"],
        "error":      s["error"]
    }


@app.get("/api/report/{session_id}")
async def get_report(session_id: str):
    if session_id not in SESSIONS:
        return JSONResponse(
            {"error": "Session not found"},
            status_code=404
        )
    s = SESSIONS[session_id]
    if s["status"] != "complete":
        return JSONResponse(
            {"error": "Report not ready yet"},
            status_code=202
        )
    return s["report"]


@app.get("/api/context/{session_id}")
async def get_context(session_id: str):
    result = {"session_id": session_id}
    for name, filename in [
        ("triage_context",   f"{session_id}_triage.txt"),
        ("sigma_hits",       f"{session_id}_sigma_hits.json"),
        ("event_groups",     f"{session_id}_templates.json"),
        ("scenario_hits",    f"{session_id}_scenario_hits.json"),
    ]:
        path = UPLOAD_DIR / filename
        try:
            with open(path) as f:
                if filename.endswith(".json"):
                    result[name] = json.load(f)
                else:
                    result[name] = f.read()
        except Exception:
            result[name] = None
    return result


@app.get("/api/health")
async def health_check():
    import shutil
    disk = shutil.disk_usage("/")
    disk_free_gb = round(disk.free / (1024 ** 3), 1)

    gemini_key_count = 0
    if os.environ.get("GEMINI_API_KEY", ""):
        gemini_key_count += 1
    i = 2
    while os.environ.get(f"GEMINI_API_KEY_{i}", ""):
        gemini_key_count += 1
        i += 1

    return {
        "status":          "healthy",
        "version":         "1.0.0",
        "gemini_keys":     gemini_key_count,
        "xai_configured":  bool(os.environ.get("XAI_API_KEY", "")),
        "vt_configured":   bool(os.environ.get("VT_API_KEY", "")),
        "abuseipdb_configured": bool(
            os.environ.get("ABUSEIPDB_API_KEY", "")
        ),
        "disk_free_gb":    disk_free_gb,
        "active_sessions": len(SESSIONS),
        "upload_dir":      str(UPLOAD_DIR),
    }


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=port,
        reload=True
    )
