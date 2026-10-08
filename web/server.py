"""DNSGuard-X web backend.

A small FastAPI service that wraps the existing detection engine and returns JSON,
and serves the built React frontend so the whole app runs from one command:

    python web/server.py

Endpoints
---------
GET  /api/health            liveness probe
GET  /api/sample            run detection on the bundled data/pcaps/mixed.pcap
POST /api/analyze           run detection on an uploaded .pcap/.pcapng file
GET  /api/runs              list runs stored in the SQLite database
GET  /api/runs/{run_id}     warnings + stats for one stored run

The static React build (web/frontend/dist) is mounted at "/".
"""

from __future__ import annotations

import sqlite3
import sys
import tempfile
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from dnsguard.capture import CaptureError, read_pcap
from dnsguard.config import load_config
from dnsguard.engine import DetectionEngine
from dnsguard.parser import parse_packet
from dnsguard.whitelist import Whitelist

app = FastAPI(title="DNSGuard-X", version="1.0.0")

# Allow the Vite dev server (port 5173) to call the API during development.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

_CONFIG = load_config()
_WHITELIST = Whitelist.load(_CONFIG["whitelist"]["path"], _CONFIG["whitelist"]["enabled"])

# Plain-language description of every attack category, shown in the UI.
CATEGORY_HELP = {
    "DNS Tunneling (payload)": "Data is being hidden inside the website names themselves. The "
        "names are unusually long and look scrambled, which is how smuggled data appears.",
    "DNS Tunneling (volume)": "One computer is looking up a huge number of different made-up names "
        "under the same domain in a short time, a common sign of data being sent out.",
    "DGA / C2 / Water Torture": "A computer is looking up many names that do not exist. Malware "
        "does this while hunting for its control server, or to overload another server.",
    "DNS Flood": "One computer is sending lookups far faster than normal, which can overwhelm a "
        "DNS server.",
    "DNS Amplification": "Small questions are producing very large answers. Attackers abuse this to "
        "flood a victim with traffic.",
    "Suspected DGA Domain": "A single name looks machine-generated rather than human-chosen "
        "(random letters, few vowels). On its own this is only a weak hint.",
    "Cache Poisoning Indicator": "Answers arrived that do not match the questions asked, or two "
        "different answers came back for the same question. This can mean someone is forging replies.",
}


def _entropy_histogram(points: list[tuple[float, bool]], bins: int = 30) -> dict[str, Any]:
    """Bucket entropy values into a benign/flagged histogram for the chart."""
    vals = [e for e, _ in points if e > 0]
    if not vals:
        return {"edges": [], "normal": [], "flagged": []}
    lo, hi = min(vals), max(vals)
    if hi <= lo:
        hi = lo + 1.0
    width = (hi - lo) / bins
    edges = [round(lo + i * width, 3) for i in range(bins + 1)]
    normal = [0] * bins
    flagged = [0] * bins
    for e, is_flagged in points:
        if e <= 0:
            continue
        idx = min(int((e - lo) / width), bins - 1)
        (flagged if is_flagged else normal)[idx] += 1
    centers = [round((edges[i] + edges[i + 1]) / 2, 3) for i in range(bins)]
    return {"centers": centers, "normal": normal, "flagged": flagged}


def _run_engine(pcap_path: str) -> dict[str, Any]:
    """Run the detection engine on a capture and build the JSON payload."""
    entropy_points: list[tuple[float, bool]] = []

    def on_query(record, feats, flagged):
        if feats is not None:
            entropy_points.append((feats.entropy, bool(flagged)))

    engine = DetectionEngine(_CONFIG, _WHITELIST, on_query=on_query)
    try:
        for pkt in read_pcap(pcap_path):
            engine.stats.total_packets += 1
            rec = parse_packet(pkt)
            if rec is not None:
                engine.process_record(rec)
    except CaptureError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    s = engine.stats
    warnings = [{
        "timestamp": a.timestamp,
        "src_ip": a.src_ip,
        "domain": a.domain,
        "attack_type": a.attack_type,
        "severity": a.severity,
        "detector_id": a.detector_id,
        "hit_count": a.hit_count,
        "reason": a.reason,
    } for a in engine.alerts.alerts]

    categories = sorted({w["attack_type"] for w in warnings})
    return {
        "stats": {
            "packets": s.total_packets,
            "lookups_checked": s.inspected_queries,
            "queries_seen": s.queries,
            "responses_seen": s.responses,
            "whitelisted": s.whitelisted,
            "warnings": len(warnings),
            "matches": sum(w["hit_count"] for w in warnings),
            "hosts": len({w["src_ip"] for w in warnings}),
        },
        "warnings": warnings,
        "entropyHistogram": _entropy_histogram(entropy_points),
        "categoryHelp": {c: CATEGORY_HELP.get(c, "") for c in categories},
    }


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "whitelist": str(len(_WHITELIST))}


@app.get("/api/sample")
def analyze_sample() -> dict[str, Any]:
    sample = PROJECT_ROOT / "data" / "pcaps" / "mixed.pcap"
    if not sample.is_file():
        raise HTTPException(
            status_code=404,
            detail="Sample capture not found. Run: python tools/generate_traffic.py")
    payload = _run_engine(str(sample))
    payload["source"] = "Sample capture (mixed.pcap)"
    return payload


@app.post("/api/analyze")
async def analyze_upload(file: UploadFile = File(...)) -> dict[str, Any]:
    name = (file.filename or "").lower()
    if not name.endswith((".pcap", ".pcapng", ".cap")):
        raise HTTPException(status_code=400,
                            detail="Please upload a .pcap, .pcapng or .cap file.")
    data = await file.read()
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
        tmp.write(data)
        tmp_path = tmp.name
    try:
        payload = _run_engine(tmp_path)
    finally:
        try:
            Path(tmp_path).unlink()
        except OSError:
            pass
    payload["source"] = file.filename
    return payload


@app.get("/api/runs")
def list_runs() -> dict[str, Any]:
    db_path = _CONFIG["storage"].get("db_path", "dnsguard.db")
    if not Path(db_path).is_file():
        return {"runs": []}
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        rows = con.execute("SELECT * FROM runs ORDER BY run_id DESC").fetchall()
    finally:
        con.close()
    return {"runs": [dict(r) for r in rows]}


@app.get("/api/runs/{run_id}")
def get_run(run_id: int) -> dict[str, Any]:
    db_path = _CONFIG["storage"].get("db_path", "dnsguard.db")
    if not Path(db_path).is_file():
        raise HTTPException(status_code=404, detail="No database found.")
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        warnings = [dict(r) for r in con.execute(
            "SELECT timestamp, src_ip, domain, attack_type, severity, detector_id, "
            "hit_count, reason FROM alerts WHERE run_id=?", (run_id,)).fetchall()]
        ent = con.execute(
            "SELECT entropy, flagged FROM queries WHERE run_id=? AND is_response=0",
            (run_id,)).fetchall()
        lookups = con.execute(
            "SELECT COUNT(*) FROM queries WHERE run_id=? AND is_response=0 AND flagged IN (0,1)",
            (run_id,)).fetchone()[0]
    finally:
        con.close()
    points = [(float(r["entropy"]), bool(r["flagged"])) for r in ent]
    categories = sorted({w["attack_type"] for w in warnings})
    return {
        "stats": {
            "lookups_checked": lookups,
            "warnings": len(warnings),
            "matches": sum(w["hit_count"] for w in warnings),
            "hosts": len({w["src_ip"] for w in warnings}),
        },
        "warnings": warnings,
        "entropyHistogram": _entropy_histogram(points),
        "categoryHelp": {c: CATEGORY_HELP.get(c, "") for c in categories},
        "source": f"Stored run {run_id}",
    }


# ------------------------------------------------------------------ static frontend
_DIST = Path(__file__).resolve().parent / "frontend" / "dist"
if _DIST.is_dir():
    app.mount("/assets", StaticFiles(directory=_DIST / "assets"), name="assets")

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(_DIST / "index.html")

    @app.get("/{path:path}")
    def spa(path: str) -> FileResponse:
        candidate = _DIST / path
        if candidate.is_file():
            return FileResponse(candidate)
        return FileResponse(_DIST / "index.html")  # SPA fallback


def main() -> None:
    import uvicorn
    print("DNSGuard-X web UI → http://localhost:8000")
    if not _DIST.is_dir():
        print("NOTE: frontend not built yet. Run `npm run build` in web/frontend, "
              "or use the Vite dev server (npm run dev) on port 5173.")
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="warning")


if __name__ == "__main__":
    main()
