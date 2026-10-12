# AGENTS.md — working guide for DNSGuard-X

This file orients an AI coding agent (or a new developer) working in this repository.
`AGENTS.md` is a common convention: agents read it first to learn how the project is
laid out, how to build and test, and the conventions to follow. Keep it short and
current.

## What this project is

DNSGuard-X is a **rule-based DNS anomaly detection system** written in Python. It reads
DNS traffic (from a `.pcap` file or a live interface), extracts features from each
lookup, runs five independent rule detectors plus a cache-poisoning check, and raises
explainable alerts. It ships with a synthetic traffic generator, an evaluator, a pytest
suite, a Streamlit dashboard, and a React + FastAPI web UI.

## Repository layout

```
dnsguard-x/
  config.yaml            All detection thresholds and settings. NOTHING is hardcoded elsewhere.
  requirements.txt       Core Python dependencies.
  run.py                 Click-to-run launcher (analyses the sample pcap by default).
  dnsguard/              The detection engine (the heart of the project):
    config.py            Loads config.yaml and resolves paths.
    capture.py           PCAP reading + live sniffing (scapy).
    parser.py            scapy packet -> DNSRecord dict.
    features.py          Per-query + per-host (60 s window) features; response matching.
    whitelist.py         Known-safe domain list.
    detectors.py         Detector base class + D1..D5 (rule detectors).
    alerts.py            AlertManager: dedupe/merge findings into alerts.
    storage.py           SQLite logging (runs, alerts, queries).
    engine.py            DetectionEngine: ties the pipeline together (incl. cache-poisoning).
    main.py              CLI entry point (python -m dnsguard.main).
  tools/
    generate_traffic.py  Writes labelled synthetic PCAPs (never sends packets).
    evaluate.py          Scores detection vs labels.csv (precision/recall/F1 + FP rate).
  tests/                 pytest: entropy, features, detectors, parser, end-to-end.
  dashboard/app.py       Streamlit dashboard.
  web/
    server.py            FastAPI backend + serves the built React UI (one command).
    frontend/            Vite + React + TypeScript app (built output in frontend/dist).
  data/
    whitelist.txt        ~400 popular parent domains (committed).
    pcaps/               Generated captures + labels.csv (gitignored; recreate on demand).
  docs/                  Project report (dnsguard_x.tex / .pdf) and explainers.
  onboarding/            This folder: AGENTS.md + HANDOUT.md.
```

## Pipeline (how a lookup flows)

`capture -> parse -> preprocess (parent domain) -> whitelist -> features
-> detectors -> alert manager -> SQLite -> dashboard`

See `dnsguard/engine.py:DetectionEngine.process_record` — it is the single place the
whole pipeline is wired together.

## Environment & setup

- **Python 3.10+** (developed and run on 3.14). Core deps: scapy, pandas, numpy,
  tldextract, pyyaml, streamlit, plotly, pytest. Web backend adds fastapi, uvicorn,
  python-multipart (see `web/requirements.txt`). The frontend needs Node 18+ / npm.
- Install: `pip install -r requirements.txt` (and `pip install -r web/requirements.txt`
  for the web UI).
- On Windows `python` may not be on PATH; use the full interpreter path, e.g.
  `C:\Users\<you>\AppData\Local\Programs\Python\Python314\python.exe`.

## Build / run / test commands

Run **from the `dnsguard-x` directory** (paths like `data/pcaps/mixed.pcap` are relative).

```bash
# 1. Generate labelled test traffic (add --random for fresh data each run)
python tools/generate_traffic.py

# 2. Run detection on a capture
python -m dnsguard.main --pcap data/pcaps/mixed.pcap        # use -m, NOT "python dnsguard/main.py"

# 3. Score accuracy against ground truth
python tools/evaluate.py

# 4. Run the test suite
python -m pytest -q

# 5a. Streamlit dashboard
streamlit run dashboard/app.py

# 5b. React web UI (build once, then the backend serves it on :8000)
cd web/frontend && npm install && npm run build && cd ../..
python web/server.py
```

Live capture (`python -m dnsguard.main --live --iface "<name>"`) needs admin/root and,
on Windows, Npcap installed.

## Conventions

- **All thresholds live in `config.yaml`.** Never hardcode a detection threshold in
  Python; read it from the detector's config slice.
- **Relative imports**: the package uses `from .module import ...`, so run the CLI with
  `python -m dnsguard.main`, never `python dnsguard/main.py`.
- Type hints and docstrings on public functions; match the surrounding style.
- Keep detectors independent and side-effect-free in `inspect()`; the engine owns state.
- Frontend: strict TypeScript, functional React components, an ErrorBoundary around the
  results; theme/colours come from `web/frontend/src/theme.ts` and `index.css`
  (orange/white day, cyan-green/black night).

## How to add a new rule detector

1. In `dnsguard/detectors.py`, subclass `Detector` and implement
   `inspect(self, ctx: DetectionContext) -> list[Finding]`. Use `self.cfg` for
   thresholds and `self._finding(...)` to build findings.
2. Add a config block for it under `detectors:` in `config.yaml`
   (include `enabled`, `severity`, `attack_type`, and your thresholds).
3. Register the class in `RULE_DETECTOR_CLASSES` and map its id in `build_detectors()`.
4. Add a test in `tests/test_detectors.py` (fire case + silent case).

The cache-poisoning check is **not** a `Detector` subclass — it runs on responses in
`engine.py` (`_handle_poisoning`) via `features.ResponseMatcher`. Extend it there.

## Testing notes

- `python -m pytest` runs the full suite. The end-to-end tests in `tests/test_parser.py`
  need the sample PCAPs; they auto-skip if `data/pcaps/` is empty, so run
  `python tools/generate_traffic.py` first to exercise them.
- There is no network or external-service dependency in the tests.

## Gotchas

- `data/pcaps/` and `*.db` are gitignored (generated artifacts). Regenerate with the
  traffic generator / by running the CLI.
- `web/frontend/dist` **is** committed so the web UI runs after a clone without a build;
  rebuild it with `npm run build` if you change the frontend.
- tldextract uses a bundled public-suffix snapshot (offline); do not add network calls
  to feature extraction.
- Attribution for commits, if the repo requires it, is set per the contributor's own
  git config; there are no special commit hooks.

## Safe scope for automated changes

Good first automated tasks: adding tests, documenting thresholds, improving the
traffic generator, UI polish, docs. Avoid changing the detection semantics (thresholds,
rule logic) without a corresponding test and a note in `docs/`.
