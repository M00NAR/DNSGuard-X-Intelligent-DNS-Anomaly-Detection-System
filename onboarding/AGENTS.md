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

## Detailed workflow (stage by stage)

Every packet — from a live interface or a `.pcap` — passes through the same eight stages.
The numbers in brackets are the default thresholds from `config.yaml`.

### Stage 0 — Input (`dnsguard/capture.py`)
- **Offline:** `read_pcap()` streams packets from a file in capture order (repeatable;
  used by tests and demos).
- **Live:** `sniff_live()` sniffs an interface with BPF filter
  `udp port 53 or tcp port 53`. Requires admin/root (and Npcap on Windows); a
  missing-privilege error is turned into a clear `CaptureError`, not a traceback.
- Both feed raw scapy packets into `DetectionEngine.process_record`, one at a time.

### Stage 1 — Parse (`dnsguard/parser.py:parse_packet`)
Each packet becomes a normalised `DNSRecord`:
`timestamp, src_ip, dst_ip, query_name, qtype, is_response, rcode, dns_id,
packet_size, answers[], ttl, transport`. Non-DNS packets return `None` and are dropped.
Numeric qtype/rcode values are mapped to names. `DNSRecord.host_pair` is the sorted
`(src, dst)` tuple, used later to match a response to its request regardless of direction.

### Stage 2 — Preprocess (`dnsguard/features.py`)
- Lowercase the name and strip the trailing dot.
- `parent_domain()` uses **tldextract** (offline public-suffix snapshot — never hits the
  network) to extract the registered domain, so `a1.x.evil.com` and `b2.x.evil.com` both
  group under `evil.com`.
- `subdomain_part()` isolates the labels left of the parent, where encoded data and
  random strings live.

### Stage 3 — Whitelist (`dnsguard/whitelist.py`)
If the parent domain is in `data/whitelist.txt` (~400 popular domains), the lookup is
marked benign and **skipped** — but still handed to the response matcher so later
matching stays correct. This drops most benign traffic early.

### Stage 4 — Feature extraction (`dnsguard/features.py`)
**Per query:** name length, longest label length, Shannon entropy of the subdomain
(`H = -sum p_i log2 p_i`), digit ratio, vowel ratio, longest consonant run, number of
labels, qtype, and response/request size ratio.
**Per host, sliding 60 s window** (`HostWindow`, a deque keyed by `src_ip` that evicts
entries older than the window): queries per second, unique subdomains per parent domain
(keeps the worst parent), NXDOMAIN ratio, and TXT/NULL share.
**Response matching** (`ResponseMatcher`): each query is keyed by `(dns_id, host_pair)`;
when a response arrives it yields the size ratio and any cache-poisoning signals.

### Stage 5 — Detection (`dnsguard/detectors.py`, `engine.py`)
All detectors run independently, so one lookup can raise several alerts.

| Detector | Fires when | Severity |
|----------|------------|----------|
| D1 Tunneling (payload) | `entropy > 3.8` AND `name_length > 50` | High |
| D2 Tunneling (volume) | `unique_subdomains(parent) > 30` in the window | High |
| D3 DGA / C2 / water torture | `responses >= 20` AND `nxdomain_ratio > 0.5` (per host) | Medium |
| D4 Flood / Amplification | `QPS > 100` OR (`qtype == ANY` AND `size_ratio > 10`) | High |
| D5 Suspected DGA name | `entropy > 3.5` AND (`vowel_ratio < 0.2` OR `consonant_run >= 5`) | Low |
| CP Cache-poisoning | two responses, same `dns_id`, different answers; or a response with no matching query | Medium |

Each hit becomes a `Finding(detector_id, attack_type, severity, src_ip, domain, reason,
timestamp)` whose `reason` carries the real values (e.g. `entropy 4.57 > 3.8, name
length 87 > 50, qtype TXT`). CP is **not** a `Detector` subclass — it runs on responses
in `engine._handle_poisoning()` from the matcher's signals.

### Stage 6 — Alert management (`dnsguard/alerts.py:AlertManager`)
Findings are de-duplicated by key `(src_ip, parent_domain, attack_type)` within a 60 s
window: the first hit creates an `Alert`; repeats increment a **hit count** and refresh
the window; the highest severity and its reason are kept. A flood that matches a rule
2,000 times becomes one alert that says "x2000".

### Stage 7 — Storage (`dnsguard/storage.py`, SQLite)
Three tables: `runs` (one per CLI run, with source and totals), `alerts` (upserted as
hit counts grow; unique on run + src + domain + type), and `queries` (one row per
inspected lookup, feeding the dashboard's entropy histogram). Live mode flushes
periodically (`storage.flush_interval_seconds`).

### Stage 8 — Output
- **CLI** (`dnsguard/main.py`): prints each new alert as it fires, then a coloured
  summary (alerts per type, top 5 hosts, severity breakdown).
- **Dashboards:** Streamlit (`dashboard/app.py`) or the React web UI
  (`web/server.py` -> http://localhost:8000): metrics, charts, top hosts, entropy
  histogram, and a filterable alert table with reasons.

**Responses vs queries:** in `process_record`, a *response* updates the host window and
the matcher (and may raise D4-amplification or CP); a *query* is whitelisted-checked,
featurised, and run through D1/D2/D3/D5 before alerts are raised.

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
