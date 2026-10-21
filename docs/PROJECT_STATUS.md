# DNSGuard-X - Project Status (21 October 2026)

## Verdict

The documented **rule-based MVP is implemented in source**: offline and live capture paths, parsing, domain preprocessing, whitelist, query and host features, five configured rule detectors, response-level cache-poisoning indicators, alert grouping, SQLite persistence, a CLI, synthetic PCAP generation, an evaluator, tests, Streamlit, and a React/FastAPI UI. The full report referenced from `onboarding/HANDOUT.md` was absent; `docs/dnsguard_x.pdf` now supplies it.

The project is **not independently verified as complete in this checkout**. Python tests could not collect because the installed Python lacks `scapy` and `tldextract`; installation was blocked by unavailable access to PyPI. The generated PCAPs are intentionally absent from version control. Live capture was not tested because it requires a suitable interface, Npcap, and privileges. The bundled frontend build is present, but a fresh build requires npm dependencies.

The review also found a concrete mismatch with the promised de-duplication window: a later alert for the same host/domain/type was separate in memory, but the CLI collector and SQLite key collapsed it into the old alert. The collector and SQLite schema now include the window's first timestamp; an existing database is migrated without dropping its alerts. Two regression tests were added, but they cannot run until Python dependencies are installed.

## Evidence against the documented workflow

| Documented stage | Implementation | Status |
| --- | --- | --- |
| Capture PCAP/live DNS traffic | `dnsguard/capture.py` | Implemented; live path unverified |
| Parse and group by registered domain | `dnsguard/parser.py`, `dnsguard/features.py` | Implemented |
| Skip safe domains; retain query-response matching | `dnsguard/whitelist.py`, `dnsguard/engine.py` | Implemented |
| Calculate per-query and 60-second host features | `dnsguard/features.py` | Implemented |
| Run D1-D5 and cache-poisoning indicator | `dnsguard/detectors.py`, `dnsguard/engine.py`, `config.yaml` | Implemented |
| Group alerts and store run/query/alert data | `dnsguard/alerts.py`, `dnsguard/storage.py`, `dnsguard/main.py` | Implemented; cross-window persistence fixed; regression tests pending |
| Display CLI, Streamlit and React/FastAPI results | `dnsguard/main.py`, `dashboard/app.py`, `web/` | Implemented in source; runtime unverified |
| Generate and score labelled synthetic captures | `tools/generate_traffic.py`, `tools/evaluate.py` | Implemented in source; runtime unverified |
| Full design report linked by handout | `docs/dnsguard_x.pdf` | Added |

## Checks performed

- `python -m compileall -q dnsguard dashboard web tools tests`: passed.
- Focused SQLite smoke check: fresh database kept separate 60-second alert windows; migration retained an older alert and accepted a new one. This exercised storage with lightweight import stubs, not the full engine.
- `python -m pytest -q`: stopped at collection on missing `scapy` and `tldextract`, before any tests ran.
- `python -m pip install -r requirements.txt -r web/requirements.txt`: blocked by DNS resolution of `pypi.org`; no dependency or application installation succeeded.
- `npm run build`: blocked because `node_modules` is absent (`tsc` not found). `web/frontend/dist/` is committed.
- `onboarding/workflow.pdf` was read end to end (two pages), alongside the contributor guide, handout, README, configuration, and code.

## Remaining validation before a completion sign-off

From the repository root on a machine with dependency access: install the two requirement files; generate the labelled PCAPs; run pytest, the CLI, and the evaluator; build the frontend; exercise `/api/sample` and a PCAP upload; and test live capture with Npcap/privileges if that mode is part of the delivery. Treat the README's near-perfect synthetic scores as a demonstration only, not a real-traffic accuracy claim. The evaluator maps findings by host and parent domain over the full run, so it should be strengthened with event-level attribution before using its query-level figures as research evidence.

## Good next features after validation

1. Better evaluation: event-level labels, held-out captures, confusion matrix, and false-positive analysis across different networks.
2. Adaptive baselines per host/network and tunable whitelist exclusions; retain the existing explainable rules.
3. Syslog/JSON or SIEM export, alert triage state, and time-based filtering.
4. Optional ML detector behind the existing `Detector` interface, with model provenance and explanations.

The current cache-poisoning logic provides indicators, not DNSSEC validation or definitive attribution. The application observes and reports; it does not block DNS traffic.
