# DNSGuard-X

**Rule-based DNS anomaly detection.** DNSGuard-X watches DNS traffic — live or from a
PCAP — measures how "normal" each lookup looks, runs it through five independent rule
detectors, and raises alerts that explain *why* something was flagged, in plain English
with the actual values.

It detects the common ways DNS gets abused:

For the end-to-end architecture and workflow, see the [project report](docs/dnsguard_x.pdf).
The [status and validation note](docs/PROJECT_STATUS.md) records what has and has not been verified in this checkout.

| Attack | Signals | Detector | Severity |
| --- | --- | --- | --- |
| DNS tunneling (payload) | high entropy + long names | D1 | High |
| DNS tunneling (volume) | many unique subdomains of one parent / 60 s | D2 | High |
| DGA / C2 / water torture | high NXDOMAIN ratio per host | D3 | Medium |
| Flood / amplification | high QPS, or ANY with large response/request ratio | D4 | High |
| Suspected DGA domain | high entropy + unnatural letter pattern | D5 | Low |
| Cache poisoning (indicator) | conflicting / unsolicited responses | response check | Medium |

All thresholds live in [`config.yaml`](config.yaml) — nothing is hardcoded.

---

## Pipeline

```
Input (live UDP/TCP 53  OR  PCAP)
  -> parse        (scapy packet -> record: ts, src, qname, qtype, rcode, sizes, ttl)
  -> preprocess   (lowercase, split labels, parent domain via tldextract)
  -> whitelist    (skip known-safe parents)
  -> features     (per-query + per-host over a sliding 60 s window)
  -> 5 detectors  (run independently; one query can raise several alerts)
  -> alert manager (merge, dedupe per (src_ip, parent, attack_type) / 60 s, hit count)
  -> SQLite        (alerts + per-query stats)
  -> dashboard     (Streamlit + Plotly)
```

## Project layout

```
dnsguard-x/
  config.yaml               all thresholds and settings
  dnsguard/
    config.py               config loader
    capture.py              live sniffing + PCAP reading
    parser.py               DNS packet -> record
    features.py             per-query + per-host features, response matching
    whitelist.py            known-safe domain list
    detectors.py            Detector base class + D1..D5 + CP (ML-ready)
    alerts.py               alert manager (merge / dedupe / severity)
    storage.py              SQLite logging
    engine.py               the detection pipeline
    main.py                 CLI entry point
  dashboard/app.py          Streamlit dashboard
  tools/
    generate_traffic.py     synthetic labelled PCAP generator (writes to disk only)
    evaluate.py             precision / recall / F1 + false-positive rate
  tests/                    pytest tests for entropy, features and detectors
  data/
    whitelist.txt           ~400 popular domains
    pcaps/                  generated PCAPs + labels.csv
```

## Setup

Python 3.10+.

```bash
cd dnsguard-x
python -m venv .venv
# Windows:  .venv\Scripts\activate
# Linux/mac: source .venv/bin/activate
pip install -r requirements.txt
```

## Quick start (demo)

```bash
# 1) Generate labelled test traffic (no packets are sent — PCAPs are written to disk)
python tools/generate_traffic.py

# 2) Run detection on the mixed capture
python -m dnsguard.main --pcap data/pcaps/mixed.pcap

# 3) Score the detector against ground truth
python tools/evaluate.py

# 4) Explore results in the dashboard
streamlit run dashboard/app.py
```

## Running each mode

**Offline (PCAP):**
```bash
python -m dnsguard.main --pcap data/pcaps/mixed.pcap
python -m dnsguard.main --pcap my.pcap --no-store      # skip SQLite logging
python -m dnsguard.main --pcap my.pcap --db out.db     # custom database path
```

**Live capture (needs administrator / root):**
```bash
python -m dnsguard.main --live --iface "Ethernet"      # Windows interface name
sudo python -m dnsguard.main --live --iface eth0       # Linux
```
On Windows, live capture also needs [Npcap](https://npcap.com/) installed and the
terminal run **as Administrator**. Without privileges DNSGuard-X prints a clear
message instead of a stack trace. Press `Ctrl+C` to stop; a summary is printed.

The CLI ends with a coloured summary: alerts per attack type, the top 5 hosts, and a
severity breakdown.

## Generating test data

`tools/generate_traffic.py` uses scapy to build labelled PCAPs. It never sends
traffic — it only writes files. Scenarios:

| File | What it models |
| --- | --- |
| `normal.pcap` | benign lookups from several hosts with realistic timing |
| `tunneling.pcap` | long base32 subdomains of one parent domain |
| `dga.pcap` | 200 random-letter domains, ~90 % NXDOMAIN |
| `flood.pcap` | 2000 queries from one host in ~10 s |
| `amplification.pcap` | ANY queries with large responses |
| `poisoning.pcap` | conflicting / unsolicited responses |
| `mixed.pcap` | all of the above interleaved with normal traffic |
| `labels.csv` | ground truth (query, true_label, host, ...) for `mixed.pcap` |

```bash
python tools/generate_traffic.py --out data/pcaps --seed 42
```

## Evaluation

`tools/evaluate.py` runs detection on `mixed.pcap`, joins findings back to
`labels.csv`, and reports precision / recall / F1 per attack type plus the
false-positive rate on `normal.pcap`:

```
=== Per-attack-type detection (mixed.pcap) ===
attack type          TP     FP     FN     prec   recall       F1
tunneling            31      0      0    1.000    1.000    1.000
dga                 200      0      0    1.000    1.000    1.000
flood              2000      0      0    1.000    1.000    1.000
amplification       120      0      0    1.000    1.000    1.000
poisoning            12      0      0    1.000    1.000    1.000
...
False positives on benign traffic: 0/589 queries = 0.00%
```

These scores reflect the bundled synthetic generator, whose scenarios are cleanly
separable and whose thresholds are tuned to it; real-world traffic is noisier and
will produce lower, more realistic numbers.

## Testing

```bash
python -m pytest
```
Covers Shannon entropy, per-query and per-host feature extraction, response matching,
each of the five detectors, the alert manager, the packet parser, and an end-to-end
run over `mixed.pcap`.

## Web UI (React)

A polished React + TypeScript frontend with a FastAPI backend lives in [`web/`](web).
It runs from one command and serves the built UI itself:

```bash
pip install -r web/requirements.txt
python web/server.py          # open http://localhost:8000
```

Click *Run the sample capture* or drag in your own `.pcap`. It has an orange day theme
and a cyan-green night theme (toggle top-right). See [web/README.md](web/README.md).

## Dashboard (Streamlit)

```bash
streamlit run dashboard/app.py
```
Upload a PCAP (detection runs live) or point it at the SQLite DB written by the CLI.
Shows total queries, total alerts, alerts by type (bar), alerts over time (line), top
suspicious hosts, an entropy histogram (benign vs flagged), and a filterable alert
table with the full reason for each alert.

## How detection works

Per-query features: name length, longest label length, Shannon entropy of the
subdomain part, digit ratio, vowel ratio, longest consonant run, number of labels,
query type, and response/request size ratio.

Per-host features over a sliding 60 s window (keyed by source IP): queries per second,
unique subdomains per parent domain, NXDOMAIN ratio, and TXT/NULL share.

Shannon entropy of a name with character probabilities `p_i` is
`H = -Σ p_i log2 p_i`. Benign names like `google` score ~1.9–2.6; random or encoded
strings often exceed 3.8.

Each alert carries a plain-English reason with the real numbers, e.g.
`entropy 4.31 > 3.8, name length 62 > 50, qtype TXT`.

## Future work

The rule engine is fast and explainable, but fixed thresholds can be evaded by
attackers who slow down or use dictionary-word domains. `detectors.py` defines a
`Detector` base class (`inspect(ctx) -> list[Finding]`) specifically so a machine-learning
detector can be dropped into the same pipeline **without changing any callers** — see the
`TODO(ml)` marker at the bottom of that file. Planned:

- **`MLDetector`** wrapping an **Isolation Forest** (unsupervised, per-host behaviour)
  and a **Random Forest** (supervised, DGA vs benign domains), reusing the existing
  feature extractor. Add it to `build_detectors()` and it participates automatically.
- **Character-level deep models** (LSTM/CNN) for dictionary-based DGAs that defeat
  entropy checks.
- **Adaptive thresholds** learned per network instead of fixed values.
- **Explainability** (feature importances / SHAP) attached to each ML alert.
- Inline blocking via a DNS proxy / RPZ, and SIEM export (Syslog, Elastic).

## Notes / limitations

- Cache-poisoning coverage is a best-effort *indicator* (mismatched IDs, duplicate or
  unsolicited answers, low TTLs); full protection requires DNSSEC.
- tldextract uses a bundled public-suffix snapshot, so no network access is needed.
- The whitelist in `data/whitelist.txt` is a small popular-domains sample; in production
  you would load a larger list (e.g. Tranco top-1M, same `rank,domain` format is supported).
