# DNSGuard-X — Contributor Handout

Welcome! This is a one-page guide to get a new team member productive on DNSGuard-X.
For the deeper "how the code is organised" reference, read [AGENTS.md](AGENTS.md) next to
this file. For the full project write-up, see [`../docs/dnsguard_x.pdf`](../docs/).

---

## 1. What the project does (in one minute)

DNS is the Internet's phone book: it turns names like `www.google.com` into IP
addresses. Because DNS traffic is almost never blocked, attackers abuse it to **steal
data**, **control malware**, **flood servers**, and **forge answers**. DNSGuard-X watches
DNS lookups, measures how "normal" each one looks, and raises a **plain-language alert**
when something matches a known attack pattern.

It detects five things:

| Short name | What it catches |
|------------|-----------------|
| Tunneling (D1, D2) | Data hidden inside long/scrambled names, or many made-up names under one domain |
| DGA / C2 (D3, D5) | Malware looking up many random, non-existent domains to find its control server |
| Flood / Amplification (D4) | Too many lookups per second, or tiny "ANY" queries with huge replies |
| Water torture (D2, D3) | Floods of random non-existent subdomains of a real site |
| Cache poisoning (CP) | Forged or conflicting DNS answers |

The thresholds for every rule live in **`config.yaml`** — change behaviour there, no code
edits needed.

## 2. Set up (once)

You need **Python 3.10+** (and **Node 18+** only if you touch the web UI).

```bash
cd dnsguard-x
python -m venv .venv
# Windows:  .venv\Scripts\activate      Linux/macOS:  source .venv/bin/activate
pip install -r requirements.txt
pip install -r web/requirements.txt    # only if you'll run the web dashboard
```

> **Windows tip:** if `python` is "not recognized", use the full path, e.g.
> `C:\Users\<you>\AppData\Local\Programs\Python\Python314\python.exe`, or re-run the
> Python installer and tick *Add Python to PATH*.

## 3. See it work (5 minutes)

Run everything **from the `dnsguard-x` folder**:

```bash
python tools/generate_traffic.py                       # make labelled test traffic
python -m dnsguard.main --pcap data/pcaps/mixed.pcap   # detect attacks in it
python tools/evaluate.py                               # score accuracy
python -m pytest -q                                    # run the tests (should all pass)
```

You should see ~8 alerts covering all the attack types, and the evaluator reporting high
precision/recall with no false alarms on normal traffic.

**Dashboards (optional):**
- Streamlit: `streamlit run dashboard/app.py`
- React web UI: `python web/server.py`, then open <http://localhost:8000>.

## 4. How the code is organised (where to look)

| You want to… | Open |
|--------------|------|
| Change a threshold | `config.yaml` |
| Understand the whole pipeline | `dnsguard/engine.py` |
| See how a lookup becomes numbers | `dnsguard/features.py` |
| Read/modify the five rules | `dnsguard/detectors.py` |
| Change how alerts are grouped | `dnsguard/alerts.py` |
| Change the CLI output | `dnsguard/main.py` |
| Make new test traffic / scenarios | `tools/generate_traffic.py` |
| Work on the web UI | `web/frontend/src/` and `web/server.py` |

A single DNS lookup flows through: **capture → parse → extract parent domain →
whitelist → features → detectors → alert manager → storage → dashboard.**

## 5. Good first tasks

- **Easy:** add a domain to `data/whitelist.txt`; add a new benign/attack scenario to the
  traffic generator; improve wording of an alert reason.
- **Medium:** add a new per-query or per-host feature in `features.py` and a test for it;
  add filters or a chart to the dashboard.
- **Advanced:** add a sixth rule detector (see "How to add a new rule detector" in
  [AGENTS.md](AGENTS.md)); begin the planned ML detector behind the existing `Detector`
  interface.

**Always** add or update a test in `tests/` when you change detection behaviour, and keep
thresholds in `config.yaml`.

## 6. Workflow & house rules

- Branch, commit with a clear message, open a pull request. Keep commits focused.
- Run `python -m pytest` before pushing — all tests should pass.
- Never hardcode a detection threshold in Python; read it from `config.yaml`.
- Run the CLI as a module: `python -m dnsguard.main …` (not `python dnsguard/main.py`).
- Generated files (`data/pcaps/`, `*.db`) are gitignored — don't commit them.

## 7. Where to get help

- Code structure and conventions: [AGENTS.md](AGENTS.md).
- The design report and diagrams: [`../docs/`](../docs/).
- Still stuck? Open an issue describing what you ran and what you saw.

Happy hacking!
