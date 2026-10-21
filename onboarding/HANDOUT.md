# DNSGuard-X — Contributor Handout

Welcome! This is a one-page guide to get a new team member productive on DNSGuard-X.
For the deeper "how the code is organised" reference, read [AGENTS.md](AGENTS.md) next to
this file. For the full project write-up, see [the project report](../docs/dnsguard_x.pdf).

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

## 5. Detailed workflow — follow one lookup end to end

This is the whole system in plain language. The bracketed numbers are the default
settings in `config.yaml` (change them there, not in code).

1. **Capture.** A DNS packet arrives — either read from a `.pcap` file or sniffed live
   from a network card (`dnsguard/capture.py`). Live sniffing needs admin rights.
2. **Parse.** The packet is decoded into a tidy record: who asked, the name queried, the
   record type (A, TXT, ANY…), whether the answer succeeded, the sizes, and the time
   (`dnsguard/parser.py`). Anything that isn't DNS is thrown away.
3. **Find the parent domain.** The name is lower-cased and its registered domain is
   pulled out, so `a.evil.com` and `b.evil.com` both count as `evil.com`
   (`dnsguard/features.py`).
4. **Whitelist check.** If that domain is a known-safe site (one of ~400 in
   `data/whitelist.txt`), the lookup is skipped. This removes most ordinary traffic so we
   only study the suspicious remainder.
5. **Measure the clues (features).** For the lookup itself: how long the name is, how
   *random* it looks (**Shannon entropy** — low for real words, high for scrambled/encoded
   strings), how many digits/vowels, the record type, and how much bigger the answer is
   than the question. For the *computer* over the last **60 seconds**: how many lookups
   per second, how many different made-up names it tried under one domain, and what share
   of answers came back "does not exist" (NXDOMAIN).
6. **Run the detectors.** Five independent rules check those clues; a lookup can trip more
   than one:
   - **D1 Tunneling (payload)** — name is long (>50 chars) *and* scrambled (entropy >3.8).
   - **D2 Tunneling (volume)** — >30 different made-up names under one domain in 60 s.
   - **D3 DGA / water torture** — over half of a host's last (≥20) answers were "does not
     exist".
   - **D4 Flood / Amplification** — >100 lookups/second, *or* an "ANY" query whose answer
     is >10× the request.
   - **D5 Suspected DGA name** — scrambled (entropy >3.5) with an unnatural letter pattern
     (few vowels or 5+ consonants in a row).
   - **CP Cache poisoning** — two different answers for the same question, or an answer
     nobody asked for.
7. **Raise and group alerts.** Each rule hit becomes an alert with a type, severity, the
   offending host, and a plain-English reason containing the real numbers (e.g. *"entropy
   4.57 > 3.8, name length 87, type TXT"*). Repeats for the same host + domain + type are
   merged into one alert with a **hit count**, so a flood of 2,000 shows as one line that
   says "×2000" (`dnsguard/alerts.py`).
8. **Store and show.** Alerts and per-lookup stats are written to a SQLite database
   (`dnsguard/storage.py`) and shown in the CLI summary, the Streamlit dashboard, or the
   React web UI.

The one place all of this is wired together is
`dnsguard/engine.py` → `DetectionEngine.process_record()`. If you only read one function
to understand the project, read that one.

## 6. Good first tasks

- **Easy:** add a domain to `data/whitelist.txt`; add a new benign/attack scenario to the
  traffic generator; improve wording of an alert reason.
- **Medium:** add a new per-query or per-host feature in `features.py` and a test for it;
  add filters or a chart to the dashboard.
- **Advanced:** add a sixth rule detector (see "How to add a new rule detector" in
  [AGENTS.md](AGENTS.md)); begin the planned ML detector behind the existing `Detector`
  interface.

**Always** add or update a test in `tests/` when you change detection behaviour, and keep
thresholds in `config.yaml`.

## 7. Workflow & house rules

- Branch, commit with a clear message, open a pull request. Keep commits focused.
- Run `python -m pytest` before pushing — all tests should pass.
- Never hardcode a detection threshold in Python; read it from `config.yaml`.
- Run the CLI as a module: `python -m dnsguard.main --pcap data/pcaps/mixed.pcap`
  (not `python dnsguard/main.py`).
- Generated files (`data/pcaps/`, `*.db`) are gitignored — don't commit them.

## 8. Where to get help

- Code structure and conventions: [AGENTS.md](AGENTS.md).
- The design report and workflow: [dnsguard_x.pdf](../docs/dnsguard_x.pdf).
- Still stuck? Open an issue describing what you ran and what you saw.

Happy hacking!
