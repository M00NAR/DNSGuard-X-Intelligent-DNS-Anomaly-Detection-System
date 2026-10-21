"""Rebuild docs/dnsguard_x.pdf using the bundled ReportLab runtime.

Run from the repository root with a Python interpreter that has reportlab:
    python docs/build_report.py
"""

from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate, Frame, KeepTogether, PageTemplate, Paragraph, Spacer,
    Table, TableStyle,
)


OUT = Path(__file__).with_name("dnsguard_x.pdf")
NAVY = colors.HexColor("#15324a")
TEAL = colors.HexColor("#087e86")
PALE = colors.HexColor("#eaf3f4")
INK = colors.HexColor("#243443")
MUTED = colors.HexColor("#5c6b78")
RULE = colors.HexColor("#d8e1e6")


class Report(BaseDocTemplate):
    def __init__(self, path: Path) -> None:
        super().__init__(str(path), pagesize=A4, leftMargin=19 * mm,
                         rightMargin=19 * mm, topMargin=19 * mm,
                         bottomMargin=17 * mm, title="DNSGuard-X - Project and Workflow",
                         author="DNSGuard-X project documentation")
        frame = Frame(self.leftMargin, self.bottomMargin, self.width,
                      self.height, leftPadding=0, rightPadding=0,
                      topPadding=0, bottomPadding=0)
        self.addPageTemplates(PageTemplate(id="report", frames=[frame], onPage=self.chrome))

    def chrome(self, canvas, doc) -> None:
        canvas.saveState()
        w, h = A4
        canvas.setFillColor(NAVY)
        canvas.rect(0, h - 10 * mm, w, 10 * mm, fill=1, stroke=0)
        canvas.setStrokeColor(RULE)
        canvas.line(self.leftMargin, 14 * mm, w - self.rightMargin, 14 * mm)
        canvas.setFillColor(MUTED)
        canvas.setFont("Helvetica", 8)
        canvas.drawString(self.leftMargin, 10 * mm, "DNSGuard-X  |  Project walkthrough  |  21 Oct 2026")
        canvas.drawRightString(w - self.rightMargin, 10 * mm, f"Page {doc.page}")
        canvas.restoreState()


styles = getSampleStyleSheet()
styles.add(ParagraphStyle(name="CoverTitleX", fontName="Helvetica-Bold", fontSize=24,
                          leading=29, textColor=NAVY, spaceAfter=7 * mm))
styles.add(ParagraphStyle(name="DeckX", fontName="Helvetica", fontSize=11,
                          leading=16, textColor=MUTED, spaceAfter=7 * mm))
styles.add(ParagraphStyle(name="HeadingX", fontName="Helvetica-Bold", fontSize=13,
                          leading=16, textColor=NAVY, spaceBefore=3.5 * mm,
                          spaceAfter=1.8 * mm, keepWithNext=True))
styles.add(ParagraphStyle(name="SubX", fontName="Helvetica-Bold", fontSize=10.5,
                          leading=13, textColor=TEAL, spaceBefore=2 * mm,
                          spaceAfter=1 * mm, keepWithNext=True))
styles.add(ParagraphStyle(name="BodyX", fontName="Helvetica", fontSize=9.2,
                          leading=13, textColor=INK, spaceAfter=1.5 * mm))
styles.add(ParagraphStyle(name="SmallX", parent=styles["BodyX"], fontSize=8.5,
                          leading=11.5, spaceAfter=1.5 * mm))
styles.add(ParagraphStyle(name="CellX", fontName="Helvetica", fontSize=8,
                          leading=11, textColor=INK))
styles.add(ParagraphStyle(name="CellHeadX", parent=styles["CellX"],
                          fontName="Helvetica-Bold", textColor=colors.white))
styles.add(ParagraphStyle(name="CalloutX", parent=styles["BodyX"],
                          fontName="Helvetica-Bold", textColor=NAVY, spaceAfter=0))

story = []


def p(text: str, small: bool = False, keep: bool = False) -> None:
    item = Paragraph(text, styles["SmallX" if small else "BodyX"])
    story.append(KeepTogether([item]) if keep else item)


def h(text: str) -> None:
    story.append(Paragraph(text, styles["HeadingX"]))


def sub(text: str) -> None:
    story.append(Paragraph(text, styles["SubX"]))


def table(headers: list[str], rows: list[list[str]], widths: list[float]) -> None:
    content = [[Paragraph(x, styles["CellHeadX"]) for x in headers]]
    content += [[Paragraph(x, styles["CellX"]) for x in row] for row in rows]
    t = Table(content, colWidths=widths, repeatRows=1, hAlign="LEFT")
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f8fa")]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LINEBELOW", (0, -1), (-1, -1), 0.4, RULE),
    ]))
    story.extend([t, Spacer(1, 2 * mm)])


def callout(text: str) -> None:
    t = Table([[Paragraph(text, styles["CalloutX"])]], colWidths=[172 * mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), PALE),
        ("BOX", (0, 0), (-1, -1), 0.6, TEAL),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
        ("TOPPADDING", (0, 0), (-1, -1), 9),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
    ]))
    story.extend([t, Spacer(1, 3 * mm)])


story.append(Spacer(1, 5 * mm))
story.append(Paragraph("DNSGuard-X", styles["CoverTitleX"]))
story.append(Paragraph("Project report and end-to-end workflow", styles["DeckX"]))
callout("An explainable, rule-based monitor for suspicious DNS lookups in saved captures or live traffic.")
p("<b>What it is.</b> DNSGuard-X is a Python prototype that identifies patterns associated with DNS tunneling, domain-generation algorithms (DGA), high-rate DNS floods, amplification, and possible cache poisoning. It reports observations with a severity, host, domain, and human-readable reason. It does not block traffic or prove that an attack occurred.")
p("<b>Current status.</b> All principal components described in the repository handout and workflow are implemented in source. The linked full project report was missing and is supplied by this document. Runtime correctness has not been signed off in this checkout: the local Python lacks core dependencies, PyPI was unreachable, and live capture has not been exercised. See <b>docs/PROJECT_STATUS.md</b> for the audit and remaining checks.")

h("1. Architecture at a glance")
table(["Step", "Input and decision", "Implementation"], [
    ["1. Capture", "Read a PCAP/PCAPNG, or sniff DNS on UDP/TCP port 53.", "capture.py"],
    ["2. Parse", "Decode packet into a normalised DNSRecord; ignore non-DNS.", "parser.py"],
    ["3. Preprocess", "Normalise name; derive registered parent and subdomain.", "features.py"],
    ["4. Whitelist", "Skip known-safe parent domains but retain matching state.", "whitelist.py / engine.py"],
    ["5. Features", "Measure one query and 60-second behaviour per source host.", "features.py"],
    ["6. Detect", "Run D1-D5 on queries; D4/CP also inspect responses.", "detectors.py / engine.py"],
    ["7. Alert", "Merge repeated findings into explainable, counted alerts.", "alerts.py"],
    ["8. Persist / show", "SQLite, CLI, Streamlit dashboard, React/FastAPI UI.", "storage.py / main.py / web/"],
], [23 * mm, 105 * mm, 44 * mm])
p("<b>The orchestration point:</b> <font name='Courier'>DetectionEngine.process_record()</font> in <font name='Courier'>dnsguard/engine.py</font>. Both offline replay and live sniffing call this same method; the dashboards consume its output or the SQLite run data.")

h("2. Packet and feature model")
p("<b>Capture and parse.</b> Scapy streams packets from disk in order, or sniffs a chosen interface with a DNS BPF filter. The parser records timestamp, source/destination IP, lowercased question name, query type, response flag and code, transaction ID, packet size, answer records, minimum TTL, and UDP/TCP transport. A sorted host pair and DNS ID help associate a reply with a request.")
p("<b>Parent domain.</b> An offline public-suffix snapshot identifies the registered domain: <font name='Courier'>a.x.evil.com</font> and <font name='Courier'>b.x.evil.com</font> group as <font name='Courier'>evil.com</font>. The left-hand labels are analysed for encoded or algorithmic names. The whitelist stores parent domains, so a listed parent suppresses its subdomains. Requests still enter the response matcher to avoid orphaning a later reply.")
p("<b>Query-level signals.</b> Name length, longest label, number of labels, character entropy of the subdomain, digit/vowel ratios, longest consonant run, record type, and (when a response arrives) the reply/request byte ratio. Shannon entropy is <font name='Courier'>H = -sum(p_i log2 p_i)</font>; random-looking strings generally score higher than repeated or simple strings.")
p("<b>Host-level signals.</b> A deque per source IP keeps a sliding 60-second window. It calculates lookup rate, the largest count of unique subdomains beneath a single parent, fraction of NXDOMAIN responses, response count, and TXT/NULL share. Responses count toward the client host (destination of the reply). The window and minimum rate span are configured in <font name='Courier'>config.yaml</font>.", keep=True)

h("3. Rules and default settings")
table(["Rule", "Trigger from config.yaml", "Meaning / severity"], [
    ["D1", "Subdomain entropy &gt; 3.8 AND full name length &gt; 50.", "Encoded payload in a DNS name; High."],
    ["D2", "More than 30 unique subdomains of the same parent in 60 s.", "Repeated data-bearing lookups; High."],
    ["D3", "At least 20 responses AND NXDOMAIN fraction &gt; 0.5.", "DGA/C2 discovery or water torture; Medium."],
    ["D4", "Host QPS &gt; 100 OR ANY reply/request bytes &gt; 10x.", "Flood or amplification; High."],
    ["D5", "Subdomain entropy &gt; 3.5 AND vowel share &lt; 0.2 OR consonant run &gt;= 5.", "Possible machine-made name; Low. See note below."],
    ["CP", "Conflicting replies with same matched ID, or unsolicited reply after grace.", "Possible forged answer; Medium."],
], [15 * mm, 86 * mm, 71 * mm])
p("<b>D5 logic detail:</b> The actual rule is entropy &gt; 3.5 AND (vowel share &lt; 0.2 OR consonant run &gt;= 5), with a nonempty subdomain. CP is a response-level check in the engine, not a sixth <font name='Courier'>Detector</font> subclass. D4 rate runs on queries; its amplification branch uses matched responses. All operational thresholds are exposed in configuration.", small=True)
p("Each hit is a Finding with detector ID, type, severity, source host, parent domain, timestamp, and reason. Several rules can fire for one record. The reason describes the measured behaviour, while the UI also provides a simple category explanation.")

h("4. From findings to a useful warning")
p("<b>Grouping.</b> AlertManager merges findings with the same source IP, domain/group, and attack type when hits occur within the configured 60-second interval. It increments the hit count, updates the last timestamp, and retains the highest severity. D3 is grouped at host level because its NXDOMAIN pattern spans many unrelated domains. A new interval creates another in-memory alert.")
p("<b>Persistence.</b> The CLI writes three SQLite tables: <font name='Courier'>runs</font> (source and totals), <font name='Courier'>queries</font> (per-inspected-lookup statistics), and <font name='Courier'>alerts</font> (deduplicated warnings). Alerts are upserted as counts increase; a later de-duplication window keeps its own row. Older databases are migrated to this key. The API's on-demand sample and upload analyses return JSON directly; they do not automatically create a stored run. SQLite runs come from the CLI.")
p("<b>Displays.</b> CLI prints each new warning and a summary of categories, top hosts, and severities. Streamlit accepts an uploaded capture or a saved database and draws category/time/entropy charts, top-host summaries, and a filterable table. The React UI calls a FastAPI backend, which serves the committed production bundle on localhost:8000 and exposes sample, upload, health, and stored-run routes.")

h("5. Example walkthroughs")
sub("A possible tunneling attempt")
p("A client asks for many long, encoded labels beneath <font name='Courier'>data-exfil-demo.net</font>. D1 can flag a sufficiently long, high-entropy name immediately. As different subdomains accumulate in the window, D2 can flag the volume. Separate findings may become two alert categories; repeated hits within each category increase a count instead of filling the UI with thousands of rows.")
sub("A host trying many nonexistent names")
p("The host sends random-looking domain lookups. D5 may flag individual suspicious subdomain names, but it requires a nonempty subdomain. Once at least 20 responses have been observed and more than half are NXDOMAIN, D3 can fire on a later query; its alert is aggregated by host.")
sub("Large answers and conflicting replies")
p("A matched ANY request whose response is over 10 times the request size can trigger D4 amplification. The matcher also remembers an answered transaction briefly. A later reply with a different answer set, or an unmatched response after the start-of-capture grace, produces a CP indicator. Such signals are not proof of successful cache poisoning; DNSSEC is outside this prototype.")

h("6. Reproducing and validating")
table(["Action", "Command from repository root"], [
    ["Install", "python -m pip install -r requirements.txt -r web/requirements.txt"],
    ["Make sample data", "python tools/generate_traffic.py"],
    ["Analyse PCAP", "python -m dnsguard.main --pcap data/pcaps/mixed.pcap"],
    ["Score synthetic data", "python tools/evaluate.py"],
    ["Run tests", "python -m pytest -q"],
    ["Web UI", "python web/server.py (browse localhost:8000)"],
    ["Streamlit", "streamlit run dashboard/app.py"],
], [46 * mm, 126 * mm])
p("The generator writes normal, tunneling, DGA, flood, amplification, poisoning, and mixed PCAPs plus query labels under <font name='Courier'>data/pcaps/</font>; it does not send network packets. The evaluator reports per-category precision/recall/F1 and benign false positives. Its current host/domain-level association can attribute a finding to other queries from the same host/domain in the same run, so the synthetic query-level scores should be treated as demonstration figures, not field validation.")
p("<b>Verification during this review:</b> Python source compilation and a focused SQLite storage/migration smoke check passed. Pytest could not collect because the host interpreter lacked scapy and tldextract. Installing requirements failed when PyPI DNS lookup was unavailable. New full-suite regression tests for separate alert windows remain pending. No live interface or Npcap test was run. A fresh frontend build requires npm packages; the committed <font name='Courier'>web/frontend/dist</font> supports the documented clone-and-serve path.")

h("7. Completion and sensible extensions")
p("<b>Assessment:</b> The documented feature paths are present in source; runtime acceptance remains open until dependencies, generated captures, test suite, evaluator, UI endpoints, and relevant live-capture environment are exercised. This report fills the missing docs deliverable. It is an explainable class-project prototype, not a validated production IDS.")
p("<b>Next:</b> (1) event-level evaluation on held-out, varied captures; (2) per-network adaptive baselines and whitelist controls; (3) JSON/syslog/SIEM export plus analyst triage; (4) an optional, explainable ML rule plugged into the existing Detector interface. Treat DNS over HTTPS visibility, DNSSEC validation, and active blocking as separate design decisions.")
p("<b>Source map:</b> onboarding/AGENTS.md; onboarding/HANDOUT.md; onboarding/workflow.pdf; README.md; config.yaml; dnsguard/{capture,parser,features,whitelist,detectors,engine,alerts,storage,main}.py; tools/{generate_traffic,evaluate}.py; dashboard/app.py; web/server.py; web/frontend/src/. This report describes the checkout reviewed on 21 October 2026.", small=True)


if __name__ == "__main__":
    OUT.parent.mkdir(parents=True, exist_ok=True)
    Report(OUT).build(story)
    print(OUT)
