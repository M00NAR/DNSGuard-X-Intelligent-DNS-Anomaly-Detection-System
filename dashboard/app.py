"""DNSGuard-X dashboard.

Two ways to load data:

* Upload a capture file (.pcap) and the detection engine runs on it in the browser
  session.
* Read the SQLite database that the command-line tool writes.

Colours, fonts and light/dark modes come from .streamlit/config.toml. Start the
dashboard with::

    streamlit run dashboard/app.py
"""

from __future__ import annotations

import sqlite3
import sys
import tempfile
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dnsguard.capture import read_pcap
from dnsguard.config import load_config
from dnsguard.engine import DetectionEngine
from dnsguard.parser import parse_packet
from dnsguard.whitelist import Whitelist

st.set_page_config(page_title="DNSGuard-X", page_icon=":material/security:", layout="wide")

# Plain-language descriptions shown in the "What these categories mean" panel.
CATEGORY_HELP = {
    "DNS Tunneling (payload)": "Data is being hidden inside the website names themselves. "
        "The names are unusually long and look scrambled, which is how smuggled data appears.",
    "DNS Tunneling (volume)": "One computer is looking up a huge number of different made-up "
        "names under the same domain in a short time. That is a common sign of data being sent out.",
    "DGA / C2 / Water Torture": "A computer is looking up many names that do not exist. Malware "
        "often does this while hunting for its control server, or to overload someone else's server.",
    "DNS Flood": "One computer is sending lookups far faster than normal, which can overwhelm a "
        "DNS server.",
    "DNS Amplification": "Small questions are producing very large answers. Attackers abuse this to "
        "flood a victim with traffic.",
    "Suspected DGA Domain": "A single name looks machine-generated rather than human-chosen "
        "(random letters, few vowels). On its own this is only a weak hint.",
    "Cache Poisoning Indicator": "Answers arrived that do not match the questions asked, or two "
        "different answers came back for the same question. This can mean someone is forging replies.",
}

# How serious each level is, in plain words.
SEVERITY_HELP = {
    "High": "Act on these first.",
    "Medium": "Worth a closer look.",
    "Low": "A weak hint; review if you have time.",
}
SEVERITY_BADGE = {"High": "red", "Medium": "orange", "Low": "blue"}


@st.cache_data(show_spinner=False)
def _load_config_cached(path: str | None):
    return load_config(path)


def run_on_pcap(pcap_path: str, config: dict):
    """Run detection on a capture file and return (warnings_df, lookups_df, stats)."""
    wl = Whitelist.load(config["whitelist"]["path"], config["whitelist"]["enabled"])
    lookups: list[dict] = []

    def on_query(record, feats, flagged):
        lookups.append({
            "timestamp": record.timestamp,
            "src_ip": record.src_ip,
            "query_name": record.query_name,
            "parent_domain": feats.parent_domain if feats else "",
            "qtype": record.qtype,
            "entropy": feats.entropy if feats else 0.0,
            "name_length": feats.name_length if feats else len(record.query_name),
            "flagged": bool(flagged),
        })

    engine = DetectionEngine(config, wl, on_query=on_query)
    for pkt in read_pcap(pcap_path):
        engine.stats.total_packets += 1
        rec = parse_packet(pkt)
        if rec is not None:
            engine.process_record(rec)

    warnings = [{
        "timestamp": a.timestamp, "src_ip": a.src_ip, "domain": a.domain,
        "attack_type": a.attack_type, "severity": a.severity,
        "detector_id": a.detector_id, "hit_count": a.hit_count, "reason": a.reason,
    } for a in engine.alerts.alerts]
    return pd.DataFrame(warnings), pd.DataFrame(lookups), engine.stats


def load_from_db(db_path: str, run_id: int | None):
    con = sqlite3.connect(db_path)
    try:
        runs = pd.read_sql_query("SELECT * FROM runs ORDER BY run_id DESC", con)
        if run_id is None and not runs.empty:
            run_id = int(runs.iloc[0]["run_id"])
        wdf = pd.read_sql_query("SELECT * FROM alerts WHERE run_id=?", con, params=(run_id,))
        ldf = pd.read_sql_query("SELECT * FROM queries WHERE run_id=?", con, params=(run_id,))
    finally:
        con.close()
    return wdf, ldf, runs, run_id


def _to_dt(series: pd.Series) -> pd.Series:
    return pd.to_datetime(series, unit="s", errors="coerce")


def _severity_legend() -> None:
    parts = []
    for sev, color in SEVERITY_BADGE.items():
        parts.append(f":{color}-badge[{sev}] {SEVERITY_HELP[sev]}")
    st.caption("Severity:  " + "    ".join(parts))


def render(wdf: pd.DataFrame, ldf: pd.DataFrame, stats=None) -> None:
    total_lookups = int(stats.inspected_queries) if stats else (
        int((ldf["is_response"] == 0).sum()) if ("is_response" in ldf) else len(ldf))
    total_warnings = len(wdf)
    total_matches = int(wdf["hit_count"].sum()) if "hit_count" in wdf and not wdf.empty else 0
    hosts = wdf["src_ip"].nunique() if not wdf.empty else 0

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Lookups checked", f"{total_lookups:,}",
              help="DNS lookups that were inspected (known-safe domains are skipped).")
    c2.metric("Warnings raised", f"{total_warnings:,}",
              help="Each warning groups repeated matches for the same host, domain and type.")
    c3.metric("Total matches", f"{total_matches:,}",
              help="How many individual lookups triggered a warning, before grouping.")
    c4.metric("Hosts involved", f"{hosts:,}",
              help="Distinct computers that raised at least one warning.")

    if wdf.empty:
        st.success("Nothing suspicious was found in this data.",
                   icon=":material/check_circle:")
    else:
        _severity_legend()
        left, right = st.columns(2)
        with left:
            st.subheader("Warnings by category", help="How many warnings of each kind were raised.")
            by_type = wdf.groupby("attack_type").size().reset_index(name="count")
            fig = px.bar(by_type.sort_values("count"), x="count", y="attack_type",
                         orientation="h")
            fig.update_layout(showlegend=False, height=320,
                              margin=dict(l=0, r=0, t=10, b=0),
                              xaxis_title="warnings", yaxis_title=None)
            st.plotly_chart(fig, width="stretch")
        with right:
            st.subheader("Warnings over time", help="When warnings were raised during the capture.")
            tmp = wdf.copy()
            tmp["time"] = _to_dt(tmp["timestamp"])
            tmp = tmp.sort_values("time")
            tmp["running total"] = range(1, len(tmp) + 1)
            fig = px.line(tmp, x="time", y="running total", markers=True,
                          hover_data=["attack_type", "src_ip"])
            fig.update_layout(height=320, margin=dict(l=0, r=0, t=10, b=0),
                              xaxis_title=None)
            st.plotly_chart(fig, width="stretch")

        st.subheader("Most active hosts", help="The computers that raised the most warnings.")
        top = (wdf.groupby("src_ip")
               .agg(warnings=("attack_type", "size"), matches=("hit_count", "sum"),
                    categories=("attack_type", lambda s: ", ".join(sorted(set(s)))))
               .reset_index().sort_values("warnings", ascending=False).head(10))
        top = top.rename(columns={"src_ip": "host"})
        st.dataframe(top, width="stretch", hide_index=True)

    # Name-randomness chart.
    if not ldf.empty and "entropy" in ldf:
        st.subheader("How random the looked-up names were",
                     help="Randomness (entropy) of each name. Everyday names score low; "
                          "scrambled or machine-made names score high. Flagged names are shown "
                          "separately so you can see the split.")
        q = ldf.copy()
        if "flagged" in q:
            q["name type"] = q["flagged"].map(lambda f: "flagged" if f else "normal")
        else:
            q["name type"] = "normal"
        q = q[q["entropy"] > 0]
        if not q.empty:
            fig = px.histogram(q, x="entropy", color="name type", nbins=40, barmode="overlay",
                               opacity=0.75)
            fig.update_layout(height=320, margin=dict(l=0, r=0, t=10, b=0),
                              xaxis_title="randomness score", yaxis_title="number of names")
            st.plotly_chart(fig, width="stretch")

    # Plain-language explanation of the categories.
    if not wdf.empty:
        with st.expander("What these categories mean", icon=":material/help:"):
            for atype in sorted(wdf["attack_type"].unique()):
                st.markdown(f"**{atype}** — {CATEGORY_HELP.get(atype, '')}")

    # Detailed, filterable table.
    if not wdf.empty:
        st.subheader("All warnings", help="Filter and read the full reason for each warning.")
        types = sorted(wdf["attack_type"].unique())
        sevs = [s for s in ("High", "Medium", "Low") if s in set(wdf["severity"])]
        fc1, fc2 = st.columns(2)
        sel_types = fc1.multiselect("Category", types, default=types)
        sel_sevs = fc2.multiselect("Severity", sevs, default=sevs)
        view = wdf[wdf["attack_type"].isin(sel_types) & wdf["severity"].isin(sel_sevs)].copy()
        view["time"] = _to_dt(view["timestamp"])
        rename = {"attack_type": "category", "src_ip": "host", "hit_count": "matches"}
        view = view.rename(columns=rename)
        cols = ["time", "severity", "category", "host", "domain", "matches", "reason"]
        cols = [c for c in cols if c in view.columns]
        st.dataframe(view[cols].sort_values("time"), width="stretch", hide_index=True)


def main() -> None:
    st.title("DNSGuard-X", anchor=False)
    st.caption("Reviews DNS lookups and flags the ones that match known attack patterns, "
               "with a plain-language reason for each.")

    with st.sidebar:
        st.subheader("Data source", anchor=False)
        source = st.radio("Where should the data come from?",
                          ["Upload a capture file", "Read the saved database"],
                          label_visibility="collapsed")
        config_path = st.text_input("Settings file", value="config.yaml",
                                    help="Path to config.yaml (thresholds and options).")
        try:
            config = _load_config_cached(config_path if config_path else None)
        except Exception as exc:
            st.error(f"Could not read the settings file: {exc}", icon=":material/error:")
            st.stop()

    if source == "Upload a capture file":
        up = st.file_uploader("Upload a capture file (.pcap or .pcapng)",
                              type=["pcap", "pcapng", "cap"])
        if up is None:
            st.caption("No file selected yet. You can also create sample traffic with "
                       "`python tools/generate_traffic.py`, then use the button below.")
            default = Path("data/pcaps/mixed.pcap")
            if default.is_file() and st.button("Use the sample capture (data/pcaps/mixed.pcap)",
                                               icon=":material/play_arrow:"):
                with st.spinner("Checking the capture..."):
                    wdf, ldf, stats = run_on_pcap(str(default), config)
                render(wdf, ldf, stats)
            return
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
            tmp.write(up.getbuffer())
            tmp_path = tmp.name
        with st.spinner("Checking the capture..."):
            wdf, ldf, stats = run_on_pcap(tmp_path, config)
        render(wdf, ldf, stats)
    else:
        db_path = st.text_input("Database file",
                                value=config["storage"].get("db_path", "dnsguard.db"))
        if not Path(db_path).is_file():
            st.warning(f"No database found at {db_path}. Run the command-line tool first to "
                       "create it.", icon=":material/info:")
            return
        wdf, ldf, runs, run_id = load_from_db(db_path, None)
        if not runs.empty:
            opts = {f"Run {int(r.run_id)} — {r.source}": int(r.run_id)
                    for r in runs.itertuples()}
            label = st.selectbox("Which run would you like to view?", list(opts.keys()))
            wdf, ldf, _, _ = load_from_db(db_path, opts[label])
        render(wdf, ldf, None)


main()
