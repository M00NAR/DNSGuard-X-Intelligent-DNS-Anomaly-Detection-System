"""DNSGuard-X command-line entry point.

Examples::

    python -m dnsguard.main --pcap data/pcaps/mixed.pcap
    python -m dnsguard.main --live --iface "Ethernet"      # needs admin/root
    python -m dnsguard.main --pcap mixed.pcap --no-store    # skip SQLite logging
"""

from __future__ import annotations

import argparse
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any

from .alerts import Alert
from .capture import CaptureError, read_pcap, sniff_live
from .config import ConfigError, load_config
from .engine import DetectionEngine
from .parser import DNSRecord, parse_packet
from .storage import Storage
from .whitelist import Whitelist

# ANSI colours (disabled automatically when output is not a TTY or on NO_COLOR).
_USE_COLOR = sys.stdout.isatty() and "NO_COLOR" not in __import__("os").environ


def _c(text: str, code: str) -> str:
    if not _USE_COLOR:
        return text
    return f"\033[{code}m{text}\033[0m"


SEV_COLOR = {"High": "1;31", "Medium": "1;33", "Low": "1;36"}


def _sev(text: str) -> str:
    return _c(text, SEV_COLOR.get(text, "0"))


class RunCollector:
    """Buffers queries/alerts and (optionally) persists them to SQLite."""

    def __init__(self, storage: Storage | None, log_queries: bool) -> None:
        self.storage = storage
        self.log_queries = log_queries
        self.alerts: dict[tuple[str, str, str], Alert] = {}
        self.new_alert_lines: list[str] = []

    def on_alert(self, alert: Alert, is_new: bool) -> None:
        self.alerts[alert.key()] = alert
        if self.storage:
            self.storage.upsert_alert(alert)
        if is_new:
            line = (f"[{_sev(alert.severity):>6}] {alert.attack_type} "
                    f"| {alert.src_ip} -> {alert.domain} | {alert.reason}")
            self.new_alert_lines.append(line)
            print("  " + line)

    def on_query(self, record: DNSRecord, feats: Any, flagged: bool) -> None:
        if self.storage and self.log_queries:
            self.storage.log_query(record, feats, flagged)


def run_pcap(engine: DetectionEngine, collector: RunCollector, path: str) -> None:
    for pkt in read_pcap(path):
        engine.stats.total_packets += 1
        record = parse_packet(pkt)
        if record is not None:
            engine.process_record(record)


def run_live(engine: DetectionEngine, collector: RunCollector, iface: str | None,
             bpf: str, flush_interval: float, storage: Storage | None) -> None:
    last_flush = [time.time()]

    def handle(pkt) -> None:
        engine.stats.total_packets += 1
        record = parse_packet(pkt)
        if record is not None:
            engine.process_record(record)
        now = time.time()
        if storage and now - last_flush[0] >= flush_interval:
            storage.commit()
            last_flush[0] = now

    print(_c("Starting live capture. Press Ctrl+C to stop.", "1;32"))
    try:
        sniff_live(iface, bpf, handle)
    except KeyboardInterrupt:
        print("\nStopping capture...")


def print_summary(engine: DetectionEngine, collector: RunCollector, elapsed: float) -> None:
    stats = engine.stats
    alerts = list(collector.alerts.values())

    print()
    print(_c("=" * 64, "1;34"))
    print(_c(" DNSGuard-X detection summary", "1;34"))
    print(_c("=" * 64, "1;34"))
    print(f" Packets processed     : {stats.total_packets}")
    print(f" DNS records parsed    : {stats.parsed_records}  "
          f"({stats.queries} queries, {stats.responses} responses)")
    print(f" Whitelisted (skipped) : {stats.whitelisted}")
    print(f" Queries inspected     : {stats.inspected_queries}")
    print(f" Raw findings          : {stats.findings}")
    print(f" Distinct alerts       : {_c(str(len(alerts)), '1;31' if alerts else '1;32')}")
    print(f" Elapsed               : {elapsed:.2f}s")

    if not alerts:
        print("\n " + _c("No anomalies detected.", "1;32"))
        return

    # Alerts per attack type.
    by_type = Counter(a.attack_type for a in alerts)
    print("\n " + _c("Alerts by attack type", "1;37"))
    width = max(len(t) for t in by_type)
    for atype, count in by_type.most_common():
        print(f"   {atype:<{width}}  {count}")

    # Top 5 hosts by alert count.
    by_host: Counter = Counter()
    hits_by_host: Counter = Counter()
    for a in alerts:
        by_host[a.src_ip] += 1
        hits_by_host[a.src_ip] += a.hit_count
    print("\n " + _c("Top hosts", "1;37"))
    print(f"   {'source IP':<18}{'alerts':>8}{'hits':>8}")
    for host, count in by_host.most_common(5):
        print(f"   {host:<18}{count:>8}{hits_by_host[host]:>8}")

    # Severity breakdown.
    by_sev = Counter(a.severity for a in alerts)
    sev_str = "  ".join(f"{_sev(s)}: {by_sev.get(s, 0)}" for s in ("High", "Medium", "Low"))
    print("\n Severity: " + sev_str)


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="dnsguard", description="DNSGuard-X: rule-based DNS anomaly detection.")
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--pcap", metavar="FILE", help="read packets from a PCAP file")
    src.add_argument("--live", action="store_true", help="sniff live traffic (needs admin/root)")
    p.add_argument("--iface", metavar="NAME", help="interface for --live")
    p.add_argument("--config", metavar="FILE", help="path to config.yaml")
    p.add_argument("--no-store", action="store_true", help="do not write to SQLite")
    p.add_argument("--db", metavar="FILE", help="override SQLite path from config")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)

    try:
        config = load_config(args.config)
    except ConfigError as exc:
        print(_c(f"Config error: {exc}", "1;31"), file=sys.stderr)
        return 2

    wl_cfg = config["whitelist"]
    whitelist = Whitelist.load(wl_cfg.get("path"), wl_cfg.get("enabled", True))
    print(f"Loaded whitelist: {len(whitelist)} domains")

    store_cfg = config["storage"]
    storage: Storage | None = None
    use_store = store_cfg.get("enabled", True) and not args.no_store
    if use_store:
        db_path = args.db or store_cfg.get("db_path", "dnsguard.db")
        storage = Storage(db_path)
        source = f"pcap:{args.pcap}" if args.pcap else f"live:{args.iface or 'default'}"
        storage.start_run(source, time.time())

    collector = RunCollector(storage, store_cfg.get("log_queries", True))
    engine = DetectionEngine(config, whitelist,
                             on_alert=collector.on_alert, on_query=collector.on_query)

    start = time.time()
    print(_c("\nDetections (new alerts appear below):", "1;37"))
    try:
        if args.pcap:
            run_pcap(engine, collector, args.pcap)
        else:
            flush = store_cfg.get("flush_interval_seconds", 2.0)
            bpf = config.get("capture", {}).get("bpf_filter", "udp port 53 or tcp port 53")
            iface = args.iface or config.get("capture", {}).get("iface")
            run_live(engine, collector, iface, bpf, flush, storage)
    except CaptureError as exc:
        print(_c(f"\nCapture error: {exc}", "1;31"), file=sys.stderr)
        if storage:
            storage.close()
        return 1

    elapsed = time.time() - start
    if storage:
        storage.finish_run(time.time(), engine.stats.total_packets,
                           engine.stats.inspected_queries, len(collector.alerts))
        storage.close()

    print_summary(engine, collector, elapsed)
    if storage is not None:
        print(f"\nResults written to {store_cfg.get('db_path') if not args.db else args.db}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
