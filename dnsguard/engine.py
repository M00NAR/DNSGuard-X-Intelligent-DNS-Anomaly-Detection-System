"""Detection pipeline: parsed records -> features -> detectors -> alerts.

:class:`DetectionEngine` holds all per-run state (host windows, response matcher,
detectors, alert manager) and exposes :meth:`process_record` for one parsed packet.
It is transport-agnostic: the same engine drives both PCAP replay and live capture.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from .alerts import Alert, AlertManager
from .detectors import DetectionContext, Finding, build_detectors
from .features import (HostWindow, PoisoningSignal, ResponseMatcher,
                       extract_query_features, parent_domain)
from .parser import DNSRecord
from .whitelist import Whitelist


@dataclass
class EngineStats:
    """Running counters for a detection run."""

    total_packets: int = 0
    parsed_records: int = 0
    queries: int = 0
    responses: int = 0
    whitelisted: int = 0
    inspected_queries: int = 0
    findings: int = 0


class DetectionEngine:
    """Stateful DNS anomaly detection pipeline."""

    def __init__(self, config: dict[str, Any], whitelist: Whitelist | None = None,
                 on_alert: Callable[[Alert, bool], None] | None = None,
                 on_query: Callable[[DNSRecord, Any, bool], None] | None = None,
                 on_finding: Callable[[Finding], None] | None = None) -> None:
        self.config = config
        self.whitelist = whitelist or Whitelist(set())
        self._on_alert = on_alert
        self._on_query = on_query
        self._on_finding = on_finding

        hw = config["host_window"]
        self.window = HostWindow(hw["seconds"], hw.get("min_span_seconds", 1.0))

        m = config["matching"]
        self.matcher = ResponseMatcher(
            query_timeout=m.get("query_timeout_seconds", 10.0),
            answered_memory=m.get("answered_memory_seconds", 10.0),
            unmatched_grace=m.get("unmatched_grace_seconds", 2.0))

        self.detectors = build_detectors(config)
        self.alerts = AlertManager(config["alerts"].get("dedupe_window_seconds", 60.0))
        self._cp_cfg = config["detectors"].get("CP", {})
        self.stats = EngineStats()

    # ------------------------------------------------------------------ core
    def _emit(self, finding: Finding) -> Alert | None:
        """Count a finding, fire the finding hook, and fold it into an alert."""
        self.stats.findings += 1
        if self._on_finding:
            self._on_finding(finding)
        alert = self.alerts.process(finding)
        if alert is not None and self._on_alert:
            self._on_alert(alert, alert.hit_count == 1)
        return alert

    def process_record(self, record: DNSRecord) -> list[Alert]:
        """Run one parsed record through the full pipeline. Returns new/updated alerts."""
        self.stats.parsed_records += 1
        produced: list[Alert] = []

        if record.is_response:
            self.stats.responses += 1
            produced.extend(self._handle_response(record))
            return produced

        self.stats.queries += 1
        parent = parent_domain(record.query_name)

        # Whitelist: skip known-safe parents entirely (but still track for matching).
        if self.whitelist.is_whitelisted(parent):
            self.stats.whitelisted += 1
            self.matcher.observe_query(record)
            if self._on_query:
                self._on_query(record, None, False)
            return produced

        self.matcher.observe_query(record)
        subdomain_feats = extract_query_features(record, size_ratio=0.0, parent=parent)
        self.window.add_query(record, parent, subdomain_feats.subdomain)
        host_feats = self.window.features(record.src_ip, record.timestamp)
        self.stats.inspected_queries += 1

        ctx = DetectionContext(record=record, query=subdomain_feats, host=host_feats)
        flagged = False
        for det in self.detectors:
            for finding in det.inspect(ctx):
                flagged = True
                alert = self._emit(finding)
                if alert is not None:
                    produced.append(alert)

        if self._on_query:
            self._on_query(record, subdomain_feats, flagged)
        return produced

    def _handle_response(self, record: DNSRecord) -> list[Alert]:
        produced: list[Alert] = []
        self.window.add_response(record)
        _ratio, signals = self.matcher.observe_response(record)
        # D4 amplification uses the size ratio on the *query*; we approximate by
        # re-deriving features for the response's question and feeding size_ratio.
        if _ratio and record.query_name:
            parent = parent_domain(record.query_name)
            if not self.whitelist.is_whitelisted(parent):
                q_like = DNSRecord(
                    timestamp=record.timestamp, src_ip=record.dst_ip, dst_ip=record.src_ip,
                    query_name=record.query_name, qtype=record.qtype, is_response=False,
                    rcode="NOERROR", dns_id=record.dns_id, packet_size=record.packet_size)
                feats = extract_query_features(q_like, size_ratio=_ratio, parent=parent)
                host_feats = self.window.features(record.dst_ip, record.timestamp)
                ctx = DetectionContext(record=q_like, query=feats, host=host_feats)
                for det in self.detectors:
                    if det.detector_id != "D4":
                        continue
                    for finding in det.inspect(ctx):
                        alert = self._emit(finding)
                        if alert is not None:
                            produced.append(alert)

        produced.extend(self._handle_poisoning(record, signals))
        return produced

    def _handle_poisoning(self, record: DNSRecord,
                          signals: list[PoisoningSignal]) -> list[Alert]:
        if not self._cp_cfg.get("enabled", True) or not signals:
            return []
        produced: list[Alert] = []
        for sig in signals:
            if sig.kind == "conflicting_answers" and not self._cp_cfg.get(
                    "flag_conflicting_answers", True):
                continue
            if sig.kind == "unmatched_response" and not self._cp_cfg.get(
                    "flag_unmatched_responses", True):
                continue
            parent = parent_domain(sig.query_name) or sig.query_name
            finding = Finding(
                detector_id="CP",
                attack_type=self._cp_cfg.get("attack_type", "Cache Poisoning Indicator"),
                severity=self._cp_cfg.get("severity", "Medium"),
                src_ip=sig.src_ip,
                domain=parent,
                reason=sig.detail,
                timestamp=record.timestamp,
            )
            alert = self._emit(finding)
            if alert is not None:
                produced.append(alert)
        return produced
