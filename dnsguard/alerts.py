"""Alert manager: de-duplicate findings into alerts.

Findings from the detectors are merged so that one ``(src_ip, parent domain,
attack_type)`` combination raises a single alert per de-dupe window, carrying a hit
count and the first/last timestamps. The most severe reason is kept.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .detectors import Finding

_SEVERITY_RANK = {"High": 3, "Medium": 2, "Low": 1}


@dataclass
class Alert:
    """A de-duplicated alert ready for storage / display."""

    timestamp: float          # first time this alert fired (in its current window)
    last_timestamp: float
    src_ip: str
    domain: str
    attack_type: str
    severity: str
    detector_id: str
    reason: str
    hit_count: int = 1

    def key(self) -> tuple[str, str, str]:
        return (self.src_ip, self.domain, self.attack_type)


class AlertManager:
    """Collapses repeated findings into alerts within a sliding de-dupe window."""

    def __init__(self, dedupe_window_seconds: float = 60.0) -> None:
        self._window = dedupe_window_seconds
        # active key -> Alert currently accumulating hits
        self._active: dict[tuple[str, str, str], Alert] = {}
        self._emitted: list[Alert] = []

    def process(self, finding: Finding) -> Alert | None:
        """Fold ``finding`` into the matching alert.

        Returns the :class:`Alert` object (new or updated). The same object is
        returned on subsequent hits so callers can observe the running hit count.
        """
        key = (finding.src_ip, finding.domain, finding.attack_type)
        existing = self._active.get(key)
        if existing is not None and finding.timestamp - existing.last_timestamp <= self._window:
            existing.hit_count += 1
            existing.last_timestamp = finding.timestamp
            # Keep the highest-severity reason; otherwise keep the first.
            if _SEVERITY_RANK.get(finding.severity, 0) > _SEVERITY_RANK.get(existing.severity, 0):
                existing.severity = finding.severity
                existing.reason = finding.reason
                existing.detector_id = finding.detector_id
            return existing

        alert = Alert(
            timestamp=finding.timestamp,
            last_timestamp=finding.timestamp,
            src_ip=finding.src_ip,
            domain=finding.domain,
            attack_type=finding.attack_type,
            severity=finding.severity,
            detector_id=finding.detector_id,
            reason=finding.reason,
            hit_count=1,
        )
        self._active[key] = alert
        self._emitted.append(alert)
        return alert

    @property
    def alerts(self) -> list[Alert]:
        """All distinct alerts emitted so far, in order of first appearance."""
        return list(self._emitted)
