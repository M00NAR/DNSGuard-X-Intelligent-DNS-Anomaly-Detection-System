"""Rule-based detection engine for DNSGuard-X.

Five independent rule detectors plus a response-level cache-poisoning check. Every
detector subclasses :class:`Detector`, so a future ``MLDetector`` (Isolation Forest /
Random Forest) can be dropped into the same pipeline without changing callers.

Each detector inspects a :class:`DetectionContext` (one query's features plus the
current per-host window features) and returns zero or more :class:`Finding` objects.
Detectors run independently, so a single query can produce several findings.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from .features import HostFeatures, QueryFeatures
from .parser import DNSRecord


@dataclass
class DetectionContext:
    """Everything a detector needs to judge a single query."""

    record: DNSRecord
    query: QueryFeatures
    host: HostFeatures


@dataclass
class Finding:
    """A raw detection, before alert de-duplication."""

    detector_id: str
    attack_type: str
    severity: str             # "High" | "Medium" | "Low"
    src_ip: str
    domain: str               # parent domain the alert is grouped under
    reason: str               # plain-English explanation with actual values
    timestamp: float


class Detector(ABC):
    """Base class for all detectors (rule-based today, ML tomorrow).

    Subclasses implement :meth:`inspect`. The constructor receives this detector's
    slice of ``config.yaml`` (e.g. ``config["detectors"]["D1"]``).
    """

    detector_id: str = "D?"

    def __init__(self, cfg: dict[str, Any]) -> None:
        self.cfg = cfg or {}
        self.enabled: bool = bool(self.cfg.get("enabled", True))
        self.severity: str = self.cfg.get("severity", "Medium")
        self.dedupe_by: str = self.cfg.get("dedupe_by", "domain")

    @abstractmethod
    def inspect(self, ctx: DetectionContext) -> list[Finding]:
        """Return findings raised for this query (possibly empty)."""
        raise NotImplementedError

    # Label used to group host-level alerts that span many parent domains
    # (e.g. DGA / water torture), so they collapse to one alert per host.
    HOST_AGGREGATE = "(host aggregate)"

    # Convenience for subclasses.
    def _finding(self, ctx: DetectionContext, attack_type: str, reason: str,
                 severity: str | None = None, domain: str | None = None) -> Finding:
        if domain is not None:
            group = domain
        elif self.dedupe_by == "host":
            group = self.HOST_AGGREGATE
        else:
            group = ctx.query.parent_domain or ctx.record.query_name
        return Finding(
            detector_id=self.detector_id,
            attack_type=attack_type,
            severity=severity or self.severity,
            src_ip=ctx.record.src_ip,
            domain=group,
            reason=reason,
            timestamp=ctx.record.timestamp,
        )


class D1TunnelingPayload(Detector):
    """D1 - high entropy and long names: encoded tunnel payload."""

    detector_id = "D1"

    def inspect(self, ctx: DetectionContext) -> list[Finding]:
        if not self.enabled:
            return []
        q = ctx.query
        ent_thr = self.cfg.get("entropy_threshold", 3.8)
        len_thr = self.cfg.get("min_name_length", 50)
        if q.entropy > ent_thr and q.name_length > len_thr:
            reason = (f"Very long name ({q.name_length} characters) that looks scrambled "
                      f"(randomness {q.entropy:.2f}, high); request type {q.qtype}. "
                      f"Data hidden in DNS usually looks like this.")
            return [self._finding(ctx, self.cfg.get("attack_type", "DNS Tunneling (payload)"), reason)]
        return []


class D2TunnelingVolume(Detector):
    """D2 - many unique subdomains of one parent in the window: tunneling by volume."""

    detector_id = "D2"

    def inspect(self, ctx: DetectionContext) -> list[Finding]:
        if not self.enabled:
            return []
        h = ctx.host
        thr = self.cfg.get("unique_subdomains_threshold", 30)
        # Only fire for the parent domain this host is hammering.
        if h.unique_subdomains > thr and h.top_parent == ctx.query.parent_domain:
            reason = (f"Looked up {h.unique_subdomains} different made-up names under "
                      f"{h.top_parent} within a minute (normal is under {thr}). "
                      f"This is how data is often sent out over DNS.")
            return [self._finding(ctx, self.cfg.get("attack_type", "DNS Tunneling (volume)"),
                                  reason, domain=h.top_parent or None)]
        return []


class D3DGAWaterTorture(Detector):
    """D3 - high NXDOMAIN ratio from one host: DGA / C2 / water torture."""

    detector_id = "D3"

    def inspect(self, ctx: DetectionContext) -> list[Finding]:
        if not self.enabled:
            return []
        h = ctx.host
        ratio_thr = self.cfg.get("nxdomain_ratio_threshold", 0.5)
        min_resp = self.cfg.get("min_responses", 20)
        if h.responses_in_window >= min_resp and h.nxdomain_ratio > ratio_thr:
            reason = (f"{h.nxdomain_ratio:.0%} of this host's last {h.responses_in_window} "
                      f"lookups were for names that do not exist (normal is well under "
                      f"{ratio_thr:.0%}). Malware does this while hunting for its control server.")
            return [self._finding(ctx, self.cfg.get("attack_type", "DGA / C2 / Water Torture"), reason)]
        return []


class D4FloodAmplification(Detector):
    """D4 - high QPS (flood) or ANY with large size ratio (amplification)."""

    detector_id = "D4"

    def inspect(self, ctx: DetectionContext) -> list[Finding]:
        if not self.enabled:
            return []
        q, h = ctx.query, ctx.host
        findings: list[Finding] = []
        qps_thr = self.cfg.get("qps_threshold", 100)
        size_thr = self.cfg.get("size_ratio_threshold", 10)
        amp_qtypes = set(self.cfg.get("amplification_qtypes", ["ANY"]))

        if h.qps > qps_thr:
            reason = (f"Sending about {h.qps:.0f} lookups every second, far above the normal "
                      f"limit of {qps_thr}. This can overload a DNS server.")
            findings.append(self._finding(
                ctx, self.cfg.get("flood_attack_type", "DNS Flood"), reason))

        if q.qtype in amp_qtypes and q.size_ratio > size_thr:
            reason = (f"An '{q.qtype}' request produced an answer {q.size_ratio:.1f} times "
                      f"larger than the request (limit {size_thr}). Attackers abuse this to "
                      f"flood a victim with traffic.")
            findings.append(self._finding(
                ctx, self.cfg.get("amplification_attack_type", "DNS Amplification"), reason))
        return findings


class D5SuspectedDGA(Detector):
    """D5 - high entropy with unnatural letter pattern: suspected DGA domain."""

    detector_id = "D5"

    def inspect(self, ctx: DetectionContext) -> list[Finding]:
        if not self.enabled:
            return []
        q = ctx.query
        ent_thr = self.cfg.get("entropy_threshold", 3.5)
        max_vowel = self.cfg.get("max_vowel_ratio", 0.2)
        min_run = self.cfg.get("min_consonant_run", 5)
        unnatural = q.vowel_ratio < max_vowel or q.longest_consonant_run >= min_run
        if q.entropy > ent_thr and unnatural and q.subdomain:
            reason = (f"Name looks machine-generated rather than human-chosen: "
                      f"highly random (randomness {q.entropy:.2f}), few vowels "
                      f"({q.vowel_ratio:.0%}), up to {q.longest_consonant_run} consonants "
                      f"in a row.")
            return [self._finding(ctx, self.cfg.get("attack_type", "Suspected DGA Domain"), reason)]
        return []


# Ordered list of rule detectors D1..D5, mirroring Figure 2 of the design.
RULE_DETECTOR_CLASSES: list[type[Detector]] = [
    D1TunnelingPayload, D2TunnelingVolume, D3DGAWaterTorture,
    D4FloodAmplification, D5SuspectedDGA,
]


def build_detectors(config: dict[str, Any]) -> list[Detector]:
    """Instantiate all enabled rule detectors from the config."""
    det_cfg = config.get("detectors", {})
    key_by_id = {"D1": "D1", "D2": "D2", "D3": "D3", "D4": "D4", "D5": "D5"}
    detectors: list[Detector] = []
    for cls in RULE_DETECTOR_CLASSES:
        cfg = det_cfg.get(key_by_id[cls.detector_id], {})
        det = cls(cfg)
        if det.enabled:
            detectors.append(det)
    return detectors


# --------------------------------------------------------------------------- Future work
# TODO(ml): Add an MLDetector(Detector) that loads a trained Isolation Forest
# (unsupervised, per-host behaviour) and/or Random Forest (supervised, DGA vs benign)
# and returns Findings from model scores. Because it implements the same
# Detector.inspect(ctx) -> list[Finding] interface, the engine and alert manager need
# no changes: just append it in build_detectors(). See README "Future work".
