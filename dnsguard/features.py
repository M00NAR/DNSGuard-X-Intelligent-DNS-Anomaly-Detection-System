"""Feature extraction for DNSGuard-X.

Two levels of features:

* **Per query** - computed from a single name/record (entropy, length, ratios...).
* **Per host** - computed over a sliding time window keyed by source IP
  (QPS, unique subdomains per parent, NXDOMAIN ratio, TXT/NULL share).

The module also matches responses to their queries by ``(dns_id, host-pair)`` to
derive the response/request size ratio, and surfaces cache-poisoning indicators.
"""

from __future__ import annotations

import math
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Iterable

import tldextract

from .parser import DNSRecord

# Offline extractor: never hits the network for the public-suffix list.
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())

_VOWELS = set("aeiou")
_CONSONANTS = set("bcdfghjklmnpqrstvwxyz")


def shannon_entropy(text: str) -> float:
    """Shannon entropy (bits/char) of ``text``. Empty string -> 0.0."""
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    entropy = 0.0
    for c in counts.values():
        p = c / n
        entropy -= p * math.log2(p)
    return entropy


def longest_consonant_run(text: str) -> int:
    """Length of the longest run of consecutive consonant letters."""
    best = run = 0
    for ch in text.lower():
        if ch in _CONSONANTS:
            run += 1
            best = max(best, run)
        else:
            run = 0
    return best


def parent_domain(query_name: str) -> str:
    """Registered domain (e.g. ``evil.com`` for ``a.b.evil.com``). Falls back gracefully."""
    if not query_name:
        return ""
    ext = _EXTRACT(query_name)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}".lower()
    if ext.domain:
        return ext.domain.lower()
    # No recognised suffix: use the last two labels.
    parts = query_name.strip(".").split(".")
    return ".".join(parts[-2:]).lower() if len(parts) >= 2 else query_name.lower()


def subdomain_part(query_name: str, parent: str | None = None) -> str:
    """The labels to the left of the registered domain, concatenated (dots removed)."""
    if not query_name:
        return ""
    parent = parent if parent is not None else parent_domain(query_name)
    name = query_name.strip(".").lower()
    if parent and name.endswith(parent):
        sub = name[: -len(parent)].rstrip(".")
    else:
        sub = ".".join(name.split(".")[:-2])
    return sub.replace(".", "")


@dataclass
class QueryFeatures:
    """Per-query numeric features."""

    name_length: int
    longest_label_length: int
    entropy: float            # entropy of the subdomain part
    digit_ratio: float
    vowel_ratio: float
    longest_consonant_run: int
    num_labels: int
    qtype: str
    size_ratio: float         # response bytes / request bytes (0.0 if no response seen)
    parent_domain: str
    subdomain: str


def extract_query_features(record: DNSRecord, size_ratio: float = 0.0,
                           parent: str | None = None) -> QueryFeatures:
    """Compute per-query features for a parsed DNS record."""
    name = record.query_name
    parent = parent if parent is not None else parent_domain(name)
    sub = subdomain_part(name, parent)
    labels = [lbl for lbl in name.split(".") if lbl]
    letters = [c for c in sub if c.isalpha()]
    digits = [c for c in name if c.isdigit()]

    entropy = shannon_entropy(sub)
    vowel_ratio = (sum(c in _VOWELS for c in letters) / len(letters)) if letters else 0.0
    digit_ratio = (len(digits) / len(name)) if name else 0.0

    return QueryFeatures(
        name_length=len(name),
        longest_label_length=max((len(lbl) for lbl in labels), default=0),
        entropy=entropy,
        digit_ratio=digit_ratio,
        vowel_ratio=vowel_ratio,
        longest_consonant_run=longest_consonant_run(sub),
        num_labels=len(labels),
        qtype=record.qtype,
        size_ratio=size_ratio,
        parent_domain=parent,
        subdomain=sub,
    )


@dataclass
class HostFeatures:
    """Per-host features over the current sliding window."""

    src_ip: str
    qps: float
    queries_in_window: int
    unique_subdomains: int          # max unique subdomains seen for any single parent
    top_parent: str                 # the parent domain with that many unique subdomains
    nxdomain_ratio: float
    responses_in_window: int
    txt_null_share: float


@dataclass
class _WinEntry:
    ts: float
    parent: str
    subdomain: str
    qtype: str


class HostWindow:
    """Maintains sliding-window per-host state and derives :class:`HostFeatures`."""

    def __init__(self, window_seconds: float, min_span_seconds: float = 1.0) -> None:
        self._w = window_seconds
        self._min_span = min_span_seconds
        self._queries: dict[str, deque[_WinEntry]] = defaultdict(deque)
        # Response outcomes keyed by host: (ts, is_nxdomain)
        self._responses: dict[str, deque[tuple[float, bool]]] = defaultdict(deque)

    def _evict(self, now: float, host: str) -> None:
        cutoff = now - self._w
        q = self._queries[host]
        while q and q[0].ts < cutoff:
            q.popleft()
        r = self._responses[host]
        while r and r[0][0] < cutoff:
            r.popleft()

    def add_query(self, record: DNSRecord, parent: str, subdomain: str) -> None:
        self._queries[record.src_ip].append(
            _WinEntry(record.timestamp, parent, subdomain, record.qtype))

    def add_response(self, record: DNSRecord) -> None:
        """Record a response outcome against the *client* host.

        ``record.dst_ip`` is the client that issued the query.
        """
        is_nx = record.rcode == "NXDOMAIN"
        self._responses[record.dst_ip].append((record.timestamp, is_nx))

    def features(self, host: str, now: float) -> HostFeatures:
        """Compute current window features for ``host`` at time ``now``."""
        self._evict(now, host)
        q = self._queries[host]
        n = len(q)

        if n:
            span = max(q[-1].ts - q[0].ts, self._min_span)
            qps = n / span
        else:
            qps = 0.0

        # Unique subdomains per parent -> keep the worst parent.
        per_parent: dict[str, set[str]] = defaultdict(set)
        txt_null = 0
        for e in q:
            per_parent[e.parent].add(e.subdomain)
            if e.qtype in ("TXT", "NULL"):
                txt_null += 1
        if per_parent:
            top_parent, subs = max(per_parent.items(), key=lambda kv: len(kv[1]))
            unique_subs = len(subs)
        else:
            top_parent, unique_subs = "", 0

        resp = self._responses[host]
        resp_n = len(resp)
        nx = sum(1 for _, is_nx in resp if is_nx)
        nx_ratio = (nx / resp_n) if resp_n else 0.0

        return HostFeatures(
            src_ip=host,
            qps=qps,
            queries_in_window=n,
            unique_subdomains=unique_subs,
            top_parent=top_parent,
            nxdomain_ratio=nx_ratio,
            responses_in_window=resp_n,
            txt_null_share=(txt_null / n) if n else 0.0,
        )


@dataclass
class PoisoningSignal:
    """A cache-poisoning indicator raised while matching responses to queries."""

    kind: str                 # "conflicting_answers" or "unmatched_response"
    src_ip: str               # client host (victim)
    query_name: str
    dns_id: int
    detail: str


class ResponseMatcher:
    """Matches responses to queries and emits size ratios + poisoning indicators.

    A query is keyed by ``(dns_id, host-pair)``. The first matching response yields
    a size ratio; a second response for an already-answered query with a *different*
    answer set is a conflicting-answer indicator; a response with no outstanding or
    recently-seen query is an unmatched-response indicator.
    """

    def __init__(self, query_timeout: float = 10.0, answered_memory: float = 10.0,
                 unmatched_grace: float = 2.0) -> None:
        self._timeout = query_timeout
        self._answered_memory = answered_memory
        self._grace = unmatched_grace
        self._start_ts: float | None = None
        # key -> (ts, request_size, query_name)
        self._pending: dict[tuple[int, tuple[str, str]], tuple[float, int, str]] = {}
        # key -> (ts, answer_signature, query_name) for already-answered queries
        self._answered: dict[tuple[int, tuple[str, str]], tuple[float, str, str]] = {}

    @staticmethod
    def _answer_sig(record: DNSRecord) -> str:
        parts = sorted(f"{a['type']}:{a['rdata']}" for a in record.answers)
        return "|".join(parts)

    def _gc(self, now: float) -> None:
        for key in [k for k, (ts, _, _) in self._pending.items() if now - ts > self._timeout]:
            del self._pending[key]
        for key in [k for k, (ts, _, _) in self._answered.items()
                    if now - ts > self._answered_memory]:
            del self._answered[key]

    def observe_query(self, record: DNSRecord) -> None:
        if self._start_ts is None:
            self._start_ts = record.timestamp
        key = (record.dns_id, record.host_pair)
        self._pending[key] = (record.timestamp, record.packet_size, record.query_name)

    def observe_response(self, record: DNSRecord) -> tuple[float, list[PoisoningSignal]]:
        """Process a response. Returns ``(size_ratio, signals)``.

        ``size_ratio`` is 0.0 when no matching request is known.
        """
        if self._start_ts is None:
            self._start_ts = record.timestamp
        self._gc(record.timestamp)
        key = (record.dns_id, record.host_pair)
        signals: list[PoisoningSignal] = []
        client = record.dst_ip
        sig = self._answer_sig(record)

        if key in self._pending:
            ts, req_size, qname = self._pending.pop(key)
            ratio = (record.packet_size / req_size) if req_size else 0.0
            self._answered[key] = (record.timestamp, sig, qname or record.query_name)
            return ratio, signals

        if key in self._answered:
            prev_ts, prev_sig, qname = self._answered[key]
            if sig != prev_sig:
                signals.append(PoisoningSignal(
                    kind="conflicting_answers", src_ip=client,
                    query_name=qname or record.query_name, dns_id=record.dns_id,
                    detail=(f"Two different answers came back for the same question "
                            f"(request id {record.dns_id}). This can mean someone is "
                            f"forging replies.")))
            # Refresh memory window.
            self._answered[key] = (record.timestamp, prev_sig, qname)
            return 0.0, signals

        # No matching query at all -> unmatched (ignore the brief start-of-capture grace).
        if self._start_ts is not None and record.timestamp - self._start_ts >= self._grace:
            signals.append(PoisoningSignal(
                kind="unmatched_response", src_ip=client,
                query_name=record.query_name, dns_id=record.dns_id,
                detail=(f"An answer arrived that nobody asked for (request id "
                        f"{record.dns_id}). This can mean someone is forging replies.")))
        return 0.0, signals
