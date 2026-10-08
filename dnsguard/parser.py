"""DNS packet parsing: scapy packet -> plain record dict.

A ``DNSRecord`` captures everything the feature extractor and detectors need from
a single packet. Responses are matched to their queries elsewhere
(:mod:`dnsguard.features`) via ``(dns_id, host-pair)``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.inet6 import IPv6
from scapy.packet import Packet

# Reverse maps for numeric DNS codes that scapy sometimes leaves as ints.
QTYPE_NAMES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT",
    28: "AAAA", 33: "SRV", 10: "NULL", 43: "DS", 48: "DNSKEY", 65: "HTTPS",
    64: "SVCB", 257: "CAA", 255: "ANY", 252: "AXFR",
}
RCODE_NAMES = {
    0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP",
    5: "REFUSED", 9: "NOTAUTH",
}


@dataclass
class DNSRecord:
    """A normalised view of one DNS packet."""

    timestamp: float
    src_ip: str
    dst_ip: str
    query_name: str          # lowercased, trailing dot stripped
    qtype: str               # "A", "TXT", "ANY", ... (or "TYPE<n>" if unknown)
    is_response: bool
    rcode: str               # "NOERROR", "NXDOMAIN", ... (queries report "NOERROR")
    dns_id: int
    packet_size: int         # total captured bytes
    answers: list[dict] = field(default_factory=list)  # [{name, type, ttl, rdata}]
    ttl: int | None = None   # minimum answer TTL, or None
    transport: str = "udp"

    @property
    def host_pair(self) -> tuple[str, str]:
        """(client, server) ordering independent of direction, for request/response matching."""
        return tuple(sorted((self.src_ip, self.dst_ip)))  # type: ignore[return-value]


def _qtype_name(value: Any) -> str:
    if isinstance(value, str):
        return value.upper()
    try:
        num = int(value)
    except (TypeError, ValueError):
        return "UNKNOWN"
    return QTYPE_NAMES.get(num, f"TYPE{num}")


def _rcode_name(value: Any) -> str:
    try:
        num = int(value)
    except (TypeError, ValueError):
        return "NOERROR"
    return RCODE_NAMES.get(num, f"RCODE{num}")


def _decode(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, (list, tuple)):
        return " ".join(_decode(v) for v in value)
    return str(value)


def _iter_rrs(an: object) -> list[DNSRR]:
    """Return the answer resource records, handling list, single-RR and chained forms.

    scapy exposes ``dns.an`` as a list when read from a PCAP, but as a single
    :class:`DNSRR` (possibly chained via ``.payload``) for in-memory packets whose
    ``ancount`` has not been recomputed yet.
    """
    if an is None:
        return []
    if isinstance(an, (list, tuple)):
        return [rr for rr in an if isinstance(rr, DNSRR)]
    rrs: list[DNSRR] = []
    rr = an
    seen = 0
    while isinstance(rr, DNSRR) and seen < 128:
        rrs.append(rr)
        rr = rr.payload
        seen += 1
    return rrs


def _extract_answers(dns: DNS) -> tuple[list[dict], int | None]:
    answers: list[dict] = []
    min_ttl: int | None = None
    for rr in _iter_rrs(dns.an):
        rr_type = _qtype_name(getattr(rr, "type", 0))
        ttl = int(getattr(rr, "ttl", 0) or 0)
        min_ttl = ttl if min_ttl is None else min(min_ttl, ttl)
        answers.append({
            "name": _decode(getattr(rr, "rrname", b"")).rstrip("."),
            "type": rr_type,
            "ttl": ttl,
            "rdata": _decode(getattr(rr, "rdata", "")),
        })
    return answers, min_ttl


def parse_packet(pkt: Packet) -> DNSRecord | None:
    """Convert a scapy packet into a :class:`DNSRecord`, or ``None`` if it has no DNS layer."""
    if not pkt.haslayer(DNS):
        return None
    dns = pkt[DNS]
    if dns.qd is None and int(getattr(dns, "qdcount", 0) or 0) == 0:
        # Malformed / empty DNS message with no question section.
        if not dns.qr:
            return None

    if pkt.haslayer(IP):
        src_ip, dst_ip = pkt[IP].src, pkt[IP].dst
    elif pkt.haslayer(IPv6):
        src_ip, dst_ip = pkt[IPv6].src, pkt[IPv6].dst
    else:
        return None

    transport = "tcp" if pkt.haslayer(TCP) else "udp"

    qname = ""
    qtype = "UNKNOWN"
    try:
        qd = dns.qd
        if qd is not None:
            first = qd[0] if not isinstance(qd, DNSQR) else qd
            qname = _decode(getattr(first, "qname", b"")).rstrip(".").lower()
            qtype = _qtype_name(getattr(first, "qtype", 0))
    except (TypeError, IndexError):
        pass

    is_response = bool(dns.qr)
    answers: list[dict] = []
    ttl: int | None = None
    if is_response:
        answers, ttl = _extract_answers(dns)

    try:
        size = len(bytes(pkt))
    except Exception:  # pragma: no cover - scapy build failure on exotic packets
        size = int(getattr(pkt, "wirelen", 0) or 0)

    return DNSRecord(
        timestamp=float(getattr(pkt, "time", 0.0) or 0.0),
        src_ip=src_ip,
        dst_ip=dst_ip,
        query_name=qname,
        qtype=qtype,
        is_response=is_response,
        rcode=_rcode_name(getattr(dns, "rcode", 0)) if is_response else "NOERROR",
        dns_id=int(getattr(dns, "id", 0) or 0),
        packet_size=size,
        answers=answers,
        ttl=ttl,
        transport=transport,
    )
