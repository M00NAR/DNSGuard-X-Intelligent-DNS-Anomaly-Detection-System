"""Synthetic DNS traffic generator for DNSGuard-X.

Builds labelled PCAP files with scapy so the detection engine can be tested and
scored offline. Packets are only *written to disk*; nothing is ever sent on a
network. Every scenario models a well-known benign or anomalous DNS pattern.

Scenarios (written to ``--out``, default ``data/pcaps``):

* ``normal.pcap``         - benign lookups from several hosts with realistic timing
* ``tunneling.pcap``      - long base32 subdomains of one parent domain (tunneling pattern)
* ``dga.pcap``            - 200 random-letter domains, ~90 % answered with NXDOMAIN
* ``flood.pcap``          - 2000 queries from one host within 10 seconds
* ``amplification.pcap``  - ANY queries with large responses
* ``poisoning.pcap``      - conflicting / unsolicited responses (cache-poisoning indicators)
* ``mixed.pcap``          - all of the above interleaved with normal traffic
* ``labels.csv``          - ground truth for every query in mixed.pcap

Usage::

    python tools/generate_traffic.py [--out data/pcaps] [--seed 42]
"""

from __future__ import annotations

import argparse
import base64
import csv
import random
import string
from dataclasses import dataclass, field
from pathlib import Path

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Packet
from scapy.utils import wrpcap

PROJECT_ROOT = Path(__file__).resolve().parent.parent
BASE_TIME = 1_790_000_000.0  # fixed epoch so generated captures are reproducible

RESOLVER = "10.0.0.53"
NORMAL_HOSTS = [f"10.0.0.{i}" for i in range(10, 18)]
TUNNEL_HOST = "10.0.0.66"
DGA_HOST = "10.0.0.77"
FLOOD_HOST = "10.0.0.88"
AMP_VICTIM = "203.0.113.50"
OPEN_RESOLVERS = ["198.51.100.1", "198.51.100.2", "198.51.100.3"]
POISON_VICTIM = "10.0.0.30"

QTYPE_NUM = {"A": 1, "NS": 2, "CNAME": 5, "PTR": 12, "MX": 15, "TXT": 16,
             "AAAA": 28, "NULL": 10, "HTTPS": 65, "ANY": 255}

# Popular domains (also in data/whitelist.txt) plus benign-but-unlisted names, so the
# false-positive rate is measured on names the detectors actually inspect.
POPULAR = [
    "www.google.com", "mail.google.com", "fonts.googleapis.com", "www.youtube.com",
    "i.ytimg.com", "www.facebook.com", "static.xx.fbcdn.net", "www.instagram.com",
    "graph.instagram.com", "www.wikipedia.org", "en.wikipedia.org", "upload.wikimedia.org",
    "www.amazon.com", "images-na.ssl-images-amazon.com", "s3.amazonaws.com",
    "login.microsoftonline.com", "outlook.office365.com", "www.bing.com",
    "github.com", "api.github.com", "avatars.githubusercontent.com", "www.reddit.com",
    "www.netflix.com", "assets.nflxext.com", "www.linkedin.com", "static.licdn.com",
    "twitter.com", "abs.twimg.com", "www.apple.com", "icloud.com", "www.whatsapp.com",
    "web.whatsapp.com", "stackoverflow.com", "cdn.sstatic.net", "zoom.us",
    "ajax.cloudflare.com", "cdn.jsdelivr.net", "www.spotify.com", "open.spotify.com",
    "www.dropbox.com", "slack.com", "clients4.google.com", "update.googleapis.com",
    "ocsp.digicert.com", "ctldl.windowsupdate.com", "settings-win.data.microsoft.com",
]
BENIGN_UNLISTED = [
    "vtop.vit.ac.in", "moodle.vitlearning.example", "portal.mycollege.edu",
    "library.mycollege.edu", "printer01.corp.local", "fileserver.corp.local",
    "intranet.acme-widgets.com", "mail.acme-widgets.com", "shop.localbakery.in",
    "www.citybuslines.org", "api.weatherdesk.io", "news.dailyherald.co.uk",
    "blog.techreviewer.net", "cdn.photogallery-site.com", "www.cricketscores.in",
    "docs.python.org", "pypi.org", "files.pythonhosted.org", "www.kaggle.com",
    "registry.npmjs.org", "www.overleaf.com", "www.geeksforgeeks.org",
    "www.irctc.co.in", "www.swiggy.com", "www.zomato.com", "www.flipkart.com",
]
TYPOS = ["gooogle.com", "faceboook.com", "githbu.com", "wikipeida.org", "yotube.com",
         "stackoverflw.com", "amazn.com"]


@dataclass
class Trace:
    """A list of packets plus ground-truth labels for each query."""

    packets: list[Packet] = field(default_factory=list)
    labels: list[dict] = field(default_factory=list)

    def extend(self, other: "Trace") -> None:
        self.packets.extend(other.packets)
        self.labels.extend(other.labels)

    def sorted_packets(self) -> list[Packet]:
        return sorted(self.packets, key=lambda p: float(p.time))


class IdAllocator:
    """Hands out DNS transaction IDs that increment per source host."""

    def __init__(self, rng: random.Random) -> None:
        self._rng = rng
        self._next: dict[str, int] = {}

    def next(self, host: str) -> int:
        if host not in self._next:
            self._next[host] = self._rng.randint(1, 30000)
        val = self._next[host]
        self._next[host] = (val + 1) % 65536
        return val


def build_query(ts: float, src: str, dst: str, sport: int, dns_id: int,
                qname: str, qtype: str) -> Packet:
    """Create a DNS query packet stamped with time ``ts``."""
    pkt = (Ether() / IP(src=src, dst=dst) / UDP(sport=sport, dport=53)
           / DNS(id=dns_id, rd=1, qd=DNSQR(qname=qname, qtype=QTYPE_NUM[qtype])))
    pkt.time = ts
    return pkt


def build_response(ts: float, query: Packet, rcode: int = 0,
                   answers: list[DNSRR] | None = None, src: str | None = None) -> Packet:
    """Create a response packet answering ``query``."""
    q_ip, q_udp, q_dns = query[IP], query[UDP], query[DNS]
    dns = DNS(id=q_dns.id, qr=1, rd=1, ra=1, rcode=rcode, qd=q_dns.qd[0])
    if answers:
        dns.an = answers
    pkt = (Ether() / IP(src=src or q_ip.dst, dst=q_ip.src)
           / UDP(sport=53, dport=q_udp.sport) / dns)
    pkt.time = ts
    return pkt


def a_record(name: str, ip: str, ttl: int = 300) -> DNSRR:
    return DNSRR(rrname=name, type="A", ttl=ttl, rdata=ip)


def _wire_name(name: str) -> bytes:
    out = b""
    for label in name.strip(".").split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def answers_for(rng: random.Random, qname: str, qtype: str) -> list[DNSRR]:
    """Plausible benign answers for a given query type."""
    ttl = rng.choice([60, 120, 300, 300, 600, 3600])
    if qtype == "AAAA":
        return [DNSRR(rrname=qname, type="AAAA", ttl=ttl,
                      rdata=f"2606:4700::{rng.randint(1, 0xffff):x}")]
    if qtype == "MX":
        return [DNSRR(rrname=qname, type="MX", ttl=ttl,
                      rdata=b"\x00\x0a" + _wire_name(f"mx1.{qname}"))]
    if qtype == "TXT":
        return [DNSRR(rrname=qname, type="TXT", ttl=ttl, rdata=["v=spf1 include:_spf.example ~all"])]
    if qtype == "HTTPS":
        return []
    return [a_record(qname, f"{rng.randint(1, 223)}.{rng.randint(0, 255)}."
                            f"{rng.randint(0, 255)}.{rng.randint(1, 254)}", ttl)]


def exchange(trace: Trace, rng: random.Random, ids: IdAllocator, ts: float, src: str,
             dst: str, qname: str, qtype: str, label: str, rcode: int = 0,
             answers: list[DNSRR] | None = None, latency: float | None = None,
             respond: bool = True) -> Packet:
    """Append one query (and usually its response) to ``trace`` and label the query."""
    dns_id = ids.next(src)
    sport = rng.randint(1024, 65535)
    q = build_query(ts, src, dst, sport, dns_id, qname, qtype)
    trace.packets.append(q)
    trace.labels.append({"query": qname.lower(), "true_label": label, "src_ip": src,
                         "dns_id": dns_id, "qtype": qtype, "timestamp": f"{ts:.6f}"})
    if respond:
        lat = latency if latency is not None else rng.uniform(0.002, 0.060)
        if answers is None:
            answers = answers_for(rng, qname, qtype) if rcode == 0 else []
        trace.packets.append(build_response(ts + lat, q, rcode, answers))
    return q


# --------------------------------------------------------------------------- scenarios

def gen_normal(rng: random.Random, ids: IdAllocator, start: float, duration: float) -> Trace:
    """Benign browsing: each host issues bursts of lookups with think time between them."""
    trace = Trace()
    for host in NORMAL_HOSTS:
        t = start + rng.uniform(0, 5)
        while t < start + duration:
            burst = rng.randint(1, 6)  # a page load triggers a few lookups at once
            for _ in range(burst):
                r = rng.random()
                if r < 0.62:
                    name = rng.choice(POPULAR)
                elif r < 0.97:
                    name = rng.choice(BENIGN_UNLISTED)
                else:
                    name = rng.choice(TYPOS)
                qtype = rng.choices(["A", "AAAA", "HTTPS", "MX", "TXT"],
                                    weights=[60, 25, 10, 3, 2])[0]
                rcode = 3 if name in TYPOS else 0
                exchange(trace, rng, ids, t, host, RESOLVER, name, qtype, "normal", rcode)
                t += rng.uniform(0.005, 0.08)
            t += rng.expovariate(1 / 6.0)  # mean 6 s think time
    return trace


def gen_tunneling(rng: random.Random, ids: IdAllocator, start: float,
                  payload_path: Path, domain: str = "data-exfil-demo.net") -> Trace:
    """Encode a text file as long base32 subdomains of one parent domain.

    This reproduces the signature of DNS-based data smuggling: many long,
    high-entropy names under a single domain, with a mix of TXT and A queries.
    """
    trace = Trace()
    raw = payload_path.read_bytes()
    b32 = base64.b32encode(raw).decode().rstrip("=").lower()
    chunk_label = 30          # chars per DNS label (well under the 63 limit)
    labels_per_name = 2       # two encoded labels per query -> ~60-char names
    seq = 0
    t = start
    per_name = chunk_label * labels_per_name
    for i in range(0, len(b32), per_name):
        block = b32[i:i + per_name]
        parts = [block[j:j + chunk_label] for j in range(0, len(block), chunk_label)]
        qname = f"{'.'.join(parts)}.s{seq:04d}.{domain}"
        qtype = "TXT" if seq % 3 == 0 else "A"
        # Attacker-controlled authoritative server answers, so NOERROR with a token.
        ans = [DNSRR(rrname=qname, type="TXT", ttl=0, rdata=["ok"])] if qtype == "TXT" \
            else [a_record(qname, "198.51.100.200", ttl=0)]
        exchange(trace, rng, ids, t, TUNNEL_HOST, RESOLVER, qname, qtype,
                 "tunneling", rcode=0, answers=ans)
        seq += 1
        t += rng.uniform(0.01, 0.05)
    return trace


def _random_domain(rng: random.Random) -> str:
    length = rng.randint(10, 20)
    name = "".join(rng.choice(string.ascii_lowercase) for _ in range(length))
    return f"{name}.{rng.choice(['com', 'net', 'info', 'biz', 'org'])}"


def gen_dga(rng: random.Random, ids: IdAllocator, start: float, count: int = 200) -> Trace:
    """Random-letter domains, ~90 % answered NXDOMAIN (bot hunting for a live C2)."""
    trace = Trace()
    t = start
    for _ in range(count):
        name = _random_domain(rng)
        nxdomain = rng.random() < 0.9
        rcode = 3 if nxdomain else 0
        exchange(trace, rng, ids, t, DGA_HOST, RESOLVER, name, "A", "dga", rcode=rcode)
        t += rng.uniform(0.05, 0.25)
    return trace


def gen_flood(rng: random.Random, ids: IdAllocator, start: float,
              count: int = 2000, span: float = 10.0) -> Trace:
    """One host sends a very high rate of queries (DoS flood)."""
    trace = Trace()
    target = "flood-demo.net"
    for i in range(count):
        t = start + (i / count) * span + rng.uniform(0, span / count)
        name = f"flood{i}.{target}"
        # Server is overwhelmed; answer only a fraction.
        respond = rng.random() < 0.3
        exchange(trace, rng, ids, t, FLOOD_HOST, RESOLVER, name, "A", "flood",
                 rcode=0, respond=respond)
    return trace


def gen_amplification(rng: random.Random, ids: IdAllocator, start: float,
                      count: int = 120) -> Trace:
    """Spoofed ANY queries to open resolvers that return large responses."""
    trace = Trace()
    t = start
    big_domain = "isc.org"
    for _ in range(count):
        resolver = rng.choice(OPEN_RESOLVERS)
        # Source is the spoofed victim; query is small, response is large.
        q = exchange(trace, rng, ids, t, AMP_VICTIM, resolver, big_domain, "ANY",
                     "amplification", respond=False)
        # Build a deliberately large response (many records) back to the victim.
        answers = []
        for _ in range(28):
            answers.append(a_record(big_domain, f"149.20.{rng.randint(0,255)}.{rng.randint(1,254)}", 3600))
        answers.append(DNSRR(rrname=big_domain, type="TXT", ttl=3600,
                             rdata=["x" * 240]))
        resp = build_response(t + rng.uniform(0.005, 0.03), q, rcode=0,
                              answers=answers, src=resolver)
        trace.packets.append(resp)
        t += rng.uniform(0.02, 0.1)
    return trace


def gen_poisoning(rng: random.Random, ids: IdAllocator, start: float) -> Trace:
    """Cache-poisoning indicators: conflicting answers and unsolicited responses."""
    trace = Trace()
    t = start
    # 1) Legit query that receives two responses with different answers (same dns_id).
    for i in range(6):
        name = f"bank{i}.poison-demo.com"
        q = exchange(trace, rng, ids, t, POISON_VICTIM, RESOLVER, name, "A",
                     "poisoning", rcode=0,
                     answers=[a_record(name, "93.184.216.34", 3600)],
                     latency=0.02)
        # Forged second answer arrives with a different IP, same transaction id.
        forged = build_response(t + 0.005, q, rcode=0,
                                answers=[a_record(name, "6.6.6.6", 5)])
        trace.packets.append(forged)
        t += rng.uniform(0.1, 0.3)
    # 2) Unsolicited responses with no matching query.
    for i in range(6):
        name = f"orphan{i}.poison-demo.com"
        fake_q = build_query(t, POISON_VICTIM, RESOLVER, rng.randint(1024, 65535),
                             ids.next("poison-unsolicited"), name, "A")
        resp = build_response(t, fake_q, rcode=0, answers=[a_record(name, "6.6.6.7", 5)])
        trace.packets.append(resp)
        trace.labels.append({"query": name.lower(), "true_label": "poisoning",
                             "src_ip": POISON_VICTIM, "dns_id": fake_q[DNS].id,
                             "qtype": "A", "timestamp": f"{t:.6f}"})
        t += rng.uniform(0.1, 0.3)
    return trace


# --------------------------------------------------------------------------- driver

def write_trace(trace: Trace, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(path), trace.sorted_packets())


def write_labels(trace: Trace, path: Path) -> None:
    rows = sorted(trace.labels, key=lambda r: float(r["timestamp"]))
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(
            fh, fieldnames=["timestamp", "src_ip", "dns_id", "query", "qtype", "true_label"])
        writer.writeheader()
        for r in rows:
            writer.writerow(r)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate labelled DNS PCAPs for DNSGuard-X.")
    parser.add_argument("--out", default=str(PROJECT_ROOT / "data" / "pcaps"),
                        help="output directory for PCAP files and labels.csv")
    parser.add_argument("--seed", type=int, default=42, help="RNG seed for reproducibility")
    parser.add_argument("--random", action="store_true",
                        help="use a fresh random seed so every run produces different traffic")
    parser.add_argument("--payload", default=str(Path(__file__).resolve().parent / "sample_secret.txt"),
                        help="text file encoded into the tunneling scenario")
    args = parser.parse_args()

    if args.random:
        import time as _time
        args.seed = int(_time.time()) % 100000
        print(f"Using random seed {args.seed} (traffic will differ each run)\n")

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    payload = Path(args.payload)

    rng = random.Random(args.seed)
    ids = IdAllocator(rng)

    # Individual scenario files (each starts at BASE_TIME for clarity).
    scenarios = {
        "normal": gen_normal(random.Random(args.seed), IdAllocator(random.Random(args.seed)),
                             BASE_TIME, duration=120.0),
        "tunneling": gen_tunneling(random.Random(args.seed + 1), IdAllocator(random.Random(args.seed + 1)),
                                   BASE_TIME, payload),
        "dga": gen_dga(random.Random(args.seed + 2), IdAllocator(random.Random(args.seed + 2)), BASE_TIME),
        "flood": gen_flood(random.Random(args.seed + 3), IdAllocator(random.Random(args.seed + 3)), BASE_TIME),
        "amplification": gen_amplification(random.Random(args.seed + 4),
                                           IdAllocator(random.Random(args.seed + 4)), BASE_TIME),
        "poisoning": gen_poisoning(random.Random(args.seed + 5),
                                   IdAllocator(random.Random(args.seed + 5)), BASE_TIME),
    }
    for name, trace in scenarios.items():
        write_trace(trace, out_dir / f"{name}.pcap")
        print(f"  {name:14s} {len(trace.packets):6d} packets, {len(trace.labels):5d} queries "
              f"-> {name}.pcap")

    # Mixed capture: interleave everything on one shared timeline, with normal traffic
    # spread across the whole window so attacks are embedded in background noise.
    mixed = Trace()
    mixed.extend(gen_normal(rng, ids, BASE_TIME, duration=300.0))
    mixed.extend(gen_tunneling(rng, ids, BASE_TIME + 40.0, payload))
    mixed.extend(gen_dga(rng, ids, BASE_TIME + 90.0))
    mixed.extend(gen_flood(rng, ids, BASE_TIME + 150.0))
    mixed.extend(gen_amplification(rng, ids, BASE_TIME + 200.0))
    mixed.extend(gen_poisoning(rng, ids, BASE_TIME + 250.0))

    write_trace(mixed, out_dir / "mixed.pcap")
    write_labels(mixed, out_dir / "labels.csv")
    print(f"  {'mixed':14s} {len(mixed.packets):6d} packets, {len(mixed.labels):5d} queries "
          f"-> mixed.pcap + labels.csv")
    print(f"\nWrote all PCAPs to {out_dir}")


if __name__ == "__main__":
    main()
