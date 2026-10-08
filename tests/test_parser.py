"""Tests for the scapy -> DNSRecord parser and end-to-end pipeline on a PCAP."""

from pathlib import Path

import pytest
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether

from dnsguard.engine import DetectionEngine
from dnsguard.parser import parse_packet
from dnsguard.whitelist import Whitelist

PCAP_DIR = Path(__file__).resolve().parent.parent / "data" / "pcaps"


def _query(qname="example.com", qtype=1, dns_id=7):
    p = (Ether() / IP(src="10.0.0.1", dst="10.0.0.53") / UDP(sport=5000, dport=53)
         / DNS(id=dns_id, rd=1, qd=DNSQR(qname=qname, qtype=qtype)))
    p.time = 1000.0
    return p


def _response(qname="example.com", dns_id=7, rcode=0, ttl=300):
    p = (Ether() / IP(src="10.0.0.53", dst="10.0.0.1") / UDP(sport=53, dport=5000)
         / DNS(id=dns_id, qr=1, rd=1, ra=1, rcode=rcode, qd=DNSQR(qname=qname, qtype=1),
               an=DNSRR(rrname=qname, type="A", ttl=ttl, rdata="1.2.3.4")))
    p.time = 1000.1
    return p


def test_parse_query():
    rec = parse_packet(_query("mail.google.com", qtype=16))
    assert rec is not None
    assert rec.query_name == "mail.google.com"
    assert rec.qtype == "TXT"
    assert rec.is_response is False
    assert rec.src_ip == "10.0.0.1"
    assert rec.dns_id == 7


def test_parse_response_nxdomain():
    rec = parse_packet(_response(rcode=3))
    assert rec.is_response is True
    assert rec.rcode == "NXDOMAIN"


def test_parse_response_answers_and_ttl():
    rec = parse_packet(_response(ttl=120))
    assert rec.is_response is True
    assert rec.ttl == 120
    assert rec.answers and rec.answers[0]["type"] == "A"


def test_parse_any_qtype():
    rec = parse_packet(_query("isc.org", qtype=255))
    assert rec.qtype == "ANY"


def test_parse_non_dns_returns_none():
    p = Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / UDP(sport=1, dport=80)
    assert parse_packet(p) is None


def test_host_pair_is_direction_independent():
    q = parse_packet(_query())
    r = parse_packet(_response())
    assert q.host_pair == r.host_pair


@pytest.mark.skipif(not (PCAP_DIR / "mixed.pcap").is_file(),
                    reason="run tools/generate_traffic.py to create PCAPs")
def test_engine_detects_each_attack_on_mixed(config):
    from dnsguard.capture import read_pcap
    wl = Whitelist.load(config["whitelist"]["path"], config["whitelist"]["enabled"])
    engine = DetectionEngine(config, wl)
    for pkt in read_pcap(PCAP_DIR / "mixed.pcap"):
        rec = parse_packet(pkt)
        if rec is not None:
            engine.process_record(rec)
    types = {a.attack_type for a in engine.alerts.alerts}
    assert "DNS Tunneling (payload)" in types
    assert "DNS Tunneling (volume)" in types
    assert "DGA / C2 / Water Torture" in types
    assert "DNS Flood" in types
    assert "DNS Amplification" in types
    assert "Cache Poisoning Indicator" in types


@pytest.mark.skipif(not (PCAP_DIR / "normal.pcap").is_file(),
                    reason="run tools/generate_traffic.py to create PCAPs")
def test_engine_low_false_positives_on_normal(config):
    from dnsguard.capture import read_pcap
    wl = Whitelist.load(config["whitelist"]["path"], config["whitelist"]["enabled"])
    engine = DetectionEngine(config, wl)
    for pkt in read_pcap(PCAP_DIR / "normal.pcap"):
        rec = parse_packet(pkt)
        if rec is not None:
            engine.process_record(rec)
    assert len(engine.alerts.alerts) == 0
