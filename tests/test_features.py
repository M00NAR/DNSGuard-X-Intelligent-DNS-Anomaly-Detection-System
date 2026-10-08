"""Tests for entropy and per-query / per-host feature extraction."""

import math

import pytest

from dnsguard.features import (HostWindow, ResponseMatcher, extract_query_features,
                               longest_consonant_run, parent_domain, shannon_entropy,
                               subdomain_part)
from dnsguard.parser import DNSRecord


# --------------------------------------------------------------------- entropy

def test_entropy_empty_is_zero():
    assert shannon_entropy("") == 0.0


def test_entropy_uniform_string_is_zero():
    # A single repeated character carries no information.
    assert shannon_entropy("aaaaaa") == 0.0


def test_entropy_two_symbols_half_half_is_one_bit():
    assert shannon_entropy("abab") == pytest.approx(1.0)


def test_entropy_four_distinct_uniform_is_two_bits():
    assert shannon_entropy("abcd") == pytest.approx(2.0)


def test_entropy_benign_name_is_low():
    # "google" should sit well under the DGA thresholds.
    assert shannon_entropy("google") < 3.0


def test_entropy_random_base32_is_high():
    rnd = "mzxw6ytboirgk3tufqqgs4zamfxgiidu"
    assert shannon_entropy(rnd) > 3.5


# --------------------------------------------------------------- helper features

def test_longest_consonant_run():
    assert longest_consonant_run("aeiou") == 0
    assert longest_consonant_run("strength") == 4  # "ngth" is the longest run
    assert longest_consonant_run("xyzzy") == 5      # y counts as a consonant here
    assert longest_consonant_run("") == 0


def test_parent_domain_extraction():
    assert parent_domain("a1.x.evil.com") == "evil.com"
    assert parent_domain("mail.google.com") == "google.com"
    assert parent_domain("foo.bar.co.uk") == "bar.co.uk"


def test_subdomain_part_strips_parent():
    assert subdomain_part("a1.x.evil.com", "evil.com") == "a1x"
    assert subdomain_part("evil.com", "evil.com") == ""


def _mk(qname: str, qtype: str = "A", is_response: bool = False,
        rcode: str = "NOERROR", size: int = 60, src="10.0.0.1", dst="10.0.0.53",
        dns_id: int = 1, ts: float = 0.0, answers=None) -> DNSRecord:
    return DNSRecord(timestamp=ts, src_ip=src, dst_ip=dst, query_name=qname,
                     qtype=qtype, is_response=is_response, rcode=rcode, dns_id=dns_id,
                     packet_size=size, answers=answers or [])


def test_query_features_lengths_and_labels():
    rec = _mk("abc.def.example.com")
    f = extract_query_features(rec)
    assert f.name_length == len("abc.def.example.com")
    assert f.num_labels == 4
    assert f.longest_label_length == 7  # "example"
    assert f.parent_domain == "example.com"
    assert f.subdomain == "abcdef"


def test_query_features_digit_and_vowel_ratio():
    rec = _mk("a1b2c3.example.com")
    f = extract_query_features(rec)
    assert f.digit_ratio == pytest.approx(3 / len("a1b2c3.example.com"))
    # subdomain letters: a,b,c -> no vowels among {a}? a is a vowel.
    assert 0.0 <= f.vowel_ratio <= 1.0


def test_query_features_entropy_uses_subdomain_only():
    rec = _mk("mzxw6ytboirgk3tufqqgs4zam.data-exfil-demo.net")
    f = extract_query_features(rec)
    assert f.entropy > 3.5


# ------------------------------------------------------------------ host window

def test_host_window_qps_and_unique_subdomains():
    hw = HostWindow(window_seconds=60.0, min_span_seconds=1.0)
    for i in range(40):
        rec = _mk(f"s{i}.tunnel.example", ts=float(i) * 0.1)
        hw.add_query(rec, "tunnel.example", f"s{i}")
    feats = hw.features("10.0.0.1", now=3.9)
    assert feats.queries_in_window == 40
    assert feats.unique_subdomains == 40
    assert feats.top_parent == "tunnel.example"
    assert feats.qps > 0


def test_host_window_evicts_old_entries():
    hw = HostWindow(window_seconds=60.0)
    hw.add_query(_mk("a.x.com", ts=0.0), "x.com", "a")
    hw.add_query(_mk("b.x.com", ts=1000.0), "x.com", "b")
    feats = hw.features("10.0.0.1", now=1000.0)
    # The entry at t=0 is far outside the 60 s window.
    assert feats.queries_in_window == 1


def test_host_window_nxdomain_ratio():
    hw = HostWindow(window_seconds=60.0)
    for i in range(10):
        resp = _mk(f"d{i}.com", is_response=True,
                   rcode="NXDOMAIN" if i < 7 else "NOERROR", dst="10.0.0.1", ts=float(i))
        hw.add_response(resp)
    feats = hw.features("10.0.0.1", now=9.0)
    assert feats.responses_in_window == 10
    assert feats.nxdomain_ratio == pytest.approx(0.7)


# --------------------------------------------------------------- response matcher

def test_response_matcher_size_ratio():
    m = ResponseMatcher()
    q = _mk("isc.org", qtype="ANY", size=50, src="1.1.1.1", dst="8.8.8.8", dns_id=5, ts=0.0)
    m.observe_query(q)
    r = _mk("isc.org", qtype="ANY", is_response=True, size=700, src="8.8.8.8",
            dst="1.1.1.1", dns_id=5, ts=0.1)
    ratio, signals = m.observe_response(r)
    assert ratio == pytest.approx(14.0)
    assert signals == []


def test_response_matcher_conflicting_answers():
    m = ResponseMatcher()
    q = _mk("bank.poison-demo.com", size=50, src="10.0.0.30", dst="10.0.0.53",
            dns_id=9, ts=0.0)
    m.observe_query(q)
    r1 = _mk("bank.poison-demo.com", is_response=True, size=80, src="10.0.0.53",
             dst="10.0.0.30", dns_id=9, ts=0.1,
             answers=[{"type": "A", "rdata": "93.184.216.34", "ttl": 3600, "name": "bank.poison-demo.com"}])
    r2 = _mk("bank.poison-demo.com", is_response=True, size=80, src="10.0.0.53",
             dst="10.0.0.30", dns_id=9, ts=0.2,
             answers=[{"type": "A", "rdata": "6.6.6.6", "ttl": 5, "name": "bank.poison-demo.com"}])
    m.observe_response(r1)
    _, signals = m.observe_response(r2)
    assert any(s.kind == "conflicting_answers" for s in signals)


def test_response_matcher_unmatched_response():
    m = ResponseMatcher(unmatched_grace=0.0)
    r = _mk("orphan.poison-demo.com", is_response=True, size=80, src="10.0.0.53",
            dst="10.0.0.30", dns_id=123, ts=5.0)
    _, signals = m.observe_response(r)
    assert any(s.kind == "unmatched_response" for s in signals)
