"""Tests for each rule detector and the alert manager."""

import pytest

from dnsguard.alerts import AlertManager
from dnsguard.detectors import (DetectionContext, D1TunnelingPayload, D2TunnelingVolume,
                                D3DGAWaterTorture, D4FloodAmplification, D5SuspectedDGA,
                                build_detectors)
from dnsguard.features import HostFeatures, QueryFeatures
from dnsguard.parser import DNSRecord


def _ctx(query_kwargs=None, host_kwargs=None, src="10.0.0.9", qname="x.evil.com",
         ts=0.0) -> DetectionContext:
    q_defaults = dict(name_length=20, longest_label_length=5, entropy=2.0, digit_ratio=0.0,
                      vowel_ratio=0.4, longest_consonant_run=2, num_labels=3, qtype="A",
                      size_ratio=0.0, parent_domain="evil.com", subdomain="x")
    h_defaults = dict(src_ip=src, qps=1.0, queries_in_window=1, unique_subdomains=1,
                      top_parent="evil.com", nxdomain_ratio=0.0, responses_in_window=0,
                      txt_null_share=0.0)
    q_defaults.update(query_kwargs or {})
    h_defaults.update(host_kwargs or {})
    rec = DNSRecord(timestamp=ts, src_ip=src, dst_ip="10.0.0.53", query_name=qname,
                    qtype=q_defaults["qtype"], is_response=False, rcode="NOERROR",
                    dns_id=1, packet_size=60)
    return DetectionContext(record=rec, query=QueryFeatures(**q_defaults),
                            host=HostFeatures(**h_defaults))


# ---------------------------------------------------------------------- D1

def test_d1_fires_on_long_high_entropy_name():
    d1 = D1TunnelingPayload({"entropy_threshold": 3.8, "min_name_length": 50,
                             "attack_type": "DNS Tunneling (payload)", "severity": "High"})
    ctx = _ctx({"entropy": 4.3, "name_length": 62, "qtype": "TXT"})
    findings = d1.inspect(ctx)
    assert len(findings) == 1
    assert findings[0].severity == "High"
    assert "4.30" in findings[0].reason and "62" in findings[0].reason


def test_d1_silent_when_short_even_if_high_entropy():
    d1 = D1TunnelingPayload({"entropy_threshold": 3.8, "min_name_length": 50})
    assert d1.inspect(_ctx({"entropy": 4.5, "name_length": 20})) == []


def test_d1_silent_when_low_entropy():
    d1 = D1TunnelingPayload({"entropy_threshold": 3.8, "min_name_length": 50})
    assert d1.inspect(_ctx({"entropy": 2.0, "name_length": 80})) == []


# ---------------------------------------------------------------------- D2

def test_d2_fires_on_many_unique_subdomains():
    d2 = D2TunnelingVolume({"unique_subdomains_threshold": 30, "severity": "High",
                            "attack_type": "DNS Tunneling (volume)", "dedupe_by": "domain"})
    ctx = _ctx(host_kwargs={"unique_subdomains": 45, "top_parent": "evil.com"})
    findings = d2.inspect(ctx)
    assert len(findings) == 1
    assert "45 different" in findings[0].reason


def test_d2_silent_below_threshold():
    d2 = D2TunnelingVolume({"unique_subdomains_threshold": 30})
    assert d2.inspect(_ctx(host_kwargs={"unique_subdomains": 10})) == []


# ---------------------------------------------------------------------- D3

def test_d3_fires_on_high_nxdomain_ratio():
    d3 = D3DGAWaterTorture({"nxdomain_ratio_threshold": 0.5, "min_responses": 20,
                            "severity": "Medium", "dedupe_by": "host"})
    ctx = _ctx(host_kwargs={"nxdomain_ratio": 0.9, "responses_in_window": 25})
    findings = d3.inspect(ctx)
    assert len(findings) == 1
    assert findings[0].domain == d3.HOST_AGGREGATE  # grouped per host


def test_d3_needs_minimum_responses():
    d3 = D3DGAWaterTorture({"nxdomain_ratio_threshold": 0.5, "min_responses": 20})
    assert d3.inspect(_ctx(host_kwargs={"nxdomain_ratio": 1.0, "responses_in_window": 5})) == []


# ---------------------------------------------------------------------- D4

def test_d4_fires_on_high_qps():
    d4 = D4FloodAmplification({"qps_threshold": 100, "size_ratio_threshold": 10,
                               "amplification_qtypes": ["ANY"], "severity": "High",
                               "flood_attack_type": "DNS Flood",
                               "amplification_attack_type": "DNS Amplification"})
    findings = d4.inspect(_ctx(host_kwargs={"qps": 250.0}))
    assert any(f.attack_type == "DNS Flood" for f in findings)


def test_d4_fires_on_any_amplification():
    d4 = D4FloodAmplification({"qps_threshold": 100, "size_ratio_threshold": 10,
                               "amplification_qtypes": ["ANY"],
                               "flood_attack_type": "DNS Flood",
                               "amplification_attack_type": "DNS Amplification"})
    findings = d4.inspect(_ctx({"qtype": "ANY", "size_ratio": 15.0}))
    assert any(f.attack_type == "DNS Amplification" for f in findings)


def test_d4_silent_on_normal_a_query():
    d4 = D4FloodAmplification({"qps_threshold": 100, "size_ratio_threshold": 10,
                               "amplification_qtypes": ["ANY"]})
    assert d4.inspect(_ctx({"qtype": "A", "size_ratio": 2.0}, {"qps": 5.0})) == []


# ---------------------------------------------------------------------- D5

def test_d5_fires_on_low_vowel_ratio():
    d5 = D5SuspectedDGA({"entropy_threshold": 3.5, "max_vowel_ratio": 0.2,
                         "min_consonant_run": 5, "severity": "Low"})
    findings = d5.inspect(_ctx({"entropy": 3.8, "vowel_ratio": 0.1, "subdomain": "xkqjzvbpwl"}))
    assert len(findings) == 1
    assert findings[0].severity == "Low"


def test_d5_fires_on_long_consonant_run():
    d5 = D5SuspectedDGA({"entropy_threshold": 3.5, "max_vowel_ratio": 0.2,
                         "min_consonant_run": 5})
    findings = d5.inspect(_ctx({"entropy": 3.6, "vowel_ratio": 0.5,
                                "longest_consonant_run": 6, "subdomain": "strngthz"}))
    assert len(findings) == 1


def test_d5_silent_on_natural_name():
    d5 = D5SuspectedDGA({"entropy_threshold": 3.5, "max_vowel_ratio": 0.2,
                         "min_consonant_run": 5})
    assert d5.inspect(_ctx({"entropy": 3.6, "vowel_ratio": 0.45,
                            "longest_consonant_run": 2, "subdomain": "banana"})) == []


# --------------------------------------------------------------- disabled / build

def test_disabled_detector_is_silent():
    d1 = D1TunnelingPayload({"enabled": False, "entropy_threshold": 3.8, "min_name_length": 50})
    assert d1.inspect(_ctx({"entropy": 9.9, "name_length": 99})) == []


def test_build_detectors_respects_enabled(config):
    detectors = build_detectors(config)
    ids = {d.detector_id for d in detectors}
    assert {"D1", "D2", "D3", "D4", "D5"}.issubset(ids)


# ------------------------------------------------------------------ alert manager

def test_alert_manager_dedupes_within_window():
    from dnsguard.detectors import Finding
    mgr = AlertManager(dedupe_window_seconds=60.0)
    f = Finding("D1", "DNS Tunneling (payload)", "High", "10.0.0.5", "evil.com", "r", 0.0)
    mgr.process(f)
    mgr.process(Finding("D1", "DNS Tunneling (payload)", "High", "10.0.0.5", "evil.com", "r", 10.0))
    assert len(mgr.alerts) == 1
    assert mgr.alerts[0].hit_count == 2


def test_alert_manager_separates_by_key():
    from dnsguard.detectors import Finding
    mgr = AlertManager(dedupe_window_seconds=60.0)
    mgr.process(Finding("D1", "DNS Tunneling (payload)", "High", "10.0.0.5", "a.com", "r", 0.0))
    mgr.process(Finding("D1", "DNS Tunneling (payload)", "High", "10.0.0.6", "a.com", "r", 0.0))
    assert len(mgr.alerts) == 2


def test_alert_manager_reopens_after_window():
    from dnsguard.detectors import Finding
    mgr = AlertManager(dedupe_window_seconds=60.0)
    mgr.process(Finding("D1", "T", "High", "10.0.0.5", "a.com", "r", 0.0))
    mgr.process(Finding("D1", "T", "High", "10.0.0.5", "a.com", "r", 200.0))
    assert len(mgr.alerts) == 2
