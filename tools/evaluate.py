"""Evaluate DNSGuard-X detection against ground-truth labels.

Runs the detection engine on ``mixed.pcap``, joins the raw findings back to
``labels.csv`` by source host and parent domain, and reports precision, recall and
F1 per attack type. Also measures the false-positive rate on ``normal.pcap``.

Usage::

    python tools/evaluate.py [--pcap-dir data/pcaps] [--config config.yaml]
"""

from __future__ import annotations

import argparse
import csv
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dnsguard.capture import read_pcap
from dnsguard.config import load_config
from dnsguard.detectors import Detector, Finding
from dnsguard.engine import DetectionEngine
from dnsguard.features import parent_domain
from dnsguard.parser import parse_packet
from dnsguard.whitelist import Whitelist

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Map detector attack types to evaluation categories (== true_label values).
ATTACK_TO_CATEGORY = {
    "DNS Tunneling (payload)": "tunneling",
    "DNS Tunneling (volume)": "tunneling",
    "DGA / C2 / Water Torture": "dga",
    "Suspected DGA Domain": "dga",
    "DNS Flood": "flood",
    "DNS Amplification": "amplification",
    "Cache Poisoning Indicator": "poisoning",
}

# When a host triggers several detectors (e.g. a flood also looks like high-volume
# tunneling), assign the query the single highest-priority category.
CATEGORY_PRIORITY = ["flood", "amplification", "poisoning", "tunneling", "dga"]

ATTACK_CATEGORIES = ["tunneling", "dga", "flood", "amplification", "poisoning"]


def collect_findings(config: dict, whitelist: Whitelist, pcap: Path) -> list[Finding]:
    findings: list[Finding] = []
    engine = DetectionEngine(config, whitelist, on_finding=findings.append)
    for pkt in read_pcap(pcap):
        rec = parse_packet(pkt)
        if rec is not None:
            engine.process_record(rec)
    return findings


def index_findings(findings: list[Finding]) -> dict[str, set[tuple[str, str]]]:
    """src_ip -> set of (category, domain) that fired for that host."""
    idx: dict[str, set[tuple[str, str]]] = defaultdict(set)
    for f in findings:
        cat = ATTACK_TO_CATEGORY.get(f.attack_type)
        if cat:
            idx[f.src_ip].add((cat, f.domain))
    return idx


def predict_category(idx: dict, src_ip: str, parent: str) -> str | None:
    """Highest-priority category a host's findings assign to a query, or None."""
    hits = idx.get(src_ip, set())
    cats = {cat for (cat, domain) in hits
            if domain == Detector.HOST_AGGREGATE or domain == parent}
    for cat in CATEGORY_PRIORITY:
        if cat in cats:
            return cat
    return None


def load_labels(path: Path) -> list[dict]:
    with path.open("r", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def evaluate_mixed(idx: dict, labels: list[dict]) -> dict[str, dict[str, int]]:
    """Per-category TP/FP/FN over labelled queries (multi-class, one label per query)."""
    counts = {c: {"tp": 0, "fp": 0, "fn": 0} for c in ATTACK_CATEGORIES}
    for row in labels:
        true_cat = row["true_label"]
        parent = parent_domain(row["query"])
        pred = predict_category(idx, row["src_ip"], parent)
        for cat in ATTACK_CATEGORIES:
            is_true = true_cat == cat
            is_pred = pred == cat
            if is_true and is_pred:
                counts[cat]["tp"] += 1
            elif is_pred and not is_true:
                counts[cat]["fp"] += 1
            elif is_true and not is_pred:
                counts[cat]["fn"] += 1
    return counts


def prf(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return precision, recall, f1


def false_positive_rate(config: dict, whitelist: Whitelist, normal_pcap: Path) -> tuple[int, int]:
    """Return (flagged_queries, total_queries) for benign traffic."""
    findings = collect_findings(config, whitelist, normal_pcap)
    idx = index_findings(findings)
    total = flagged = 0
    for pkt in read_pcap(normal_pcap):
        rec = parse_packet(pkt)
        if rec is None or rec.is_response:
            continue
        total += 1
        parent = parent_domain(rec.query_name)
        if predict_category(idx, rec.src_ip, parent) is not None:
            flagged += 1
    return flagged, total


def main() -> int:
    ap = argparse.ArgumentParser(description="Score DNSGuard-X against labelled PCAPs.")
    ap.add_argument("--pcap-dir", default=str(PROJECT_ROOT / "data" / "pcaps"))
    ap.add_argument("--config", default=None)
    args = ap.parse_args()

    pcap_dir = Path(args.pcap_dir)
    mixed = pcap_dir / "mixed.pcap"
    normal = pcap_dir / "normal.pcap"
    labels_csv = pcap_dir / "labels.csv"
    for p in (mixed, normal, labels_csv):
        if not p.is_file():
            print(f"Missing {p}. Run tools/generate_traffic.py first.")
            return 1

    config = load_config(args.config)
    wl_cfg = config["whitelist"]
    whitelist = Whitelist.load(wl_cfg.get("path"), wl_cfg.get("enabled", True))

    print("Running detection on mixed.pcap ...")
    findings = collect_findings(config, whitelist, mixed)
    idx = index_findings(findings)
    labels = load_labels(labels_csv)
    counts = evaluate_mixed(idx, labels)

    print("\n=== Per-attack-type detection (mixed.pcap) ===")
    print(f"{'attack type':<16}{'TP':>7}{'FP':>7}{'FN':>7}{'prec':>9}{'recall':>9}{'F1':>9}")
    macro = []
    for cat in ATTACK_CATEGORIES:
        c = counts[cat]
        p, r, f1 = prf(c["tp"], c["fp"], c["fn"])
        macro.append((p, r, f1))
        print(f"{cat:<16}{c['tp']:>7}{c['fp']:>7}{c['fn']:>7}"
              f"{p:>9.3f}{r:>9.3f}{f1:>9.3f}")
    mp = sum(x[0] for x in macro) / len(macro)
    mr = sum(x[1] for x in macro) / len(macro)
    mf = sum(x[2] for x in macro) / len(macro)
    print(f"{'macro avg':<16}{'':>21}{mp:>9.3f}{mr:>9.3f}{mf:>9.3f}")

    # Overall malicious-vs-benign (any attack vs normal) at query level on mixed.
    tp = sum(counts[c]["tp"] for c in ATTACK_CATEGORIES)
    fp = sum(counts[c]["fp"] for c in ATTACK_CATEGORIES)
    fn = sum(counts[c]["fn"] for c in ATTACK_CATEGORIES)
    op, orr, of1 = prf(tp, fp, fn)
    print(f"\nOverall (attack vs normal): precision {op:.3f}  recall {orr:.3f}  F1 {of1:.3f}")

    print("\nMeasuring false-positive rate on normal.pcap ...")
    flagged, total = false_positive_rate(config, whitelist, normal)
    fpr = flagged / total if total else 0.0
    print(f"False positives on benign traffic: {flagged}/{total} queries = {fpr:.2%}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
