#!/usr/bin/env python3
"""
score_detection.py — compare what actually fired against what should have fired.

This is the script that makes the detection-rate number in the README real. It
reads the ground truth emitted by gen_test_pcap.py and the SIDs present in
Suricata's eve.json, then reports coverage, misses and unexpected hits.

A miss here is a rule that is broken — wrong buffer, wrong direction, wrong
protocol. Finding those before an interview is considerably better than finding
them during one.

    python3 score_detection.py --truth ../data/ground_truth.csv -i ../logs/eve.json
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter


def load_truth(path: str) -> dict[int, str]:
    truth = {}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            sid, _, desc = line.partition(",")
            truth[int(sid)] = desc
    return truth


def load_fired(path: str) -> Counter:
    fired: Counter = Counter()
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            if ev.get("event_type") == "alert":
                sid = ev.get("alert", {}).get("signature_id")
                if sid is not None:
                    fired[int(sid)] += 1
    return fired


def main() -> int:
    p = argparse.ArgumentParser(description="Score detections against ground truth.")
    p.add_argument("--truth", default="../data/ground_truth.csv")
    p.add_argument("-i", "--input", default="../logs/eve.json")
    args = p.parse_args()

    try:
        truth = load_truth(args.truth)
        fired = load_fired(args.input)
    except FileNotFoundError as e:
        print(f"[!] {e}", file=sys.stderr)
        print("    Generate the PCAP and run Suricata first.", file=sys.stderr)
        return 2

    expected = set(truth)
    got = set(fired)
    hits = expected & got
    misses = expected - got
    extra = got - expected

    print("=" * 66)
    print("  DETECTION COVERAGE vs GROUND TRUTH")
    print("=" * 66)

    for sid in sorted(expected):
        mark = "PASS" if sid in got else "MISS"
        count = fired.get(sid, 0)
        print(f"  [{mark}]  SID {sid}  x{count:<3}  {truth[sid]}")

    if extra:
        print("\n  Alerts not in ground truth (ET ruleset, or a rule firing wider")
        print("  than intended — check whether these are false positives):")
        for sid in sorted(extra):
            print(f"         SID {sid}  x{fired[sid]}")

    rate = (len(hits) / len(expected) * 100) if expected else 0.0
    print("\n" + "-" * 66)
    print(f"  Rules expected : {len(expected)}")
    print(f"  Rules fired    : {len(hits)}")
    print(f"  Coverage       : {rate:.1f}%")
    print(f"  Total alerts   : {sum(fired.values())}")

    if misses:
        print("\n  MISSED — these rules did not fire and need debugging:")
        for sid in sorted(misses):
            print(f"      SID {sid}  {truth[sid]}")
        print("\n  Debug a miss with:")
        print("      suricata -c config/suricata.yaml -S rules/local.rules \\")
        print("               -r data/output.pcap -l logs/ -k none -v")
        print("  Common causes: wrong sticky buffer, wrong flow direction,")
        print("  HOME_NET not matching the test addresses, or app-layer parser off.")
        return 1

    print("\n  All expected rules fired.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
