#!/usr/bin/env python3
"""
parse_alerts.py — turn Suricata's eve.json into something an analyst can triage.

Reads EVE JSON (newline-delimited), extracts alert events, and emits:
  * a flat CSV of alerts (one row per alert)
  * a triage summary (top signatures, top talkers, severity breakdown)
  * optionally a JSON summary for downstream tooling

Exit codes:
  0  parsed cleanly, nothing at or above --fail-severity
  1  alerts found at or above --fail-severity (useful for pipeline gating)
  2  input problem (missing file, zero parseable lines)

Suricata severity: 1 = most severe, 3 = least. We keep Suricata's convention
and label it for humans rather than silently inverting it.

Usage:
    python3 parse_alerts.py -i ../logs/eve.json -o ../out/alerts.csv
    python3 parse_alerts.py -i ../logs/eve.json --json ../out/summary.json --top 15
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from collections import Counter
from datetime import datetime
from typing import Any, Iterator

SEVERITY_LABEL = {1: "high", 2: "medium", 3: "low"}

CSV_FIELDS = [
    "timestamp",
    "severity",
    "severity_label",
    "signature",
    "sid",
    "category",
    "proto",
    "src_ip",
    "src_port",
    "dest_ip",
    "dest_port",
    "app_proto",
    "http_hostname",
    "http_url",
    "dns_query",
    "tls_sni",
    "mitre_tactic",
    "mitre_technique",
    "flow_id",
]


def read_events(path: str) -> Iterator[tuple[int, dict[str, Any]]]:
    """Yield (line_no, event) for every parseable JSON line.

    eve.json is newline-delimited JSON. A truncated final line is normal if
    Suricata was killed mid-write, so we skip bad lines instead of dying.
    """
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line_no, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                yield line_no, json.loads(line)
            except json.JSONDecodeError:
                continue


def first_mitre(alert: dict[str, Any]) -> tuple[str, str]:
    """Pull MITRE ATT&CK tactic/technique out of rule metadata if the ruleset has it.

    Emerging Threats and many custom rules put this in metadata as
    'mitre_tactic_name' / 'mitre_technique_id'. Metadata values are lists.
    """
    meta = alert.get("metadata") or {}
    if not isinstance(meta, dict):
        return "", ""

    def grab(*keys: str) -> str:
        for k in keys:
            val = meta.get(k)
            if isinstance(val, list) and val:
                return str(val[0]).replace("_", " ")
            if isinstance(val, str) and val:
                return val.replace("_", " ")
        return ""

    return grab("mitre_tactic_name", "mitre_tactic"), grab(
        "mitre_technique_id", "mitre_technique_name", "mitre_technique"
    )


def flatten(event: dict[str, Any]) -> dict[str, Any]:
    """Flatten one Suricata alert event into a single CSV-ready row."""
    alert = event.get("alert", {}) or {}
    sev = alert.get("severity")
    try:
        sev = int(sev)
    except (TypeError, ValueError):
        sev = 0

    tactic, technique = first_mitre(alert)
    http = event.get("http") or {}
    dns = event.get("dns") or {}
    tls = event.get("tls") or {}

    # dns can be a dict (v2 schema) or carry the query under 'rrname'
    dns_query = dns.get("rrname") or ""
    if not dns_query and isinstance(dns.get("query"), list) and dns["query"]:
        dns_query = dns["query"][0].get("rrname", "")

    return {
        "timestamp": event.get("timestamp", ""),
        "severity": sev,
        "severity_label": SEVERITY_LABEL.get(sev, "unknown"),
        "signature": alert.get("signature", ""),
        "sid": alert.get("signature_id", ""),
        "category": alert.get("category", ""),
        "proto": event.get("proto", ""),
        "src_ip": event.get("src_ip", ""),
        "src_port": event.get("src_port", ""),
        "dest_ip": event.get("dest_ip", ""),
        "dest_port": event.get("dest_port", ""),
        "app_proto": event.get("app_proto", ""),
        "http_hostname": http.get("hostname", ""),
        "http_url": http.get("url", ""),
        "dns_query": dns_query,
        "tls_sni": tls.get("sni", ""),
        "mitre_tactic": tactic,
        "mitre_technique": technique,
        "flow_id": event.get("flow_id", ""),
    }


def build_summary(rows: list[dict[str, Any]], total_events: int, top: int) -> dict[str, Any]:
    sev_counts = Counter(r["severity_label"] for r in rows)
    sigs = Counter(r["signature"] for r in rows if r["signature"])
    src = Counter(r["src_ip"] for r in rows if r["src_ip"])
    dst = Counter(r["dest_ip"] for r in rows if r["dest_ip"])
    cats = Counter(r["category"] for r in rows if r["category"])
    pairs = Counter(
        f"{r['src_ip']} -> {r['dest_ip']}" for r in rows if r["src_ip"] and r["dest_ip"]
    )

    timestamps = sorted(t for t in (r["timestamp"] for r in rows) if t)

    return {
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "total_events_read": total_events,
        "total_alerts": len(rows),
        "unique_signatures": len(sigs),
        "unique_source_ips": len(src),
        "unique_dest_ips": len(dst),
        "first_alert": timestamps[0] if timestamps else None,
        "last_alert": timestamps[-1] if timestamps else None,
        "severity_breakdown": dict(sev_counts),
        "top_signatures": sigs.most_common(top),
        "top_categories": cats.most_common(top),
        "top_source_ips": src.most_common(top),
        "top_dest_ips": dst.most_common(top),
        "top_conversations": pairs.most_common(top),
    }


def bar(n: int, peak: int, width: int = 24) -> str:
    if peak <= 0:
        return ""
    return "#" * max(1, round(n / peak * width))


def print_summary(s: dict[str, Any]) -> None:
    def section(title: str, items: list, unit: str = "alerts") -> None:
        if not items:
            return
        print(f"\n{title}")
        print("-" * len(title))
        peak = items[0][1]
        for label, count in items:
            label = (label[:58] + "...") if len(str(label)) > 61 else label
            print(f"  {count:>5}  {bar(count, peak):<24}  {label}")

    print("=" * 72)
    print("  SURICATA ALERT TRIAGE SUMMARY")
    print("=" * 72)
    print(f"  Events read        : {s['total_events_read']}")
    print(f"  Alerts extracted   : {s['total_alerts']}")
    print(f"  Unique signatures  : {s['unique_signatures']}")
    print(f"  Unique src / dst   : {s['unique_source_ips']} / {s['unique_dest_ips']}")
    if s["first_alert"]:
        print(f"  Window             : {s['first_alert']}  ->  {s['last_alert']}")

    sev = s["severity_breakdown"]
    print("\n  Severity           : ", end="")
    print(
        "  ".join(
            f"{lab}={sev.get(lab, 0)}" for lab in ("high", "medium", "low", "unknown")
            if sev.get(lab)
        )
        or "none"
    )

    section("TOP SIGNATURES", s["top_signatures"])
    section("TOP CATEGORIES", s["top_categories"])
    section("TOP SOURCE IPs", s["top_source_ips"])
    section("TOP CONVERSATIONS", s["top_conversations"])
    print()


def main() -> int:
    p = argparse.ArgumentParser(
        description="Parse Suricata eve.json into a triage CSV plus a summary.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("-i", "--input", default="../logs/eve.json", help="path to eve.json")
    p.add_argument("-o", "--csv", default="../out/alerts.csv", help="CSV output path")
    p.add_argument("--json", dest="json_out", default=None, help="write JSON summary here")
    p.add_argument("--top", type=int, default=10, help="rows per summary table")
    p.add_argument(
        "--min-severity",
        type=int,
        default=3,
        choices=[1, 2, 3],
        help="keep alerts at this severity or worse (1=high)",
    )
    p.add_argument(
        "--fail-severity",
        type=int,
        default=0,
        help="exit 1 if any alert is at this severity or worse (0=never fail)",
    )
    p.add_argument("-q", "--quiet", action="store_true", help="suppress console summary")
    args = p.parse_args()

    if not os.path.isfile(args.input):
        print(f"[!] no such file: {args.input}", file=sys.stderr)
        print("    Run Suricata first, or use gen_sample_eve.py to make test data.", file=sys.stderr)
        return 2

    total = 0
    rows: list[dict[str, Any]] = []
    for _, event in read_events(args.input):
        total += 1
        if event.get("event_type") != "alert":
            continue
        row = flatten(event)
        if row["severity"] and row["severity"] > args.min_severity:
            continue
        rows.append(row)

    if total == 0:
        print(f"[!] {args.input} had no parseable JSON lines", file=sys.stderr)
        return 2

    rows.sort(key=lambda r: (r["severity"] or 99, r["timestamp"]))

    os.makedirs(os.path.dirname(os.path.abspath(args.csv)), exist_ok=True)
    with open(args.csv, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    summary = build_summary(rows, total, args.top)

    if args.json_out:
        os.makedirs(os.path.dirname(os.path.abspath(args.json_out)), exist_ok=True)
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump(summary, fh, indent=2)

    if not args.quiet:
        print_summary(summary)
    print(f"[+] {len(rows)} alerts -> {args.csv}")
    if args.json_out:
        print(f"[+] summary      -> {args.json_out}")

    if args.fail_severity:
        worst = min((r["severity"] for r in rows if r["severity"]), default=99)
        if worst <= args.fail_severity:
            print(f"[!] severity {worst} alert present (threshold {args.fail_severity})")
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
