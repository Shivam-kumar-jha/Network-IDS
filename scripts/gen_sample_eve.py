#!/usr/bin/env python3
"""
gen_sample_eve.py — emit a realistic Suricata eve.json for testing the parser.

Why this exists: you should be able to prove the parsing/triage half of the
pipeline works before you have Suricata installed, a capture interface, or a
PCAP. It also gives you a fixed, known-content file to write unit tests and
metrics against (you know the ground truth, so you can measure the parser).

The schema matches Suricata 7.x EVE output: same field names, same nesting,
same severity convention (1 = most severe).

    python3 gen_sample_eve.py -o ../logs/eve.json -n 300
"""

from __future__ import annotations

import argparse
import json
import os
import random
from datetime import datetime, timedelta, timezone

# (signature, sid, category, severity, app_proto, mitre_tactic, mitre_technique)
SIGNATURES = [
    ("ET MALWARE Observed DNS Query to Known Sinkhole Domain", 2027865, "A Network Trojan was detected", 1, "dns", "command_and_control", "T1071"),
    ("ET EXPLOIT Possible Log4j RCE Attempt (jndi:ldap)", 2034647, "Attempted Administrator Privilege Gain", 1, "http", "initial_access", "T1190"),
    ("ET SCAN Potential SSH Brute Force Attack", 2001219, "Attempted Information Leak", 2, "ssh", "credential_access", "T1110"),
    ("ET POLICY Outbound Connection to Tor Node", 2522000, "Potentially Bad Traffic", 2, "tcp", "command_and_control", "T1090"),
    ("GPL SHELLCODE x86 NOOP Sled Detected", 2100648, "Executable Code was Detected", 1, "tcp", "execution", "T1203"),
    ("ET INFO Observed HTTP Request to Dynamic DNS Provider", 2027758, "Misc activity", 3, "http", "command_and_control", "T1568"),
    ("ET SCAN Nmap Scripting Engine User-Agent Detected", 2024364, "Web Application Attack", 2, "http", "reconnaissance", "T1595"),
    ("ET POLICY Cleartext Credentials Sent Over HTTP", 2012887, "Potential Corporate Privacy Violation", 2, "http", "credential_access", "T1040"),
    ("ET INFO Suspicious Empty User-Agent", 2013028, "Misc activity", 3, "http", "defense_evasion", "T1071"),
    ("ET TROJAN Cobalt Strike Beacon Observed", 2028700, "A Network Trojan was detected", 1, "http", "command_and_control", "T1071"),
]

# RFC 5737 / RFC 3849 documentation ranges - safe to publish, never routable.
INTERNAL = [f"192.0.2.{i}" for i in (10, 11, 12, 25, 40, 77)]
EXTERNAL = [f"198.51.100.{i}" for i in (5, 6, 44, 90, 200)] + [
    f"203.0.113.{i}" for i in (7, 33, 66, 120)
]

HOSTNAMES = [
    "cdn.example-update.net", "login-secure.example.org", "api.dyn-ddns.example",
    "tracking.example-ads.net", "files.example-share.io",
]
URLS = ["/api/v2/beacon", "/wp-login.php", "/index.php?id=1%27+OR+1%3D1", "/cgi-bin/status", "/download/payload.bin"]
DNS_NAMES = ["sinkhole.example-abuse.net", "c2.example-bad.org", "updates.example-cdn.net"]


def make_alert(ts: datetime, flow_id: int) -> dict:
    sig, sid, cat, sev, app, tactic, tech = random.choice(SIGNATURES)
    src = random.choice(INTERNAL)
    dst = random.choice(EXTERNAL)

    # Scans and brute force come from outside hitting in; flip the direction.
    if "SCAN" in sig or "Brute Force" in sig:
        src, dst = random.choice(EXTERNAL), random.choice(INTERNAL)

    event = {
        "timestamp": ts.isoformat(timespec="milliseconds"),
        "flow_id": flow_id,
        "in_iface": "en0",
        "event_type": "alert",
        "src_ip": src,
        "src_port": random.randint(1024, 65535),
        "dest_ip": dst,
        "dest_port": {"http": 80, "dns": 53, "ssh": 22, "tcp": 443}.get(app, 443),
        "proto": "UDP" if app == "dns" else "TCP",
        "app_proto": app,
        "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": sid,
            "rev": 3,
            "signature": sig,
            "category": cat,
            "severity": sev,
            "metadata": {
                "mitre_tactic_name": [tactic],
                "mitre_technique_id": [tech],
                "created_at": ["2021_12_10"],
            },
        },
        "flow": {
            "pkts_toserver": random.randint(2, 60),
            "pkts_toclient": random.randint(1, 40),
            "bytes_toserver": random.randint(200, 90000),
            "bytes_toclient": random.randint(100, 60000),
        },
    }

    if app == "http":
        event["http"] = {
            "hostname": random.choice(HOSTNAMES),
            "url": random.choice(URLS),
            "http_user_agent": random.choice(
                ["Mozilla/5.0", "curl/8.4.0", "", "Nmap Scripting Engine"]
            ),
            "http_method": random.choice(["GET", "POST"]),
            "status": random.choice([200, 302, 404, 500]),
        }
    elif app == "dns":
        event["dns"] = {"type": "query", "id": random.randint(1, 65535),
                        "rrname": random.choice(DNS_NAMES), "rrtype": "A"}
    elif app == "tcp" and random.random() < 0.5:
        event["tls"] = {"sni": random.choice(HOSTNAMES), "version": "TLS 1.2"}

    return event


def make_noise(ts: datetime, flow_id: int) -> dict:
    """Non-alert events. Real eve.json is mostly these; the parser must skip them."""
    kind = random.choice(["flow", "http", "dns", "stats"])
    base = {
        "timestamp": ts.isoformat(timespec="milliseconds"),
        "flow_id": flow_id,
        "event_type": kind,
        "src_ip": random.choice(INTERNAL),
        "dest_ip": random.choice(EXTERNAL),
        "proto": "TCP",
    }
    if kind == "stats":
        return {"timestamp": base["timestamp"], "event_type": "stats",
                "stats": {"uptime": 120, "capture": {"kernel_packets": 98213, "kernel_drops": 4}}}
    return base


def main() -> int:
    p = argparse.ArgumentParser(description="Generate a synthetic Suricata eve.json.")
    p.add_argument("-o", "--output", default="../logs/eve.json")
    p.add_argument("-n", "--alerts", type=int, default=120, help="number of alert events")
    p.add_argument("--noise-ratio", type=float, default=4.0,
                   help="non-alert events per alert (real captures are noisy)")
    p.add_argument("--minutes", type=int, default=60, help="spread events over N minutes")
    p.add_argument("--seed", type=int, default=1337, help="fixed seed = reproducible test data")
    args = p.parse_args()

    random.seed(args.seed)
    start = datetime.now(timezone.utc) - timedelta(minutes=args.minutes)

    events = []
    for i in range(args.alerts):
        events.append(make_alert(start + timedelta(seconds=random.randint(0, args.minutes * 60)), 1000 + i))
    for i in range(int(args.alerts * args.noise_ratio)):
        events.append(make_noise(start + timedelta(seconds=random.randint(0, args.minutes * 60)), 5000 + i))

    events.sort(key=lambda e: e["timestamp"])

    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as fh:
        for e in events:
            fh.write(json.dumps(e) + "\n")

    print(f"[+] wrote {len(events)} events ({args.alerts} alerts) -> {args.output}")
    print(f"[+] seed={args.seed} — rerun with the same seed for identical data")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
