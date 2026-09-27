# SOC Detection Lab

Hands-on blue-team projects built and tuned to run entirely on a MacBook Air M1
(ARM64, 8 GB RAM) — no cloud, no enterprise licences, no lab budget.

Each project is a working pipeline rather than a tutorial walkthrough: real
detection content, real parsing code, measurable results, and honest notes on
what it does *not* catch.

---

## Projects

| # | Project | Stack | Status |
|---|---------|-------|--------|
| 1 | [Network IDS](./01-network-ids-suricata) | Suricata 7.x, Python | ✅ Complete |
| 2 | Log Analytics & Sigma Detection | OpenSearch, Sigma, Python | 🔨 In progress |
| 3 | Threat Intel Fusion | MISP, PyMISP | 📋 Planned |
| 4 | Endpoint Monitoring | osquery, Fleet | 📋 Planned |
| 5 | Incident Response Automation | TheHive, Cortex | 📋 Planned |
| 6 | Honeypot Analysis | Cowrie, Sigma | 📋 Planned |

---

## 1 — Network IDS with Suricata

A network intrusion detection pipeline that turns Suricata's raw alert firehose
into a triage queue an analyst can actually work.

**The problem it solves:** `eve.json` is newline-delimited JSON where alerts are
only ~20% of lines, and the loudest signatures are usually the least important
ones. Sorting by volume buries severity-1 detections under informational noise.

**What's in it:**
- 10 custom Suricata rules mapped to MITRE ATT&CK (T1110, T1190, T1048, T1071, T1568)
- A stdlib-only Python parser: filters, flattens nested JSON, ranks, and exits
  non-zero on severity-1 so it can gate a CI pipeline
- `suricata.yaml` tuned for 8 GB — 400–600 MB steady-state RSS
- A from-scratch PCAP generator (stdlib only — no scapy) producing valid frames
  with correct checksums, so detection coverage is measured against labels I
  control rather than asserted
- A seeded synthetic EVE generator, so the pipeline is demonstrable with zero setup

```bash
cd 01-network-ids-suricata
bash scripts/demo.sh        # runs immediately — no Suricata install required
```

**Two details worth reading the code for:**

The brute-force rule uses `threshold ... track by_src`, keying the counter on the
attacker rather than the victim — key it the other way and one noisy scanner
suppresses the rule for every other host.

SID 1000010 is a canary that fires on a benign request to `testmynids.org`. If it
stops firing, the sensor is dead. Without a canary, a broken pipeline and a quiet
network produce identical dashboards.

[→ Full README](./01-network-ids-suricata/README.md) ·
[Metrics methodology](./01-network-ids-suricata/docs/METRICS.md)

---

## Design principles across all projects

**Measurable, not asserted.** Every project ships a `METRICS.md` with the commands
that produce its numbers. Detection rate is computed against ground-truth-labelled
corpora (CTU-13, malware-traffic-analysis.net) — not against traffic where the
answer is unknown.

**Honest about limits.** Suricata cannot see inside TLS. Most modern C2 is
encrypted. Each project documents its blind spot and which other project covers it.

**Runs on a laptop.** Memory caps, disabled parsers, and bounded reassembly depth
are chosen deliberately and documented with the reasoning, not copied from a
default config.

**Safe to publish.** All synthetic data uses RFC 5737 documentation IP ranges.
No real capture data, credentials, or network topology is committed.

---

## Running anything here

Requires Python 3.9+. Project 1 has no third-party Python dependencies.

```bash
git clone https://github.com/<your-username>/soc-lab.git
cd soc-lab/01-network-ids-suricata
bash scripts/demo.sh
```

---

## Licence

MIT — see [LICENSE](./LICENSE).
