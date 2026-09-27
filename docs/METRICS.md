# Metrics — Project 1

Measure the thing, don't assert it. Every number below has a command that produces it.

## 1. Detection rate

Needs a labelled dataset — you cannot compute this on your own network traffic,
because you don't know what was actually malicious. Use CTU-13 or a
malware-traffic-analysis.net capture with a published write-up.

```bash
bash scripts/run_suricata.sh -r data/labelled.pcap
python3 scripts/parse_alerts.py -i logs/eve.json -o out/alerts.csv -q
# detected: unique malicious IPs the ruleset flagged
cut -d, -f8 out/alerts.csv | tail -n +2 | sort -u > out/flagged_ips.txt
comm -12 out/flagged_ips.txt data/ground_truth_ips.txt | wc -l
```

`detection_rate = flagged ∩ ground_truth / ground_truth`

Report it per attack class, not as one number. "84% overall" hides that you catch
every port scan and miss every encrypted C2 channel — and the second half is what
matters.

## 2. False positive rate

Run against a capture you believe is clean (your own browsing for an hour). Every
alert is, by definition, a false positive.

```bash
sudo tcpdump -i en0 -w data/benign.pcap -G 3600 -W 1
bash scripts/run_suricata.sh -r data/benign.pcap
python3 scripts/parse_alerts.py -i logs/eve.json -o out/fp.csv -q
echo "FPs/hour: $(($(wc -l < out/fp.csv) - 1))"
cut -d, -f4 out/fp.csv | tail -n +2 | sort | uniq -c | sort -rn | head
```

The `uniq -c` line is the useful one: it names which rule to tune. In practice two
or three signatures produce most of the noise. Threshold or disable those and the
rate drops by an order of magnitude without touching detection coverage.

**Alert fatigue is the real failure mode.** A sensor producing 400 alerts/hour gets
ignored, and an ignored sensor has a detection rate of zero regardless of what the
lab numbers say.

## 3. Throughput

```bash
SECONDS=0
suricata -c config/suricata.yaml -S rules/local.rules -r data/large.pcap -l logs/
echo "elapsed: ${SECONDS}s for $(du -m data/large.pcap | cut -f1) MB"
```

`throughput_mbps = (pcap_size_MB * 8) / elapsed_s`

Offline PCAP throughput is an upper bound — live capture adds kernel copy overhead.
The number that matters for live capture is drops, not speed:

```bash
grep -E 'kernel_(packets|drops)' logs/stats.log | tail -4
```

Any non-zero `kernel_drops` means you are blind to some traffic. Fix it by raising
`pcap.buffer-size` or cutting rule count — not by ignoring it.

## 4. Resource usage

```bash
/usr/bin/time -l suricata -c config/suricata.yaml -S rules/local.rules \
  -r data/output.pcap -l logs/ 2>&1 | grep -E 'maximum resident|real'
```

Target on an 8 GB machine: peak RSS under 1 GB. This config measures 400–600 MB
steady state. If you exceed 1 GB, the cause is almost always `detect.profile: high`
or an unbounded `stream.memcap`.

## 5. MTTR proxy

End-to-end wall clock from packet-on-wire to a row in the triage queue:

```bash
time (bash scripts/run_suricata.sh -r data/output.pcap && \
      python3 scripts/parse_alerts.py -i logs/eve.json -o out/alerts.csv -q)
```

This is the honest version of "mean time to respond" for a project this size. Real
MTTR includes a human, and you don't have one. Say so rather than inflating it.

## 6. Parser correctness

The synthetic generator is seeded, so ground truth is known exactly:

```bash
python3 scripts/gen_sample_eve.py -o /tmp/t.json -n 120 --seed 1337
python3 scripts/parse_alerts.py -i /tmp/t.json -o /tmp/t.csv -q
test $(($(wc -l < /tmp/t.csv) - 1)) -eq 120 && echo PASS || echo FAIL
```

| Check | Expected | Status |
|---|---|---|
| Alerts extracted from 600 events | 120 | PASS |
| Non-alert events skipped | 480 | PASS |
| Malformed lines survived | no crash | PASS |
| Missing input file | exit 2 | PASS |
| `--fail-severity 1` with sev-1 present | exit 1 | PASS |
| `--min-severity 1` filter | 49 of 120 | PASS |

## Recording results

Keep a table in the README with dataset, date and version — a metric without the
dataset it was measured on is not a metric.

| Dataset | Alerts | Detection rate | FP/hr | Peak RSS | Throughput |
|---|---|---|---|---|---|
| synthetic (seed 1337) | 120 | n/a | n/a | — | — |
| _your capture here_ | | | | | |
