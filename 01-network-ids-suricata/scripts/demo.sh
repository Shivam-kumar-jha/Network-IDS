#!/usr/bin/env bash
# demo.sh — end-to-end demo of the detection pipeline.
#
# Works in two modes, picked automatically:
#   LIVE      Suricata is installed and a PCAP exists -> real detection run
#   SYNTHETIC otherwise -> generated eve.json, same parser, same output
#
# Synthetic mode exists so you can demo this on a machine with nothing set up
# (an interview laptop, a fresh clone) and still show the triage output.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

C='\033[0;36m'; G='\033[0;32m'; Y='\033[0;33m'; N='\033[0m'
step() { printf "\n${C}==>${N} %s\n" "$*"; }
ok()   { printf "${G}[+]${N} %s\n" "$*"; }
note() { printf "${Y}[!]${N} %s\n" "$*"; }

MODE="synthetic"
if command -v suricata >/dev/null 2>&1; then
  MODE="live"
  # No capture yet? Build the ground-truth one so a real run is always possible.
  if [[ ! -f data/output.pcap ]]; then
    step "No PCAP found — generating ground-truth test capture"
    python3 scripts/gen_test_pcap.py -o data/output.pcap --truth data/ground_truth.csv
  fi
fi

step "Mode: ${MODE}"
[[ "$MODE" == "synthetic" ]] && note "No Suricata and/or no PCAP — generating representative EVE data."

mkdir -p logs out

if [[ "$MODE" == "live" ]]; then
  step "Running Suricata against data/output.pcap"
  bash scripts/run_suricata.sh -r data/output.pcap -l logs
else
  step "Generating synthetic eve.json (seed 1337 — reproducible)"
  python3 scripts/gen_sample_eve.py -o logs/eve.json -n 120
fi

if [[ "$MODE" == "live" && -f data/ground_truth.csv ]]; then
  step "Scoring detections against ground truth"
  python3 scripts/score_detection.py --truth data/ground_truth.csv -i logs/eve.json || true
fi

step "Parsing alerts and building triage summary"
python3 scripts/parse_alerts.py -i logs/eve.json -o out/alerts.csv --json out/summary.json --top 5

step "High-severity slice (severity 1 only)"
python3 scripts/parse_alerts.py -i logs/eve.json -o out/alerts_high.csv --min-severity 1 -q

step "Top 5 rows an analyst would open first"
if command -v column >/dev/null 2>&1; then
  { head -1 out/alerts_high.csv; sed -n '2,6p' out/alerts_high.csv; } \
    | cut -d, -f2,4,8,10 | column -s, -t
else
  { head -1 out/alerts_high.csv; sed -n '2,6p' out/alerts_high.csv; } | cut -d, -f2,4,8,10
fi

step "Artifacts"
ls -lh out/ | tail -n +2 | awk '{printf "    %-22s %s\n", $9, $5}'

printf "\n${G}Demo complete.${N}\n"
cat <<EOF

  out/alerts.csv       every alert, sorted worst-first
  out/alerts_high.csv  severity 1 only — the triage queue
  out/summary.json     machine-readable stats for the README / metrics

  Pipeline gating example (exit 1 when a sev-1 alert appears):
      python3 scripts/parse_alerts.py -i logs/eve.json -o out/a.csv --fail-severity 1 -q
EOF
