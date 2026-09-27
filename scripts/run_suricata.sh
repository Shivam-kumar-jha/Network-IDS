#!/usr/bin/env bash
# run_suricata.sh — run Suricata against a PCAP (offline) or a live interface.
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BREW_PREFIX="$(brew --prefix 2>/dev/null || echo /opt/homebrew)"

PCAP="${PROJECT_ROOT}/data/output.pcap"
IFACE=""
LOG_DIR="${PROJECT_ROOT}/logs"
CONFIG="${PROJECT_ROOT}/config/suricata.yaml"
RULES="${PROJECT_ROOT}/rules/local.rules"
RUNMODE="autofp"
THREADS=2   # M1 Air has 8 cores but only 8 GB RAM; 2 detect threads is plenty offline.

usage() {
  cat <<EOF
Usage: $(basename "$0") [options]

  -r, --pcap PATH     read a PCAP offline (default: data/output.pcap)
  -i, --iface NAME    sniff a live interface instead (requires sudo)
  -l, --logdir PATH   where eve.json lands (default: logs/)
  -c, --config PATH   suricata.yaml to use
  -S, --rules PATH    rule file to load
  -t, --threads N     detect threads (default: ${THREADS}; lower = less RAM)
  -h, --help

Offline PCAP mode needs no root and is the right default on a laptop.
Live capture needs sudo and a real interface — find yours with:
    route get default | awk '/interface:/{print \$2}'
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -r|--pcap)   PCAP="$2"; shift 2 ;;
    -i|--iface)  IFACE="$2"; shift 2 ;;
    -l|--logdir) LOG_DIR="$2"; shift 2 ;;
    -c|--config) CONFIG="$2"; shift 2 ;;
    -S|--rules)  RULES="$2"; shift 2 ;;
    -t|--threads) THREADS="$2"; shift 2 ;;
    -h|--help)   usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage; exit 1 ;;
  esac
done

command -v suricata >/dev/null 2>&1 || { echo "[x] suricata not on PATH — run scripts/setup.sh" >&2; exit 1; }
mkdir -p "$LOG_DIR"

# Start clean so alert counts reflect this run only.
rm -f "${LOG_DIR}/eve.json" "${LOG_DIR}/fast.log" "${LOG_DIR}/stats.log"

# -k none disables checksum validation. macOS NICs offload checksums, so
# without this Suricata silently drops traffic you can read fine in Wireshark.
COMMON=(-c "$CONFIG" -S "$RULES" -l "$LOG_DIR" -k none
        --set "threading.detect-thread-ratio=${THREADS}"
        --set "app-layer.protocols.modbus.enabled=no")

if [[ -n "$IFACE" ]]; then
  echo "[*] LIVE capture on ${IFACE} — Ctrl-C to stop."
  sudo suricata "${COMMON[@]}" -i "$IFACE" --runmode "$RUNMODE"
else
  [[ -f "$PCAP" ]] || { echo "[x] no PCAP at ${PCAP}" >&2
                        echo "    Grab one from https://www.malware-traffic-analysis.net/ or use scripts/demo.sh" >&2
                        exit 1; }
  echo "[*] Offline analysis of ${PCAP}"
  SECONDS=0
  suricata "${COMMON[@]}" -r "$PCAP"
  echo "[+] Finished in ${SECONDS}s"
fi

if [[ -f "${LOG_DIR}/eve.json" ]]; then
  echo "[+] eve.json: $(wc -l < "${LOG_DIR}/eve.json" | tr -d ' ') events, $(du -h "${LOG_DIR}/eve.json" | cut -f1)"
  echo "[*] Next: python3 scripts/parse_alerts.py -i ${LOG_DIR}/eve.json -o out/alerts.csv"
else
  echo "[!] No eve.json produced — check outputs.eve-log is enabled in ${CONFIG}"
fi
