#!/usr/bin/env bash
# setup.sh — install and verify Suricata on macOS (Apple Silicon).
# Idempotent: safe to re-run.
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Apple Silicon Homebrew lives under /opt/homebrew; Intel under /usr/local.
BREW_PREFIX="$(brew --prefix 2>/dev/null || echo /opt/homebrew)"

info() { printf '\033[0;36m[*]\033[0m %s\n' "$*"; }
ok()   { printf '\033[0;32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[0;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\033[0;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

command -v brew >/dev/null 2>&1 || die "Homebrew not found. https://brew.sh"

info "Architecture: $(uname -m)   Homebrew prefix: ${BREW_PREFIX}"
[[ "$(uname -m)" == "arm64" ]] || warn "Not arm64 — paths below assume Apple Silicon."

if command -v suricata >/dev/null 2>&1; then
  ok "Suricata already installed: $(suricata -V 2>&1 | head -1)"
else
  info "Installing Suricata via Homebrew (this pulls a bottle, no Rust build needed)..."
  brew install suricata
  ok "Installed: $(suricata -V 2>&1 | head -1)"
fi

# tcpreplay lets us replay a PCAP onto a live interface for realistic testing.
if ! command -v tcpreplay >/dev/null 2>&1; then
  info "Installing tcpreplay (for PCAP replay demos)..."
  brew install tcpreplay || warn "tcpreplay install failed — offline PCAP mode still works."
fi

info "Fetching Emerging Threats Open ruleset..."
sudo suricata-update || warn "suricata-update failed; continuing with local.rules only."

# Wire our custom rules in alongside the ET set.
RULES_DIR="${BREW_PREFIX}/var/lib/suricata/rules"
if [[ -d "$RULES_DIR" ]]; then
  sudo cp "${PROJECT_ROOT}/rules/local.rules" "${RULES_DIR}/local.rules"
  ok "Copied local.rules -> ${RULES_DIR}/local.rules"
else
  warn "Rules dir not found at ${RULES_DIR}; local.rules stays in-project."
fi

info "Validating configuration and rule syntax (suricata -T)..."
if suricata -T -c "${PROJECT_ROOT}/config/suricata.yaml" -S "${PROJECT_ROOT}/rules/local.rules" 2>&1 | tail -5; then
  ok "Config and rules validated."
else
  die "Validation failed — fix the errors above before running."
fi

cat <<EOF

$(ok "Setup complete.")

  Default capture interface : $(route get default 2>/dev/null | awk '/interface:/{print $2}' || echo en0)
  Suricata binary           : $(command -v suricata)
  Config in use             : ${PROJECT_ROOT}/config/suricata.yaml

  Next:  bash scripts/demo.sh          # full offline demo, no root needed
         bash scripts/run_suricata.sh --help
EOF
