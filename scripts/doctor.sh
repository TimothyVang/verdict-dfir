#!/usr/bin/env bash
# scripts/doctor.sh — environment preflight for the Find Evil! agent.
#
# Turns the silent, mid-investigation `BinaryNotFound -32602` surprise into a
# five-second up-front checklist. Reports, for a stock Linux / SIFT Workstation:
#
#   REQUIRED   — without these no investigation can run at all
#                (claude CLI, cargo/rustc, uv).
#   DFIR tools — the external binaries the Rust MCP server shells out to.
#                Resolved the SAME way the server resolves them ($VOLATILITY_BIN
#                then vol/vol.py/volatility3, $HAYABUSA_BIN then hayabusa, etc.).
#                Missing ones degrade gracefully: the in-process tools (case_open,
#                evtx_query, mft_timeline, prefetch_parse, sysmon_network_query —
#                linked evtx=0.11.2) still run, and a missing binary surfaces as a
#                clean BinaryNotFound the agent can pivot on.
#   Reporting  — pandoc + a Chrome/Chromium for PDF/HTML report rendering.
#   Recording  — ffmpeg (+ Playwright/Chrome) for scripts/record-demo.sh.
#
# Read-only: this script inspects PATH and prints install commands. It never
# installs, builds, or mutates anything. Exit code is 0 only when every REQUIRED
# tool is present; missing DFIR/reporting/recording tools warn but do not fail.

set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO}"

# cargo is commonly installed under ~/.cargo/bin but absent from a fresh shell's
# PATH (the rust MCP wrapper sources this too — scripts/run-mcp-rust.sh).
[ -f "${HOME}/.cargo/env" ] && source "${HOME}/.cargo/env"

c_red=$'\033[0;31m'
c_grn=$'\033[0;32m'
c_yel=$'\033[0;33m'
c_blu=$'\033[0;34m'
c_dim=$'\033[2m'
c_off=$'\033[0m'

missing_required=0
declare -a REMEDIES=()

# row STATUS LABEL DETAIL — print one aligned status line.
row() {
  local status="$1" label="$2" detail="${3:-}"
  local tag
  case "${status}" in
    ok)   tag="${c_grn}[ ok ]${c_off}" ;;
    warn) tag="${c_yel}[warn]${c_off}" ;;
    err)  tag="${c_red}[ -- ]${c_off}" ;;
  esac
  printf "  %b  %-16s ${c_dim}%s${c_off}\n" "${tag}" "${label}" "${detail}"
}

# resolve_bin VAR_NAME CANDIDATE... — echo the first usable binary.
# Honors the $<VAR_NAME> override first (matching the Rust server), then walks
# the candidate names on PATH. Echoes nothing and returns 1 if none resolve.
resolve_bin() {
  local var_name="$1"; shift
  local override="${!var_name:-}"
  if [ -n "${override}" ] && [ -x "${override}" ]; then
    echo "${override}"; return 0
  fi
  local cand
  for cand in "$@"; do
    if command -v "${cand}" >/dev/null 2>&1; then
      command -v "${cand}"; return 0
    fi
  done
  return 1
}

# require LABEL REMEDY COMMAND... — a REQUIRED check; failure blocks a run.
require() {
  local label="$1" remedy="$2"; shift 2
  if command -v "$1" >/dev/null 2>&1; then
    row ok "${label}" "$("$@" 2>&1 | head -1)"
  else
    row err "${label}" "not on PATH"
    REMEDIES+=("${label}: ${remedy}")
    missing_required=$((missing_required + 1))
  fi
}

# dfir LABEL VAR_NAME REMEDY -- CANDIDATE... — a DFIR-binary check (warn-only).
dfir() {
  local label="$1" var_name="$2" remedy="$3"; shift 3
  [ "$1" = "--" ] && shift
  local found
  if found="$(resolve_bin "${var_name}" "$@")"; then
    row ok "${label}" "${found}"
  else
    row warn "${label}" "absent — tools using it return BinaryNotFound (in-process tools unaffected)"
    REMEDIES+=("${label}: ${remedy}")
  fi
}

# optional LABEL REMEDY COMMAND... — reporting/recording check (warn-only).
optional() {
  local label="$1" remedy="$2"; shift 2
  if command -v "$1" >/dev/null 2>&1; then
    row ok "${label}" "$("$@" 2>&1 | head -1)"
  else
    row warn "${label}" "absent"
    REMEDIES+=("${label}: ${remedy}")
  fi
}

echo "=========================================="
echo "Find Evil! — environment doctor"
echo "=========================================="

# ---------------------------------------------------------------------------
# Claude credential mode (mirrors scripts/install.sh §1).
# ---------------------------------------------------------------------------
echo
echo "${c_blu}Claude credential${c_off}"
if [ -n "${CLAUDE_CODE_OAUTH_TOKEN:-}" ] && command -v claude >/dev/null 2>&1; then
  row ok "credential" "mode 1: CLAUDE_CODE_OAUTH_TOKEN + claude CLI"
elif command -v claude >/dev/null 2>&1 && [ -d "${HOME}/.claude" ]; then
  row ok "credential" "mode 2: interactive ~/.claude session"
elif [ -n "${ANTHROPIC_API_KEY:-}" ]; then
  row ok "credential" "mode 3: ANTHROPIC_API_KEY"
else
  row err "credential" "none of the 3 modes detected"
  REMEDIES+=("credential: run 'claude setup-token', or 'claude auth login', or export ANTHROPIC_API_KEY")
  missing_required=$((missing_required + 1))
fi

# ---------------------------------------------------------------------------
# Required toolchain.
# ---------------------------------------------------------------------------
echo
echo "${c_blu}Required toolchain${c_off}"
require "python3" "install Python 3.11+ from https://www.python.org/downloads/ or via your OS package manager" \
        python3 --version
require "git"     "install git from https://git-scm.com/downloads" \
        git --version
require "unzip"   "install unzip: apt install unzip / brew install unzip / choco install unzip" \
        unzip -v
require "claude"  "npm install -g @anthropic-ai/claude-code  (https://docs.anthropic.com/en/docs/claude-code/install)" \
        claude --version
require "cargo"   "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh" \
        cargo --version
require "uv"      "curl -LsSf https://astral.sh/uv/install.sh | sh" \
        uv --version

# Is the Rust MCP server already built? (a run needs the binary, not cargo per se)
if [ -x "target/release/findevil-mcp" ] || [ -x "target/release/findevil-mcp.exe" ]; then
  row ok "findevil-mcp" "target/release/findevil-mcp (built)"
else
  row warn "findevil-mcp" "not built — run: bash scripts/install.sh  (or cargo build --release -p findevil-mcp)"
  REMEDIES+=("findevil-mcp: bash scripts/install.sh   # builds the Rust MCP server")
fi

# ---------------------------------------------------------------------------
# DFIR external binaries (warn-only; the in-process tools work without them).
# ---------------------------------------------------------------------------
echo
echo "${c_blu}DFIR tools${c_off} ${c_dim}(external subprocess binaries; in-process EVTX/MFT/prefetch run without them)${c_off}"
dfir "volatility3"  VOLATILITY_BIN  "pipx install volatility3   (or: uv tool install volatility3)" \
     -- vol vol.py volatility3 volatility
dfir "hayabusa"     HAYABUSA_BIN    "download a release from https://github.com/Yamato-Security/hayabusa/releases onto PATH (or set \$HAYABUSA_BIN)" \
     -- hayabusa
dfir "velociraptor" VELOCIRAPTOR_BIN "download from https://github.com/Velocidex/velociraptor/releases (or set \$VELOCIRAPTOR_BIN)" \
     -- velociraptor
dfir "tshark/zeek"  TSHARK_BIN      "sudo apt-get install -y tshark   (pcap_triage; or set \$TSHARK_BIN/\$ZEEK_BIN)" \
     -- tshark zeek

# ---------------------------------------------------------------------------
# Reporting + demo-recording helpers (warn-only).
# ---------------------------------------------------------------------------
echo
echo "${c_blu}Reporting${c_off}"
optional "pandoc"  "sudo apt-get install -y pandoc" pandoc --version
if found_chrome="$(resolve_bin CHROME_BIN google-chrome google-chrome-stable chromium chromium-browser)"; then
  row ok "chrome" "${found_chrome}"
else
  row warn "chrome" "absent — needed for PDF/HTML report render"
  REMEDIES+=("chrome: sudo apt-get install -y chromium-browser   (or install Google Chrome)")
fi

echo
echo "${c_blu}Demo recording${c_off} ${c_dim}(for scripts/record-demo.sh)${c_off}"
optional "ffmpeg"  "sudo apt-get install -y ffmpeg" ffmpeg -version
if (cd apps/web 2>/dev/null && npx --no-install playwright --version >/dev/null 2>&1); then
  row ok "playwright" "$(cd apps/web && npx --no-install playwright --version 2>/dev/null)"
else
  row warn "playwright" "absent — install in apps/web: pnpm --filter @findevil/web exec playwright install chromium"
  REMEDIES+=("playwright: (cd apps/web && npx playwright install chromium)")
fi

# ---------------------------------------------------------------------------
# Verdict.
# ---------------------------------------------------------------------------
echo
echo "=========================================="
if [ "${#REMEDIES[@]}" -gt 0 ]; then
  echo "${c_yel}To install what's missing:${c_off}"
  for r in "${REMEDIES[@]}"; do
    echo "  - ${r}"
  done
  echo
fi

if [ "${missing_required}" -eq 0 ]; then
  echo "${c_grn}READY${c_off} — all required tools present. EVTX investigations run fully in-process;"
  echo "any missing DFIR binary above just surfaces as a clean BinaryNotFound the agent pivots on."
  echo "=========================================="
  exit 0
else
  echo "${c_red}NOT READY${c_off} — ${missing_required} required tool(s) missing (see remedies above)."
  echo "=========================================="
  exit 1
fi
