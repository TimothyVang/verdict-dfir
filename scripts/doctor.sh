#!/usr/bin/env bash
# scripts/doctor.sh — environment preflight for the Find Evil! agent.
#
# Turns the silent, mid-investigation `BinaryNotFound -32602` surprise into a
# five-second up-front checklist. Reports, for a stock Linux / SIFT Workstation:
#
#   REQUIRED   — without these no investigation can run at all
#                (claude CLI except for explicit on-prem providers, cargo/rustc, uv).
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

# --json emits a machine-readable report (consumed by /api/doctor + /setup) and
# suppresses the human output. Without it, behaviour is unchanged.
JSON_MODE=""
for _arg in "$@"; do [ "${_arg}" = "--json" ] && JSON_MODE=1; done
declare -a JSON_ROWS=()
GROUP="general"

json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  printf '%s' "${s}"
}

missing_required=0
declare -a REMEDIES=()

# row STATUS LABEL DETAIL — print one aligned status line.
row() {
  local status="$1" label="$2" detail="${3:-}"
  if [ -n "${JSON_MODE}" ]; then
    JSON_ROWS+=("{\"group\":\"$(json_escape "${GROUP}")\",\"label\":\"$(json_escape "${label}")\",\"status\":\"${status}\",\"detail\":\"$(json_escape "${detail}")\"}")
    return
  fi
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

claude_credentials_support_inference() {
  python3 - "${HOME}/.claude/.credentials.json" <<'PY' >/dev/null 2>&1
import json
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as handle:
        oauth = json.load(handle).get("claudeAiOauth", {})
except (OSError, AttributeError, json.JSONDecodeError):
    raise SystemExit(1)

token = oauth.get("accessToken")
scopes = oauth.get("scopes", [])
raise SystemExit(0 if token and "user:inference" in scopes else 1)
PY
}

if [[ -v FINDEVIL_DOCTOR_AGENT_PROVIDER ]]; then
  DOCTOR_AGENT_PROVIDER="${FINDEVIL_DOCTOR_AGENT_PROVIDER}"
else
  DOCTOR_AGENT_PROVIDER="claude_cli"
fi
PROVIDER_VALID=1
case "${DOCTOR_AGENT_PROVIDER}" in
  deterministic|anthropic|claude_cli|openai|openrouter|local|dgx) ;;
  *) PROVIDER_VALID=0 ;;
esac

if [ -z "${JSON_MODE}" ]; then
  echo "=========================================="
  echo "Find Evil! — environment doctor"
  echo "=========================================="
fi

GROUP="Agent provider"
if [[ "${PROVIDER_VALID}" == "1" ]]; then
  row ok "agent provider" "${DOCTOR_AGENT_PROVIDER}"
else
  row err "agent provider" "unsupported provider: ${DOCTOR_AGENT_PROVIDER:-<empty>}"
  REMEDIES+=("agent provider: use deterministic, anthropic, claude_cli, openai, openrouter, local, or dgx")
  missing_required=$((missing_required + 1))
fi

# ---------------------------------------------------------------------------
# Claude credential mode (mirrors scripts/install.sh §1). The canonical launcher
# sets FINDEVIL_DOCTOR_AGENT_PROVIDER for execution paths that do not use Claude.
# ---------------------------------------------------------------------------
GROUP="Claude credential"
[ -z "${JSON_MODE}" ] && { echo; echo "${c_blu}Claude credential${c_off}"; }
case "${DOCTOR_AGENT_PROVIDER}" in
  deterministic|local|dgx|openai|openrouter)
    row ok "credential" "skipped: not required for ${DOCTOR_AGENT_PROVIDER} execution"
    ;;
  anthropic)
    if [ -n "${ANTHROPIC_API_KEY:-}" ]; then
      row ok "credential" "ANTHROPIC_API_KEY"
    elif claude_credentials_support_inference; then
      row ok "credential" "supported ~/.claude/.credentials.json"
    else
      row err "credential" "direct anthropic needs ANTHROPIC_API_KEY or supported ~/.claude/.credentials.json"
      REMEDIES+=("credential: export ANTHROPIC_API_KEY or log in to Claude Code to create a user:inference credential")
      missing_required=$((missing_required + 1))
    fi
    ;;
  claude_cli)
    if [ -n "${CLAUDE_CODE_OAUTH_TOKEN:-}" ]; then
      row ok "credential" "CLAUDE_CODE_OAUTH_TOKEN"
    elif [ -n "${ANTHROPIC_API_KEY:-}" ]; then
      row ok "credential" "ANTHROPIC_API_KEY"
    elif claude_credentials_support_inference; then
      row ok "credential" "supported ~/.claude/.credentials.json"
    else
      row err "credential" "claude_cli needs supported Claude authentication"
      REMEDIES+=("credential: run 'claude setup-token', 'claude auth login', or export ANTHROPIC_API_KEY")
      missing_required=$((missing_required + 1))
    fi
    ;;
  *)
    row err "credential" "blocked by unsupported agent provider"
    ;;
esac

# ---------------------------------------------------------------------------
# Required toolchain.
# ---------------------------------------------------------------------------
GROUP="Required toolchain"
[ -z "${JSON_MODE}" ] && { echo; echo "${c_blu}Required toolchain${c_off}"; }
require "python3" "install Python 3.11+ from https://www.python.org/downloads/ or via your OS package manager" \
        python3 --version
require "git"     "install git from https://git-scm.com/downloads" \
        git --version
require "unzip"   "install unzip: apt install unzip / brew install unzip / choco install unzip" \
        unzip -v
if [ "${DOCTOR_AGENT_PROVIDER}" = "claude_cli" ]; then
  require "claude"  "npm install -g @anthropic-ai/claude-code  (https://docs.anthropic.com/en/docs/claude-code/install)" \
          claude --version
elif [ "${PROVIDER_VALID}" = "1" ]; then
  row ok "claude" "skipped: not required for ${DOCTOR_AGENT_PROVIDER} execution"
else
  row err "claude" "blocked by unsupported agent provider"
fi
require "cargo"   "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh" \
        cargo --version
require "uv"      "curl -LsSf https://astral.sh/uv/install.sh | sh" \
        uv --version

# ---------------------------------------------------------------------------
# MCP servers — the typed tool surface Claude Code auto-spawns from .mcp.json.
# These ARE the app: no servers, no investigation. Built by scripts/install.sh.
# ---------------------------------------------------------------------------
GROUP="MCP servers"
[ -z "${JSON_MODE}" ] && { echo; echo "${c_blu}MCP servers${c_off} ${c_dim}(auto-spawned by Claude Code from .mcp.json)${c_off}"; }

# findevil-mcp — Rust, 32 typed DFIR tools. Needs the release binary
# (scripts/run-mcp-rust.sh falls back to a slow `cargo run` without it).
if [ -x "target/release/findevil-mcp" ] || [ -x "target/release/findevil-mcp.exe" ]; then
  row ok "findevil-mcp" "Rust · 32 DFIR tools · target/release/findevil-mcp"
else
  row err "findevil-mcp" "not built — run: bash scripts/install.sh"
  REMEDIES+=("findevil-mcp: bash scripts/install.sh   # cargo build --release -p findevil-mcp")
  missing_required=$((missing_required + 1))
fi

# findevil-agent-mcp — Python, 13 crypto/ACH/memory/ACP tools. Needs the uv
# venv synced + the package present (run-mcp-python.sh does `uv run … -m`).
if [ -d "services/agent_mcp/.venv" ] && [ -d "services/agent_mcp/findevil_agent_mcp" ]; then
  row ok "findevil-agent-mcp" "Python · 12 tools · services/agent_mcp/.venv"
else
  row err "findevil-agent-mcp" "venv not synced — run: bash scripts/install.sh"
  REMEDIES+=("findevil-agent-mcp: bash scripts/install.sh   # uv sync --directory services/agent_mcp")
  missing_required=$((missing_required + 1))
fi

# .mcp.json must register both so Claude Code spawns them on session start.
if [ -f ".mcp.json" ] && grep -q '"findevil-mcp"' .mcp.json && grep -q '"findevil-agent-mcp"' .mcp.json; then
  row ok ".mcp.json" "registers both servers"
else
  row err ".mcp.json" "missing or does not register both MCP servers"
  REMEDIES+=(".mcp.json: restore the committed .mcp.json (registers both MCP servers)")
  missing_required=$((missing_required + 1))
fi

# stdio launch wrappers the .mcp.json entries exec.
if [ -f "scripts/run-mcp-rust.sh" ] && [ -f "scripts/run-mcp-python.sh" ]; then
  row ok "mcp launchers" "run-mcp-rust.sh + run-mcp-python.sh"
else
  row err "mcp launchers" "missing run-mcp-rust.sh / run-mcp-python.sh"
  REMEDIES+=("mcp launchers: restore scripts/run-mcp-rust.sh and scripts/run-mcp-python.sh")
  missing_required=$((missing_required + 1))
fi

# n8n-mcp — OPTIONAL post-verdict automation MCP (user-scope; needs Node/npx).
if command -v npx >/dev/null 2>&1; then
  row ok "n8n-mcp (opt)" "npx present — optional automation MCP runs on demand"
else
  row warn "n8n-mcp (opt)" "optional — needs Node/npx; see docs/runbooks/n8n-automation-integration.md"
  REMEDIES+=("n8n-mcp (opt): install Node 20+ (npx); then python3 scripts/setup-n8n.py")
fi

# Grounding infra — OPTIONAL post-verdict anti-hallucination sidecar. Needs the
# self-hosted browserless + SearXNG containers reachable on localhost. Warn-only.
if curl -fsS --max-time 2 http://127.0.0.1:5678/healthz >/dev/null 2>&1; then
  bl=$(curl -fsS -o /dev/null -w '%{http_code}' --max-time 2 -X POST \
       http://127.0.0.1:3000/content -H 'Content-Type: application/json' \
       -d '{"url":"https://attack.mitre.org/"}' 2>/dev/null || echo 000)
  sx=$(curl -fsS -o /dev/null -w '%{http_code}' --max-time 3 \
       'http://127.0.0.1:8888/search?q=ping&format=json' 2>/dev/null || echo 000)
  if [ "${bl}" = "200" ] && [ "${sx}" = "200" ]; then
    row ok "grounding (opt)" "n8n + browserless + searxng up — grounding runs post-verdict"
  else
    row warn "grounding (opt)" "n8n up; browserless=${bl} searxng=${sx} — deploy: scripts/setup-grounding-workflow.py"
    REMEDIES+=("grounding (opt): python3 scripts/setup-grounding-workflow.py (starts browserless + searxng)")
  fi
else
  row warn "grounding (opt)" "optional anti-hallucination sidecar — n8n down; see docs/runbooks/n8n-automation-integration.md"
fi

# ---------------------------------------------------------------------------
# DFIR external binaries (warn-only; the in-process tools work without them).
# ---------------------------------------------------------------------------
GROUP="DFIR tools"
[ -z "${JSON_MODE}" ] && { echo; echo "${c_blu}DFIR tools${c_off} ${c_dim}(external subprocess binaries; in-process EVTX/MFT/prefetch run without them)${c_off}"; }
dfir "volatility3"  VOLATILITY_BIN  "pipx install volatility3   (or: uv tool install volatility3)" \
     -- vol vol.py volatility3 volatility
dfir "hayabusa"     HAYABUSA_BIN    "download a release from https://github.com/Yamato-Security/hayabusa/releases onto PATH (or set \$HAYABUSA_BIN)" \
     -- hayabusa
dfir "velociraptor" VELOCIRAPTOR_BIN "download from https://github.com/Velocidex/velociraptor/releases (or set \$VELOCIRAPTOR_BIN)" \
     -- velociraptor
dfir "tshark/zeek"  TSHARK_BIN      "sudo apt-get install -y tshark   (pcap_triage; or set \$TSHARK_BIN/\$ZEEK_BIN)" \
     -- tshark zeek
dfir "sleuthkit"    SLEUTHKIT_BIN   "sudo apt-get install -y sleuthkit   (disk_extract_artifacts on .e01/.dd; fls/icat/mmls)" \
     -- fls
dfir "EZ tools"     EZTOOLS_DIR     "install the Eric Zimmerman tools (ship on the SIFT VM; native-Linux since the .NET port) and set \$EZTOOLS_DIR or add them to PATH   (ez_parse: LNK/Amcache/ShimCache/RecycleBin/shellbags)" \
     -- LECmd AmcacheParser RBCmd SBECmd
dfir "plaso"        PLASO_DIR       "install plaso/log2timeline (ships on the SIFT VM) and set \$PLASO_DIR or add to PATH   (plaso_parse: Linux/legacy-Win/macOS logs)" \
     -- log2timeline.py psort.py
dfir "mac_apt"      MAC_APT         "install mac_apt (ships on the SIFT VM) and set \$MAC_APT to mac_apt.py or add it to PATH   (mac_triage: macOS image triage)" \
     -- mac_apt.py mac_apt
dfir "journalctl"   JOURNALCTL_BIN  "install systemd or set \$JOURNALCTL_BIN   (journalctl_query: binary systemd journals)" \
     -- journalctl
dfir "last (wtmp)"  LAST_BIN        "install util-linux or set \$LAST_BIN   (login_accounting: wtmp/btmp)" \
     -- last
dfir "ausearch"     AUSEARCH_BIN    "sudo apt-get install -y auditd   (ausearch: Linux audit.log; INSTALL-FIRST, absent on stock SIFT)" \
     -- ausearch
dfir "nfdump"       NFDUMP_BIN      "sudo apt-get install -y nfdump   (nfdump_query: NetFlow/IPFIX; INSTALL-FIRST)" \
     -- nfdump
dfir "suricata"     SURICATA_BIN    "sudo apt-get install -y suricata   (suricata_eve: IDS on PCAP; INSTALL-FIRST)" \
     -- suricata
dfir "INDXParse"    INDXPARSE_BIN   "pip install INDXParse   (or: pipx install INDXParse) for indx_parse (\$I30/INDX slack; INSTALL-FIRST)" \
     -- INDXParse.py

# ---------------------------------------------------------------------------
# Reporting + demo-recording helpers (warn-only).
# ---------------------------------------------------------------------------
GROUP="Reporting"
[ -z "${JSON_MODE}" ] && { echo; echo "${c_blu}Reporting${c_off}"; }
optional "pandoc"  "sudo apt-get install -y pandoc" pandoc --version
if found_chrome="$(resolve_bin CHROME_BIN google-chrome google-chrome-stable chromium chromium-browser)"; then
  row ok "chrome" "${found_chrome}"
else
  row warn "chrome" "absent — needed for PDF/HTML report render"
  REMEDIES+=("chrome: sudo apt-get install -y chromium-browser   (or install Google Chrome)")
fi
if python3 -c 'import matplotlib' >/dev/null 2>&1; then
  row ok "matplotlib" "$(python3 -c 'import matplotlib as m; print(m.__version__)' 2>/dev/null)"
else
  row warn "matplotlib" "absent — report figures skipped (text/HTML/PDF still render)"
  REMEDIES+=("matplotlib: pip3 install --user matplotlib")
fi

GROUP="Demo recording"
[ -z "${JSON_MODE}" ] && { echo; echo "${c_blu}Demo recording${c_off} ${c_dim}(for scripts/record-demo.sh)${c_off}"; }
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
if [ -n "${JSON_MODE}" ]; then
  ready=true
  [ "${missing_required}" -ne 0 ] && ready=false
  saved_ifs="${IFS}"
  IFS=,
  rows_joined="${JSON_ROWS[*]:-}"
  IFS="${saved_ifs}"
  rem_json=""
  if [ "${#REMEDIES[@]}" -gt 0 ]; then
    for r in "${REMEDIES[@]}"; do
      [ -n "${rem_json}" ] && rem_json+=","
      rem_json+="\"$(json_escape "${r}")\""
    done
  fi
  printf '{"ready":%s,"missing_required":%d,"checks":[%s],"remedies":[%s]}\n' \
    "${ready}" "${missing_required}" "${rows_joined}" "${rem_json}"
  exit 0
fi

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
