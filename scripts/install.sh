#!/usr/bin/env bash
# scripts/install.sh — pre-flight + build script for the Find Evil! agent.
#
# Per CLAUDE.md "Credential modes (Amendment A1)" and the Amendment A2
# spec, the Product is Claude Code in this repo with two MCP servers
# (findevil-mcp Rust + findevil-agent-mcp Python) auto-spawned by
# .mcp.json. This script:
#
#   1. Detects which of the three Claude credential modes is active
#      (CLAUDE_CODE_OAUTH_TOKEN / interactive ~/.claude / ANTHROPIC_API_KEY)
#      and errors out clearly if none are present.
#   2. Verifies the toolchain prerequisites (cargo, uv).
#   3. Builds the Rust MCP server in release mode (target/release/findevil-mcp).
#   4. Syncs the Python MCP server's uv venv (services/agent_mcp/).
#   5. Confirms .mcp.json is in place and points at both servers.
#   6. Prints next-step pointers (scripts/find-evil, scripts/find-evil-sift,
#      scripts/find-evil-auto).
#
# The Next.js SPA install (pnpm) is intentionally NOT done here — A2
# defers apps/web and apps/mcp-widgets to bonus polish. If those
# directories are present and contain a package.json, the user can
# `pnpm install` themselves.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO}"

c_red=$'\033[0;31m'
c_grn=$'\033[0;32m'
c_yel=$'\033[0;33m'
c_blu=$'\033[0;34m'
c_off=$'\033[0m'

ok()    { echo "${c_grn}[OK]${c_off}    $*"; }
info()  { echo "${c_blu}[INFO]${c_off}  $*"; }
warn()  { echo "${c_yel}[WARN]${c_off}  $*"; }
fail()  { echo "${c_red}[ERR]${c_off}   $*" >&2; }

echo ""
echo "  ██╗   ██╗███████╗██████╗ ██████╗ ██╗ ██████╗████████╗"
echo "  ██║   ██║██╔════╝██╔══██╗██╔══██╗██║██╔════╝╚══██╔══╝"
echo "  ██║   ██║█████╗  ██████╔╝██║  ██║██║██║        ██║   "
echo "  ╚██╗ ██╔╝██╔══╝  ██╔══██╗██║  ██║██║██║        ██║   "
echo "   ╚████╔╝ ███████╗██║  ██║██████╔╝██║╚██████╗   ██║   "
echo "    ╚═══╝  ╚══════╝╚═╝  ╚═╝╚═════╝ ╚═╝ ╚═════╝   ╚═╝  "
echo ""
echo "  DFIR at machine speed. — SANS Find Evil! 2026"
echo ""
echo "=========================================="
echo "Find Evil! — install pre-flight"
echo "=========================================="

# ---------------------------------------------------------------------------
# 1. Credential mode detection (Amendment A1 §3.2 — verbatim contract).
# ---------------------------------------------------------------------------

info "Detecting Claude credential mode..."

if [ -n "${CLAUDE_CODE_OAUTH_TOKEN:-}" ] && command -v claude &> /dev/null; then
    ok "CLAUDE_CODE_OAUTH_TOKEN present + claude CLI on PATH (mode 1: long-lived token)."
elif command -v claude &> /dev/null && [ -d "${HOME}/.claude" ]; then
    ok "claude CLI on PATH + ~/.claude/ populated (mode 2: interactive session)."
elif [ -n "${ANTHROPIC_API_KEY:-}" ]; then
    ok "ANTHROPIC_API_KEY present (mode 3: direct API)."
else
    fail "Find Evil! requires one of (any works — pick whichever you have):"
    echo ""
    echo "  (1) CLAUDE_CODE_OAUTH_TOKEN env var — non-interactive, script-friendly."
    echo "      Generate with: claude setup-token"
    echo "      Requires a Claude Code subscription; token is inference-only."
    echo ""
    echo "  (2) Claude Code interactive session — for dev/demo use."
    echo "      Install: https://docs.anthropic.com/en/docs/claude-code/install"
    echo "      Then run: claude auth login"
    echo ""
    echo "  (3) ANTHROPIC_API_KEY env var — direct Anthropic API, metered."
    echo "      Get a key at: https://console.anthropic.com"
    echo "      Expected cost: <\$1 per standard SIFT evidence run."
    exit 1
fi

# ---------------------------------------------------------------------------
# 2. Toolchain prerequisites.
# ---------------------------------------------------------------------------

info "Checking toolchain prerequisites..."

# Source rustup env in case this is a fresh shell where ~/.cargo/bin isn't on PATH yet.
# doctor.sh does the same at line 30.
[ -f "${HOME}/.cargo/env" ] && source "${HOME}/.cargo/env"

if ! command -v cargo &> /dev/null; then
    fail "cargo not on PATH. Install Rust: https://rustup.rs/"
    exit 1
fi
ok "cargo: $(cargo --version)"

if ! command -v rustc &> /dev/null; then
    fail "rustc not on PATH. Install Rust: https://rustup.rs/"
    exit 1
fi
RUST_VER="$(rustc --version | awk '{print $2}')"
ok "rustc: ${RUST_VER}"

# Rust 1.85 is the floor under A2 (CLAUDE.md spec/code divergence #1 —
# repo ships rust-toolchain.toml = 1.88; transitive deps need edition-2024).
if ! printf '%s\n%s\n' "1.85" "${RUST_VER}" | sort -V -C; then
    warn "rustc ${RUST_VER} is older than the 1.85 floor. cargo will pull"
    warn "the toolchain pinned in rust-toolchain.toml (1.88) on first build."
fi

if ! command -v uv &> /dev/null; then
    fail "uv not on PATH."
    echo ""
    echo "  Install uv (Python environment manager):"
    echo "    curl -LsSf https://astral.sh/uv/install.sh | sh"
    echo "  Then re-run this script."
    exit 1
fi
ok "uv: $(uv --version)"

# Node 20+ (required for apps/web dashboard + Remotion demo video)
if ! command -v node &> /dev/null; then
    warn "node not on PATH. The live dashboard (apps/web/) and demo video builder will not work."
    echo "  Install Node 20 LTS: https://nodejs.org/en/download"
    echo "  Or via nvm: nvm install 20 && nvm use 20"
    NODE_OK=false
else
    NODE_VER_MAJOR=$(node --version | sed 's/v//' | cut -d. -f1)
    if [ "${NODE_VER_MAJOR}" -lt 20 ]; then
        warn "node $(node --version) is < 20. Upgrade to Node 20 LTS."
        echo "  nvm install 20 && nvm use 20"
        NODE_OK=false
    else
        ok "node: $(node --version)"
        NODE_OK=true
    fi
fi

# pnpm (required for dashboard + demo video)
if $NODE_OK; then
    if ! command -v pnpm &> /dev/null; then
        warn "pnpm not on PATH. Installing via npm..."
        npm install -g pnpm --silent && ok "pnpm installed." || warn "pnpm install failed — run: npm install -g pnpm"
    else
        ok "pnpm: $(pnpm --version)"
    fi
fi

# edge-tts (optional — only needed for demo video TTS generation)
if python3 -c "import edge_tts" 2>/dev/null; then
    ok "edge-tts: present"
else
    info "edge-tts not installed (optional — only needed for demo video TTS)."
    info "  Install when ready: pip install edge-tts"
fi

# ---------------------------------------------------------------------------
# 3. Build the Rust MCP server (target/release/findevil-mcp).
# ---------------------------------------------------------------------------

info "Building findevil-mcp (Rust, release mode — first build can take 5-10 min)..."
# `-p findevil-mcp` selects the single package to build; we don't need
# `--workspace` (cargo silently ignores it when -p is also passed).
cargo build --release --locked -p findevil-mcp -q
if [ ! -x "target/release/findevil-mcp" ] && [ ! -x "target/release/findevil-mcp.exe" ]; then
    fail "target/release/findevil-mcp not found after cargo build."
    exit 1
fi
ok "findevil-mcp built."

# ---------------------------------------------------------------------------
# 4. Sync the Python MCP server (services/agent_mcp).
# ---------------------------------------------------------------------------

info "Syncing services/agent_mcp/ Python venv..."
(
    cd services/agent_mcp
    if [ -f uv.lock ]; then
        uv sync --extra dev --frozen 2>/dev/null || uv sync --extra dev
    else
        uv sync --extra dev
    fi
)
ok "services/agent_mcp/.venv ready."

# ---------------------------------------------------------------------------
# 5. Confirm .mcp.json registration.
# ---------------------------------------------------------------------------

if [ ! -f .mcp.json ]; then
    fail ".mcp.json missing at repo root. Claude Code won't auto-spawn the servers."
    exit 1
fi
if ! grep -q '"findevil-mcp"' .mcp.json; then
    fail ".mcp.json does not register 'findevil-mcp'."
    exit 1
fi
if ! grep -q '"findevil-agent-mcp"' .mcp.json; then
    fail ".mcp.json does not register 'findevil-agent-mcp'."
    exit 1
fi
ok ".mcp.json registers both MCP servers."

# ---------------------------------------------------------------------------
# 6. Optional: visible launch-banner alias.
# ---------------------------------------------------------------------------
#
# The SessionStart hook (.claude/settings.json -> scripts/session-suggest.sh)
# already injects the onboarding suggestions into every session automatically.
# Whether its banner is *visible at launch* depends on how the installed Claude
# Code version surfaces hook stderr. scripts/claude is a thin wrapper that prints
# the banner unconditionally, then forwards to the real CLI. Aliasing `claude` to
# it guarantees the banner for this user. Idempotent; skipped non-interactively.

setup_banner_alias() {
    local rc alias_line marker
    case "${SHELL:-}" in
        */zsh) rc="${HOME}/.zshrc" ;;
        *)     rc="${HOME}/.bashrc" ;;
    esac
    marker="# VERDICT launch-banner alias"
    alias_line="alias claude='bash ${REPO}/scripts/claude'  ${marker}"

    if [ -f "${rc}" ] && grep -qF "${marker}" "${rc}"; then
        ok "Launch-banner alias already present in ${rc}."
        return 0
    fi

    if [ ! -t 0 ]; then
        info "Non-interactive shell — skipping alias prompt. To enable the visible"
        info "  launch banner, add this line to your shell rc (${rc}):"
        echo "    ${alias_line}"
        return 0
    fi

    echo ""
    info "Optional: alias \`claude\` to print the VERDICT launch banner at startup?"
    info "  Adds to ${rc}:  ${alias_line}"
    printf "  Add it now? [y/N] "
    read -r reply
    case "${reply}" in
        [yY]|[yY][eE][sS])
            printf '\n%s\n' "${alias_line}" >> "${rc}"
            ok "Alias added to ${rc}. Run: source ${rc}  (or open a new terminal)."
            ;;
        *)
            info "Skipped. You can add it later:"
            echo "    ${alias_line}"
            ;;
    esac
}

setup_banner_alias

# ---------------------------------------------------------------------------
# 7. Next steps.
# ---------------------------------------------------------------------------

echo ""
echo "=========================================="
echo "${c_grn}VERDICT / Find Evil! is ready.${c_off}"
echo "=========================================="
echo ""
echo "${c_blu}HOW TO USE THIS TOOL${c_off}"
echo ""
echo "  1. Open Claude Code in this repo:"
echo "       claude"
echo "     Claude Code IS the agent — it reads CLAUDE.md automatically."
echo ""
echo "  2. Type 'help' to see all commands."
echo ""
echo "  3. To run an investigation:"
echo "       investigate /path/to/evidence.E01"
echo "     The agent will open the case, fork Pool A + Pool B, emit signed Findings,"
echo "     and produce REPORT.html + a sigstore-verified audit.jsonl."
echo ""
echo "  4. To watch the live dashboard while an investigation runs:"
echo "       pnpm --filter @findevil/web dev"
echo "     Then open ${c_blu}http://localhost:3000${c_off} in Chrome."
echo "     If you have Chrome DevTools MCP configured, Claude Code will"
echo "     open that URL in Chrome for you automatically."
echo ""
echo "  5. To start Chrome with remote debugging (enables Claude to browse for you):"
echo "       google-chrome --remote-debugging-port=9222 &"
echo "     Then ask Claude Code: 'open the dashboard' or 'open the report'."
echo ""
echo "${c_blu}QUICK COMMAND REFERENCE${c_off}"
echo ""
echo "  bash scripts/find-evil                    # interactive local mode"
echo "  bash scripts/find-evil-sift               # SIFT-VM mode (VMware Workstation)"
echo "  bash scripts/find-evil-auto <evidence>    # headless single-shot"
echo "  bash scripts/run-all-smokes.sh            # full smoke gate (pre-commit)"
echo "  bash scripts/make-demo-video.sh           # generate demo video"
echo "  pnpm --filter @findevil/web dev           # start live dashboard"
echo ""
echo "${c_blu}USEFUL DOCS${c_off}"
echo ""
echo "  QUICKSTART.md              — 3-step quick start for judges and new users"
echo "  SUBMISSION_COMPLIANCE.md   — 10-item Devpost compliance checklist"
echo "  docs/false-positives.md    — analyst checklists"
echo "  docs/demo-script-a2.md    — walkthrough script for the demo video"
echo ""
echo "  To verify a signed manifest offline:"
echo "    uv run --directory services/agent_mcp python -m findevil_agent_mcp.server"
echo "    # then call the manifest_verify MCP tool"
echo ""
