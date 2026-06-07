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
    fail "uv not on PATH. Install: https://docs.astral.sh/uv/"
    exit 1
fi
ok "uv: $(uv --version)"

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
# 6. Next steps.
# ---------------------------------------------------------------------------

echo ""
echo "=========================================="
echo "${c_grn}Find Evil! is ready.${c_off}"
echo "=========================================="
echo ""
echo "Next steps:"
echo ""
echo "  ${c_blu}Local mode${c_off} (DFIR tool binaries on this host):"
echo "    bash scripts/find-evil"
echo "    # or, equivalently"
echo "    claude    # the official Claude Code CLI; opens an interactive session in cwd"
echo ""
  echo "  ${c_blu}SIFT-VM mode${c_off} (Tesla-mode automation, agents run inside SIFT):"
  echo "    bash scripts/find-evil-sift"
  echo "    # Pre-flight: run bash scripts/sift-vm-bootstrap.sh once."
  echo "    # Implemented hypervisor path: VMware Workstation."
echo ""
echo "  ${c_blu}Headless single-shot${c_off} (point at an evidence path, get a signed verdict):"
echo "    bash scripts/find-evil-auto <evidence-path-inside-VM> --unattended"
echo ""
echo "  See ${c_blu}QUICKSTART.md${c_off} for the full per-mode walkthrough."
