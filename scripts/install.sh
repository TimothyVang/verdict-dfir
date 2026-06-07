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
# 4b. Verify BOTH MCP servers are actually ready to spawn.
# ---------------------------------------------------------------------------
# The Rust binary was built in §3; the Python venv was synced in §4. Confirm the
# Python MCP module imports (not just that the venv exists) and that the stdio
# launch wrappers .mcp.json execs are present, so a fresh session's auto-spawn
# of both servers can't silently fail.

info "Verifying MCP servers (findevil-mcp + findevil-agent-mcp)..."

if [ -x "target/release/findevil-mcp" ] || [ -x "target/release/findevil-mcp.exe" ]; then
    ok "findevil-mcp (Rust, 19 DFIR tools) binary present."
else
    fail "findevil-mcp binary missing after build — cannot continue."
    exit 1
fi

if (cd services/agent_mcp && uv run --frozen python -c "import findevil_agent_mcp" >/dev/null 2>&1); then
    ok "findevil-agent-mcp (Python, 12 crypto/ACH/memory tools) imports cleanly."
else
    warn "findevil-agent-mcp import check failed — the Python MCP server may not start; re-run: uv sync --directory services/agent_mcp"
fi

if [ -f scripts/run-mcp-rust.sh ] && [ -f scripts/run-mcp-python.sh ]; then
    ok "MCP launch wrappers present (run-mcp-rust.sh + run-mcp-python.sh)."
else
    fail "MCP launch wrappers missing — .mcp.json auto-spawn will fail."
    exit 1
fi

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
ok ".mcp.json registers the project MCP servers (findevil-mcp + findevil-agent-mcp)."

# ---------------------------------------------------------------------------
# 5a. Install the required Claude Code MCP servers.
# ---------------------------------------------------------------------------
#
# The two project servers (findevil-mcp Rust + findevil-agent-mcp Python) are
# built in §3/§4 and auto-spawned from .mcp.json. The third is n8n-mcp — the
# npx-based automation MCP that gives Claude Code the n8n node catalog +
# workflow validation for the post-verdict finding-to-action lane. It's
# registered in .mcp.json reading N8N_API_URL/N8N_API_KEY from your env (docs
# tools work with neither set; the n8n_* management tools need them). Pre-fetch
# it here so its first spawn is instant instead of a cold npx download.

if grep -q '"n8n-mcp"' .mcp.json; then
    ok ".mcp.json registers n8n-mcp (Claude Code automation MCP)."
    if command -v npx &> /dev/null; then
        info "Pre-fetching n8n-mcp into the npx cache..."
        if timeout 120 env MCP_MODE=stdio DISABLE_CONSOLE_OUTPUT=true \
            npx -y n8n-mcp </dev/null >/dev/null 2>&1; then
            ok "n8n-mcp pre-fetched (first spawn will be instant)."
        else
            info "n8n-mcp pre-fetch skipped/timed out (non-fatal — npx fetches on first use)."
        fi
    else
        warn "node/npx not on PATH — n8n-mcp can't spawn. Install Node 20+ to enable it."
    fi
else
    warn ".mcp.json does not register n8n-mcp — Claude Code won't load the automation MCP."
fi

# ---------------------------------------------------------------------------
# 5b. Browser automation — Playwright + Puppeteer (libraries + MCP servers).
# ---------------------------------------------------------------------------
#
# Claude Code drives the live dashboard / report via Playwright (preferred) or
# Puppeteer — the replacement for the removed cloakbrowser MCP. Install both
# libraries + the Playwright Chromium, then pre-fetch the two MCP servers that
# .mcp.json registers: @playwright/mcp and @modelcontextprotocol/server-puppeteer.
# All best-effort + non-fatal (needs Node/npx; Puppeteer pulls its own Chromium
# on install). Set FINDEVIL_SKIP_BROWSER=1 to skip.

if [ "${FINDEVIL_SKIP_BROWSER:-}" = "1" ]; then
    info "Skipping Playwright/Puppeteer install (FINDEVIL_SKIP_BROWSER=1)."
elif command -v npm &> /dev/null; then
    info "Installing Playwright + Puppeteer (browser automation libraries)..."
    if npm install -g playwright puppeteer --silent >/dev/null 2>&1; then
        ok "playwright + puppeteer installed (global)."
    else
        warn "playwright/puppeteer global install failed (non-fatal) — run: npm i -g playwright puppeteer"
    fi

    info "Installing the Playwright Chromium browser..."
    if npx -y playwright install chromium >/dev/null 2>&1; then
        ok "Playwright Chromium installed (~/.cache/ms-playwright)."
    else
        info "Playwright Chromium install skipped (non-fatal — first use fetches it)."
    fi

    info "Pre-fetching browser MCP servers (@playwright/mcp + server-puppeteer)..."
    timeout 150 npx -y @playwright/mcp@latest --help </dev/null >/dev/null 2>&1 || true
    timeout 150 npx -y @modelcontextprotocol/server-puppeteer </dev/null >/dev/null 2>&1 || true
    if grep -q '"playwright"' .mcp.json; then ok ".mcp.json registers playwright MCP."; else warn ".mcp.json missing playwright MCP."; fi
    if grep -q '"puppeteer"' .mcp.json;  then ok ".mcp.json registers puppeteer MCP.";  else warn ".mcp.json missing puppeteer MCP.";  fi
else
    warn "node/npm not on PATH — skipping Playwright/Puppeteer + their MCPs. Install Node 20+."
fi

# ---------------------------------------------------------------------------
# 5c. Optional: provision the n8n automation layer.
# ---------------------------------------------------------------------------
#
# n8n is the optional post-verdict automation (route findings -> Slack/ticket).
# Best-effort and NEVER fatal: scripts/setup-n8n.py self-skips when no n8n is
# reachable at N8N_BASE (default http://localhost:5678). When one is up it
# provisions an owner + REST API key (saved to gitignored tmp/n8n-*.txt) and
# deploys + activates the findevil-finding-to-action workflow, so the dashboard
# AutomationPanel and scripts/n8n_post.py route live verdicts out of the box.
# Set FINDEVIL_SKIP_N8N=1 to skip; N8N_AUTO_DOCKER=1 to start a container when
# none is running. See docs/runbooks/n8n-automation-integration.md.

if [ "${FINDEVIL_SKIP_N8N:-}" = "1" ]; then
    info "Skipping n8n setup (FINDEVIL_SKIP_N8N=1)."
else
    info "Provisioning optional n8n automation layer (best-effort)..."
    python3 "${REPO}/scripts/setup-n8n.py" || warn "n8n setup skipped/failed (optional, non-fatal)."
fi

# ---------------------------------------------------------------------------
# 6. Evidence discovery — surface any evidence already on disk.
# ---------------------------------------------------------------------------
#
# The canonical drop location is evidence/, but evidence frequently lands
# elsewhere (tmp/evidence/, a prior run, an absolute case path). The
# SessionStart banner only scans evidence/, so a real image sitting in
# tmp/evidence/ reads as "no evidence". Scan the common locations here and
# print ready-to-run `investigate` pointers so nothing gets missed.

info "Scanning for evidence images..."

# Real evidence extensions. Case/Velociraptor .zip is intentionally excluded:
# matching *.zip would surface the dozens of dependency archives under
# .venv/ and node_modules/. Point `investigate` at a .zip by hand if needed.
evidence_exts=(E01 dd raw img mem vmem aff4 aff evtx pcap pcapng vhd vhdx)
find_args=()
for ext in "${evidence_exts[@]}"; do
    find_args+=(-iname "*.${ext}" -o)
done
unset 'find_args[${#find_args[@]}-1]'  # drop the trailing -o

# Scan only the roots that hold evidence, skipping vendored trees. The 1 KiB
# floor drops zero-byte placeholders and the 103-byte rust-smoke mock fixture.
evidence_roots=()
for root in evidence tmp/evidence goldens; do
    [ -d "${root}" ] && evidence_roots+=("${root}")
done

evidence_hits=""
if [ "${#evidence_roots[@]}" -gt 0 ]; then
    evidence_hits=$(
        find "${evidence_roots[@]}" -type f \( "${find_args[@]}" \) \
            -not -path "*/node_modules/*" \
            -not -path "*/.venv/*" \
            -size +1024c \
            2>/dev/null | sort -u || true
    )
fi

if [ -n "${evidence_hits}" ]; then
    ok "Evidence found — run any of these in Claude Code:"
    while IFS= read -r ev; do
        [ -z "${ev}" ] && continue
        sz=$(du -h "${ev}" 2>/dev/null | cut -f1)
        printf '      %sinvestigate %s%s   (%s)\n' "${c_grn}" "${ev}" "${c_off}" "${sz}"
    done <<< "${evidence_hits}"
else
    info "No evidence images found in evidence/, tmp/evidence/, or goldens/."
    info "  Drop a file (.E01/.img/.mem/.evtx/.pcap/...) into evidence/, or run:"
    echo "      bash scripts/verdict --watch     # waits for a drop, then investigates"
fi

# ---------------------------------------------------------------------------
# 7. Optional: visible launch-banner alias.
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
# 8. Connect to SIFT VM (optional, non-blocking).
# ---------------------------------------------------------------------------
#
# SIFT mode runs the DFIR tools inside the SANS SIFT VM over SSH; local host is
# the default. This step is opt-in and NEVER fails the installer — on any problem
# it prints guidance and continues. Set FINDEVIL_SKIP_SIFT=1 to skip entirely.

connect_sift_vm() {
    # Honor every env var name the two SIFT entrypoints use, then the canonical
    # defaults from scripts/find_evil_auto.py:68-71. (find-evil-sift reads
    # SIFT_SSH_KEY/GUEST_USER/GUEST_REPO_PATH/SIFT_VM_IP; find_evil_auto.py reads
    # FIND_EVIL_GUEST_IP/_USER/_SSH_KEY/_GUEST_REPO.)
    local guest_ip="${FIND_EVIL_GUEST_IP:-${SIFT_VM_IP:-192.168.197.143}}"
    local guest_user="${FIND_EVIL_GUEST_USER:-${GUEST_USER:-sansforensics}}"
    local ssh_key="${FIND_EVIL_SSH_KEY:-${SIFT_SSH_KEY:-${HOME}/.ssh/sift_key}}"
    local guest_repo="${FIND_EVIL_GUEST_REPO:-${GUEST_REPO_PATH:-/home/sansforensics/find-evil}}"

    if [ "${FINDEVIL_SKIP_SIFT:-}" = "1" ]; then
        info "Skipping SIFT VM connect (FINDEVIL_SKIP_SIFT=1)."
        return 0
    fi

    # No key yet -> first-time VM creation must go through the bootstrap.
    if [ ! -f "${ssh_key}" ]; then
        info "SIFT VM is optional (local host is the default). No SSH key at:"
        echo "    ${ssh_key}"
        info "To create the SIFT VM + key, run:  bash scripts/sift-vm-bootstrap.sh"
        return 0
    fi

    # Non-interactive shell: don't reach out over the network; print the hint.
    if [ ! -t 0 ]; then
        info "Non-interactive shell — skipping SIFT reachability probe."
        info "  To use SIFT mode later:  scripts/find-evil-sift   (or  bash scripts/verdict --sift)"
        return 0
    fi

    # Key exists -> short, timeout-bounded, BatchMode probe. Same idiom as
    # scripts/find-evil-sift; guarded so a failed ssh can't kill the script.
    info "Probing SIFT VM at ${guest_user}@${guest_ip} (5s timeout)..."
    if ssh -i "${ssh_key}" -o BatchMode=yes -o ConnectTimeout=5 \
        -o StrictHostKeyChecking=accept-new \
        "${guest_user}@${guest_ip}" \
        "test -x ${guest_repo}/target/release/findevil-mcp" >/dev/null 2>&1; then
        ok "SIFT VM reachable; findevil-mcp is built inside the guest."
        if [ -f .mcp.json.sift ]; then
            ok ".mcp.json.sift template is present."
        else
            warn ".mcp.json.sift missing — run scripts/sift-vm-bootstrap.sh to regenerate it."
        fi
        info "To run in SIFT mode:  scripts/find-evil-sift   (or  bash scripts/verdict --sift)"
    else
        warn "SIFT VM not reachable at ${guest_ip} (or findevil-mcp not built in the guest)."
        info "  Optional — local host mode still works. The VM uses DHCP, so if it's"
        info "  running, set FIND_EVIL_GUEST_IP=<ip> (or SIFT_VM_IP=<ip>) and re-run."
        info "  To create/repair the VM:  bash scripts/sift-vm-bootstrap.sh"
    fi
    return 0
}

connect_sift_vm || true

# ---------------------------------------------------------------------------
# 9. DFIR tools — install any missing (host / local mode), then verify.
# ---------------------------------------------------------------------------
#
# Local-host mode (the default; SIFT VM and Docker bundle their own) runs the
# DFIR tools on this machine. scripts/install-dfir-tools.sh installs the ones the
# Rust MCP server shells out to — volatility3, hayabusa, chainsaw, velociraptor,
# plus pandoc for report rendering — user-space into ~/.local/bin (no sudo),
# pinned to the verdict-runner image versions, idempotent and best-effort. Then
# scripts/doctor.sh (the canonical checker, resolving binaries the SAME way the
# server does) re-verifies them and prints a remedy for any still absent. Never
# fatal: a missing DFIR binary degrades to a clean BinaryNotFound at run time.

echo ""
info "Installing host DFIR tools (user-space, ~/.local/bin)..."
bash "${REPO}/scripts/install-dfir-tools.sh" || warn "some DFIR tools did not install (non-fatal)."
# Make fresh ~/.local/bin installs visible to the doctor check below.
export PATH="${HOME}/.local/bin:${PATH}"

echo ""
info "Verifying DFIR tools + environment (scripts/doctor.sh)..."
bash "${REPO}/scripts/doctor.sh" || true

# ---------------------------------------------------------------------------
# 10. Next steps.
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
echo "     Then open ${c_blu}http://localhost:3000${c_off} in your browser."
echo "     Claude Code can open or screenshot the dashboard/report for you via"
echo "     Playwright or Puppeteer (host Chrome) — just ask: 'screenshot the dashboard'."
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
