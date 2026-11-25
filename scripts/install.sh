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

# Opt-in prerequisite bootstrap. Default OFF: the canonical contract is
# fail-closed on a missing toolchain (judges/CI rely on it). With --bootstrap
# (or FINDEVIL_BOOTSTRAP=1) install.sh installs missing cargo/uv/node via their
# official installers before the checks, instead of erroring out. The remote
# installers below are reached ONLY through bootstrap_enabled.
BOOTSTRAP="${FINDEVIL_BOOTSTRAP:-0}"
for _arg in "$@"; do
    case "${_arg}" in
        --bootstrap) BOOTSTRAP=1 ;;
    esac
done
bootstrap_enabled() { [ "${BOOTSTRAP}" = "1" ]; }

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
    ok "ANTHROPIC_API_KEY present (mode 3: direct API credential)."
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

# A C toolchain (cc/linker) is required to build Rust crates; rustup warns but
# does not install one. Bootstrap it on Debian/Ubuntu via apt; elsewhere point
# the user at the right package.
if bootstrap_enabled && ! command -v cc &> /dev/null && ! command -v gcc &> /dev/null; then
    if command -v apt-get &> /dev/null; then
        info "[bootstrap] no C compiler — installing build-essential via apt..."
        if [ "$(id -u)" -eq 0 ]; then
            apt-get update -qq && apt-get install -y --no-install-recommends build-essential \
                || warn "[bootstrap] build-essential install failed; install a C toolchain manually."
        elif command -v sudo &> /dev/null; then
            sudo apt-get update -qq && sudo apt-get install -y --no-install-recommends build-essential \
                || warn "[bootstrap] build-essential install failed; install a C toolchain manually."
        else
            warn "[bootstrap] need root/sudo to apt-install build-essential; install it manually."
        fi
    elif [ "$(uname -s)" = "Darwin" ]; then
        warn "[bootstrap] no C compiler — run 'xcode-select --install', then re-run."
    else
        warn "[bootstrap] no C compiler found; install your distro's build tools (gcc/clang)."
    fi
fi

if bootstrap_enabled && ! command -v cargo &> /dev/null; then
    info "[bootstrap] cargo missing — installing Rust via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable \
        || warn "[bootstrap] rustup install failed; falling back to the manual step below."
    # shellcheck disable=SC1091
    [ -f "${HOME}/.cargo/env" ] && source "${HOME}/.cargo/env"
fi

if ! command -v cargo &> /dev/null; then
    fail "cargo not on PATH. Install Rust: https://rustup.rs/  (or re-run: bash scripts/install.sh --bootstrap)"
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

if bootstrap_enabled && ! command -v uv &> /dev/null; then
    info "[bootstrap] uv missing — installing via astral.sh/uv/install.sh..."
    curl -LsSf https://astral.sh/uv/install.sh | sh \
        || warn "[bootstrap] uv install failed; falling back to the manual step below."
    export PATH="${HOME}/.local/bin:${PATH}"
    # shellcheck disable=SC1091
    [ -f "${HOME}/.local/bin/env" ] && source "${HOME}/.local/bin/env"
fi

if ! command -v uv &> /dev/null; then
    fail "uv not on PATH."
    echo ""
    echo "  Install uv (Python environment manager):"
    echo "    curl -LsSf https://astral.sh/uv/install.sh | sh"
    echo "  Then re-run this script (or re-run with: bash scripts/install.sh --bootstrap)."
    exit 1
fi
ok "uv: $(uv --version)"

# Node 20+ (required for apps/web dashboard + Remotion demo video)
if bootstrap_enabled && ! command -v node &> /dev/null; then
    info "[bootstrap] node missing — installing Node 20 via fnm (best-effort; node is optional)..."
    curl -fsSL https://fnm.vercel.app/install | bash -s -- --skip-shell \
        || warn "[bootstrap] fnm install failed; install Node 20 manually if you want the dashboard."
    for _fnmdir in "${HOME}/.local/share/fnm" "${HOME}/.fnm"; do
        [ -d "${_fnmdir}" ] && export PATH="${_fnmdir}:${PATH}"
    done
    if command -v fnm &> /dev/null; then
        eval "$(fnm env)" || true
        fnm install 20 || warn "[bootstrap] 'fnm install 20' failed."
        fnm use 20 || true
    fi
fi

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

# Piper + ffmpeg (optional — only needed for demo video TTS generation)
if command -v piper >/dev/null 2>&1; then
    ok "piper: $(command -v piper)"
else
    info "piper not installed (optional — only needed for demo video TTS)."
    info "  Install when ready: pip install piper-tts"
fi
if command -v ffmpeg >/dev/null 2>&1 && command -v ffprobe >/dev/null 2>&1; then
    ok "ffmpeg/ffprobe: present"
else
    info "ffmpeg/ffprobe not both on PATH (optional — only needed for demo video TTS)."
fi

# ---------------------------------------------------------------------------
# 3. Build the Rust MCP server (target/release/findevil-mcp).
# ---------------------------------------------------------------------------

# Prefer a published, checksum-verified prebuilt binary over a 5-10 min compile.
# This is the DEFAULT fast path for a new user: when FINDEVIL_MCP_VERSION is unset
# we auto-detect the latest published release and fetch its binary. ANY failure
# (no release, no asset for this host, missing/mismatched checksum, no curl) falls
# back to `cargo build`, so install always succeeds. Build from source explicitly
# with FINDEVIL_MCP_FROM_SOURCE=1; CI builds from source by default (set
# FINDEVIL_MCP_PREBUILT=1 to force the binary even under CI).
FINDEVIL_MCP_RELEASE_BASE="${FINDEVIL_MCP_RELEASE_BASE:-https://github.com/TimothyVang/verdict-dfir/releases/download}"
FINDEVIL_MCP_RELEASE_REPO="${FINDEVIL_MCP_RELEASE_REPO:-TimothyVang/verdict-dfir}"

# Latest published release tag (newest non-draft, non-prerelease) via the GitHub
# API, parsed without jq. Empty on any failure — the caller falls back to compiling.
detect_latest_release() {
    command -v curl &> /dev/null || return 1
    curl -fsSL "https://api.github.com/repos/${FINDEVIL_MCP_RELEASE_REPO}/releases/latest" 2>/dev/null \
        | grep -m1 '"tag_name"' \
        | sed -E 's/.*"tag_name"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/'
}

host_triple() {
    case "$(uname -s)-$(uname -m)" in
        Linux-x86_64)  echo "x86_64-unknown-linux-gnu" ;;
        Linux-aarch64) echo "aarch64-unknown-linux-gnu" ;;
        Darwin-x86_64) echo "x86_64-apple-darwin" ;;
        Darwin-arm64)  echo "aarch64-apple-darwin" ;;
        *) return 1 ;;
    esac
}

try_fetch_prebuilt() {
    # Explicit source build, or CI (which should build from source to test it)
    # unless the prebuilt binary is force-enabled.
    [ -n "${FINDEVIL_MCP_FROM_SOURCE:-}" ] && return 1
    if [ -n "${CI:-}" ] && [ -z "${FINDEVIL_MCP_PREBUILT:-}" ]; then
        return 1
    fi
    command -v curl &> /dev/null || return 1
    local triple ver base tarball tmp extracted
    triple="$(host_triple)" || { warn "[prebuilt] no published binary for this host; compiling."; return 1; }
    # Explicit version wins; otherwise auto-detect the latest release so the fast
    # path is the default. Still falls back to compile on any failure below.
    ver="${FINDEVIL_MCP_VERSION:-}"
    if [ -z "${ver}" ]; then
        info "[prebuilt] checking for a published findevil-mcp release..."
        ver="$(detect_latest_release || true)"
        [ -n "${ver}" ] || { info "[prebuilt] none published yet; compiling from source."; return 1; }
        info "[prebuilt] latest release is ${ver}; trying its binary (falls back to compile)."
    fi
    base="${FINDEVIL_MCP_RELEASE_BASE}/${ver}"
    tarball="findevil-mcp-${triple}.tar.xz"
    tmp="$(mktemp -d)"
    info "[prebuilt] fetching ${tarball} from ${base}..."
    if ! curl -fsSL "${base}/${tarball}" -o "${tmp}/${tarball}"; then
        rm -rf "${tmp}"; warn "[prebuilt] download failed; compiling."; return 1
    fi
    # Refuse any binary we cannot checksum against the release SHA256SUMS.
    if ! curl -fsSL "${base}/SHA256SUMS" -o "${tmp}/SHA256SUMS"; then
        rm -rf "${tmp}"; warn "[prebuilt] no SHA256SUMS published; refusing unverified binary, compiling."; return 1
    fi
    if ! ( cd "${tmp}" && grep -F "${tarball}" SHA256SUMS | sha256sum -c - ); then
        rm -rf "${tmp}"; fail "[prebuilt] checksum mismatch for ${tarball}; refusing."; return 1
    fi
    if ! tar -xJf "${tmp}/${tarball}" -C "${tmp}"; then
        rm -rf "${tmp}"; warn "[prebuilt] extract failed; compiling."; return 1
    fi
    extracted="$(find "${tmp}" -name findevil-mcp -type f | head -1)"
    [ -n "${extracted}" ] || { rm -rf "${tmp}"; warn "[prebuilt] binary not found in tarball; compiling."; return 1; }
    mkdir -p target/release
    install -m 0755 "${extracted}" target/release/findevil-mcp || { rm -rf "${tmp}"; return 1; }
    rm -rf "${tmp}"
    ok "[prebuilt] installed findevil-mcp ${ver} (${triple}) — compile skipped."
}

if try_fetch_prebuilt; then
    : # checksum-verified prebuilt binary is in place; compile skipped
else
    info "Building findevil-mcp (Rust, release mode — first build can take 5-10 min)..."
    # `-p findevil-mcp` selects the single package to build; we don't need
    # `--workspace` (cargo silently ignores it when -p is also passed).
    cargo build --release --locked -p findevil-mcp -q
fi
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
    ok "findevil-mcp (Rust, 32 DFIR tools) binary present."
else
    fail "findevil-mcp binary missing after build — cannot continue."
    exit 1
fi

if (cd services/agent_mcp && uv run --frozen python -c "import findevil_agent_mcp" >/dev/null 2>&1); then
    ok "findevil-agent-mcp (Python, 13 crypto/ACH/memory tools) imports cleanly."
else
    fail "findevil-agent-mcp import check failed — the Python MCP server will not start; re-run: uv sync --directory services/agent_mcp"
    exit 1
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
# provisions an owner + REST API key (saved to gitignored tmp/n8n-*.txt) ONLY.
# It does NOT deploy a finding-to-action workflow out of the box (that path is
# superseded by host-side grounding-aware routing in scripts/ground_actions.py),
# so unless an operator deploys a workflow (e.g. scripts/setup-grounding-workflow.py)
# scripts/n8n_post.py records the automation as skipped in the out-of-band
# automation.json sidecar. The verdict stands either way — automation is
# never in the audit chain and is not surfaced in the dashboard.
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
# A local Claude Code SessionStart hook can invoke scripts/session-suggest.sh to
# inject onboarding suggestions into every session automatically.
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
# 8. Set up / connect the SIFT VM (optional, non-blocking).
# ---------------------------------------------------------------------------
#
# SIFT mode runs the DFIR tools inside the SANS SIFT Workstation VM over SSH;
# local host is the default. If a SIFT OVA is staged at the repo root this step
# offers to BUILD the VM end-to-end via scripts/sift-vm-bootstrap.sh (convert /
# import the OVA, boot, install an SSH key, sync the repo, build the MCP server
# inside). It NEVER fails the installer. Controls:
#   FINDEVIL_SKIP_SIFT=1    skip this step entirely
#   FINDEVIL_SETUP_SIFT=1   build without prompting (for non-interactive runs)
#   (no OVA at repo root)    -> local-host mode; prints how to enable SIFT

connect_sift_vm() {
    # Honor every env var name the two SIFT entrypoints use. (find-evil-sift reads
    # SIFT_SSH_KEY/GUEST_USER/GUEST_REPO_PATH/SIFT_VM_IP; find_evil_auto.py reads
    # FIND_EVIL_GUEST_IP/_USER/_SSH_KEY/_GUEST_REPO.) No IP default — the VM uses
    # DHCP, so a reachability probe only runs when an IP was actually provided.
    local guest_ip="${FIND_EVIL_GUEST_IP:-${SIFT_VM_IP:-}}"
    local guest_user="${FIND_EVIL_GUEST_USER:-${GUEST_USER:-sansforensics}}"
    local ssh_key="${FIND_EVIL_SSH_KEY:-${SIFT_SSH_KEY:-${HOME}/.ssh/sift_key}}"
    local guest_repo="${FIND_EVIL_GUEST_REPO:-${GUEST_REPO_PATH:-/home/sansforensics/find-evil}}"

    if [ "${FINDEVIL_SKIP_SIFT:-}" = "1" ]; then
        info "Skipping SIFT VM setup (FINDEVIL_SKIP_SIFT=1)."
        return 0
    fi

    # A SIFT OVA at the repo root is the trigger for VM setup. No OVA -> the user
    # is in local-host mode (the default); just tell them how to enable SIFT.
    local ova=""
    ova="$(ls -S "${REPO}"/sift-*.ova 2>/dev/null | head -1 || true)"
    [ -z "${ova}" ] && ova="$(ls -S "${REPO}"/*.ova 2>/dev/null | head -1 || true)"
    if [ -z "${ova}" ]; then
        info "SIFT VM is optional (local-host mode is the default)."
        info "  For disk forensics in the SANS SIFT Workstation, download the OVA"
        info "  (https://www.sans.org/tools/sift-workstation/), drop it at the repo"
        info "  root, and re-run this installer — it will build + connect the VM."
        return 0
    fi
    info "SIFT OVA detected: $(basename "${ova}")"

    # Fast path: already built + reachable at a known IP -> never rebuild.
    if [ -f "${ssh_key}" ] && [ -n "${guest_ip}" ]; then
        if ssh -i "${ssh_key}" -o BatchMode=yes -o ConnectTimeout=5 \
            -o StrictHostKeyChecking=accept-new \
            "${guest_user}@${guest_ip}" \
            "test -x ${guest_repo}/target/release/findevil-mcp" >/dev/null 2>&1; then
            ok "SIFT VM already set up + reachable at ${guest_ip}."
            info "Run in SIFT mode:  scripts/find-evil-sift   (or  bash scripts/verdict --sift)"
            return 0
        fi
    fi

    # Which backend will the bootstrap use? (Prompt text only — the bootstrap
    # auto-detects and installs KVM/libvirt itself when VMware is absent.)
    local backend_msg
    if command -v vmrun >/dev/null 2>&1 && command -v ovftool >/dev/null 2>&1; then
        backend_msg="VMware Workstation"
    elif command -v virsh >/dev/null 2>&1 || command -v apt-get >/dev/null 2>&1; then
        backend_msg="KVM/libvirt (VMware Workstation not found)"
    else
        backend_msg="(no hypervisor found — install VMware Workstation or KVM/libvirt)"
    fi

    # Decide whether to run the (long, possibly sudo-prompting) bootstrap.
    if [ "${FINDEVIL_SETUP_SIFT:-}" = "1" ]; then
        info "FINDEVIL_SETUP_SIFT=1 — building the SIFT VM via ${backend_msg}..."
    elif [ -t 0 ]; then
        echo
        info "Ready to build the SIFT VM from $(basename "${ova}") via ${backend_msg}."
        info "This can take 20-40 min and may prompt for sudo (kernel modules / packages)."
        printf "  Build it now? [Y/n] "
        local reply=""
        read -r reply || reply=""
        case "${reply}" in
            [Nn]*)
                info "Skipped. Build later:  bash scripts/sift-vm-bootstrap.sh"
                return 0 ;;
        esac
    else
        info "OVA present but shell is non-interactive — not building automatically."
        info "  Build now:   FINDEVIL_SETUP_SIFT=1 bash scripts/install.sh"
        info "  Or run:      bash scripts/sift-vm-bootstrap.sh"
        return 0
    fi

    info "Running scripts/sift-vm-bootstrap.sh ..."
    if bash "${REPO}/scripts/sift-vm-bootstrap.sh"; then
        ok "SIFT VM bootstrap complete. Run:  scripts/find-evil-sift"
    else
        warn "SIFT bootstrap did not complete (non-fatal — local-host mode still works)."
        warn "  Re-run when ready:  bash scripts/sift-vm-bootstrap.sh"
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
# pinned to known-good versions, idempotent and best-effort. Then
# scripts/doctor.sh (the canonical checker, resolving binaries the SAME way the
# server does) re-verifies them and prints a remedy for any still absent. The
# installer exits with doctor.sh readiness status; individual missing DFIR
# binaries still degrade to clean BinaryNotFound at run time if an operator runs
# with reduced coverage.

echo ""
info "Installing host DFIR tools (user-space, ~/.local/bin)..."
bash "${REPO}/scripts/install-dfir-tools.sh" || warn "some DFIR tools did not install (non-fatal)."
# Make fresh ~/.local/bin installs visible to the doctor check below.
export PATH="${HOME}/.local/bin:${PATH}"

# Long-tail DFIR system packages (ausearch / nfdump / suricata), behind the
# ausearch / nfdump_query / suricata_eve tools. install-dfir-tools.sh stays
# user-space (no sudo), so these apt-only packages are installed here, and only
# under --bootstrap (the same gate as the toolchain installs above) — so a plain
# `install.sh` never sudo-prompts. Best-effort and non-fatal: a miss degrades to a
# clean BinaryNotFound the agent pivots on.
if bootstrap_enabled && command -v apt-get &> /dev/null; then
    dfir_apt_missing=()
    command -v ausearch &> /dev/null || dfir_apt_missing+=(auditd)
    command -v nfdump   &> /dev/null || dfir_apt_missing+=(nfdump)
    command -v suricata &> /dev/null || dfir_apt_missing+=(suricata)
    if [ "${#dfir_apt_missing[@]}" -gt 0 ]; then
        info "[bootstrap] installing long-tail DFIR packages: ${dfir_apt_missing[*]}"
        if [ "$(id -u)" -eq 0 ]; then
            apt-get update -qq && apt-get install -y --no-install-recommends "${dfir_apt_missing[@]}" \
                || warn "long-tail DFIR apt install failed (non-fatal; ausearch/nfdump/suricata stay BinaryNotFound)."
        elif command -v sudo &> /dev/null; then
            sudo apt-get update -qq && sudo apt-get install -y --no-install-recommends "${dfir_apt_missing[@]}" \
                || warn "long-tail DFIR apt install failed (non-fatal; ausearch/nfdump/suricata stay BinaryNotFound)."
        else
            warn "ausearch/nfdump/suricata need root/sudo to apt-install; skipping (run: sudo apt-get install -y ${dfir_apt_missing[*]})."
        fi
    else
        ok "long-tail DFIR packages present (ausearch/nfdump/suricata)."
    fi
fi

# plaso (log2timeline.py / psort.py) powers plaso_parse — the long-tail timeline
# parser behind legacy Windows .evt event logs, IE index.dat (msiecf), and broad
# super-timeline coverage. It is NOT in the default Ubuntu archive, and a bare
# `pip install plaso` builds the libyal native extensions (libfsntfs/libfsfat/…)
# from source, which fails on a box without the C toolchain + headers. So install
# it from the GIFT PPA (prebuilt; the SIFT-standard source) under the same
# --bootstrap gate as the long-tail packages above, so a plain `install.sh` never
# sudo-prompts. Best-effort and non-fatal: without plaso, plaso_parse degrades to a
# clean BinaryNotFound the agent pivots on (legacy .evt / index.dat timeline
# coverage is then SIFT-only). doctor.sh already verifies it (log2timeline.py).
if bootstrap_enabled && command -v apt-get &> /dev/null; then
    if command -v log2timeline.py &> /dev/null || command -v log2timeline &> /dev/null; then
        ok "plaso present (log2timeline.py — powers plaso_parse: legacy .evt / index.dat / super-timeline)."
    else
        info "[bootstrap] installing plaso from the GIFT PPA (plaso-tools)..."
        # Run each apt step as root directly, else via sudo, else bail to the manual remedy.
        _plaso_apt() {
            if [ "$(id -u)" -eq 0 ]; then "$@"
            elif command -v sudo &> /dev/null; then sudo "$@"
            else return 127; fi
        }
        if _plaso_apt apt-get install -y --no-install-recommends software-properties-common \
            && _plaso_apt add-apt-repository -y ppa:gift/stable \
            && _plaso_apt apt-get update -qq \
            && _plaso_apt apt-get install -y --no-install-recommends plaso-tools; then
            ok "plaso installed (log2timeline.py / psort.py)."
        else
            warn "plaso install skipped/failed (non-fatal; plaso_parse stays BinaryNotFound — legacy .evt / index.dat parsing is SIFT-only). Manual (Ubuntu): sudo add-apt-repository -y ppa:gift/stable && sudo apt-get update && sudo apt-get install -y plaso-tools"
        fi
    fi
fi

echo ""
info "Verifying DFIR tools + environment (scripts/doctor.sh)..."
if bash "${REPO}/scripts/doctor.sh"; then
    DOCTOR_STATUS=0
else
    DOCTOR_STATUS=$?
    warn "scripts/doctor.sh reported NOT READY; build artifacts may be present, but the environment still needs the remedies above."
fi

# ---------------------------------------------------------------------------
# 10. Next steps.
# ---------------------------------------------------------------------------

echo ""
echo "=========================================="
if [ "${DOCTOR_STATUS}" -eq 0 ]; then
    echo "${c_grn}VERDICT / Find Evil! is ready.${c_off}"
else
    echo "${c_yel}VERDICT / Find Evil! build complete, but environment is NOT READY.${c_off}"
    echo "Run ${c_blu}bash scripts/doctor.sh${c_off} after applying the remedies above."
fi
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
echo "       scripts/verdict /path/to/evidence.E01"
echo "     Add --sift when disk evidence should run through the SANS SIFT VM."
echo "     Interactive path: open claude or scripts/find-evil, then prompt investigate <path>."
echo ""
echo "  4. To watch the live dashboard while an investigation runs:"
echo "       pnpm --filter @findevil/web dev"
echo "     Then open ${c_blu}http://localhost:3000${c_off} in your browser."
echo "     Claude Code can open or screenshot the dashboard/report for you via"
echo "     Playwright or Puppeteer (host Chrome) — just ask: 'screenshot the dashboard'."
echo ""
echo "${c_blu}QUICK COMMAND REFERENCE${c_off}"
echo ""
echo "  bash scripts/verdict <evidence>           # canonical one-shot local mode"
echo "  bash scripts/verdict <evidence> --sift    # one-shot SIFT-VM mode"
echo "  bash scripts/verdict <evidence> --run-summary tmp/run.json"
echo "  bash scripts/find-evil                    # interactive local mode"
echo "  bash scripts/sift-vm-bootstrap.sh         # build the SIFT VM (VMware or KVM/libvirt)"
echo "  bash scripts/find-evil-sift               # SIFT-VM mode (after bootstrap)"
echo "  bash scripts/find-evil-auto <evidence>    # internal engine wrapper used by scripts/verdict"
echo "  bash scripts/run-all-smokes.sh            # full smoke gate (pre-commit)"
echo "  pnpm --filter @findevil/web dev           # start live dashboard"
echo ""
echo "${c_blu}USEFUL DOCS${c_off}"
echo ""
echo "  QUICKSTART.md              — 3-step quick start for judges and new users"
echo "  docs/false-positives.md    — analyst checklists"
echo "  docs/accuracy-report.md    — scoring and coverage method"
echo ""
echo "  To verify a signed manifest offline:"
echo "    uv run --directory services/agent_mcp python -m findevil_agent_mcp.server"
echo "    # then call the manifest_verify MCP tool"
echo ""
exit "${DOCTOR_STATUS}"
