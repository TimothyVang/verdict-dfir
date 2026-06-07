#!/usr/bin/env bash
# scripts/run-all-smokes.sh — run local smoke/lint/test gates outside docker.
#
# A developer iterating locally on the typed MCP surface, find-evil-auto's
# verdict policy, fleet_correlate's filter logic, or the demo script's
# timing should not have to wait for a docker compose build to find out
# they broke something. This script complements docker/l1-compose.yml
# with a fast local gate and final tally; Docker still runs broader
# cargo/pytest/pnpm checks in an Ubuntu container.
#
# Usage:
#   bash scripts/run-all-smokes.sh
#
# Exits 0 if every smoke passed; non-zero if any failed.
#
# Pre-flight: requires `cargo build --release -p findevil-mcp` (the Rust
# smoke resolves the release binary under `${CARGO_TARGET_DIR:-target}`) and
# `uv sync` in services/agent_mcp (the agent_mcp smoke spawns the Python MCP server).

set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO}"

# Skip ANSI color codes when stdout isn't a TTY (CI logs, file
# redirects, Windows cmd.exe without ENABLE_VIRTUAL_TERMINAL_
# PROCESSING). Colors are nice-to-have for interactive terminals;
# raw escape sequences in a CI log file are noise.
if [ -t 1 ]; then
    c_red=$'\033[0;31m'
    c_grn=$'\033[0;32m'
    c_yel=$'\033[0;33m'
    c_blu=$'\033[0;34m'
    c_off=$'\033[0m'
else
    c_red=""
    c_grn=""
    c_yel=""
    c_blu=""
    c_off=""
fi

passed=0
failed=0
skipped=0

run_smoke() {
    local label="$1"
    local cmd="$2"
    local prereq="${3:-}"
    echo
    echo "${c_blu}━━━ ${label} ━━━${c_off}"

    if [ -n "${prereq}" ] && ! eval "${prereq}" >/dev/null 2>&1; then
        echo "${c_yel}  SKIP: prerequisite not met (${prereq})${c_off}"
        skipped=$((skipped + 1))
        return 0
    fi

    local start=${SECONDS}
    if eval "${cmd}"; then
        local elapsed=$((SECONDS - start))
        echo "${c_grn}  ✓ ${label} passed (${elapsed}s)${c_off}"
        passed=$((passed + 1))
    else
        local elapsed=$((SECONDS - start))
        echo "${c_red}  ✗ ${label} FAILED (${elapsed}s)${c_off}"
        failed=$((failed + 1))
    fi
}

echo "=========================================="
echo "Find Evil! - run all L1 smokes locally"
echo "=========================================="

# 1. Rust MCP server end-to-end.
run_smoke \
    "rust-mcp-smoke (19-tool dispatch + error paths)" \
    "python3 scripts/rust-mcp-smoke.py --release" \
    '[ -x "${CARGO_TARGET_DIR:-target}/release/findevil-mcp" ] || [ -x "${CARGO_TARGET_DIR:-target}/release/findevil-mcp.exe" ]'

# 2. Python agent_mcp end-to-end (synthetic).
run_smoke \
    "agent-mcp-smoke (synthetic Findings + crypto chain)" \
    "uv run --directory services/agent_mcp python ../../scripts/agent-mcp-smoke.py" \
    "[ -d services/agent_mcp ]"

# 3. compute_verdict + detect_evidence_type policy lock.
run_smoke \
    "verdict-policy-smoke (compute_verdict + detect_evidence_type)" \
    "python3 scripts/verdict-policy-smoke.py"

# 4. fleet_correlate pure-function lock.
run_smoke \
    "fleet-policy-smoke (normalize/filter/cluster/density/uniqueness/aggregate)" \
    "python3 scripts/fleet-policy-smoke.py"

# 4b. Customer-facing report policy lock. This is intentionally part of the
# default smoke gate because report QA / expert signoff is a release blocker,
# not an optional documentation check.
run_smoke \
    "report-policy-smoke (report QA + expert signoff + visual evidence policy)" \
    "python3 scripts/report-policy-smoke.py"

# 4c. Windows readiness packet smoke. It uses PacketOnly synthetic evidence
# and skips cleanly outside environments that can launch PowerShell.
run_smoke \
    "readiness-gate-smoke (PacketOnly packaging + fail-closed blockers)" \
    "python3 scripts/readiness-gate-smoke.py" \
    "command -v uv && (command -v powershell || command -v pwsh)"

# 5. demo-script-a2.md structural lock.
run_smoke \
    "demo-script-smoke (9 contiguous beats summing to 5:00)" \
    "python3 scripts/demo-script-smoke.py" \
    "[ -f docs/demo-script-a2.md ]"

# 6. Launcher invariants lock.
run_smoke \
    "launcher-smoke (bash -n + claude binary + no positional .)" \
    "python3 scripts/launcher-smoke.py"

# 7. Spec/code divergence lock — asserts no active file has reintroduced
#    a bad-half pattern.
run_smoke \
    "divergence-smoke (active divergences from CLAUDE.md downstream-clean)" \
    "python3 scripts/divergence-smoke.py"

# 8. Path-existence audit — every backtick-quoted path discovered in
#    operator docs resolves to a real file/dir as new docs, agent config,
#    and service README files are added.
run_smoke \
    "path-existence-smoke (every backtick-quoted path resolves to a real file/dir)" \
    "python3 scripts/path-existence-smoke.py"

# 9. Self-test the audit-smoke regexes themselves (protect the protectors).
run_smoke \
    "smoke-regex-tests (synthetic +/- cases against audit-smoke regex/helper policies)" \
    "python3 scripts/smoke-regex-tests.py"

# 10. Autonomous-loop CLI behavior smoke.
run_smoke \
    "autonomous-loop-smoke (8h dry-run + tiny empty-queue timing)" \
    "python3 scripts/autonomous-loop-smoke.py"

# 11. Phase 2 cross-platform smokes (render, sift config, starter data, find-evil-run).
run_smoke \
    "render-binary-smoke (pandoc/chrome resolve via PATH, graceful degrade)" \
    "python3 scripts/render-binary-smoke.py"

run_smoke \
    "starter-data-smoke (SANS_STARTER_URL contract + goldens stub)" \
    "python3 scripts/starter-data-smoke.py"

run_smoke \
    "find-evil-run-smoke (one-command operator entry, --dry-run)" \
    "python3 scripts/find-evil-run-smoke.py"

# Lint / format gates. L0 GHA workflow runs these too; mirror them locally
# so a contributor running this script before commit catches a missing
# `ruff format` or unformatted Rust before the push. Each gate uses
# `command -v` so a stripped install SKIPs cleanly.
run_smoke \
    "ruff check . (lint clean across all Python services)" \
    "ruff check ." \
    "command -v ruff"
run_smoke \
    "ruff format --check . (formatter clean — matches L0 GHA gate)" \
    "ruff format --check ." \
    "command -v ruff"
run_smoke \
    "cargo fmt --all --check (Rust formatter clean — matches L0 GHA gate)" \
    "cargo fmt --all --check" \
    "command -v cargo && [ -f Cargo.toml ]"

# Rust lint/test gates from the autonomous-loop verification spec. The ruff
# pair and cargo fmt are above; clippy and test go here. cargo test is the
# slowest entry (~20s cached); set SKIP_SLOW_RUST=1 to skip it during fast
# iteration.
run_smoke \
    "cargo clippy --deny warnings (Rust lint clean — matches L0 GHA gate)" \
    "cargo clippy --workspace --all-targets --locked -- -D warnings" \
    "command -v cargo && [ -f Cargo.toml ]"
if [ "${SKIP_SLOW_RUST:-0}" != "1" ]; then
    run_smoke \
        "cargo test --workspace --locked (Rust test suite — matches autonomous-loop verification spec)" \
        "cargo test --workspace --locked" \
        "command -v cargo && [ -f Cargo.toml ]"
fi

total=$((passed + failed + skipped))
echo
echo "=========================================="
if [ "${failed}" -eq 0 ]; then
    echo "${c_grn}OK${c_off} - ${passed} passed, ${skipped} skipped, 0 failed (of ${total})"
    echo "=========================================="
    exit 0
fi
echo "${c_red}FAIL${c_off} - ${passed} passed, ${skipped} skipped, ${failed} failed (of ${total})"
echo "The CI-equivalent gate runs via docker/l1-compose.yml. If a smoke"
echo "fails locally and passes in Docker/CI, check toolchain versions:"
echo "  cargo build --release -p findevil-mcp  (Rust 1.88 per rust-toolchain.toml)"
echo "  uv sync --directory services/agent_mcp --extra dev (Python 3.11 in services/agent_mcp)"
echo "=========================================="
exit 1
