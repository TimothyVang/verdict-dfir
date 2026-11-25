#!/usr/bin/env bash
# scripts/verify-release.sh — one no-credential command that re-proves VERDICT's
# safety and custody claims for a reviewer.
#
# A judge can run this on a fresh clone with NOTHING but Python 3 (and optionally
# Rust) — no API key, no Claude credential, no MCP server, no network. It composes
# the existing no-key gates plus an offline re-verification of every committed
# audit/hash-chain trace, prints a PASS/SKIP/FAIL checklist, and exits non-zero on
# any failure.
#
# What it proves, in order:
#   1. Policy/custody smokes — verdict-word policy, report-QA/expert-signoff policy,
#      tool-surface count, every backtick-quoted doc path resolves, post-finalize
#      verdict/manifest tampering is rejected, and the audit-smoke regexes self-test.
#   2. Committed audit traces — re-verifies docs/release-evidence/*-trace*.jsonl
#      offline: hash-chained excerpts replay their prev_hash chain and match their
#      sealed excerpt_sha256; flat structured traces match their summary spot-check
#      finding -> tool_call -> output-hash mapping.
#   3. Rust read-only/no-execute_shell guardrail — the path-bypass tests, IF cargo
#      is available. A reviewer without Rust gets a clear SKIP, not a failure.
#
# This script does NOT reinvent any check: it calls the existing committed scripts.
# It is idempotent — it reads evidence and runs read-only gates; it never mutates
# source evidence, the working tree, or the git index.
#
# Usage:
#   bash scripts/verify-release.sh
#
# Exit 0 iff every check passed (skips do not fail). Non-zero if any check failed.

set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO}"

# Make a cargo on the user's standard install path discoverable even when the
# caller did not export it, without overriding an already-resolvable cargo.
if ! command -v cargo >/dev/null 2>&1 && [ -x "${HOME}/.cargo/bin/cargo" ]; then
    PATH="${HOME}/.cargo/bin:${PATH}"
fi

# Plain ASCII tags so a redirected CI log or a non-UTF terminal stays readable.
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

PYTHON="${PYTHON:-python3}"

passed=0
failed=0
skipped=0

# run_check LABEL COMMAND [PREREQ]
# Runs COMMAND (captured) and records PASS/FAIL. If PREREQ is given and fails,
# the check SKIPs (skips never fail the overall run).
run_check() {
    local label="$1"
    local cmd="$2"
    local prereq="${3:-}"

    if [ -n "${prereq}" ] && ! eval "${prereq}" >/dev/null 2>&1; then
        echo "  ${c_yel}[SKIP]${c_off}  ${label}  -  prerequisite not met (${prereq})"
        skipped=$((skipped + 1))
        return 0
    fi

    local output
    if output="$(eval "${cmd}" 2>&1)"; then
        local tail
        tail="$(printf '%s\n' "${output}" | grep -v '^[[:space:]]*$' | tail -1)"
        echo "  ${c_grn}[PASS]${c_off}  ${label}  -  ${tail}"
        passed=$((passed + 1))
    else
        echo "  ${c_red}[FAIL]${c_off}  ${label}"
        printf '%s\n' "${output}" | sed 's/^/         /'
        failed=$((failed + 1))
    fi
}

echo "=============================================="
echo "VERDICT — verify-release (no API key required)"
echo "=============================================="
echo
echo "${c_blu}1. Policy / custody smokes${c_off}"

run_check "verdict-word policy (compute_verdict + detect_evidence_type)" \
    "${PYTHON} scripts/verdict-policy-smoke.py"
run_check "report-QA / expert-signoff / visual-evidence policy" \
    "${PYTHON} scripts/report-policy-smoke.py" \
    "${PYTHON} -c 'import matplotlib'"
run_check "tool-surface count guard (45 product tools: 32 Rust + 13 Python)" \
    "${PYTHON} scripts/tool-count-guard.py"
run_check "path-existence (every backtick-quoted doc path resolves)" \
    "${PYTHON} scripts/path-existence-smoke.py"
run_check "trace-finding tamper rejection (post-finalize verdict/manifest edits)" \
    "${PYTHON} scripts/trace-finding-smoke.py"
run_check "audit-smoke regex self-test (protect the protectors)" \
    "${PYTHON} scripts/smoke-regex-tests.py"

echo
echo "${c_blu}2. Committed audit traces — offline integrity${c_off}"

run_check "committed-trace verifier self-test (clean verify; tampering rejected)" \
    "${PYTHON} scripts/verify-committed-traces-smoke.py"
run_check "re-verify docs/release-evidence/*-trace*.jsonl (hash chain + spot-check)" \
    "${PYTHON} scripts/verify-committed-traces.py"

echo
echo "${c_blu}3. Rust read-only / no-execute_shell guardrail${c_off}"

run_check "Rust path-bypass tests (typed paths, no shell sink)" \
    "cargo test -p findevil-mcp --test bypass_paths --locked" \
    "command -v cargo && [ -f Cargo.toml ]"

total=$((passed + failed + skipped))
echo
echo "=============================================="
if [ "${failed}" -eq 0 ]; then
    echo "${c_grn}==== ALL CHECKS PASSED ====${c_off}"
    echo "${passed} passed, ${skipped} skipped, 0 failed (of ${total})"
    echo "=============================================="
    exit 0
fi
echo "${c_red}==== SOME CHECKS FAILED ====${c_off}"
echo "${passed} passed, ${skipped} skipped, ${failed} failed (of ${total})"
echo "=============================================="
exit 1
