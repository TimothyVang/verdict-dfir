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

caseforge_contract_prereq() {
    command -v node >/dev/null 2>&1 || return 1
    command -v uv >/dev/null 2>&1 || return 1
    if [ -n "${CASEFORGE_HOME:-${CASEFORGE_ROOT:-}}" ]; then
        return 0
    fi
    [ -f ../caseforge-cloud/packages/caseforge-cli/dist/src/cli.js ] \
        || [ -f ../caseforge/packages/caseforge-cli/dist/src/cli.js ] \
        || [ -f ../caseforge-core/packages/caseforge-cli/dist/src/cli.js ] \
        || [ -f ../../verdict/caseforge/packages/caseforge-cli/dist/src/cli.js ]
}

echo "=========================================="
echo "Find Evil! - run all L1 smokes locally"
echo "=========================================="

# 1. Rust MCP server end-to-end.
run_smoke \
    "rust-mcp-smoke (34-tool catalog + core error paths)" \
    "python3 scripts/rust-mcp-smoke.py --release" \
    '[ -x "${CARGO_TARGET_DIR:-target}/release/findevil-mcp" ] || [ -x "${CARGO_TARGET_DIR:-target}/release/findevil-mcp.exe" ]'

# 2. Python agent_mcp end-to-end (synthetic).
run_smoke \
    "agent-mcp-smoke (synthetic Findings + crypto chain)" \
    "uv run --directory services/agent_mcp python ../../scripts/agent-mcp-smoke.py" \
    "[ -d services/agent_mcp ]"

# 2a. Local ed25519 seal-proof (no Spark): default + explicit ed25519 finalize
#     verifies cryptographically offline; stub signer is coerced unless
#     FINDEVIL_ALLOW_STUB_SIGNER=1. Runs when uv + agent_mcp are present; SKIPs
#     cleanly without them. When run, a seal-proof failure fails this gate.
run_smoke \
    "local-ed25519-seal-proof (offline ed25519 seals verify; stub coerced by default)" \
    "bash scripts/local-ed25519-seal-proof.sh" \
    "command -v uv && [ -d services/agent_mcp ]"

# 2b. Finding evidence-anchor firewall (P0-4): a CONFIRMED/INFERRED finding can't
# be constructed blank-cited; HYPOTHESIS leads are exempt.
run_smoke \
    "finding-schema-smoke (tool_call_id evidence-anchor firewall)" \
    "uv run --directory services/agent python ../../scripts/finding-schema-smoke.py" \
    "[ -d services/agent ]"

# 2c. Benign-explanation gate (P0-5a, opt-in): doctrine taught + schema/correlator
# downgrade an execution/intent claim lacking counter_hypothesis when the flag is on.
run_smoke \
    "benign-gate-smoke (counter_hypothesis presumption-of-benignity gate)" \
    "uv run --directory services/agent python ../../scripts/benign-gate-smoke.py" \
    "[ -d services/agent ]"

# 3. compute_verdict + detect_evidence_type policy lock.
run_smoke \
    "verdict-policy-smoke (compute_verdict + detect_evidence_type)" \
    "python3 scripts/verdict-policy-smoke.py"

# 3b. Mechanical verifier-discipline lock. Asserts every shipped Finding cites an
#     executed tool_call_output, every shipped CONFIRMED/INFERRED Finding has a
#     verifier_action and none ship rejected, counts reconcile, and recovery
#     records cite real executed tool calls. LLM-free, custody-neutral.
run_smoke \
    "verifier-discipline-smoke (audit.jsonl: anchors executed, verifier exercised, counts reconcile)" \
    "python3 scripts/verifier-discipline-smoke.py"

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

# 4b1. Restricted-conclusions report linter. A deterministic HARD gate over
# rendered output: a banned escalation term ("compromised", "exfiltration
# confirmed", "attacker", "proves", ...) may only appear when the Finding is
# backed by >=2 artifact classes, and should carry a hedge verb. Custody-neutral
# (no chain/manifest interaction); complements report-policy-smoke's QA gate.
run_smoke \
    "report-escalation-linter (banned escalation terms gated on >=2 artifact classes)" \
    "python3 scripts/report-escalation-linter.py"

# 4b2. Evidence-agnostic lock. Production code must work for ANY evidence in
# /evidence, never hard-code one image's values (CLAUDE.md hard rule). Also
# enforces the anti-enumeration / anti-fabrication finding policy (no tool-absence
# claims, no uncited CVEs, no asserted attribution/intent).
run_smoke \
    "evidence-agnostic-smoke (no image-specific hard-coding + anti-enumeration/anti-fabrication finding policy)" \
    "python3 scripts/evidence-agnostic-smoke.py"

# 4b3. Attack-flow visualizer (offline STIX/Mermaid/DOT/D2/Navigator emit). The
# presentation-only attack-flow package must produce all documented artifacts
# from a fixture case and the two JSON artifacts must parse — no API calls, no
# Findings created.
run_smoke \
    "attack-flow visualizer (offline STIX/Mermaid/summary/timeline/process-tree/Navigator emit)" \
    "python3 scripts/attackflow-smoke.py"

# 4b'. The report hook must work under the ENGINE's host python (may be 3.10), not
# just the 3.11 agent venv. Guards the regression where the visualization was
# silently dead in the live pipeline because the hook imported through the 3.11-only
# findevil_agent package. Drives the real render_report._emit_attack_flow.
run_smoke \
    "attack-flow report hook under host python (live-pipeline parity)" \
    "python3 scripts/attackflow-hostpy-smoke.py"

# 4b''. Render/INTERACTION smoke: drives the emitted HTML in headless Chrome and
# asserts on computed layout + behavior (histogram bars have real height, a facet
# chip hides rows, the brush filters the timeline, the tree renders + expands).
# The structure-only tests can't catch invisible renders or dead interactions;
# this can. SKIPs cleanly when no Chrome/Chromium is installed.
run_smoke \
    "attack-flow render/interaction (headless Chrome, skips w/o a browser)" \
    "python3 scripts/attackflow-render-smoke.py"

# 4c. Windows readiness packet smoke. It uses PacketOnly synthetic evidence
# and skips cleanly outside environments that can launch PowerShell.
run_smoke \
    "readiness-gate-smoke (PacketOnly packaging + fail-closed blockers)" \
    "uv run --directory services/agent python ../../scripts/readiness-gate-smoke.py" \
    "command -v uv && (command -v powershell || command -v pwsh)"

# 5. Launcher invariants lock.
run_smoke \
    "launcher-smoke (bash -n + claude binary + no positional .)" \
    "python3 scripts/launcher-smoke.py"

# 6. Spec/code divergence lock — asserts no active file has reintroduced
#    a bad-half pattern.
run_smoke \
    "divergence-smoke (active divergences from CLAUDE.md downstream-clean)" \
    "python3 scripts/divergence-smoke.py"

# 7. Path-existence audit — every backtick-quoted path discovered in
#    operator docs resolves to a real file/dir as new docs, agent config,
#    and service README files are added.
run_smoke \
    "path-existence-smoke (every backtick-quoted path resolves to a real file/dir)" \
    "python3 scripts/path-existence-smoke.py"

# 7b. Repo-layout audit — the repo root may only hold sanctioned config files,
#     public docs, and known top-level dirs; a stray tracked-or-un-ignored entry
#     (loose note, duplicate asset folder, scratch dir) fails this gate.
run_smoke \
    "repo-layout-smoke (no un-sanctioned tracked/un-ignored entries at repo root)" \
    "python3 scripts/repo-layout-smoke.py"

# 7b1. Benchmark corpus manifest lock — goldens/CORPUS.json must stay well-formed
#      and every scoreable case must point at a real golden, so a broken corpus
#      entry is caught before an operator kicks off a long scripts/benchmark run.
#      (The runner itself needs staged evidence, so it stays OUT of this gate.)
run_smoke \
    "benchmark-smoke (CORPUS.json schema + golden wiring + runner syntax)" \
    "python3 scripts/benchmark-smoke.py"

# 7c. Containment regression lock — every MCP launcher + scripts/verdict must keep
#     sourcing scripts/lib/project-env.sh and .mcp.json must launch through the
#     wrappers, so all runtime + toolchain state stays inside .project-local/.
run_smoke \
    "containment-smoke (runtime + toolchain stay in .project-local/)" \
    "python3 scripts/containment-smoke.py"

# 8b. Trace-finding tamper detection — verdict and manifest edits after finalize
#     must break offline tracing.
run_smoke \
    "trace-finding-smoke (reject post-finalize verdict/manifest tampering)" \
    "python3 scripts/trace-finding-smoke.py"

# 8b-1. Committed sample-run custody fixture — the /home-free public run in
#       docs/release-evidence/sample-run must keep tracing (exit 0), verify
#       (manifest_verify overall=true), and leak no absolute /home path.
run_smoke \
    "sample-run-trace-smoke (committed fixture traces, verifies, no /home leak)" \
    "python3 scripts/sample-run-trace-smoke.py"

# 8b-1a. CaseForge contract gate — when a sibling CaseForge checkout is present,
#       prove this Dev VERDICT tree exposes the release MCP binary + launchers
#       from any CWD, stores CaseForge-created cases under .project-local, and
#       remains consumable by CaseForge verify without leaking host paths.
run_smoke \
    "caseforge-contract-smoke (MCP launchers + .project-local case store + CaseForge verify)" \
    "python3 scripts/caseforge-contract-smoke.py" \
    "caseforge_contract_prereq"

# 8b-0. Evidence traceability index — the deterministic, read-only finding ->
#       tool_call_id -> audit line + output_sha256 join must resolve a clean run
#       and surface a tampered audit line as UNRESOLVED.
run_smoke \
    "evidence-traceability-index-smoke (deterministic join; tamper -> UNRESOLVED)" \
    "python3 scripts/evidence-traceability-index-smoke.py"

# 8b-2. Committed-trace integrity — the offline verify-release entrypoint re-checks
#       every docs/release-evidence/*-trace*.jsonl against its sealed summary; this
#       smoke pins that a clean trace verifies and any record edit is rejected.
run_smoke \
    "verify-committed-traces-smoke (clean trace verifies; tampering rejected)" \
    "python3 scripts/verify-committed-traces-smoke.py"

# 8c. install.sh --bootstrap contract — opt-in prereq install stays gated and the
#     default path stays fail-closed on a missing toolchain.
run_smoke \
    "install-bootstrap-smoke (--bootstrap gated; default stays fail-closed)" \
    "python3 scripts/install-bootstrap-smoke.py"

# 9. Self-test the audit-smoke regexes themselves (protect the protectors).
run_smoke \
    "smoke-regex-tests (synthetic +/- cases against audit-smoke regex/helper policies)" \
    "python3 scripts/smoke-regex-tests.py"

run_smoke \
    "pretooluse-deny-hook-smoke (optional OS-level allow-list deny-hook: forensic binary -> exit 0, curl/rm -> blocked)" \
    "python3 scripts/pretooluse-deny-hook-smoke.py"

# 10. Phase 2 cross-platform smokes (render, sift config, starter data, find-evil-run).
run_smoke \
    "render-binary-smoke (pandoc/chrome resolve via PATH, graceful degrade)" \
    "python3 scripts/render-binary-smoke.py"

run_smoke \
    "starter-data-smoke (SANS_STARTER_URL contract + goldens stub)" \
    "python3 scripts/starter-data-smoke.py"

run_smoke \
    "golden-answer-key-smoke (all committed expected-findings schemas valid)" \
    "python3 scripts/golden-answer-key-smoke.py"

# P0-3: the run engine must never read the answer key — only the post-run scorer may.
run_smoke \
    "goldens-keyblind-smoke (run engine never reads the answer key)" \
    "python3 scripts/goldens-keyblind-smoke.py"

# P0-1/2: the committed accuracy report keeps recall and grounding as two labeled
# axes (never one blended number) and names each caught false-positive.
run_smoke \
    "accuracy-report-smoke (two-axis accuracy report well-formed)" \
    "python3 scripts/accuracy-report-smoke.py"

run_smoke \
    "toolless-negative-control-smoke (tool-less run scores recall=0; hallucination posture disclosed separately)" \
    "python3 scripts/toolless-negative-control-smoke.py"

run_smoke \
    "windows-goldens-smoke (Windows log/memory/disk golden inventory)" \
    "python3 scripts/windows-goldens-smoke.py"

run_smoke \
    "verdict-smoke (the one command, --dry-run)" \
    "python3 scripts/verdict-smoke.py"

run_smoke \
    "regenerate-sample-run-smoke (provenance scrub + custody-bound verbatim boundary)" \
    "python3 scripts/regenerate-sample-run-smoke.py"

run_smoke \
    "make-demo-video-smoke (TTS+ffmpeg video builder, --dry-run)" \
    "python3 scripts/make-demo-video-smoke.py"

run_smoke \
    "package-devpost-smoke (submission zip smoke mode)" \
    "mkdir -p tmp && FINDEVIL_DEVPOST_MODE=smoke RELEASE_TAG=v-submit-smoke OUT_ZIP=tmp/package-devpost-smoke.zip RELEASE_ASSETS_DIR=tmp/package-devpost-assets BENCHMARK_CSV=tmp/package-devpost-benchmark.csv bash scripts/package-devpost.sh"

# 10b. Soft Spark/Ollama reachability. GET /api/tags with a short timeout.
#      Always exit 0: PASS when reachable (prints model names), SKIP when
#      offline or curl missing — never fails CI for a cold Spark box.
run_smoke \
    "spark-endpoint-smoke (GET /api/tags; SKIP when Spark offline)" \
    "bash scripts/spark-endpoint-smoke.sh"

# 10c. nhc-003 carve measurement status. Exit 0 with STATUS=UNMEASURED or
#      STATUS=PARTIAL_PROBE_UNMEASURED — never invents recall %.
run_smoke \
    "nhc003-carve-status (UNMEASURED/PARTIAL_PROBE_UNMEASURED; never prints recall %)" \
    "bash scripts/nhc003-carve-status.sh"

# 11. Post-verdict grounding contract. Offline checks (claim extraction, bundle
#     merge, never-evidence boundary) always run; the live anti-hallucination
#     checks self-skip cleanly when the n8n webhook is down.
run_smoke \
    "grounding-smoke (claim extraction + boundary + anti-hallucination contract)" \
    "python3 scripts/grounding-smoke.py" \
    "[ -f scripts/ground_verdict.py ]"

# 11b. Fact-fidelity rejection rate. Measures the deterministic entailment check
#      against seeded false values across every match mode (target: 100% rejected,
#      100% of true values still accepted). Runs under the services/agent uv env
#      because it imports findevil_agent; SKIPs cleanly without uv.
run_smoke \
    "fact-fidelity-rate (seeded-fabrication rejection rate == 1.0 across all match modes)" \
    "uv run --directory services/agent python ../../scripts/fact-fidelity-rate.py" \
    "command -v uv && [ -d services/agent ]"

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

# Rust lint/test gates. The ruff pair and cargo fmt are above; clippy and
# test go here. cargo test is the
# slowest entry (~20s cached); set SKIP_SLOW_RUST=1 to skip it during fast
# iteration.
run_smoke \
    "cargo clippy --deny warnings (Rust lint clean — matches L0 GHA gate)" \
    "cargo clippy --workspace --all-targets --locked -- -D warnings" \
    "command -v cargo && [ -f Cargo.toml ]"
if [ "${SKIP_SLOW_RUST:-0}" != "1" ]; then
    run_smoke \
        "cargo test --workspace --locked (Rust test suite)" \
        "cargo test --workspace --locked" \
        "command -v cargo && [ -f Cargo.toml ]"
fi

# 12. Verifier-regression catch-rate guard. Runs a committed known-bad findings
#     corpus (attribution overclaim, phantom PID, single-citation CONFIRMED
#     execution, exfil-without-staging) through the real verifier + correlator
#     stages and asserts a minimum catch-rate, so a gate cannot silently weaken.
#     Runs under the services/agent uv env (imports findevil_agent); SKIPs cleanly
#     without uv.
run_smoke \
    "verifier-regression-smoke (known-bad findings corpus catch-rate floor)" \
    "uv run --directory services/agent pytest tests/test_verifier_regression.py -q" \
    "command -v uv && [ -d services/agent ]"

# 13. Zero-dependency offline manifest verifier. A standalone, stdlib-only
#     re-derivation of the run.manifest custody (per-line hash chain + Merkle root
#     + vendored pure-Python Ed25519 signature) that imports ZERO production code,
#     run with --check against the committed /home-free public sample-run so it
#     must agree with the committed product manifest_verify.json. Plain python3 —
#     no uv/venv/cryptography wheel.
run_smoke \
    "manifest-verify-offline-smoke (stdlib-only re-derivation agrees with committed sample-run)" \
    "python3 scripts/manifest-verify-offline.py docs/release-evidence/sample-run/run.manifest.json --check"

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
echo "  uv sync --directory services/agent --extra dev (Python 3.11 in services/agent)"
echo "  uv sync --directory services/agent_mcp --extra dev (Python 3.11 in services/agent_mcp)"
echo "=========================================="
exit 1
