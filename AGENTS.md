# AGENTS.md

Compact OpenCode guidance for this repo. `CLAUDE.md` is still authoritative; use this as the quick adapter layer and read the cited source before touching that subsystem.

## Start Here

- Product path for SANS judging is Claude Code from repo root: `scripts/find-evil` or `claude`; do not revive a separate Product CLI.
- Before investigating evidence or changing investigation behavior, read in order: `CLAUDE.md`, `agent-config/SOUL.md`, `agent-config/AGENTS.md`, `agent-config/PLAYBOOK.md`, `agent-config/TOOLS.md`, `agent-config/MEMORY.md`, `agent-config/EXPERT.md`, `agent-config/HEARTBEAT.md`, `agent-config/JUDGING.md`.
- Trust executable config over old plans/spec prose. `CLAUDE.md` records known spec/code divergences; append a new one there if you confirm intentional drift.
- Evidence and local corpora are read-only and ignored: `*.E01`, `*.evtx`, `*.mem`, `tmp/`, `test-forensics/`, VM images, and SQLite state must not be committed.

## Continuous Timebox Runs

When the user requests a continuous timed run, such as 8 hours:

- Hard blockers are scoped approval blockers, not run blockers.
- External, credentialed, paid, destructive, public, browser-account, or production actions must be parked with an approval packet.
- After parking a blocker, continue safe local work until the timebox expires or the user explicitly stops the run.
- An empty unblocked queue is not a stop condition before the timebox expires.
- If the queue is empty, create safe local follow-up work from repo evidence: stale verification, docs drift, smokes, tests, readiness checks, packaging validation, TODOs, cleanup of recently touched code, or regression coverage.
- Do not send a final response while time remains.
- Only stop when the timebox expires or the user explicitly says to stop.

## Architecture Boundaries

- `.mcp.json` is the canonical local MCP config: `findevil-mcp` via `cargo run --release -p findevil-mcp --quiet`, and `findevil-agent-mcp` via `uv run --directory services/agent_mcp python -m findevil_agent_mcp.server`.
- Expected MCP surface is 31 tools: 19 Rust DFIR tools in `services/mcp/`, 12 Python crypto/ACH/memory/ACP/expert-feedback tools in `services/agent_mcp/`.
- Do not add product-default MCPs for filesystem, git, browser, Docker, Kubernetes, GitHub, fetch, shell, or any raw-command passthrough.
- SIFT mode is encoded in `.mcp.json.sift` and launched by `bash scripts/find-evil-sift`; do not rewrite user-level Claude/Codex config unless explicitly asked.
- `services/agent/` is a library (`findevil_agent`) imported by `services/agent_mcp/`; A2 forbids restoring `graph.py`, `api.py`, `cli.py`, `supervisor.py`, `specialists/`, FastAPI, or LangGraph Product orchestrator code there.
- Python package names are `findevil_agent` and `findevil_agent_mcp`; old `services.*` imports are plan-era drift.
- Rust MCP uses a hand-rolled stdio JSON-RPC server in `services/mcp/src/server.rs`; `rmcp` is intentionally not a runtime dependency.
- `apps/web/` is the only live pnpm workspace package. `apps/mcp-widgets/` remains deferred.

## Investigation Rules

- Every Finding must cite `tool_call_id`; verifier rejects uncited findings.
- `verify_finding` runs before `judge_findings`; verifier decisions must be recorded with `pool_handoff` before the judge consumes them.
- `report_qa` must be audited before `manifest_finalize`; a failed report QA gate blocks customer-ready output and requires expert review.
- Execution claims require at least two artifact classes. Amcache/ShimCache presence alone is not execution; Prefetch absence is not absence of execution.
- Exfiltration claims require finding-specific collection/staging plus network, tool, or data-movement evidence; case-global coverage is not enough.
- Treat Hayabusa, Sigma, YARA, capa/anomaly, malfind, and malware-triage output as leads until corroborated.
- Memory process analysis must keep `vol_pslist`, `vol_psscan`, and `vol_psxview` separate; pslist/psscan divergence is the DKOM/T1014 signal.
- Auto disk mode in `scripts/find-evil-auto` is custody-only unless mounted/extracted artifacts are supplied; `case_open` alone is not a disk-content Finding or `NO_EVIL` support.
- Do not say limited coverage is clean, cleared, disproven, absent, or proof of no evil. Use `NO_EVIL` only per `docs/verdict-semantics.md` and state scope limits.
- `attack_story`, `report_evidence_cards`, visual timelines, and practitioner coverage are report aids only; they never create Findings or raise confidence.
- A5 removed `ots_stamp`, `ots_verify`, OpenTimestamps, and Bitcoin attestation runtime behavior; custody is audit `prev_hash` links -> Merkle root -> sigstore.
- Never assert attribution. Keep timestamps UTC ISO-8601 with trailing `Z`; prefer SHA-256.

## Live Tests

- We already have runners; do not build new ones. The bar: drop ANY supported evidence type into `evidence/`, run `scripts/verdict`, and the app must run the real DFIR process and emit an honest Verdict — across every supported type.
- Canonical runner: `scripts/verdict <path>` or `scripts/verdict --watch` (drop into `evidence/`). Output: `tmp/auto-runs/<case-id>/`.
- PASS = (1) pipeline ran past `case_open`; (2) every Finding cites a `tool_call_id`; (3) `manifest_verify.json` `overall=true`; (4) the Verdict matches coverage honestly — limited coverage is `INDETERMINATE` or scoped `NO_EVIL`, never an upgraded claim or attribution. PASS does not require `SUSPICIOUS`; an honest `INDETERMINATE` is a PASS.
- Per-type expectations + current gaps: the live-test matrix in `CLAUDE.md` §5 and `agent-config/PLAYBOOK.md`. evtx works today; raw disk is custody-only/`INDETERMINATE` unless mounted+extracted; memory can show acquisition-smear false-DKOM; `registry_query` is partial.
- Smokes are not live tests — see Developer Commands.

## Developer Commands

- Initial Product preflight: `bash scripts/install.sh` builds `target/release/findevil-mcp`, syncs `services/agent_mcp`, and checks Claude credential mode.
- Interactive investigation: `scripts/find-evil` or `claude` from repo root. The Claude CLI binary is `claude`, not `claude-code`, and it uses cwd rather than a positional project path.
- SIFT VM investigation: `bash scripts/sift-vm-bootstrap.sh` once, then `bash scripts/find-evil-sift`; VMware Workstation is the implemented launcher path.
- Headless single-shot: `bash scripts/find-evil-auto <evidence-path-inside-VM> --unattended`; outputs mirror to `tmp/auto-runs/auto-<uuid>/`.
- Headless automation summary: add `--run-summary <path>` to `find-evil-auto` to write a machine-readable pointer/QA JSON with run IDs, artifact paths, report QA, release-gate/expert-signoff state, readiness state, blockers, and warnings.
- Live test (the dev "done" gate): `scripts/verdict evidence/<file>` (or `scripts/verdict --watch` + drop a file into `evidence/`). Done = a real `verdict.json` with `tool_call_id`-cited Findings and `manifest_verify` `overall=true` — not smokes passing. An honest `INDETERMINATE` / scoped `NO_EVIL` per `docs/verdict-semantics.md` is a passing outcome. See Live Tests above.
- Local smoke runners (CI predictor, optional): build/sync first with `cargo build --release -p findevil-mcp --locked` and `uv sync --directory services/agent_mcp --extra dev`, then run `bash scripts/run-all-smokes.sh` on POSIX/Git Bash or `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/run-all-smokes.ps1` on native Windows. L1 CI runs these; locally they only predict CI; they are not live tests.
- Readiness packet: use `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/readiness-gate.ps1 -Mode Full -EvidencePath <path-inside-sift-vm> -RunL1Docker` on native Windows. It writes `readiness-summary.json`, `readiness-packet-manifest.json`, and `readiness-packet.zip` under `tmp/readiness-gates/<run-id>/`; fixed `-RunId` reruns refresh generated packet contents and can use a timestamped local-build child run; passing state is ready for expert review, not customer release. `scripts/readiness-gate.sh` is POSIX strict/check-only and does not create the packet ZIP.
- L1 CI-equivalent container: `docker compose -f docker/l1-compose.yml up --build --exit-code-from l1`.

## Focused Checks

These are narrow CI-equivalent checks for fast feedback; they verify wiring, not a real investigation. For end-to-end verification use a live test (see Live Tests).

- Rust lint: `cargo check --workspace --locked`; `cargo clippy --workspace --all-targets --locked -- -D warnings`; `cargo fmt --all --check`.
- Rust tests: `cargo test --workspace --locked`; single MCP integration file: `cargo test -p findevil-mcp --test tool_smoke`; crate unit tests: `cargo test -p findevil-mcp --lib`.
- Python lint/format from repo root: `ruff check .`; `ruff format --check .`.
- Python service tests use per-service uv projects, not a root `pyproject.toml`: `uv run --directory services/agent pytest`, `uv run --directory services/agent_mcp pytest`.
- Single Python test example: `uv run --directory services/agent pytest tests/test_crypto_audit_log.py::TestCanonicalize::test_sorted_keys -v`.
- Web install/build/test: `pnpm install --frozen-lockfile`; `pnpm --filter @findevil/web lint`; `pnpm --filter @findevil/web typecheck`; `pnpm --filter @findevil/web build`; `pnpm --filter @findevil/web test`.
- Web single test file: `pnpm --filter @findevil/web test -- __tests__/audit-tail.test.ts`.
- Regenerate web event types after Pydantic event changes: `pnpm --filter @findevil/web codegen:events`.
- MCP smokes: `python scripts/rust-mcp-smoke.py` after the release binary exists; `uv run --directory services/agent_mcp python ../../scripts/agent-mcp-smoke.py`.
- Verdict/report policy smokes: `python scripts/verdict-policy-smoke.py`; `python scripts/report-policy-smoke.py`; after docs/report text changes also run `python scripts/path-existence-smoke.py`.

## Repo-Specific Gotchas

- `Cargo.lock` is intentionally committed because this ships a binary; do not remove it or add it to ignores.
- Pinned versions matter: Rust toolchain is `1.88.0`; Python is `>=3.11,<3.13`; CI uses Node 20 and pnpm 9.12.0; ruff is pinned to `0.7.4` in L0.
- New Rust MCP tools need a module under `services/mcp/src/tools/`, registration in `services/mcp/src/server.rs`, typed schemas, safe errors, and tests under `services/mcp/tests/`; tool inputs should deny unknown fields.
- New Python MCP tools are registered by adding a module exporting `SPEC` and listing it in `services/agent_mcp/findevil_agent_mcp/tools/__init__.py`; domain logic belongs in `services/agent/`.
- Web dashboard audit tail is SSE at `/api/audit`, not WebSocket; allowed case roots live in `apps/web/lib/audit-tail.ts` and `FINDEVIL_DASHBOARD_EXTRA_ROOTS` extends them.
- Codex dashboard support lives at `.agents/skills/dashboard` and `http://localhost:3000/codex`; manual fallback is `powershell -ExecutionPolicy Bypass -File scripts/codex-dashboard.ps1`.
- The `/api/codex` one-shot runner is local-only and disabled unless `FINDEVIL_CODEX_UI_ENABLE=1`; it expects a built Rust MCP binary for evidence modes.
- `manifest_verify` is an MCP/library verification path, not a standalone shell command; do not put `manifest_verify <file>` in customer-facing instructions unless a wrapper exists.
- `scripts/run-all-smokes.sh` and `scripts/run-all-smokes.ps1` are the local CI-predictor smoke runners (what L1 runs); they are not live tests. Do not hard-code smoke counts in docs; the runners print the current tally. Treat source/README/tool registry as authoritative for MCP counts.
