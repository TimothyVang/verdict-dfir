# AGENTS.md

Agent instructions for **VERDICT DFIR**. This file is for Codex, OpenCode, and other coding agents that follow the `AGENTS.md` convention. Claude Code also reads `CLAUDE.md`; for Claude-specific runtime behavior, `CLAUDE.md` is authoritative.

## Start Here

- Work from the repository root.
- Install or verify prerequisites with `bash scripts/setup`; use `bash scripts/doctor.sh` for a preflight summary.
- The canonical product run is `scripts/verdict <evidence>`.
- In Claude Code, the equivalent operator shortcut is `/verdict <evidence>` or `investigate <path>`.
- Do not create or revive a separate Product CLI. `scripts/verdict`, `scripts/find-evil`, and Claude Code are the supported entry points.
- Before changing investigation behavior, read `CLAUDE.md` and the runtime files in `agent-config/`.

## Application Contract

VERDICT is a DFIR agent. It opens a Case, drives a narrow typed MCP tool surface, verifies Findings, and emits a signed Verdict plus report.

Verdict words are scoped:

- `SUSPICIOUS` - reportable evidence was found.
- `INDETERMINATE` - leads or limited coverage prevent a scoped clearance.
- `NO_EVIL` - no reportable Finding in the artifacts actually examined; never a broad clean bill of health.

## Required Guardrails

- Evidence is read-only. Never mutate source evidence, mounted evidence, or original case files.
- Every Finding must cite a current-case `tool_call_id`; uncited Findings are invalid.
- Run `verify_finding` for each Finding and record each verifier decision with `pool_handoff` before `judge_findings` consumes the Findings.
- `report_qa` must be audited before `manifest_finalize`; a failed or missing report QA gate blocks customer-ready output and requires expert review.
- Do not assert attribution, actor identity, legal breach status, or business impact.
- Do not call limited coverage clean, cleared, disproven, absent, no compromise, or proof of no evil.
- Execution claims require at least two current-case artifact classes; Amcache, ShimCache, memory-only process evidence, YARA, Hayabusa, or malfind alone is not enough.
- Exfiltration claims require collection/staging evidence plus network, tool, or data-movement evidence.
- Disk auto mode is custody-only unless `disk_mount` / `disk_extract_artifacts` produce supported parsed artifacts, either locally through Sleuth Kit/libewf or under SIFT.
- Keep `vol_pslist`, `vol_psscan`, and `vol_psxview` separate; divergence is a signal, not automatic proof.
- Optional automation, grounding, browser tools, dashboard views, and memory sidecars are not evidence and never create Findings.
- Keep timestamps UTC ISO-8601 with trailing `Z`; prefer SHA-256.

## MCP And Tool Boundaries

- `.mcp.json` registers six servers total: two audit-chain product servers (`findevil-mcp`, `findevil-agent-mcp`) plus four non-product operator convenience servers (`n8n-mcp`, `playwright`, `puppeteer`, `qmd`).
- The four non-product servers do not touch evidence, do not emit Findings, and are not in the audit chain.
- Do not add a product-default broad filesystem, shell, Docker, Kubernetes, GitHub, fetch, browser, or raw-command MCP.
- Do not add an `execute_shell` tool. DFIR subprocess behavior must stay behind allow-listed typed tools.

## Running VERDICT

Install and verify:

```bash
bash scripts/setup
bash scripts/doctor.sh
```

Run a Case:

```bash
scripts/verdict <path-to-evidence>
scripts/verdict --sift <path-to-evidence>
scripts/verdict --watch
```

Outputs land in `tmp/auto-runs/<case-id>/`. A valid completed run has:

- `verdict.json` with a scoped Verdict.
- `manifest_verify.json` with `overall: true`.
- Audited report QA state before manifest finalization.
- Findings, if any, with valid `tool_call_id` citations.
- `REPORT.html` or `REPORT.pdf` for analyst review.

## Development Commands

Focused checks:

```bash
cargo check --workspace --locked
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo fmt --all --check

uv run --directory services/agent pytest
uv run --directory services/agent_mcp pytest
ruff check .
ruff format --check .

pnpm install --frozen-lockfile
pnpm --filter @findevil/web lint
pnpm --filter @findevil/web typecheck
pnpm --filter @findevil/web build
pnpm --filter @findevil/web test

python scripts/verdict-policy-smoke.py
python scripts/report-policy-smoke.py
python scripts/path-existence-smoke.py
bash scripts/run-all-smokes.sh
```

The real done gate is a live run:

```bash
scripts/verdict <supported-evidence-path>
```

Smokes are CI predictors. They are not a substitute for a real investigation.

## Code Boundaries

- Rust MCP code lives under `services/mcp/`.
- Python domain logic lives under `services/agent/`.
- Python MCP protocol shims live under `services/agent_mcp/`.
- The web dashboard lives under `apps/web/` and uses SSE at `/api/audit`.
- Runtime DFIR behavior and role prompts live under `agent-config/`.

Do not restore removed orchestrator code under `services/agent/` such as `graph.py`, `api.py`, `cli.py`, `supervisor.py`, `specialists/`, FastAPI, or LangGraph Product runtime files. Claude Code is the investigation orchestrator.

## Release Hygiene

Do not commit or copy private/bulky evidence into public release snapshots:

- `tmp/`
- `evidence/`
- `*.E01`
- `*.dd`
- `*.mem`
- `*.evtx` unless explicitly documented as a public fixture
- VM images and OVA files
- SQLite state
- local corpora
- `.env*`, credentials, tokens, browser profiles, or session files

Public release instructions should stay application-focused: install, run, guardrails, verification, and scoped limitations.
