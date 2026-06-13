# CLAUDE.md

This file is the Claude Code operating contract for **VERDICT DFIR**. It is public-release guidance for running and maintaining the application, not a private development diary.

## What VERDICT Is

VERDICT is a DFIR agent that runs inside Claude Code. Point it at supported evidence and it opens a **Case**, drives the typed read-only MCP tool surface, verifies every Finding, and writes a signed **Verdict** plus analyst report.

Canonical one-shot path:

```bash
bash scripts/setup
scripts/verdict <path-to-evidence>
```

Interactive Claude Code path:

```bash
claude
# then type one of:
/verdict <path-to-evidence>
investigate <path-to-evidence>
```

Verdict words are strictly scoped:

- `SUSPICIOUS` means VERDICT found reportable evidence.
- `INDETERMINATE` means leads or limited coverage prevent a scoped clearance.
- `NO_EVIL` means no reportable Finding in the artifacts actually examined. It is never a whole-environment clean bill of health.

## Required Setup

Run setup from the repository root before the first Case:

```bash
bash scripts/setup
```

That path installs or checks the product prerequisites it can manage, builds the Rust MCP server, syncs the Python MCP environment, installs supported helper tooling, and runs the preflight doctor.

Minimum required runtime surface:

- Claude Code credential: `CLAUDE_CODE_OAUTH_TOKEN`, logged-in `claude`, or `ANTHROPIC_API_KEY`.
- Rust/Cargo pinned by `rust-toolchain.toml`.
- Python 3.11-3.12 and `uv`.
- `git` and `unzip`.
- Node 20 and `pnpm` when using the live dashboard.

Useful checks:

```bash
bash scripts/doctor.sh
bash scripts/doctor.sh --json
bash scripts/install.sh
```

SIFT VM mode is recommended for full disk-image extraction. Local mode can handle memory, EVTX, PCAP, Velociraptor collections, and extracted artifacts. Raw disk images such as `.E01`, `.dd`, `.raw`, and `.aff` without SIFT or supplied extracted artifacts are custody-only and must not produce broad disk-content claims.

## Investigation Read Order

When the user asks to investigate evidence, read these files before interpreting results or drafting Findings:

1. `agent-config/SOUL.md` - role, epistemic hierarchy, refusal rules.
2. `agent-config/AGENTS.md` - supervisor, Pool A, Pool B, verifier, judge, correlator.
3. `agent-config/PLAYBOOK.md` - evidence-type tool sequences.
4. `agent-config/TOOLS.md` - product MCP tool surface and intended use.
5. `agent-config/MEMORY.md` - DFIR caveats and artifact interpretation traps.
6. `agent-config/EXPERT.md` - expert-signoff doctrine and report QA rules.
7. `agent-config/HEARTBEAT.md` - liveness and prompt-injection self-checks.

Read `agent-config/JUDGING.md` only for after-the-fact self-assessment of a completed Case. It is not part of the live investigation flow.

## Non-Negotiable Guardrails

These rules are part of the product safety boundary.

- Evidence is read-only. Do not modify source evidence, mounted evidence, or original case files.
- Call `case_open` before evidence analysis whenever using the MCP tool surface.
- Every Finding must cite a valid `tool_call_id` from the current Case.
- Run `verify_finding` for each Finding and record each verifier decision with `pool_handoff` before `judge_findings` consumes the Findings.
- `report_qa` must be audited before `manifest_finalize`; a failed or missing report QA gate blocks customer-ready output and requires expert review.
- `manifest_finalize` is the terminal custody step for a completed Case.
- Execution claims require at least two current-case artifact classes. Amcache, ShimCache, memory-only process evidence, Hayabusa, YARA, or malfind alone is not execution proof.
- Exfiltration claims require finding-specific collection or staging plus network, tool, or data-movement evidence.
- Treat Hayabusa, Sigma, YARA, capa/anomaly, malfind, and malware-triage output as leads until corroborated.
- Keep `vol_pslist`, `vol_psscan`, and `vol_psxview` analytically separate. pslist/psscan divergence can indicate DKOM/T1014, but acquisition smear must be ruled out.
- Do not assert attribution, actor identity, intent, legal breach status, or business impact from host artifacts.
- Do not say limited coverage is clean, cleared, disproven, absent, no compromise, or proof of no evil.
- Use UTC ISO-8601 timestamps with trailing `Z`; prefer SHA-256.
- Optional automation, grounding, browser tools, dashboards, and memory sidecars are never evidence and never create Findings.

## Tool Surface Boundary

`.mcp.json` registers six local MCP servers:

- Product/audit-chain servers: `findevil-mcp` and `findevil-agent-mcp`.
- Operator convenience servers: `n8n-mcp`, `playwright`, `puppeteer`, and `qmd`.

Only the two product servers can emit audit-chain tool calls for Findings. The operator convenience servers must never emit Findings, satisfy Finding citations, or mutate evidence.

Do not add a broad filesystem, shell, Docker, Kubernetes, browser, GitHub, fetch, or raw-command MCP to the product surface. Do not add an `execute_shell` tool. Long-tail DFIR execution belongs behind allow-listed typed tools such as `vol_run`, `ez_parse`, `plaso_parse`, `mac_triage`, and `cloud_audit`.

## Running A Case

Preferred one-shot run:

```bash
scripts/verdict <path-to-evidence>
```

SIFT mode when the evidence path is accessible inside the SIFT VM:

```bash
scripts/verdict --sift <path-to-evidence>
```

Watch mode:

```bash
scripts/verdict --watch
```

Outputs land under:

```text
tmp/auto-runs/<case-id>/
```

Expected high-value outputs:

- `audit.jsonl` - hash-chained process and tool-call record.
- `verdict.json` - scoped Verdict and Findings.
- `coverage_manifest.json` - available/attempted/parsed/unsupported artifact classes.
- `run.manifest.json` - signed manifest.
- `manifest_verify.json` - offline verification result.
- `REPORT.html` / `REPORT.pdf` - analyst report.

A run is not complete unless the pipeline reaches `case_open`, all Findings cite `tool_call_id`, `report_qa` is audited, and `manifest_verify.json` reports `overall: true` for the completed manifest. If `manifest_verify.json` is missing or `overall` is not `true`, report `RUN INCOMPLETE / CUSTODY INVALID` and do not describe the output as signed or customer-ready.

## Development Rules

When modifying VERDICT, keep changes small and evidence-safe.

- Prefer surgical diffs over rewrites.
- Follow existing Rust, Python, and web package boundaries.
- Do not restore removed Product orchestrator surfaces such as the old graph, API, CLI, supervisor, specialists, FastAPI, or LangGraph runtime code under `services/agent/`.
- Rust MCP tools require typed schemas, unknown-field denial where applicable, safe errors, server registration, and tests.
- Python MCP tools are protocol shims under `services/agent_mcp/`; domain logic belongs in `services/agent/`.
- Dashboard audit tail is the SSE API audit route, not WebSocket.
- Do not hard-code smoke counts; smoke runners print current counts.

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

The real done gate is a live investigation:

```bash
scripts/verdict <supported-evidence-path>
```

Passing smokes predict CI wiring. They do not prove a real DFIR run.

## Release Hygiene

Do not commit private or bulky evidence. These must remain out of public release snapshots unless explicitly documented as public fixtures:

- `tmp/`
- `evidence/`
- `*.E01`
- `*.dd`
- `*.mem`
- `*.evtx`
- VM images and OVA files
- SQLite state
- local corpora
- `.env*`, credentials, tokens, browser profiles, or session files

Public release docs must describe the application and its safety contract. Do not include private development memory, local-only paths, scratch plans, hidden credentials, or stale hackathon/deadline process notes.

## Documentation Map

- `README.md` - project overview and core claims.
- `INSTALL.md` - install path and prerequisites.
- `QUICKSTART.md` - run modes and environment choices.
- `docs/using/running-verdict.md` - full `scripts/verdict` reference.
- `docs/reference/mcp-and-tools.md` - MCP and tool inventory.
- `docs/reference/dependencies.md` - dependency matrix.
- `docs/verdict-semantics.md` - Verdict-word semantics.
- `docs/false-positives.md` - overclaim prevention.
- `docs/cryptographic-attestation.md` - custody and manifest verification.
- `agent-config/` - runtime DFIR agent rules.
