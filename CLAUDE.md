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

## VERDICT ecosystem — what is what

VERDICT is a local-first DFIR (digital forensics & incident response) agent platform, split into three repos:

| Repo | Role | It is… |
|---|---|---|
| [`caseforge-core`](https://github.com/TimothyVang/caseforge-core) | Headless **controller**: privacy routing, model selection, structured findings, custody validation, the `caseforge` CLI. | the **driver** |
| [`verdict-opencode`](https://github.com/TimothyVang/verdict-opencode) | The agent **runtime** — a branded fork of [opencode](https://github.com/sst/opencode); the `verdict` binary is built from it. | the **engine** |
| **verdict-dfir-beta** / this repo | The **forensic toolkit**: `findevil-mcp` (Rust, 34 read-only tools) + `findevil-agent-mcp` (Python, 14 custody/crypto tools) + DFIR doctrine (`agent-config/`) + hash-chained custody. Consumed by caseforge via `VERDICT_DFIR_HOME`. | the **evidence lab** (you are here) |

**Runtime flow:** `caseforge` (controls + guards) → `verdict` binary (runs the agent) → **this repo's `findevil` MCP tools (do the forensics)** → hash-chained custody → `caseforge verify`.

**Two rules everything obeys:** the LLM is not the forensic source of truth (findings must cite a `tool_call_id` + `output_sha256` + verified manifest); real evidence stays local by default.

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

SIFT VM mode is recommended for full disk-image parity. Local mode can handle memory, EVTX, PCAP, Velociraptor collections, extracted artifacts, and supported disk artifacts when Sleuth Kit/libewf prerequisites are present. Raw disk images such as `.E01`, `.dd`, `.raw`, and `.aff` remain custody-only whenever `disk_mount` / `disk_extract_artifacts` fail or produce no supported parsed artifacts; never turn `case_open` alone into broad disk-content claims.

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
- Derived whole-case staging, including `_xartifact`, belongs under the run/output directory, never under the source evidence or case root.
- Call `case_open` before evidence analysis whenever using the MCP tool surface.
- Every Finding must cite a valid `tool_call_id` from the current Case.
- Run `verify_finding` for each Finding and record each verifier decision with `pool_handoff` before `judge_findings` consumes the Findings.
- `report_qa` must be audited before `manifest_finalize`; a failed or missing report QA gate blocks customer-ready output and requires expert review.
- `manifest_finalize` is the terminal custody step for a completed Case.
- Self-correction must be organic and committed to the audit chain: a real tool or verifier failure that drives a named `course_correction`, or a confidence-tier flip committed as `verdict_revision` (offline-verifiable via `manifest_verify`). Never stage a correction; `fault_injection` is demo-only and never counts as organic recovery evidence.
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

Only the two product servers can emit audit-chain tool calls for Findings. The product surface is 48 audit-chained product tools: 34 Rust DFIR tools in `findevil-mcp` plus 14 Python crypto/ACH/memory/ACP/expert-feedback/accuracy/ai-tradecraft tools in `findevil-agent-mcp`. The operator convenience servers must never emit Findings, satisfy Finding citations, or mutate evidence.

Do not add a broad filesystem, shell, Docker, Kubernetes, browser, GitHub, fetch, or raw-command MCP to the product surface. Do not add an `execute_shell` tool. Long-tail DFIR execution belongs behind allow-listed typed tools such as `vol_run`, `ez_parse`, `plaso_parse`, `mac_triage`, and `cloud_audit`.

Both product servers neutralize attacker-controlled evidence text at the MCP output boundary before it reaches the model (`services/mcp/src/sanitize.rs` for Rust, `services/agent_mcp/findevil_agent_mcp/sanitize.py` for Python). The sanitizer replaces chat/role control tokens (`<|im_start|>`, `[INST]`, `<<SYS>>`, …) with an inert `[neutralized:<id>]` marker and strips invisible Unicode that hides or reorders text (BIDI overrides/isolates and zero-width code points — the Trojan Source class), stripping the invisible code points first so a token cannot be split to evade matching. Only JSON string values are touched, so tool-derived metadata (hashes, counts, enums, timestamps, IDs) is never mangled, and only counts are logged so the record cannot re-leak the payload. Sanitization is deterministic: a `verify_finding` replay reproduces the same `output_sha256`, so the audit chain attests exactly what the model saw. Keep the two mirrors in sync and keep the transform deterministic; never route evidence text around this boundary.

## Brand And Visual Surface

The v2 brand bible is `VERDICT_DFIR_SVG_Assets_v2/verdict-brand-board-reconstructed.png`; supporting production assets and rules live in `VERDICT_DFIR_SVG_Assets_v2/` and are summarized in `docs/brand.md`. Use the v2 palette and voice for dashboard, report, README, GitHub, and Remotion/video surfaces before inventing new treatments. Canonical voice lines are “Show Me the Evidence,” “Evidence over assumption,” “Don't trust the model. Reproduce the finding,” and “Trace it. Test it. Trust it.” Visuals are presentation only: they never create Findings, upgrade confidence, or soften the scoped verdict language above.

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

Agent mode (opt-in, Stage B): drive Pool A / Pool B as a provider-agnostic LLM agent loop instead of the deterministic engine. `find_evil_auto.py` stays the **default**; `--agent` only changes how the pools reach their Findings — everything downstream (the default-on fact-fidelity gate, `verify_finding`, judge, correlate, signed manifest, `manifest_verify`) is the same custody spine.

```bash
scripts/verdict --agent --acknowledge-evidence-egress <path-to-evidence>
```

- Backend defaults to **Claude** via the headless Claude Code CLI (`--agent-provider claude_cli`, the `claude` subscription entitlement — no API key). The loop is provider-agnostic: `--agent-provider {anthropic,openai,openrouter,local,dgx}` + `--agent-model <id>` (plus `FINDEVIL_AGENT_BASE_URL` for `local`/`dgx`) target any OpenAI-compatible endpoint; `local`/`dgx` are on-prem and need no egress ack.
- `--acknowledge-evidence-egress` is required for cloud backends (evidence text leaves the host). The flag runs the engine under the 3.11 agent venv automatically.
- Status: live-verified on single-artifact evidence (e.g. an EVTX) at report-QA parity with the deterministic engine. The `claude_cli` backend does **not** yet scale to disk-sized investigations (per-turn cost); use the deterministic engine or an efficient OpenAI-compatible endpoint for disk/memory.

Evidence location: `evidence/` at the repo root is the default drop directory (override with `$FINDEVIL_EVIDENCE_ROOT`; see `evidence/README.md`). It is **gitignored and per-checkout**, so a fresh `git worktree` starts with an empty `evidence/` — for a live run from a worktree, pass an explicit path into the checkout that actually holds the images, or set `$FINDEVIL_EVIDENCE_ROOT`. For any live run, demo, or recording, point at real evidence in this directory; never substitute stubbed or mock tool output for a "real" run.

Outputs land under:

```text
tmp/auto-runs/<case-id>/
```

Expected high-value outputs:

- `audit.jsonl` - hash-chained process and tool-call record. Named real-time recovery records live here: `course_correction` when a tool or verifier path fails, `verdict_revision` when a Finding's confidence tier organically flips across the judge/correlate stages, and `heartbeat_failure` / `heartbeat_terminated` when consecutive recovery failures seal a scoped partial verdict. A rejected or errored tool call is still logged to the chain. Demo-only fault injection is labeled `fault_injection` and is never organic evidence.
- `verdict.json` - scoped Verdict and Findings.
- `coverage_manifest.json` - available/attempted/parsed/unsupported artifact classes.
- `run.manifest.json` - signed manifest.
- `manifest_verify.json` - offline verification result.
- `REPORT.html` / `REPORT.pdf` - analyst report. Committed `verdict_revision` flips render as a Self-Correction section.

A run is not complete unless the pipeline reaches `case_open`, all Findings cite `tool_call_id`, `report_qa` is audited, and `manifest_verify.json` reports `overall: true` for the completed manifest. If `manifest_verify.json` is missing or `overall` is not `true`, report `RUN INCOMPLETE / CUSTODY INVALID` and do not describe the output as signed or customer-ready.

## Large And Multi-Host Cases

When the evidence is a whole-case folder (many hosts, many disk/memory images) rather than a single
file, run it as a **fleet** instead of one host at a time:

```bash
scripts/verdict <case-root> --fleet           # local
scripts/verdict <case-root> --fleet --sift    # SIFT (recommended for disk images)
```

Fleet mode auto-engages when `<case-root>` holds a `hosts/` and/or `disks/` subfolder. It runs each
host as its own audit-chained Case, then cross-host correlation, then a fleet report. Outputs:

```text
tmp/fleet-runs/<fleet-id>/   fleet.json, fleet_correlation.{json,md}, FLEET_REPORT.{html,pdf}
```

Operating notes for large cases (so a run does not have to be hand-driven):

- **SIFT mount-in-place for big images.** Evidence already visible inside the SIFT VM (for example a
  read-only shared folder) is mounted read-only *in place* — pass the in-VM path and no copy-staging
  happens. This is the right way to handle many large `.E01`s without copying tens of GB per host.
- **Watch VM free space.** Per-host extracted artifacts accumulate in the VM; on a small VM, clean a
  finished host's extracts before the next host. Never delete source evidence or another tool's data
  to make room without explicit operator approval.
- **Cross-artifact corroboration (fusion).** A folder holding a host's disk image **and** its memory
  image runs as one Case spanning ≥2 artifact classes — the supported way to push an execution lead
  past the two-artifact-class gate. Pairing only adds a second class; it does not lower the bar.
- **Recommended flow:** validate the pipeline on one host first, then fan out (fleet runs are
  resumable — a host with a completed run-summary is skipped), then correlate, then deep-dive the
  priority hosts the correlation surfaces.
- **Custody is still per host.** Each host carries its own `run.manifest.json` / `manifest_verify`;
  the fleet correlation report is a derivative summary, never a substitute for per-host verification.
- **On-disk YARA is opt-in.** The disk `yara_scan` only covers files `disk_extract_artifacts`
  classified as yara-targets (often `ProgramData`-class), so it can miss an implant elsewhere (e.g.
  `C:\Windows`, `\System32\drivers`). Set `FIND_EVIL_DISK_YARA_RULES` to a ruleset, and when a
  service/driver ImagePath is flagged, scan that specific file too.
- **Keep recovered-file analysis in the audit chain.** When you pull a flagged file (driver, binary)
  off a mount, characterize it with an audit-chained product tool (`yara_scan` or a typed parse) so the
  Finding carries a `tool_call_id`. Raw shell triage (vol/file/sha256sum/strings) is a lead only — a
  Finding whose only support is out-of-chain triage will not trace under `manifest_verify`, so a
  cross-class corroboration must have **each** class backed by a cited tool call, not one in-chain class
  plus one analyst-asserted class.

## Development Rules

When modifying VERDICT, keep changes small and evidence-safe.

- **Branch model.** Contributors fork the repo and open pull requests against the `develop` branch; never push to `main` (the published release line). Maintainers integrate `develop`, and publish to a release line only after review and explicit approval. Releases are cut with `git ship` (push + tag + GitHub Release over plain `git` + the platform CLI — no CI runners). See [docs/contribution-model.md](docs/contribution-model.md).
- Prefer surgical diffs over rewrites.
- **Path-agnostic always.** Scripts and code must work regardless of the caller's CWD and machine. Derive the repo root at runtime — bash: `REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"`; Python: `Path(__file__).resolve().parent.parent`. Use `$HOME`/`~`, never a hard-coded `/home/<user>`. Make environment-specific paths env-overridable defaults (`${VAR:-default}`, e.g. the SIFT-guest `/home/sansforensics/...` paths). Never hard-code an absolute machine path or assume the CWD is the repo root.
- **Repo layout (one folder for everything).** The repo root holds only config/manifest files and the load-bearing public docs; everything else lives in a named top-level directory. Enforced two ways: `scripts/repo-layout-smoke.py` (wired into `scripts/run-all-smokes.sh`) fails the gate on any stray tracked-or-un-ignored root entry, and `scripts/hooks/guard-root-writes.py` is a PreToolUse hook that blocks an agent (Claude/Codex) from writing a new root file/folder in real time. Never create files at the root — put new code under `scripts/`/`services/`/`apps/`, docs under `docs/`, assets under `assets/`. See [docs/repo-layout.md](docs/repo-layout.md) for the canonical tree and how to add a new sanctioned root entry.
- **Portable + self-contained (clone-and-go on any computer).** The project must work from a fresh clone on any machine with no machine-specific edits. Two rules make this hold, and both are gate-enforced by `scripts/containment-smoke.py`:
  1. **Everything derives its root at runtime** — bash `"$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"`, Python `Path(__file__).resolve().parent…`, hook commands `$CLAUDE_PROJECT_DIR`. Never hard-code an absolute machine path in committed code; use `$HOME`/`~` and env-overridable defaults (`${VAR:-default}`). No committed/cloned file may contain a `/home/<user>` or `/Users/<user>` path (synthetic *fixture* paths under `${FIXTURES}/…` are not machine paths and are fine).
  2. **All runtime + toolchain state is contained under `.project-local/`** (gitignored) by `scripts/lib/project-env.sh`, which every `scripts/run-mcp-*.sh` launcher and `scripts/verdict` source. It redirects `TMPDIR`, the `FINDEVIL_HOME` case store, `XDG_*`, the npm/npx cache, and the Rust/uv/pnpm toolchain caches into the folder, so nothing escapes — invoke a script from any CWD and it still saves inside the project.
  - The only thing that can't self-derive is Claude Code's `env` block in the gitignored `.claude/settings.local.json` (Claude Code does not expand vars there). `scripts/setup-containment.sh` regenerates it for the current location and is run automatically by `bash scripts/setup`, so a fresh clone is configured on install. After cloning or moving the folder, run `bash scripts/setup` (or `scripts/setup-containment.sh`) once, then restart Claude Code. See [docs/agent-containment.md](docs/agent-containment.md).
- Follow existing Rust, Python, and web package boundaries.
- Do not restore the removed Product orchestrator surfaces — the old `graph.py`, `api.py`, `cli.py`, `supervisor.py`, or `specialists/` runtime code under `services/agent/findevil_agent/`. These remain dropped (the L0 `amendment-a2-guard` job fails CI on their return).
- The opt-in custom agent orchestrator **is** allowed, scoped to `services/agent/findevil_agent/agentloop/` and exposed via `scripts/verdict --agent`. It does not reverse the boundary above: the deterministic `scripts/find_evil_auto.py` engine stays the **default**, the agent loop is strictly **opt-in**, it must **not** import `langgraph` or `fastapi` (the A2 content rule the L0 guard still enforces), and its MCP client stays in-loop over local stdio so the read-only custody boundary is preserved.
- Rust MCP tools require typed schemas, unknown-field denial where applicable, safe errors, server registration, and tests.
- Python MCP tools are protocol shims under `services/agent_mcp/`; domain logic belongs in `services/agent/`.
- Dashboard audit tail is the SSE API audit route, not WebSocket.
- Do not hard-code smoke counts; smoke runners print current counts.
- **Evidence-agnostic (hard rule).** All code — tools, MCP servers, parsers, `.py`, and Rust — MUST work for **any** evidence name and type dropped in `/evidence` (or `$FINDEVIL_EVIDENCE_ROOT`), not just the image it was last tested on. Never hard-code image-specific values: no specific usernames/hostnames (e.g. `Mr. Evil`/`MR-EVIL`), image names (`SCHARDT`), per-image misspellings, specific URLs/subjects/serials/paths, or golden/benchmark IDs (`nhc-XXX`) in production code, docstrings, or finding descriptions. Detection logic must key on **general DFIR signatures/patterns** (event IDs, registry paths, artifact names, curated signature lists, MITRE techniques); finding descriptions must report what was **actually parsed**, not a tool/value hard-coded from one image. Golden/benchmark coupling lives only under `goldens/` and tests. This rule is enforced by `scripts/evidence-agnostic-smoke.py` (in `scripts/run-all-smokes.sh`); a new image-specific literal in production code fails that gate.

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

Passing smokes are the local quality bar — the project ships via `git ship` (push + release over plain git + the platform CLI), not GitHub Actions CI. They do not prove a real DFIR run.

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
- `docs/architecture.md` - system architecture, trust boundaries, prompt-vs-architectural guardrails, and audit-visible self-correction.
- `docs/reference/dependencies.md` - dependency matrix.
- `docs/verdict-semantics.md` - Verdict-word semantics.
- `docs/false-positives.md` - overclaim prevention.
- `docs/fact-fidelity.md` - the deterministic entailment check (a finding can't assert a value not in its cited evidence).
- `docs/cryptographic-attestation.md` - custody and manifest verification.
- `agent-config/` - runtime DFIR agent rules.
