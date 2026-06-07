# CLAUDE.md

This file guides Claude Code (claude.ai/code) when working in this repository. Under **Amendment A2** (2026-04-25, active) Claude Code IS the Product's primary interface — when a SANS judge runs `scripts/find-evil` or `claude` from this repo, the session you are reading is what executes the investigation. CLI binary is `claude` (canonical; older docs alias as `claude-code`).

---

## 1. Mission

This is the SANS **Find Evil!** hackathon submission (deadline **2026-06-15 22:45 CDT**). You operate in two modes:

- **Agent mode** — a user opens `scripts/find-evil` / `claude` and asks `investigate <case path>`. You are the SANS Find Evil! DFIR agent: supervisor over Pool A (persistence) + Pool B (exfil) subagents, driving the typed MCP tool surface, emitting Findings that cite a `tool_call_id`, producing a hash-chained audit log.
- **Dev mode** — a developer (or the build swarm) asks you to read/write code in this tree. You follow the four coding principles in §6 and the conventions in §7.

If a user prompt fits *either* mode, finish reading this file before acting.

---

## 2. Agent investigation prompt (read these files in order)

When the user asks you to **investigate `<case path>`** or similar, read these in order — they encode mission, identity, and hard rules that you MUST not violate:

1. **`agent-config/SOUL.md`** — purpose; epistemic hierarchy (CONFIRMED > INFERRED > HYPOTHESIS); FRE 902(14) self-authenticating-evidence stance; strict cross-artifact rule for execution claims; no-attribution rule.
2. **`agent-config/AGENTS.md`** — supervisor / Pool A / Pool B / judge / verifier / correlator role descriptions. You are the supervisor; the two pools are forked as subagents via Claude Code's native Task mechanism (not via `CLAUDE_CODE_FORK_SUBAGENT=1`, which is a build-swarm internal).
3. **`agent-config/PLAYBOOK.md`** — investigation tool sequences per evidence type (`.e01`, `.mem`, `.evtx`, Velociraptor `.zip`, mixed case dirs). Defaults, not laws — deviate when the case shape diverges and log the deviation.
4. **`agent-config/TOOLS.md`** — the typed tool surface (Rust `findevil-mcp` + Python `findevil-agent-mcp`).
5. **`agent-config/MEMORY.md`** — Tier-1 DFIR caveats (Amcache LastModified ≠ execution, ShimCache order changed at Win8.1, EVTX Logon Type 3 vs 10, etc.).
6. **`agent-config/EXPERT.md`** — 99% automation / 1% expert-signoff doctrine; report QA rules turn expert edits into playbooks, connectors, or gates.
7. **`agent-config/HEARTBEAT.md`** — the per-iteration self-check loop.
8. **`agent-config/JUDGING.md`** — SANS Find Evil! 2026 rubric (6 criteria, verbatim) + end-of-investigation self-score checklist that appends to the audit JSONL as `kind="judge_selfscore"` before `manifest_finalize`. You are graded against this, so you must self-check against it.

**Investigation flow:** `case_open` → split into Pool A (persistence) + Pool B (exfil) subagents → each pool runs DFIR tools and emits Findings (each citing a `tool_call_id`) → `detect_contradictions` → analyst resolves → `verify_finding` re-runs each cited tool → `judge_findings` (credibility-weighted merge) → `correlate_findings` → `manifest_finalize` (signs the run; terminal beat under A5). The terminal beat map for the judge demo lives in Amendment A2 §2.3.

---

## 3. Non-negotiable invariants

These appear across multiple specs and the agent-config files. Violating any of them breaks the judging story or an integration contract.

- **No `execute_shell` MCP tool, ever.** The Rust surface is deliberately narrow (19 typed tools). Adding shell pass-through undoes the "reduces the attack surface" pitch.
- **Every Finding cites a `tool_call_id`.** The verifier vetos any Finding without one. UI chips render `[confirmed · tool · sha256]` per finding.
- **Epistemic hierarchy is strict.** `CONFIRMED` (backed by tool output) > `INFERRED` (≥2 confirmed facts, labeled) > `HYPOTHESIS` (prefixed "hypothesis:"). Nothing else is legal.
- **Execution claims need ≥2 artifact classes** (Prefetch + Amcache+ShimCache, or EDR telemetry). Amcache alone is insufficient — it's catalog-registration time, not execution.
- **Evidence is read-only.** Original `.e01` opened via libewf; write-only working dir elsewhere. No tool mutates evidence. SHA-256 verified at `case_open`.
- **Hash-chained audit JSONL is append-only.** Each line has `prev_hash` linking to the previous line. Rewriting history breaks the M2 chain-of-custody pitch. Chain is **3 tiers** post-A5 (audit prev_hash → rs_merkle → sigstore); the 4th OpenTimestamps/Bitcoin tier was removed 2026-04-30. See `docs/cryptographic-attestation.md` and rubric criterion #5.
- **AGPL/GPL tools (Hayabusa, Chainsaw, Volatility3, Velociraptor, YARA) are subprocess-only — never linked.** Linking contaminates the submission license (must be MIT or Apache-2.0 per SANS rules).
- **Draft PRs only.** The build swarm never auto-merges or force-pushes `master`. Human merges every PR after morning triage.
- **All timestamps UTC, ISO-8601, trailing `Z`.** SHA-256 preferred over MD5. Never assert attribution.
- **Judge narrative:** "orchestrator that reduces friction," never "autonomous responder." Rob Lee's explicit preference (memory: `project_judging_signals.md`).
- **Replay evidence is a customer-PDF blocker.** `verify_finding_replay_embedded` was advisory during Track 3a; Track 3b promotes it to blocker in `agent-config/expert-rules.json` and `scripts/find_evil_auto.py`. Do not downgrade without an explicit policy change.

---

## 4. Tool surface

Two MCP servers are registered in `.mcp.json` and auto-spawned by Claude Code on session start:

| Server | Lang | Count | Tools |
|---|---|---|---|
| `findevil-mcp` | Rust (`services/mcp/`) | 19 | `case_open`, `disk_mount`, `disk_extract_artifacts`, `disk_unmount`, `evtx_query`, `mft_timeline`, `hayabusa_scan`, `vol_pslist`, `vol_psscan`, `vol_psxview`, `vol_malfind`, `yara_scan`, `usnjrnl_query`, `registry_query`, `prefetch_parse`, `vel_collect`, `sysmon_network_query`, `zeek_summary`, `pcap_triage`. Read-only on evidence; SHA-256 every output. |
| `findevil-agent-mcp` | Python (`services/agent_mcp/`) | 12 | Crypto/ACH: `audit_append`, `audit_verify`, `manifest_finalize`, `manifest_verify`, `verify_finding`, `detect_contradictions`, `judge_findings`, `correlate_findings`. Hermes cross-case memory: `memory_remember`, `memory_recall`. IBM-ACP handoff: `pool_handoff`. Expert miss feedback: `expert_miss_capture`. |

**DKOM redundancy is intentional.** `vol_pslist` walks the active list; `vol_psscan` signature-scans EPROCESS pool memory; `vol_psxview` cross-references process views. Divergence between them is the textbook DKOM / T1014 (Rootkit) signature. Don't fold them.

**Entry points (Amendment A2 — Claude Code as primary interface):**

- **Local mode** (demo entry point; DFIR tools installed on host): `scripts/find-evil` or `claude` from the repo root. `.mcp.json` auto-spawns both MCP servers locally.
- **SIFT-VM mode** (Tesla-mode automation, SANS-blessed environment): `bash scripts/find-evil-sift`. Pre-flight: `bash scripts/sift-vm-bootstrap.sh` once (~15 min — converts `sift-2026.03.24.ova` → VMware Workstation VM, boots headless, builds `findevil-mcp` inside, installs SSH key). Launcher swaps `.mcp.json` → `.mcp.json.sift` for SSH spawn; restores on exit. **Hypervisor:** VMware Workstation only (`scripts/find-evil-sift:10-12`); a VirtualBox path is stubbed but not implemented.
- **Headless single-shot:** `bash scripts/find-evil-auto <evidence>` (Tesla-mode end-to-end orchestrator; optional `--run-summary <path>` writes JSON pointer with `run_id`, `case_id`, paths, report QA, release-gate/expert-signoff state, signer, `readiness_state`, blockers, warnings, result/error).
- **Manifest verification (offline):** call the `manifest_verify` MCP tool. CLI fallback: `uv run --directory services/agent_mcp python -m findevil_agent_mcp.server`.
- Pre-A2 launchers (`./find-evil serve|run|verify`, `find-evil` console script, `openclaw run`) are **deprecated** and not on the critical path.

---

## 5. Commands

Canonical commands. Do not hard-code old smoke counts in docs; the smoke runners print the current pass/skip/fail tally. Quote these verbatim so swarm-generated code and human work use the same paths.

### Local smoke gate (run this before claiming "done")
- POSIX/Git Bash: `bash scripts/run-all-smokes.sh`
- Native Windows: `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/run-all-smokes.ps1`

### Rust MCP server (`services/mcp/`)
- Build: `cargo build --workspace --release --locked`
- Lint: `cargo check --workspace && cargo clippy --workspace --all-targets -- -D warnings`
- All tests: `cargo test --workspace --locked`
- Single test (named fn in integration test file): `cargo test -p findevil-mcp --test tool_smoke test_case_open_returns_handle`
- Single crate's unit tests: `cargo test -p findevil-mcp --lib`

### Python (`services/agent/`, `services/agent_mcp/`, `services/swarm/`)
- **No root `pyproject.toml`** — each service is its own uv project. Use `--directory <svc>` (or `cd` first) for any uv command needing a project context.
- Env sync per service: `uv sync --directory services/agent` (and `services/agent_mcp`, `services/swarm`)
- Lint + format check (works from repo root): `ruff check . && ruff format --check .`
- All tests: see `docker/l1-compose.yml` lines 60–68; locally use the smoke gate above or run each service's pytest separately.
- Single file: `uv run --directory services/agent pytest tests/test_crypto_audit_log.py -v`
- Single test fn: `uv run --directory services/agent pytest tests/test_crypto_audit_log.py::TestCanonicalize::test_sorted_keys -v`

### Next.js web (`apps/web/`)
`apps/mcp-widgets/` remains deferred per A2 §2.1; commands below filter to `@findevil/web` since it's the only live workspace member.
- Install: `pnpm install --frozen-lockfile` (from repo root)
- Typecheck: `pnpm --filter @findevil/web typecheck`
- Build: `pnpm --filter @findevil/web build`
- Test: `pnpm --filter @findevil/web test` (8 Vitest tests covering `audit-tail.ts` + the path allow-list)
- Test one file: `pnpm --filter @findevil/web test -- __tests__/audit-tail.test.ts`
- Dev server: `pnpm --filter @findevil/web dev` then `http://localhost:3000` (placeholder dashboard) or `http://localhost:3000/debug` (live SSE event viewer)
- Regenerate audit-event TS types from Pydantic: `pnpm --filter @findevil/web codegen:events` (writes `apps/web/lib/events.ts`)

### Readiness packet gates
- **Native Windows (packet-producing):** `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/readiness-gate.ps1 -Mode Full -EvidencePath <path-inside-sift-vm> -RunL1Docker`. Full mode runs `scripts/build-checker.py run`, runs `find-evil-auto` unless `-ExistingRunDir` is supplied, verifies `run.manifest.json` against `audit.jsonl`, checks report QA / expert-signoff / customer-release blockers, copies required artifacts into `tmp/readiness-gates/<run-id>/packet/`, writes `readiness-summary.json` and `readiness-packet-manifest.json`, creates `readiness-packet.zip`.
- **Fixed `-RunId` reruns** are supported: gate refreshes packet contents; if `<run-id>-build` exists, uses a fresh `<run-id>-build-<timestamp>` local-build child run instead of failing.
- **Fast packet validation:** `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/readiness-gate.ps1 -Mode PacketOnly -ExistingRunDir tmp/auto-runs/<case-id>`. Packages/checks but doesn't claim full submission readiness.
- **POSIX strict check-only:** `EVIDENCE_RUN_DIR=<run-dir> L1_DOCKER_STATUS=passed L1_DOCKER_LOG=<log-with-READINESS_L1_PASS> bash scripts/readiness-gate.sh`. Prints `SUBMISSION_READY` or `READINESS_BLOCKED`; doesn't assemble `readiness-packet.zip`.
- Readiness states are deliberately conservative: `READY_FOR_EXPERT_REVIEW` / `PACKET_READY_FOR_EXPERT_REVIEW` means ready for human expert review, **not** customer release. Any skipped build, missing L1 evidence, failed manifest verification, failed report QA, or customer-releasable flag emitted by automation becomes `READINESS_BLOCKED`.

### Build swarm (Spec #1, interpret through Amendment A1)
- Pre-flight + nightly run: `bash scripts/swarm-start.sh` (verifies Postgres + git clean, then `cd services/swarm && uv run python -m findevil_swarm.main run …`)
- Dry-run gate for a week: `cd services/swarm && uv run python -m findevil_swarm.main run --week 4 --dry-run-gate`
- Resume after sleep: `cd services/swarm && uv run python -m findevil_swarm.main run --resume`
- Morning triage status: `bash scripts/swarm-status.sh`
- Postgres DAG state: `docker compose -f docker/swarm-postgres.yml up -d`

Package is `findevil_swarm` (matches `findevil_agent` / `findevil_agent_mcp` naming). Spec #1 / `docs/plans/2026-04-23-build-swarm-plan.md` use `services.swarm.*` — known plan-vs-code divergence; match `scripts/swarm-start.sh:105` (`cd services/swarm && exec uv run python -m findevil_swarm.main run "$@"`).

### Autonomous-loop harness (lightweight alternative to the swarm)
- Driver: `python scripts/autonomous-loop.py [--max-hours N] [--min-hours N] [--dry-run]` — reads user-level `memory/project_autonomous_queue.md`, picks highest-priority unblocked item (skipping `### Hard blockers (require user)`), spawns `claude -p --permission-mode acceptEdits` headless per item until queue exhausted, wall-clock cap, or 429 / `usage limit reached` / `reached your usage limit`. Auth inherits from `claude` CLI subprocess (A1 subscription path; no API key). With `--min-hours` set, waits `--empty-sleep-seconds` for new queue items instead of exiting.
- Validation smoke: `python scripts/autonomous-loop-smoke.py` — synthetic queues; verifies `--min-hours 8 --max-hours 8 --dry-run` and empty-queue wait/stop. Removes `claude` from PATH and must not spawn Claude or consume usage.
- **Which to use:** swarm = heavyweight nightly-cron PR-generator (Postgres-checkpointed, per-PR worktrees, critic gate, draft PRs). `autonomous-loop.py` = lightweight queue-driven sequential runner (one Python process, commits-on-current-branch). Both inherit subscription auth.

### Sandbox layers (Spec #3)
- L1 locally: `docker compose -f docker/l1-compose.yml up --build --exit-code-from l1` (base: `docker/l1-devbase.Dockerfile`)
- L2 locally (Sysbox installed): `bash scripts/l2-dfir-smoke.sh` (base: `docker/l2-siftlite.Dockerfile`)
- L3 Packer build: `packer build packer/sift-microvm.pkr.hcl` (reads `sift-2026.03.24.ova` from repo root)
- L3 goldens in CI: `bash scripts/l3-run-goldens.sh` (expects warm qcow2 in GHA cache)

### Workflows and CI (Spec #4)
- Static check workflow files: `actionlint .github/workflows/*.yml`
- Simulate a workflow job locally: `act -j l0-static`
- Cut weekly release: `git tag v<N> && git push origin v<N>` (triggers `release.yml`, gates on L3 green)
- Cut final submission: `git tag v-submit && git push origin v-submit` (triggers `devpost-submit.yml` after `release.yml` succeeds)

---

## 6. How to code in this repo (four principles)

Adapted from Andrej Karpathy's observations on LLM coding pitfalls — applies to **both** the live agent and the build swarm. Bias toward caution over speed; for trivial tasks use judgment.

**1. Think before coding.** State assumptions explicitly. If multiple interpretations exist, present them — don't pick silently. If a simpler approach exists, say so. If something is unclear, stop, name what's confusing, ask. Under A2, *every* tool call is on someone's evidence — uncertainty must surface, not be papered over.

**2. Simplicity first.** Minimum code that solves the problem. No features beyond what was asked. No abstractions for single-use code. No "flexibility" or "configurability" that wasn't requested. No error handling for impossible scenarios. If you write 200 lines and it could be 50, rewrite it. Test: would a senior DFIR engineer say this is overcomplicated?

**3. Surgical changes.** Touch only what you must. Don't "improve" adjacent code, comments, or formatting. Don't refactor things that aren't broken. Match existing style. If you notice unrelated dead code, mention it — don't delete it. Remove imports/variables that *your* changes made unused; never pre-existing dead code unless asked. Every changed line traces directly to the request.

**4. Goal-driven execution.** Transform tasks into verifiable goals. "Add a tool" → "write the typed Input/Output, the failing integration test, the boundary error tests; then make them all green." For multi-step work state a brief plan and verify each step. Strong success criteria let you loop independently; weak ones ("make it work") require constant clarification.

These principles are working when: diffs are small and focused, fewer rewrites needed, clarifying questions come *before* implementation rather than *after* mistakes.

---

## 7. Conventions

- **TDD loop is mandatory for every plan task.** Failing test → RED → implement → GREEN → commit with the exact message the plan specifies. One commit per plan task; never batch.
- **Conventional Commits:** `feat(scope):`, `test(scope):`, `chore(scope):`, `fix(scope):`, `docs(scope):`. Existing scopes: `mcp`, `swarm`, `sandbox`, `ci`, `plan`, `amendment A1`.
- **Never use `--no-verify`, `--no-gpg-sign`, or `git commit --amend`** in plan execution. Hook failure → fix root cause → new commit.
- **Pinned dependency versions.** Specs pin exact versions (e.g. `rmcp = "=0.16.0"`, `evtx = "=0.11.2"`). Upgrading without updating the spec is a silent contract break — but when code already ships a different pin (see §11), the shipped pin wins and the spec is the thing to update.
- **DFIR vocabulary, not software vocabulary.** Use: **Case** (not session/run/job), **Observable** (not file/path/blob — the generic container), **Task** (not step/action), **Finding** (not result/hit-as-software-result), **Verdict** (not conclusion/summary), **Confidence** (not score/certainty). Three carve-outs: (1) **"artifact"** is correct in the DFIR-canonical sense — "artifact class" (Prefetch/MFT/EVTX/Amcache) is the SOUL.md ≥2-corroboration vocabulary and must NOT become "Observable class"; (2) **"hit"** is correct for rule-engine matches (YARA hit, Sigma rule hit); (3) **"investigation"** is correct as the activity-noun — `the investigation flow`, `the investigation took 4 hours`, `end-of-investigation self-score` are fine. Unit of work is still **Case** (with `case_id`); "the investigation directory" is wrong; say "the case directory." Forbidden software meanings: a build "session", a CI "job", a search "hit". Vocab-audit sprint budgeted for week 7 (`git log | grep vocab-audit` for progress).
- **Python tooling:** `uv` for envs/lockfile; `pytest`; `ruff`. Python 3.11.
- **Rust tooling:** `cargo test --workspace --locked`, `cargo clippy --deny warnings`. Rust 1.88 (rust-toolchain.toml authoritative; Spec #2 §16's 1.83 pin is superseded — see §11).
- **Node tooling:** `pnpm --frozen-lockfile`; `tsc --noEmit` in L0; `pnpm test` in L1. Node 20.

---

## 8. Credential modes (Amendment A1)

`scripts/install.sh` detects three credential paths in priority order:

1. `CLAUDE_CODE_OAUTH_TOKEN` env var (from `claude setup-token`) — non-interactive, script-friendly. Preferred for judges with a subscription.
2. Interactive Claude Code session (`~/.claude/` populated via `claude auth login`) — dev default.
3. `ANTHROPIC_API_KEY` env var — direct metered API when no Claude Code is available.

For the **build swarm**, only modes 1 and 2 apply. Option B removed all LiteLLM/USD-cap code; rate-limit handling is `services/swarm/findevil_swarm/session_guard.py`, which halts the supervisor cleanly on 429 and resumes from the Postgres checkpoint the next night. No in-flight retry.

---

## 9. Repository layout

```
.
├── Cargo.toml / Cargo.lock / rust-toolchain.toml   # Rust workspace (members = [services/mcp]); Cargo.lock IS committed (app, not library)
├── Dockerfile                                      # Production multi-stage → ghcr.io/find-evil/find-evil:v<N>
├── LICENSE                                         # Apache-2.0
├── sift-2026.03.24.ova                             # 9.3 GB SIFT VM image — Packer input; gitignored (*.ova)
├── agent-config/                                   # Runtime DFIR agent identity (SOUL/AGENTS/TOOLS/MEMORY/HEARTBEAT/JUDGING/PLAYBOOK/EXPERT + expert-rules.json — 60+ claim rules, severity blocker/warning)
├── docs/specs/ + plans/                            # 8 specs (A1/A2/A3 amendments + per-subsystem) + 6 TDD plans (most recent: 2026-05-20-finish-to-v-submit-plan.md)
├── docs/braindumps/                                # Origin-of-feature scratch docs (A3 spawned from 2026-04-26-agent-army-and-dashboard.md)
├── docs/legacy/                                    # v1 docs superseded by v2 + amendments
├── services/mcp/                                   # Rust MCP server (19 typed DFIR tools; hand-rolled stdio JSON-RPC 2.0 — see §11)
├── services/agent/                                 # Python package findevil_agent — M2 crypto + M4 ACH + A3 memory/acp (FastAPI/LangGraph dropped under A2)
├── services/agent_mcp/                             # Python MCP server wrapping M2/M4/memory/ACP/expert feedback as 12 typed tools
├── services/swarm/                                 # Python build swarm (Option B — Claude CLI subagents)
├── .mcp.json                                       # A2: registers findevil-mcp + findevil-agent-mcp for auto-spawn
├── apps/web/                                       # Next.js 15 + Tailwind v4 + NES.css dashboard (A3 §2.1) — SSE audit-log tail at /api/audit, role-state sprite containers, /debug viewer, /codex operator cockpit (prompt suggestions + live state), pydantic→TS codegen at lib/events.ts
├── apps/mcp-widgets/                               # M3 widgets — DEFERRED per A2 §2.1 (A3 doesn't need them)
├── packer/sift-microvm.pkr.hcl                     # L3 warm-qcow2 build from the OVA
├── docker/                                         # l1-compose.yml, l1-devbase.Dockerfile, l2-siftlite.Dockerfile, swarm-postgres.yml
├── scripts/                                        # See `ls scripts/` for the current list
├── goldens/                                        # nist-hacking-case/, synthetic-benign/ — L3 golden fixtures
└── .github/workflows/                              # l0/l1/l2/l3 + release + competitor-watch + devpost-submit + budget-guard
```

The pre-A2 `python -m findevil_agent.cli` entry point was dropped by A2; the Dockerfile wrapper + `scripts/build-deb.sh` were cut 2026-04-27 (PR #4) per `docs/runbooks/dockerfile-a2-decision.md` "Option B." L0 `amendment-a2-guard` + L1 `divergence-smoke.py` §3 fail CI if `findevil_agent.cli` reappears.

### The 4 subsystems (master design §3)

```
#3 Sandbox (L0-L3) ──┐
                     ├──► #1 Build Swarm ──► #2 Product ──► #4 Orchestration Glue
                     └──► #2 Product (directly — sandbox also gates Product CI)
```

- **#3 Sandbox** — blocks everything else. L0 lint, L1 unit/build (Docker Ubuntu 22.04), L2 SIFT-lite (Sysbox runtime, advisory), L3 full SIFT VM parity (QEMU microvm + qcow2 snapshot-restore, Packer-built from `sift-2026.03.24.ova`, on GHA KVM larger runners).
- **#1 Build Swarm** — invisible to judges. Writes code overnight into draft PRs. LangGraph supervisor + Claude CLI subagents + one git worktree per PR + critic subagent gate. **Option B (A1):** user's Claude Code subscription, not metered API.
- **#2 Product** — the submission. Under A2 the layers collapse to: evidence vault → SIFT tool subprocesses → two MCP servers → Claude Code (supervisor + ACH pool subagents + audit-log driver). Primary entry point: `scripts/find-evil` (or `claude`).
- **#4 Orchestration Glue** — thin CI: 9 GHA workflows, branch protection, release pipeline, Devpost submission zip on `v-submit` tag.

### Sandbox layer cheat sheet (Spec #3)

| Layer | Runtime | Budget | Blocks merge? |
|---|---|---|---|
| L0 | GHA `ubuntu-24.04`, no containers | 30–60s | Yes |
| L1 | Docker Compose + GHA standard runner | 2–5min | Yes |
| L2 | Sysbox runtime (rootless systemd+FUSE) | 5–10min | No (advisory on PRs) |
| L3 | QEMU microvm + qcow2 snapshot-restore on GHA KVM larger runner | ~5–20min | Yes for **releases**, nightly on `master` |

L3's warm `.qcow2.zst` is built once by Packer from `sift-2026.03.24.ova` and cached via `actions/cache`. The OVA is in `.gitignore` (`*.ova`) and never committed.

### Large files to never commit

`.gitignore` already excludes `*.ova`, `*.qcow2`, `*.vmdk`, `*.vdi`, `*.E01`, `*.dd`, `*.raw`, `*.mem`, `*.aff`, `*.aff4`, `*.vhd`, `*.vhdx`, `target/`, `node_modules/`, `.venv/`, `__pycache__/`, `.next/`, `dist/`, `state/`, `checkpoints/`, `*.sqlite`. Evidence images (NIST CFReDS Hacking Case, OTRF datasets) are pulled by L3 scripts at CI time — never enter the git tree.

---

## 10. Document hierarchy

Read in precedence order. Later documents override earlier ones only where explicitly noted.

### Active amendments (live)
1. **`docs/specs/2026-04-23-find-evil-automation-master-design.md`** — master design. 4-subsystem decomposition + 4 differentiators (M1 leaderboard, M2 crypto chain-of-custody, M3 MCP App widgets, M4 ACH competing-hypothesis agents).
2. **A1** — `docs/specs/2026-04-23-amendment-option-b-claude-code-mode.md`. Removes LiteLLM proxy + `services/swarm/budget.py` + USD caps; workers use the user's Claude Code subscription via `claude` CLI. Product accepts three credential modes (see §8).
3. **A2** — `docs/specs/2026-04-25-amendment-a2-claude-code-primary-interface.md`. Drops the custom Python orchestrator (`graph.py`/`api.py`/`cli.py`/`supervisor.py`/specialists). Claude Code IS the orchestrator. Adds `services/agent_mcp/` and `.mcp.json` registering both servers. `apps/web/` + `apps/mcp-widgets/` deferred (A3 un-defers `apps/web/`).
4. **A3** — `docs/specs/2026-04-26-amendment-a3-agent-army-and-dashboard.md`. Un-defers `apps/web/` (NES.css live dashboard tailing the audit JSONL hash chain; 5 sprites mapping to AGENTS.md roles). Adds 3 tools to `findevil-agent-mcp`: `memory_remember`/`memory_recall` (Hermes FTS5 cross-case memory), `pool_handoff` (IBM ACP envelope). `apps/mcp-widgets/` remains deferred.
5. **A5** (2026-04-30, active — no spec doc yet, encoded in commits + CHANGELOG). Removes the OpenTimestamps/Bitcoin tier. Cuts `services/agent/findevil_agent/crypto/ots.py` + tests, `ots_stamp`/`ots_verify` MCP tools, and the `opentimestamps-client` dep. Chain collapses from 4 tiers to 3 (audit prev_hash → rs_merkle → sigstore). Commits `743404d`, `a75ea44`, `e265600`, `6da4d95`, `2b59572`. Post-A5 `findevil-agent-mcp` registry was 11 tools; Track 4 adds `expert_miss_capture` as the 12th. `services/agent_mcp/tests/test_stdio_smoke.py` enforces the current count.

### Per-subsystem specs (in `docs/specs/`)
- `2026-04-23-layered-test-sandbox-design.md` — Spec #3 (L0-L3 sandbox; blocks all other work).
- `2026-04-24-autonomous-build-swarm-design.md` — Spec #1 (build swarm; interpret through A1).
- `2026-04-25-the-product-design.md` — Spec #2 (the DFIR tool judges run).
- `2026-04-26-orchestration-glue-design.md` — Spec #4 (GHA CI; `budget-guard.yml` is a no-op under A1 unless `ANTHROPIC_API_KEY` is set).

### Implementation plans
`docs/plans/` — one per spec, each step a TDD checkbox with the exact failing test → implement → commit sequence.

### Archived (do not read for current architecture)
- ~~`BUILD_PLAN_v2.md`~~ — moved to `docs/legacy/BUILD_PLAN_v2.md` 2026-05-02 (pre-A2/A3/A5 research artifact; pitch surface consolidated into `README.md` per Phase 3c+3d of the doc reorg).
- `Find_Evil_Research_and_Build_Plan.docx` — v1 research doc; authoritative only for what v2 doesn't contradict.

---

## 11. Spec/code divergences (code wins)

Specs were written 2026-04-23; code has been shipped since 2026-04-24. Where they disagree, the shipped code + its pin files are authoritative. **Eight settled divergences moved to `docs/divergences-resolved.md`.** Only active uncertainty stays below. Append new bullets here only if the resolution is still moving; once it's stable, move the bullet down to the resolved ledger.

- **A5 OTS removal: legacy specs (M2 spec, A2 §2.3) still reference `ots_stamp`/`ots_verify`/Bitcoin as design-era behavior.** Code has cut all five touchpoints (`crypto/ots.py`, both MCP tool modules, `opentimestamps-client` dep, orchestrator + report-renderer + smoke refs). Chain is 3 tiers; `docs/cryptographic-attestation.md` documents the post-A5 trade-off. Code wins for any remaining legacy-spec conflict. No A5 spec doc written yet.
- **Replay evidence is a customer-PDF blocker.** `verify_finding_replay_embedded` was advisory during Track 3a; Track 3b promoted it to blocker in `agent-config/expert-rules.json` and `scripts/find_evil_auto.py`. Do not downgrade without an explicit policy change.

---

## 12. Project state + memory + external references

### Current project state

All four subsystems exist. Local smoke gate is `bash scripts/run-all-smokes.sh` (POSIX/Git Bash) or `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/run-all-smokes.ps1` (native Windows). The Product layer is feature-complete through A3 Phase 4 plus the post-A5 `vol_psxview` addition, the Track 1 disk mount/extract slice, expert miss feedback, `find-evil-auto --run-summary`, and the PowerShell readiness packet gate. Shipped MCP surface: 19 Rust DFIR tools + 12 Python crypto/ACH/memory/ACP/expert-feedback tools. The audit-log SSE tail powers a Next.js + Tailwind v4 + NES.css dashboard at `apps/web/` with role-state sprite containers and `/debug`; only the pixel-art sprite swap and AuditBeadString/HashChainBadge/FindingChip chrome remain design-polish work.

**Before writing code, read the relevant spec and plan** for the subsystem you're touching. Specs define exact file paths, pinned versions, TDD task sequences; silent divergence creates integration mismatches. When spec and code disagree, **code + committed pin files win** (see §11). `CHANGELOG.md` summarizes per-feature; `git log --oneline -20` for recent commits.

### Quickstart for the impatient

To run the agent against evidence right now, see **`QUICKSTART.md`** at the repo root. Three steps: pick environment (SIFT VM or local), open Claude Code, prompt `investigate <path>`.

- False-positive prevention strategy + analyst checklists: **`docs/false-positives.md`**.
- Example end-to-end investigation report: **`docs/reports/2026-04-26-srl2018-dc-investigation.md`** (SRL-2018 SANS HACKATHON-2026 dataset, CONFIRMED DKOM finding / MITRE T1014).

### Memory system

User-level auto-memory lives at `C:/Users/newbi/.claude/projects/C--Users-newbi-Desktop-PUG-Projects-SANS-Hackathon/memory/` and is auto-loaded into every session. The index (`MEMORY.md`) points to per-topic memory files: automation scope, top competitors, DFIR tooling picks, swarm architecture, sandbox stack, judging signals, crypto chain-of-custody, MCP Apps readiness, adversarial-agents pattern, Option B credential decision, Devpost rules compliance. Read the index at session start if you need historical context; update the relevant memory file (don't invent a new one) when facts change.

### External reference clones (never ship, never edit, never import)

Local-only research clones (`openclaw/`, `hermes-agent/`, `Linear-Coding-Agent-Harness/`, `.playwright-mcp/`, `obsidian-mind/`, `n8n-references/`, `git-hub-references/`) are `.gitignore`'d; never ship, never edit, never import. See `git-hub-references/CLAUDE.md` if you need the per-clone index. The Devpost zip is produced by `scripts/package-devpost.sh`.
