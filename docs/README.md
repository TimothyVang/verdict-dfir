# docs/ — canonical index

Read this first when navigating the documentation tree. The root README is the judge-facing landing page; this file is the maintainer/operator map.

## Start Here

| Need | Read |
|---|---|
| Install and run an investigation | [`../QUICKSTART.md`](../QUICKSTART.md) |
| Understand the architecture | [`architecture.md`](architecture.md) |
| Verify custody/manifest claims | [`cryptographic-attestation.md`](cryptographic-attestation.md) |
| Interpret verdicts safely | [`verdict-semantics.md`](verdict-semantics.md) |
| Review release evidence | [`release-evidence/README.md`](release-evidence/README.md) |
| See historical plans/specs | `plans/`, `specs/`, and `archive/` |

Status legend:

| Badge | Meaning |
|---|---|
| **SHIPPED** | The work this doc describes is built and live in code. The doc is still useful as architectural reference; don't re-execute it as a TDD plan. |
| **ACTIVE** | Currently authoritative for ongoing work. Edit when the underlying surface changes. |
| **RESEARCH** | Background, exploration, or external reference. Not load-bearing for the submission. |
| **RETIRED** | Work shipped; doc is kept for git-log archaeology only. Each retired file carries a status banner naming where the live code lives. |
| **REQUIRED** | Devpost / SANS rules require this doc; ships with the submission. |

The authoritative *precedence* hierarchy (which spec overrides which) lives in `CLAUDE.md` "Document hierarchy" — this index just makes per-file purpose scannable.

---

## Repo-root docs

| File | Status | Purpose |
|---|---|---|
| `CLAUDE.md` | **ACTIVE** | Agent instructions, document hierarchy, non-negotiable invariants, spec/code divergences. Always loaded into Claude Code sessions. |
| `AGENTS.md` | **ACTIVE** | Codex-compatible adapter instructions that defer to `CLAUDE.md` and preserve the narrow MCP surface. |
| `README.md` | **ACTIVE** | Public-facing project landing page. |
| `QUICKSTART.md` | **ACTIVE** | Three-step quickstart for impatient users. |
| `STARTUP.md` | **RESEARCH** | Team onboarding notes retained for hackathon context. |
| `CHANGELOG.md` | **ACTIVE** | Chronological project changelog. |

## `docs/` top level (analyst + judge facing)

| File | Status | Purpose |
|---|---|---|
| `architecture.md` | **REQUIRED** | Devpost Required Component #3. Trust-boundary diagram + runtime architecture. The single page judges reach first. |
| `artifact-semantics.md` | **ACTIVE** | Analyst reference: what each artifact type (Prefetch, Amcache, ShimCache, MFT, EVTX, memory, YARA, etc.) proves and doesn't prove, plus the ≥2 artifact-class corroboration table. |
| `codex-compatibility.md` | **ACTIVE** | Operator guide for using Codex with the same two product MCP servers, without broad external MCP defaults. |
| `cryptographic-attestation.md` | **REQUIRED** | Three-link chain-of-custody story (rubric criterion #5). How `manifest_verify` produces FRE 902(14) self-authenticating evidence post-A5. |
| `DATASET.md` | **REQUIRED** | Devpost Required Component #5. Every fixture the agent was tested against, with SHA-256 + license + expected findings. |
| `demo-script-a2.md` | **ACTIVE** | 5-minute Devpost demo video script (A2 flow). Pre-flight checklist + per-beat narration + rubric mapping. |
| `divergences-resolved.md` | **ACTIVE** | Ledger of settled spec/code divergences moved out of `CLAUDE.md`. |
| `false-positives.md` | **ACTIVE** | Operator's guide. Three architectural FP layers + four operational habits + per-tool FP risk table. |
| `finding-to-action.md` | **ACTIVE** | Per-MITRE-technique IR playbook: from a SUSPICIOUS/CONFIRMED finding to analyst next steps (T1014, T1055, T1547, T1543, T1053, T1070, T1041/T1048). |
| `investigation-phases.md` | **ACTIVE** | Phase-by-phase walkthrough: case_open → Pool A/B → contradictions → verify → judge → correlate → self-score → finalize. What each phase produces in audit.jsonl and verdict.json. |
| `replay-determinism.md` | **ACTIVE** | Replay determinism notes for stable verifier behavior. |
| `verdict-semantics.md` | **ACTIVE** | Analyst-facing meaning of `SUSPICIOUS` / `INDETERMINATE` / `NO_EVIL`; mirrors `compute_verdict` in `scripts/find_evil_auto.py`. |

### Current automation outputs

- `scripts/find-evil-auto --run-summary <path>` writes a machine-readable run summary outside the normal case artifact set. It points to the local run directory and records artifact paths, report QA, release-gate/expert-signoff state, signer, readiness state, blockers, warnings, and final result/error.
- `scripts/readiness-gate.ps1` is the packet-producing readiness flow. Full mode writes `readiness-summary.json`, `readiness-packet-manifest.json`, and `readiness-packet.zip` under `tmp/readiness-gates/<run-id>/`; fixed `-RunId` reruns refresh generated packet contents and may use a timestamped local-build child run; passing states mean ready for human expert review, not customer release.
- `scripts/readiness-gate.sh` is POSIX strict/check-only. It can print `SUBMISSION_READY` for its legacy checks, but it does not create the readiness packet ZIP.
- Local smoke gates are `bash scripts/run-all-smokes.sh` for POSIX/Git Bash and `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/run-all-smokes.ps1` for native Windows. Do not copy old hard-coded smoke counts; the scripts print the current tally.

## `agent-config/` (runtime DFIR agent identity)

These are read by the agent at investigation start (per CLAUDE.md "Agent investigation prompt").

| File | Status | Purpose |
|---|---|---|
| `agent-config/SOUL.md` | **ACTIVE** | Mission + epistemic hierarchy (CONFIRMED > INFERRED > HYPOTHESIS) + FRE 902(14) stance + cross-artifact rule + no-attribution rule. |
| `agent-config/AGENTS.md` | **ACTIVE** | Supervisor / Pool A / Pool B / judge / verifier / correlator role descriptions. |
| `agent-config/PLAYBOOK.md` | **ACTIVE** | Tool sequences per evidence type (`.e01`, `.mem`, `.evtx`, Velociraptor `.zip`, mixed dirs). |
| `agent-config/TOOLS.md` | **ACTIVE** | Typed tool surface — 19 Rust + 12 Python MCP tools. |
| `agent-config/MEMORY.md` | **ACTIVE** | Tier-1 DFIR caveats (Amcache LastModified ≠ execution, ShimCache order changed at Win8.1, Logon Type 3 vs 10, etc.). |
| `agent-config/HEARTBEAT.md` | **ACTIVE** | Per-iteration self-check loop. |
| `agent-config/JUDGING.md` | **ACTIVE** | SANS Find Evil! 2026 rubric (6 criteria, verbatim) + end-of-investigation self-score checklist that emits `kind=judge_selfscore` audit records. |

## `docs/specs/` (architecture specs)

Status-banner-prefixed within each file. Read in CLAUDE.md "Document hierarchy" precedence order.

| File | Status | Purpose |
|---|---|---|
| `2026-04-23-find-evil-automation-master-design.md` | **SHIPPED** | Master design — 4-subsystem decomposition + 4 differentiators (M1 leaderboard, M2 crypto, M3 widgets, M4 ACH). |
| `2026-04-23-amendment-option-b-claude-code-mode.md` (**A1**) | **SHIPPED** | Subscription-mode credentials for the swarm; LiteLLM proxy never built. |
| `2026-04-25-amendment-a2-claude-code-primary-interface.md` (**A2**) | **SHIPPED** | Drops the custom Python orchestrator; Claude Code IS the orchestrator. |
| `2026-04-26-amendment-a3-agent-army-and-dashboard.md` (**A3**) | **SHIPPED** (Phases 1-4 + role-state dashboard) / **RESEARCH** (pixel-art/chrome polish) | Memory + ACP MCP tools + SSE dashboard with role-state sprite containers; pixel-art and bead/chip chrome remain parked. |
| `2026-04-30-amendment-a5-ots-removal.md` (**A5**) | **SHIPPED** | Removes the OpenTimestamps/Bitcoin fourth tier; chain collapses to 3 tiers (audit prev_hash → rs_merkle → sigstore). |
| `2026-04-27-amendment-a4-managed-agents-runtime.md` (**A4**) | **RESEARCH** | Archived under `docs/archive/`; future-deployment design for hosted Anthropic Managed Agents runtime. Not on the SANS critical path. |
| `2026-04-23-layered-test-sandbox-design.md` (**Spec #3**) | **SHIPPED** | L0/L1/L2/L3 sandbox stack. L2 advisory only. |
| `2026-04-24-autonomous-build-swarm-design.md` (**Spec #1**) | **ACTIVE** | Build swarm architecture (still authoritative reference for swarm extension). |
| `2026-04-25-the-product-design.md` (**Spec #2**) | **SHIPPED** (with A2 + A5 amendments) | The DFIR tool the judges run. |
| `2026-04-26-orchestration-glue-design.md` (**Spec #4**) | **SHIPPED** | Thin GHA CI pipeline. |

(Amendment A5 spec: `2026-04-30-amendment-a5-ots-removal.md` — code-only removal of the OTS/Bitcoin tier; written as a standalone doc to complete the amendment lineage.)

## `docs/plans/` (plans and launch checklist)

The original five implementation plans shipped. Each carries a RETIRED banner naming where the live code lives. Do not execute retired plans as TDD plans. The launch checklist is preserved as release history now that `v-submit` exists.

| File | Status | Where it lives now |
|---|---|---|
| `2026-05-20-finish-to-v-submit-plan.md` | **SHIPPED** | Release-history checklist for commits, readiness refresh, GitHub visibility, L3 evidence, demo URL, `v-submit`, and Devpost upload |
| `2026-04-23-build-swarm-plan.md` | **RETIRED** | `services/swarm/`, `scripts/swarm-*.sh` |
| `2026-04-23-orchestration-glue-plan.md` | **RETIRED** | `.github/workflows/`, `scripts/package-devpost.sh` |
| `2026-04-23-product-plan.md` | **RETIRED** | `services/mcp/`, `services/agent/`, `services/agent_mcp/` (with A2 + A5 carve-outs) |
| `2026-04-23-sandbox-plan.md` | **RETIRED** | `.github/workflows/l[0-3]-*.yml`, `docker/l1-compose.yml`, `packer/sift-microvm.pkr.hcl` |
| `2026-04-26-amendment-a3-plan.md` | **RETIRED** (Phases 1-4) / **PARKED** (Phases 5-6) | `services/agent_mcp/findevil_agent_mcp/tools/`, `services/agent/findevil_agent/memory/`, `apps/web/` |

## `docs/runbooks/` (operational procedures)

| File | Status | Purpose |
|---|---|---|
| `ci-smoke-checklist.md` | **ACTIVE** | End-to-end pipeline verification before submission. |
| `dockerfile-a2-decision.md` | **RESEARCH** (decision archive) | Cut the in-container `find-evil` wrapper + `.deb` packaging (PR #4, 2026-04-27, "Option B"). Body retained as decision record. |
| `engram-memory-integration.md` | **ACTIVE** | Optional: wire Engram (standalone Apache-2.0 knowledge/memory MCP server) as a third, locally-run MCP server. Not bundled, not in the investigation flow, not in the audit chain. |
| `github-remote-bootstrap.md` | **ACTIVE** | Pre-submission ops doc for setting up the public GitHub repo URL Devpost requires. |
| `local-smoke-gate.md` | **ACTIVE** | Prerequisites, per-smoke coverage map, and common failure → fix pairs for `bash scripts/run-all-smokes.sh`. |
| `n8n-automation-integration.md` | **ACTIVE** | Optional: wire n8n as an operator-local harness *around* the product — repeatable runs + post-verdict finding-to-action (via `n8n-mcp`, user-scope). Not bundled, not the orchestrator, not in the audit chain. |
| `practical-sans-dfir-completion-prompt.md` | **ACTIVE** | Strict copy/paste coding-agent prompt for finishing practical SANS DFIR investigation outputs without new crypto work. |
| `readiness-packet-windows.md` | **ACTIVE** | Three invocation modes for `scripts/readiness-gate.ps1`, readiness-state meanings, and `READINESS_BLOCKED` unblocking guide. |
| `researched-dfir-automation-improvement-prompt.md` | **RESEARCH** | Research-backed prompt for future DFIR automation improvement work. |
| `swarm-operations.md` | **ACTIVE** | Swarm startup, morning triage, resume-from-checkpoint, Postgres DAG inspection, and orphan-worktree cleanup. |

## `docs/release-evidence/`

| File | Status | Purpose |
|---|---|---|
| `README.md` | **ACTIVE** | Explains why release evidence summaries are committed and what they are not. |
| `l3-local-sift.json` | **ACTIVE** | Validated local VMware/SIFT L3 fallback evidence for the `v-submit` release path. |

## `docs/design-briefs/`

| File | Status | Purpose |
|---|---|---|
| `phase-5-6-sprite-design-brief.md` | **RESEARCH** (parked) | Claude Design prototyping handoff for the 5 pixel-art sprites + AuditBeadString chrome. Gated on a separate prototyping pass. |

(The earlier Judge Mode design briefs + 8-iteration screenshots were retired in commit `20013e4` along with the Judge Mode spec + plans.)

## `docs/braindumps/`

| File | Status | Purpose |
|---|---|---|
| `2026-04-26-agent-army-and-dashboard.md` | **RESEARCH** (origin doc) | Produced Amendment A3 — kept for original brainstorming context. |

## `docs/archive/`

| File | Status | Purpose |
|---|---|---|
| `README.md` | **ACTIVE** | Explains that archived notes are non-authoritative and maps current archive contents. |
| `protocol-sift-integration-reference.md` | **RESEARCH** (external, NOT authoritative) | Where this disagrees with project specs, specs win — see CLAUDE.md "External 'Protocol SIFT' reference" for reconciled contradictions. |
| `2026-04-27-amendment-a4-managed-agents-runtime.md` | **RESEARCH** | Future hosted-agent runtime design; not on the SANS critical path. |
| `phase-5-6-sprite-design-brief.md` | **RESEARCH** | Archived copy of the parked sprite/chrome brief. |
| `figures/` | **REFERENCE** | Embedded images for archived Protocol SIFT reference material. |

## `docs/templates/`

| File | Status | Purpose |
|---|---|---|
| `devpost-readme.md` | **ACTIVE** | README template that ships in the v-submit bundle (envsubst'd by `scripts/package-devpost.sh`). |

## `docs/legacy/`

| File | Status | Purpose |
|---|---|---|
| `BUILD_PLAN_v2.md` | **RETIRED** (moved 2026-05-02) | Pre-A2/A3/A5 9-week roadmap. Pitch surface consolidated into `README.md` per Phase 3c+3d of the doc reorg (SUBMISSION_NOTES.md was deleted in 3d; judge Q&A migrated to README "Anticipated questions"). Kept for git-log archaeology. |
| `Find_Evil_Research_and_Build_Plan-v1.docx` | **RETIRED** (binary) | Original 72KB research doc; relevant content was promoted into BUILD_PLAN_v2 + the A1/A2/A3 amendments. Cannot carry a banner (binary). |

## `docs/reports/`

Investigation reports + their figures. Currently:

- `docs/reports/2026-04-26-srl2018-dc-investigation.md` (+ `.html` + `.pdf` co-renderings) — 22-host SRL-2018 fleet investigation. Status: **REFERENCE** (showcase example referenced from CLAUDE.md + README).
- `docs/reports/figures-2026-04-26/` — embedded report images.

## What this index does NOT cover

- User-level memory at `~/.claude/projects/.../memory/` — 22 files, see `MEMORY.md` index there. Not git-tracked.
- Source code (`services/`, `apps/`, `scripts/`) — see CLAUDE.md "Repository layout" + per-service `README.md`.
- External research clones (`git-hub-references/`, `openclaw/`, `hermes-agent/`, etc.) — see CLAUDE.md "External reference clones." Gitignored.
