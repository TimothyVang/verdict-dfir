# Repo Guide — Layout, Subsystems, Amendments

Internal reference extracted from `CLAUDE.md`. For the judge-facing trust-boundary diagram
see `docs/architecture.md`; for commands and the live-test gate see
`docs/live-test-matrix.md` and `CLAUDE.md` §5.

---

## Repository layout

```
.
├── Cargo.toml / Cargo.lock / rust-toolchain.toml   # Rust workspace (members = [services/mcp]); Cargo.lock IS committed (app, not library)
├── requirements.txt                                # host pip DFIR tooling (volatility3==2.27.0, matplotlib) + large-download manifest
├── Dockerfile / .dockerignore                      # Production multi-stage → ghcr.io/find-evil/find-evil:v<N>
├── LICENSE                                         # Apache-2.0
├── sift-2026-04-22.ova                             # ~9.4 GB SIFT VM image — Packer input; gitignored (*.ova), never committed
├── .mcp.json / .mcp.json.sift                      # Auto-spawn registry: 6 servers (2 product + n8n-mcp, playwright, puppeteer, qmd dev-memory); .sift swaps the 2 product servers to SSH transport
│
│   # ── PRODUCT (ships; in the audit chain) ──
├── services/mcp/                                   # Rust MCP server (20 typed DFIR tools; hand-rolled stdio JSON-RPC 2.0)
├── services/agent/                                 # Python package findevil_agent — M2 crypto + M4 ACH + A3 memory/acp (FastAPI/LangGraph dropped under A2)
├── services/agent_mcp/                             # Python MCP server wrapping M2/M4/memory/ACP/expert feedback as 12 typed tools
├── apps/web/                                       # Next.js 15 + Tailwind v4 + NES.css dashboard (A3) — SSE audit-log tail, role-state sprites, /debug, /codex
├── apps/mcp-widgets/                               # M3 widgets — DEFERRED per A2 §2.1
├── agent-config/                                   # Runtime DFIR agent identity (SOUL/AGENTS/TOOLS/MEMORY/HEARTBEAT/JUDGING/PLAYBOOK/EXPERT/GROUNDING + expert-rules.json)
├── scripts/                                        # ~70 entry points + smoke runners; `scripts/verdict` is canonical (see docs/using/running-verdict.md)
│
│   # ── DOCS / FIXTURES / CI ──
├── docs/                                           # reference/ (tool+dep+env inventory), using/ (operator guides), analyst/, specs/, plans/, runbooks/, references/, legacy/, reports/
├── goldens/                                        # 12 forensic ground-truth datasets (NIST, DFRWS, Ali Hadi, M57-Jean, Nitroba, …) with expected-findings.json
├── fixtures/                                       # downloaded test fixtures (e.g. nitroba pcap)
├── evidence/                                       # staged evidence (gitignored; never committed)
├── out/ + tmp/                                     # run outputs (auto-runs, fleet-runs, summaries) — generated
├── assets/                                         # logo + brand assets
├── packer/sift-microvm.pkr.hcl                     # L3 warm-qcow2 build from the OVA
├── docker/                                         # l1-compose.yml, l1-devbase / l2-siftlite sandbox Dockerfiles
├── .remotion/                                      # Remotion headless render cache (demo video)
├── target/ / node_modules/                         # build output — generated, gitignored
└── .github/workflows/                              # l0/l1/l2/l3 + release + competitor-watch + devpost-submit
│
│   # ── EXTERNAL CLONES (gitignored; never ship, never import) ──
├── obsidian-mind/                                  # DEV/OPERATOR MEMORY VAULT (MIT, own .git) — see docs/runbooks/obsidian-mind-memory.md. NEVER evidence, NEVER in the audit chain.
└── n8n-references/                                 # n8n docs/templates/workflows for the optional finding-to-action automation
```

> **External clones (`obsidian-mind/`, `n8n-references/`) are gitignored** — they
> do not ship in the Devpost zip. `obsidian-mind/` is the dev/operator **memory layer** (see
> CLAUDE.md §8.5 and `docs/runbooks/obsidian-mind-memory.md`); it is held strictly outside the
> investigation and the audit chain.

The pre-A2 `python -m findevil_agent.cli` entry point was dropped by A2; the Dockerfile
wrapper + `scripts/build-deb.sh` were cut 2026-04-27 (PR #4) per
`docs/runbooks/dockerfile-a2-decision.md` "Option B." L0 `amendment-a2-guard` + L1
`divergence-smoke.py` §3 fail CI if `findevil_agent.cli` reappears.

---

## The 3 subsystems (master design §3, less the retired build swarm)

```
#3 Sandbox (L0-L3) ──► #2 Product ──► #4 Orchestration Glue
                       (sandbox also gates Product CI)
```

> The original master design had a 4th subsystem — **#1 Build Swarm**, an overnight
> draft-PR generator that was invisible to judges and not part of the submission. It was
> removed 2026-06-07 (A6). The numbering (#2/#3/#4) is kept for continuity with the specs.

- **#3 Sandbox** — blocks everything else. L0 lint, L1 unit/build (Docker Ubuntu 22.04), L2 SIFT-lite (Sysbox runtime, advisory), L3 full SIFT VM parity (QEMU microvm + qcow2 snapshot-restore, Packer-built from `sift-2026.03.24.ova`, on GHA KVM larger runners).
- **#2 Product** — the submission. Under A2 the layers collapse to: evidence vault → SIFT tool subprocesses → two MCP servers → Claude Code (supervisor + ACH pool subagents + audit-log driver). Primary entry point: `scripts/find-evil` (or `claude`).
- **#4 Orchestration Glue** — thin CI: GHA workflows, branch protection, release pipeline, Devpost submission zip on `v-submit` tag.

### Sandbox layer cheat sheet (Spec #3)

| Layer | Runtime | Budget | Blocks merge? |
|---|---|---|---|
| L0 | GHA `ubuntu-24.04`, no containers | 30–60s | Yes |
| L1 | Docker Compose + GHA standard runner | 2–5min | Yes |
| L2 | Sysbox runtime (rootless systemd+FUSE) | 5–10min | No (advisory on PRs) |
| L3 | QEMU microvm + qcow2 snapshot-restore on GHA KVM larger runner | ~5–20min | Yes for **releases**, nightly on `master` |

L3's warm `.qcow2.zst` is built once by Packer from `sift-2026.03.24.ova` and cached via
`actions/cache`. The OVA is in `.gitignore` (`*.ova`) and never committed.

### Large files to never commit

`.gitignore` already excludes `*.ova`, `*.qcow2`, `*.vmdk`, `*.vdi`, `*.E01`, `*.dd`,
`*.raw`, `*.mem`, `*.aff`, `*.aff4`, `*.vhd`, `*.vhdx`, `target/`, `node_modules/`,
`.venv/`, `__pycache__/`, `.next/`, `dist/`, `state/`, `checkpoints/`, `*.sqlite`. Evidence
images (NIST CFReDS Hacking Case, OTRF datasets) are pulled by L3 scripts at CI time — never
enter the git tree.

---

## Document hierarchy

Read in precedence order. Later documents override earlier ones only where explicitly noted.

### Active amendments (live)
1. **`docs/specs/2026-04-23-find-evil-automation-master-design.md`** — master design. Originally a 4-subsystem decomposition + 4 differentiators (M1 leaderboard, M2 crypto chain-of-custody, M3 MCP App widgets, M4 ACH competing-hypothesis agents); the build-swarm subsystem was removed 2026-06-07 (see A6), leaving 3 subsystems.
2. **A1** — `docs/specs/2026-04-23-amendment-option-b-claude-code-mode.md`. Was the build-swarm credential mode (replaced LiteLLM proxy + USD caps with the user's Claude Code subscription). The swarm was removed under A6, so A1's swarm specifics are historical; the Product still accepts three credential modes (see CLAUDE.md §8).
3. **A2** — `docs/specs/2026-04-25-amendment-a2-claude-code-primary-interface.md`. Drops the custom Python orchestrator (`graph.py`/`api.py`/`cli.py`/`supervisor.py`/specialists). Claude Code IS the orchestrator. Adds `services/agent_mcp/` and `.mcp.json` registering both servers. `apps/web/` + `apps/mcp-widgets/` deferred (A3 un-defers `apps/web/`).
4. **A3** — `docs/specs/2026-04-26-amendment-a3-agent-army-and-dashboard.md`. Un-defers `apps/web/` (NES.css live dashboard tailing the audit JSONL hash chain; 5 sprites mapping to AGENTS.md roles). Adds 3 tools to `findevil-agent-mcp`: `memory_remember`/`memory_recall` (Hermes FTS5 cross-case memory), `pool_handoff` (IBM ACP envelope). `apps/mcp-widgets/` remains deferred.
5. **A5** (2026-04-30, active — no spec doc yet, encoded in commits + CHANGELOG). Removes the OpenTimestamps/Bitcoin tier. Cuts `services/agent/findevil_agent/crypto/ots.py` + tests, `ots_stamp`/`ots_verify` MCP tools, and the `opentimestamps-client` dep. Chain collapses from 4 tiers to 3 (audit prev_hash → rs_merkle → sigstore). Commits `743404d`, `a75ea44`, `e265600`, `6da4d95`, `2b59572`. Post-A5 `findevil-agent-mcp` registry was 11 tools; Track 4 adds `expert_miss_capture` as the 12th. `services/agent_mcp/tests/test_stdio_smoke.py` enforces the current count.
6. **A6** (2026-06-07, active — no spec doc; encoded in commits + CHANGELOG). Removes the **build swarm** (Spec #1) entirely: `services/swarm/`, `scripts/swarm-start.sh`/`swarm-status.sh`, `docker/swarm-postgres.yml`, the `autonomous-loop.*` scripts, the swarm spec/plan/runbook docs, the `budget-guard.yml` workflow, and the swarm CI/smoke guards. The swarm was dev-time automation invisible to judges; removing it does not touch the Product. Subsystems collapse from 4 to 3.

### Per-subsystem specs (in `docs/specs/`)
- `2026-04-23-layered-test-sandbox-design.md` — Spec #3 (L0-L3 sandbox; blocks all other work).
- `2026-04-25-the-product-design.md` — Spec #2 (the DFIR tool judges run).
- `2026-04-26-orchestration-glue-design.md` — Spec #4 (GHA CI). _(Spec #1, the build swarm, was removed under A6.)_

### Implementation plans
`docs/plans/` — one per spec, each step a TDD checkbox with the exact failing test →
implement → commit sequence.

### Archived (do not read for current architecture)
- ~~`BUILD_PLAN_v2.md`~~ — moved to `docs/legacy/BUILD_PLAN_v2.md` 2026-05-02 (pre-A2/A3/A5 research artifact; pitch surface consolidated into `README.md`).
- `Find_Evil_Research_and_Build_Plan.docx` — v1 research doc; authoritative only for what v2 doesn't contradict.

---

## Spec/code divergences (code wins)

Specs were written 2026-04-23; code has been shipped since 2026-04-24. Where they disagree,
the shipped code + its pin files are authoritative. **Eight settled divergences live in
`docs/divergences-resolved.md`.** Only active uncertainty stays below.

- **A5 OTS removal: legacy specs (M2 spec, A2 §2.3) still reference `ots_stamp`/`ots_verify`/Bitcoin as design-era behavior.** Code has cut all five touchpoints (`crypto/ots.py`, both MCP tool modules, `opentimestamps-client` dep, orchestrator + report-renderer + smoke refs). Chain is 3 tiers; `docs/cryptographic-attestation.md` documents the post-A5 trade-off. Code wins for any remaining legacy-spec conflict. No A5 spec doc written yet.
- **Replay evidence is a customer-PDF blocker.** `verify_finding_replay_embedded` was advisory during Track 3a; Track 3b promoted it to blocker in `agent-config/expert-rules.json` and `scripts/find_evil_auto.py`. Do not downgrade without an explicit policy change.

---

## Project state, memory & external references

### Current project state

All subsystems exist. L1 CI runs the smoke runners; the dev "done" gate is a passing **live
test** (`scripts/verdict`, see `docs/live-test-matrix.md`), not a smoke run. The Product
layer is feature-complete through A3 Phase 4 plus the post-A5 `vol_psxview` addition, the
Track 1 disk mount/extract slice, expert miss feedback, `find-evil-auto --run-summary`, and
the PowerShell readiness packet gate. Shipped MCP surface: 20 Rust DFIR tools + 12 Python
crypto/ACH/memory/ACP/expert-feedback tools. The audit-log SSE tail powers a Next.js +
Tailwind v4 + NES.css dashboard at `apps/web/` with role-state sprite containers and
`/debug`; only the pixel-art sprite swap and AuditBeadString/HashChainBadge/FindingChip
chrome remain design-polish work.

**Before writing code, read the relevant spec and plan** for the subsystem you're touching.
When spec and code disagree, **code + committed pin files win** (see the divergences section
above). `CHANGELOG.md` summarizes per-feature; `git log --oneline -20` for recent commits.

### Example reports & checklists
- False-positive prevention strategy + analyst checklists: **`docs/false-positives.md`**.
- Example end-to-end investigation report: **`docs/reports/2026-04-26-srl2018-dc-investigation.md`** (SRL-2018 dataset). The process-enumeration divergence (`vol_pslist`=0 vs `vol_psscan`=124) is reported as a **HYPOTHESIS**, not confirmed DKOM: on this image it is an acquisition smear / kernel-global read failure (`KeNumberProcessors`=0, core OS singletons recovered only by `psscan`, duplicate `System` EPROCESS) — which a rootkit cannot produce. A T1014 claim needs ≥2 artifact classes.

### Memory system
User-level auto-memory is auto-loaded into every session. The index (`MEMORY.md`) points to
per-topic memory files. Read the index at session start if you need historical context;
update the relevant memory file (don't invent a new one) when facts change.

### External clones (gitignored; never ship, never import)
Local-only directories with their own `.git`, all `.gitignore`'d so they never enter the Devpost
zip (produced by `scripts/package-devpost.sh`):

- **`obsidian-mind/`** — the dev/operator **memory vault** (MIT). Promoted from a reference clone
  to VERDICT's memory layer: `brain/` notes + QMD semantic search, queried via the local-scope
  `qmd` MCP. Held strictly outside the investigation and the audit chain. See
  `docs/runbooks/obsidian-mind-memory.md`.
- **`n8n-references/`** — n8n docs/templates/workflows backing the optional post-verdict
  finding-to-action automation (`docs/runbooks/n8n-automation-integration.md`).
- **`.playwright-mcp/`** — Playwright MCP scratch state.
