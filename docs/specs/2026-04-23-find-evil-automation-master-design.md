# Find Evil! — Automation Master Design (v1)

> **Status: SHIPPED, partially superseded.** The 4-subsystem decomposition described here (Sandbox, Build Swarm, Product, Orchestration Glue) was built and CI was green. **Amendment A6 (2026-06-07) removed the Build Swarm subsystem entirely** — the decomposition is now 3 subsystems (Sandbox, Product, Orchestration Glue). Treat all "Build Swarm" content below as historical. Subsequent amendments A1, A2, A3, A5 modified what's actually built — read those after this. A4 adds a future-deployment mode (not on the SANS critical path).

**Date:** 2026-04-23
**Submission deadline:** 2026-06-15 22:45 CDT (53 days out)
**Supersedes:** `BUILD_PLAN_v2.md` is still the source of truth for DFIR fundamentals; this document layers research-validated automation + differentiators on top.

---

## 1. Mission (one sentence)

Ship an automated DFIR tool — runnable via OpenClaw or Claude Code on the SIFT VM — that investigates Windows host evidence end-to-end, produces findings with cryptographic chain-of-custody, self-corrects visibly via competing-hypothesis agents, and renders through both a Lovable-grade Next.js SPA and standards-based MCP App widgets.

## 2. Constraints (non-negotiable)

- **Runtime:** must launch via `openclaw run --case X.e01` OR `claude-code` on the SIFT VM — both entry points supported via the same LangGraph graph.
- **Submission repo license:** MIT or Apache-2.0 (per SANS rules).
- **AGPL/GPL tools (Hayabusa, Chainsaw, Velociraptor):** subprocess boundary only — never linked.
- **Judge narrative:** "orchestrator that reduces friction," never "autonomous responder" — see `project_judging_signals.md`.
- **Budget ceiling:** ≤$50/night hard cap on build-swarm LLM spend via LiteLLM proxy.

## 3. The 4 subsystems

| # | Subsystem | Lives where | Judged? |
|---|---|---|---|
| **#3** | **Test Sandbox (L0-L3)** — layered pre-commit validation environment | Dev laptop + GHA | No (but blocks all others) |
| **#1** | **Autonomous Build Swarm** — meta-orchestrator that writes the Product for us nightly | Dev laptop | No (invisible to judges) |
| **#2** | **The Product** — the automated DFIR tool the judges run | SIFT VM | **YES — this is the submission** |
| **#4** | **Orchestration Glue** — CI pipeline tying swarm → sandbox → release | GHA | No |

## 4. Dependency order

```
#3 Sandbox ─────→ #1 Build Swarm ─┐
            ────→ #2 Product      ├──→ #4 Orchestration Glue
```

Sandbox blocks everything (swarm needs it to self-validate; Product needs it for CI). Orchestration glue comes last (thin layer once others exist).

## 5. The 4 differentiators and where they attach

| ID | Attaches to | What it provides |
|---|---|---|
| **M1 — Public Leaderboard** (`findevil-bench.dev`) | External service, scores #2 Product | Published DFIR-Metric benchmark scoring; lets judges look up performance numbers without running the tool |
| **M2 — Cryptographic Chain-of-Custody** (audit hash chain + rs-merkle + sigstore Rekor) | Inside #2 Product | Supports a FRE 902(14) self-authenticating-evidence claim. Pre-A5 also tail-anchored to Bitcoin via OpenTimestamps; that tier was removed — see CLAUDE.md "Spec/code divergences" + Amendment A5 |
| **M3 — MCP Apps widgets** (timeline, heatmap, evidence-diff) | Inside #2 Product UI layer | Works in Claude Desktop / ChatGPT / Cursor / custom — zero-friction for any MCP-compatible client |
| **M4 — LLM-powered ACH** (Analysis of Competing Hypotheses, Heuer 1970s) | Inside #2 Product agent layer | Visible self-correction as architecture: two pools investigate the same evidence with opposing priors, contradictions surface as first-class output before judge reconciliation |

**Cut:** M5 (Reversible Verification) — judging risk + unvalidated + expensive sandbox-in-forensic-tool engineering.

## 6. Detailed design — where each subsystem lives

### #3 Test Sandbox — L0-L3 layered stack

See **`2026-04-23-layered-test-sandbox-design.md`** for full detail. Summary:

- **L0 (lint/static)** — GHA `ubuntu-24.04`, ~30-60s
- **L1 (unit/dev loop)** — Docker Compose on laptop + GHA standard runner, Ubuntu 22.04 base
- **L2 (SIFT-lite)** — **Sysbox runtime**, systemd + FUSE + loopback without `--privileged`
- **L3 (full SIFT parity)** — **QEMU microvm + qcow2 snapshot-restore** built via Packer from the existing 9.3GB OVA, runs on **GHA KVM larger runners**. 3-8s warm restore. ~$240/mo @ 100 runs/day.

### #1 Autonomous Build Swarm

**Pattern (validated):** LangGraph Supervisor + Claude Agent SDK subagents + git worktrees per PR + LiteLLM budget proxy + PostgresSaver checkpoint.

- **Supervisor:** single Python process, LangGraph with `PostgresSaver`, holds week→PR DAG
- **Workers:** Claude Code subagents (`CLAUDE_CODE_FORK_SUBAGENT=1` → 90% prompt cache savings), one per language (Rust / Python / TS)
- **Isolation:** each worker in its own `git worktree` (so polyglot workers don't stomp each other)
- **Validation:** each PR runs L1 in worker's sandbox; critic subagent reviews diff + test output before `gh pr create --draft`
- **Budget enforcement:** LiteLLM proxy refuses calls past cumulative USD > $50/night
- **Anti-loop guards:** `--max-turns=40`, no-progress detector (3 tool calls without new diff → kill), wall-clock 8hr watchdog
- **Durability:** Postgres DAG state + git branches = resume-safe across laptop sleep
- **Scheduler:** `jshchnz/claude-code-scheduler` for nightly kickoffs

Full spec: `2026-04-24-autonomous-build-swarm-design.md` (next after Sandbox approval).

### #2 The Product — the DFIR tool judges run

**Runtime entry points (both supported):**
```
openclaw run --case <path.e01>   # primary for SIFT users
claude-code .                    # alt entry for Claude-native users
find-evil serve                  # launches Next.js + FastAPI + Rust MCP
find-evil run --case X.e01       # unattended CI/batch mode
```

**Internal architecture (7 layers — unchanged from BUILD_PLAN_v2 §3 except where noted):**

1. Evidence vault (read-only mount)
2. SIFT tool subprocess layer (unprivileged user, wall-clock + CPU budgets)
3. **Typed Rust MCP server (rmcp)** — narrow typed tools, no `execute_shell`, DuckDB per case
   - **NEW:** link `omerbenamram/evtx` Rust crate directly for in-process EVTX parsing
   - **NEW:** subprocess boundary to Hayabusa (Sigma scoring), Chainsaw v2 (timeline carving), Velociraptor (adaptive collections)
   - **NEW:** `mcp-scanner` passed as pre-submission sanity check
4. Memory layer:
   - L1 DuckDB per case
   - L2 LangGraph PostgresSaver checkpoint + **M2 crypto-audit JSONL** (sigstore-signed)
   - L3 Hermes cross-case learned memory (unchanged)
5. **Agent graph — ACH pattern (M4):** single supervisor + 2 opposing-prior worker pools (persistence-biased, exfil-biased) + judge node + **contradiction surface** emitted to UI before reconciliation. Single round. Homogeneous model strength.
6. Agent runtime — FastAPI + LangGraph in one Python process. Rust MCP is stdio subprocess.
7. **Presentation:**
   - **Primary:** Next.js 15 SPA (unchanged from v2 §6)
   - **M3 progressive enhancement:** 3 MCP App widgets (timeline / heatmap / evidence-diff) served from Rust MCP server, render inside Claude Desktop / ChatGPT / Cursor
   - CLI `find-evil run` for unattended mode
   - `notify-send` + optional Slack webhook on verdict commit

**Chain-of-custody (M2) layer — new first-class concern:**
- `sigstore-python` signs every MCP tool call (canonical JCS JSON)
- `rs-merkle` builds per-run Merkle tree over tool calls + findings
- `opentimestamps-client` anchors Merkle root to Bitcoin
- `find-evil verify <manifest>` binary + WASM web verifier = judge verifies in <60s
- Report PDF carries detached `.ots` + cosign signature in metadata
- Pitch language: "FRE 902(14) self-authenticating" verbatim

**ACH agents (M4) — new first-class concern:**
- Supervisor dispatches to two worker pools simultaneously
- Pool A: "assume attacker goal is persistence" system prompt
- Pool B: "assume attacker goal is exfiltration" system prompt
- Judge node: credibility-weighted score merge (per Estornell ICML 2025)
- Contradiction node: emits disagreements to UI as first-class event (`ContradictionFound` in the AgentEvent union)
- Budget: 2.2-2.8× single-agent LLM cost; cache evidence retrieval in L1 DuckDB aggressively
- Frame everywhere as "LLM-powered Analysis of Competing Hypotheses (Heuer)"

Full spec: `2026-04-25-the-product-design.md` (after Sandbox + Build Swarm approved).

### #4 Orchestration Glue

- Nightly: build-swarm dispatches against v2 roadmap → PRs open → L1 runs per PR → merge if critic + L1 pass
- Weekly: L3 golden-run on NIST CFReDS Hacking Case → score published to M1 leaderboard
- Release: `git tag v<week>` → CI packages `.deb` for SIFT install + Docker image + offline `report.html`
- Submission: final release on 2026-06-14 (1 day buffer) → Devpost package auto-generated + uploaded

Full spec: `2026-04-26-orchestration-glue-design.md` (last).

## 7. Revised 8-week schedule

| Week | Dates | Focus | Differentiator shipped |
|---|---|---|---|
| 1 | Apr 22-28 | **Spec #3 + #1 + #2 + #4** (all 4 written), Week-1 skeleton from v2 §10, Packer L3 build | — |
| 2 | Apr 29-May 5 | Rust MCP scaffold + 3 tools (`case_open`, `mft_timeline`, `evtx_query`). **M2 skeleton** — sigstore-signed tool calls | **M2** start |
| 3 | May 6-12 | Remaining 7 MCP tools + Hayabusa/Chainsaw subprocess wrappers. **M2 complete** (rs-merkle + sigstore + verify; original plan included OTS, removed under A5) | **M2** ship |
| 4 | May 13-19 | LangGraph graph + verifier. **M4 ACH pattern** scaffolded (supervisor + 2 pools + judge + contradiction node) | **M4** start |
| 5 | May 20-26 | Multi-source correlator. **M4 complete**. Hypothesis board UI with MITRE deltas | **M4** ship |
| 6 | May 27-Jun 2 | Benchmark harness (DFIR-Metric). **M1 leaderboard online** — scores us + 3 reference DFIR agents nightly | **M1** ship |
| 7 | Jun 3-9 | **Polish sprint**: Plan Mode UI, DFIR vocab audit, guardrails-as-chrome, verifier animations, verdict card, `notify-send`/Slack. **M3 MCP Apps widgets** (3: timeline, heatmap, evidence-diff) | **M3** ship |
| 8 | Jun 10-15 | Demo record (target Lee's 14:27 template), Devpost submission, benchmark paper, video | — |

**Buffer:** week-7 dog-leg — if polish runs over, cut M3 widgets (cheapest of the four to drop) before cutting M1 leaderboard or DFIR vocab audit.

## 8. Budget estimate (53 days)

| Line | Estimate |
|---|---|
| GHA KVM larger runners (L3 nightly) | ~$240-300/mo → ~$420-525 total |
| Claude API for build swarm (≤$50/night cap) | ~$2,650 worst case (53 × $50) |
| Claude API for product self-testing | ~$500 (validation runs, benchmarks) |
| M1 leaderboard hosting | ~$20 over 53 days |
| Postgres / LiteLLM / Sysbox / Packer | $0 (local) |
| **Total ceiling** | **~$3,500-4,000** |

## 9. Risks (new, beyond BUILD_PLAN_v2 §11)

| # | Risk | Mitigation |
|---|---|---|
| R24 | Build swarm burns $50/night + nothing merges | Dry-run gate: first PR must merge green; if fail, pause until morning |
| R25 | Cursor 2.6 `_meta` bug breaks M3 widget demos | Test on Cursor + Claude Desktop + ChatGPT explicitly; fallback text always mandated |
| R26 | OpenTimestamps calendar servers unavailable during submission | Batch submit + cache `.ots` receipts pre-submission; not time-sensitive |
| R27 | ACH agents disagree forever (infinite debate) | Single-round hard cap; judge node always emits decision within 2 min wall clock |
| R28 | OpenClaw runtime changes break our entry point | Pin OpenClaw version in `setup.sh`; keep Claude Code as fallback |
| R29 | SIFT VM updates during hackathon | Pin SIFT version `sift-2026.03.24.ova`; note in README; judges run same VM |
| R30 | Another submission ships equivalent crypto chain-of-custody before deadline | Unlikely given library specificity; if it happens our differentiator collapses to ACH + benchmark + selfscore. No active surveillance — risk is acknowledged, not monitored. |

## 10. Approval gates (brainstorming skill compliant)

- [ ] **Gate 1:** user approves this master design (this document)
- [ ] **Gate 2:** user approves Spec #3 (Sandbox)
- [ ] **Gate 3:** user approves Spec #1 (Build Swarm)
- [ ] **Gate 4:** user approves Spec #2 (Product)
- [ ] **Gate 5:** user approves Spec #4 (Orchestration Glue)
- [ ] **Gate 6:** implementation plans written per superpowers:writing-plans
- [ ] **Gate 7:** build swarm executes weeks 2-7 autonomously
- [ ] **Gate 8:** final submission 2026-06-14

## 11. Source of truth

- **This document** — automation master design; supersedes `BUILD_PLAN_v2.md` only where explicitly noted
- `BUILD_PLAN_v2.md` — v2 plan, still authoritative for DFIR fundamentals
- `Find_Evil_Research_and_Build_Plan.docx` — v1, research / rubric analysis / evidence integrity
- `agent-config/SOUL.md`, `AGENTS.md`, `TOOLS.md`, `MEMORY.md`, `HEARTBEAT.md` — agent identity + epistemic rules (unchanged)
- Memory: `C:/Users/newbi/.claude/projects/C--Users-newbi-Desktop-PUG-Projects-SANS-Hackathon/memory/` — eight project memories + index
