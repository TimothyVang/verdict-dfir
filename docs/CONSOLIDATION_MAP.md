# VERDICT Consolidation Map (2026-11-25)

This document maps every scattered legacy VERDICT / CaseForge / DFIR repository and local directory to its status in the unified `/home/assessor/Desktop/verdict` monorepo.

## Merged into `/home/assessor/Desktop/verdict`

| Legacy Repo / Directory | Commit / State Merged | Where It Lives Now |
|---|---|---|
| `TimothyVang/verdict-dfir-beta` | Latest `main` (`2026-09-01`, `object-ledger.json`) | `services/mcp`, `services/agent_mcp`, `services/agent`, `agent-config/`, `apps/web/`, `assets/`, `VERDICT_DFIR_SVG_Assets_v2/`, `goldens/`, `docker/`, `scripts/` |
| `TimothyVang/caseforge-core` | Latest `main` (`2026-07-13`, PR #44) | `packages/caseforge-sdk`, `packages/caseforge-cli`, `packages/caseforge-tui`, `crates/caseforge-fleet`, `crates/caseforge-ingest`, `configs/`, `fixtures/`, `bin/`, `docs/caseforge/`, `scripts/caseforge/` *(vendored `engine/` OpenCode fork intentionally omitted)* |
| New REA-for-DFIR Unified Layer | Built fresh in v1.0 | `packages/verdict-mcp`, `packages/verdict-cli`, `.agents/skills/verdict-dfir/`, `.claude-plugin/`, `.codex-plugin/`, `.cursor-plugin/` |

## Kept Separate Intentionally (Do NOT Delete Blindly)

| Location | Reason Kept Separate |
|---|---|
| `~/Documents/spark-findevil-preserve-2026-07-18` | **Contains private `signing.key` + real DFIR evidence/cases.** Must remain strictly outside git. |
| `~/Desktop/GN7000` (and `/srv/verdict-lab`, `TimothyVang/verdict-lab`) | Air-gapped host deployment repo, Electron `apps/verdict-console`, Gate S CAPE detonation infra, `REBUILD-PLAN.md`, and 202 cloned research repos in `local-checkouts/research/`. |
| `~/Desktop/dgx-spark-lab` & `TimothyVang/dfir-image-bench` | Hardware-specific DGX Spark bench & standalone Volt Typhoon benchmark repo. |
| `TimothyVang/REA-Argonaut` & `TimothyVang/Malvex` | Companion RE / malware frameworks bridged at Tier 2 rather than vendored. |

## Superseded / Safe to Archive on GitHub Once Verified

- `TimothyVang/Verdict` (May 2026 early LangGraph hackathon repo)
- `TimothyVang/dev-verdict-github` (historical development repo)
- `TimothyVang/verdict-dfir` (stale July 2026 v0.5.0 export — can be replaced/updated with this monorepo as the canonical public repo)
- `TimothyVang/verdict-opencode` (hard fork of OpenCode — no longer required as a hard dependency now that VERDICT is a standard MCP + CLI + multi-client plugin)
- `~/Desktop/PUG-Projects/verdict` (gutted folder containing only `dev/evidence/browser-live-fixture-20260710T1255Z`)
- `~/Desktop/PUG-Projects/verdict-checkouts/lab-team-production` (old July 2026 checkout of `verdict-lab`)
