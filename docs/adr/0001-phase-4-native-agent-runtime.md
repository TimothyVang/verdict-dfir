# ADR 0001: Phase 4 Native Agent Runtime

- Date: 2026-07-15
- Status: Accepted
- Deciders: User and VERDICT engineering

## Context

VERDICT has three related execution surfaces whose roles had become ambiguous in active guidance:

- Claude Code is the canonical interactive and cloud runtime.
- `scripts/find_evil_auto.py`, reached by default through `scripts/verdict`, is the deterministic
  engine and quality floor.
- The beta-native provider-agnostic loop under `services/agent/findevil_agent/agentloop/`, reached
  through `scripts/verdict --agent`, drives the same custody spine with real MCP calls.

Caseforge/OpenCode work demonstrates historical integration approaches, but it is outside the beta
runtime and cannot be a Phase 4 gate. Amendment A2 also removed the earlier Product orchestrator
modules and forbids LangGraph and FastAPI in the replacement path.

## Decision

The authoritative offline runtime for Phase 4 is the beta-native `scripts/verdict --agent` loop.
Claude Code remains the canonical interactive and cloud runtime. The deterministic engine remains
the default invocation and quality floor; it is not a fallback that may silently replace a failed
Phase 4 agent run.

Phase 4 native-agent acceptance is currently limited to a single EVTX file. Every non-EVTX type,
directory, and fleet input fails closed under `--agent`; those inputs continue to use the default
deterministic path when `--agent` is not requested.

A strict Phase 4 acceptance run must satisfy all of the following:

1. The native agent loop makes real calls through the product MCP servers.
2. No deterministic fallback is used if the provider or native agent loop fails.
3. A tool call not advertised to its investigation lane is rejected and audit-recorded before MCP
   dispatch.
4. The emitted Verdict is honestly scoped to the evidence and coverage actually examined.
5. `manifest_verify.json` reports `overall: true`.

Caseforge/OpenCode remains historical and legacy integration evidence. It does not gate Phase 4.
The pre-A2 modules `graph.py`, `api.py`, `cli.py`, `supervisor.py`, and `specialists/` remain removed.
The native loop must not import or add LangGraph or FastAPI.

## Consequences

- Phase 4 has one beta-owned offline acceptance path and no dependency on a separate repository or
  agent harness.
- Non-EVTX, directory, and fleet evidence cannot claim Phase 4 native-agent acceptance until the
  native loop supports those scopes directly.
- A failed native agent run fails Phase 4 rather than being masked by deterministic execution.
- The deterministic engine remains available by default for repeatability, regression comparison,
  and the minimum quality bar.
- Claude Code continues to define the primary interactive and cloud operator experience.
- This decision closes runtime custody and control-flow ambiguity only. It does not claim improved
  detection coverage, recall, precision, or forensic conclusion quality.
- Native agent mode may recover allowlisted high-signal candidates only from successful,
  current-run evidence calls made by the agent. This is not deterministic fallback: it issues no
  second investigation, cannot mask provider or tool failure, remains audit-visible, and every
  candidate still passes verifier replay and entailment before affecting the verdict.
