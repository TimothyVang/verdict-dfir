# findevil-agent

Python package hosting the M2 cryptographic chain-of-custody stack
and the M4 ACH (Analysis of Competing Hypotheses) reasoning
primitives that ship as the `findevil-agent-mcp` MCP tool surface
under Amendment A2.

**Authoritative design:** `docs/architecture.md`.
**Active invariants:** `CLAUDE.md` and `agent-config/` define credential modes and the Claude Code primary-interface model.
**Invariants:** `CLAUDE.md` §"Non-negotiable invariants".

> **Under Amendment A2 this package is a library, not a service.** The
> M2/M4 modules below are imported by `services/agent_mcp/` and exposed
> as MCP tools to Claude Code. The pre-A2 components (`graph.py`,
> `api.py`, `cli.py`, `supervisor.py`, `specialists/`) are **dropped**
> — Claude Code is the orchestrator. The L0 `amendment-a2-guard` job
> fails CI if any of those files reappear under any filename.

## Status

| Component | Status |
|---|---|
| Package scaffold + pinned deps | ✅ |
| `config.resolve_credentials()` (3 modes — Amendment A1) | ✅ |
| `events.py` AgentEvent union (11 variants) | ✅ |
| `mcp_client.py` (stdio subprocess manager for the Rust MCP server) | ✅ |
| `crypto/signer.py` Ed25519/Sigstore/stub manifest signer tiers (M2) | ✅ |
| `crypto/audit_log.py` hash-chained JSONL writer | ✅ |
| `crypto/merkle.py` rs_merkle Merkle tree builder | ✅ |
| `crypto/manifest.py` build + write `run.manifest.json` | ✅ |
| ~~`crypto/ots.py` OpenTimestamps Bitcoin anchor~~ | dropped per A5 |
| `verifier.py` re-execute cited tool calls + veto | ✅ |
| `pools/persistence.py` + `pools/exfil.py` (Pool A + Pool B) | ✅ |
| `judge.py` credibility-weighted merge | ✅ |
| `contradiction.py` Pool A vs Pool B disagreement surface | ✅ |
| `correlator.py` SOUL.md ≥2 artifact-class rule | ✅ |
| Test suite (`tests/`) | ✅ 156 tests pass |
| ~~`graph.py` LangGraph runtime~~ | dropped per A2 |
| ~~`api.py` FastAPI SSE endpoints~~ | dropped per A2 |
| ~~`cli.py` CLI entry~~ | dropped per A2 |
| ~~`supervisor.py` scatter-gather~~ | dropped per A2 |
| ~~`specialists/` per-tool subagents~~ | dropped per A2 (Pool A/B replace this; L0 guard enforces) |

## Quick start

```sh
# From the repo root:
cd services/agent
uv sync
uv run pytest -xvs
```

## Credential resolver (Amendment A1)

`resolve_credentials()` detects in this order:

1. `CLAUDE_CODE_OAUTH_TOKEN` env var (generated via `claude setup-token` — inference-only; judge-friendly).
2. `~/.claude/` interactive session (after `claude auth login`).
3. `ANTHROPIC_API_KEY` env var (direct metered API from console.anthropic.com).

Raises `CredentialsNotAvailableError` with a multi-line message listing all three options if none are found. The CLI catches this and prints the error at startup.

## AgentEvent union (Spec #2 §5)

The 11 variants:

- `ToolCallStart`, `ToolCallOutput` — tool lifecycle
- `AgentMessage` — specialist/supervisor/judge/verifier/correlator reasoning
- `Finding` (requires `tool_call_id`), `VerifierAction` — findings + vetos
- `ChainUpdate` — merkle_root + leaf_count + signature_pending
- `RunVerdict` — final verdict + confidence + manifest/verification paths
- `PlanProposed`, `PlanApproved` — Plan Mode gate
- `HypothesisUpdate` — MITRE board drive
- `ContradictionFound` — emits BEFORE the judge reconciles; the architectural moat

Every event is Pydantic-frozen, `extra="forbid"`. `event_id` auto-fills as UUID4; `ts` auto-fills as UTC ISO-8601 with trailing `Z`. TypeScript types for `apps/web/lib/events.ts` are generated with `pnpm --filter @findevil/web codegen:events`.

## For contributors

- New Pydantic model → add to `findevil_agent/events.py`, extend the `AgentEvent` discriminated union, add roundtrip test in `tests/test_events.py`.
- New config constant → put it in `findevil_agent/config.py`; export via `__all__`.
- New crypto primitive (additional Merkle algorithm, alternate signer) → `findevil_agent/crypto/<name>.py` with paired test in `tests/test_crypto_<name>.py`.
- New ACH-stack primitive → fits in `verifier.py`, `judge.py`, `contradiction.py`, or `correlator.py`. Wrap as an MCP tool in `services/agent_mcp/findevil_agent_mcp/tools/` so Claude Code can reach it.
- **Do NOT** generate `graph.py`, `api.py`, `cli.py`, `supervisor.py`, or `specialists/` — these are forbidden by the L0 `amendment-a2-guard` job. Under A2, Claude Code IS the orchestrator; the agent runtime is exposed as MCP tools, not as a custom Python service.

## Pinned dependencies

See `pyproject.toml`. Do not upgrade without a spec amendment.

Key pins:
- `langgraph >=1.0,<2.0`
- `langgraph-checkpoint-sqlite >=2.0,<3.0`  *(Product uses Sqlite)*
- `anthropic >=0.45,<1.0`
- `sigstore ==3.*`
- `fastapi >=0.115,<1.0`
- `pydantic >=2.7,<3.0`
- `mitreattack-python >=5.4,<6.0`
