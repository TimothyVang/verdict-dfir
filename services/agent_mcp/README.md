# findevil-agent-mcp

Python MCP server exposing the Find Evil! crypto custody (M2) and
ACH judge/correlator (M4) stacks as typed tools for Claude Code.

Per **Amendment A2** (Claude Code as primary interface) the agent
runtime is no longer a custom Python service — Claude Code itself
is the orchestrator. This package wraps the M2 + M4 modules so
they are reachable as MCP tools alongside the typed Rust DFIR
surface in `services/mcp/`.

## Boot

```bash
uv run --directory services/agent_mcp python -m findevil_agent_mcp.server
```

In normal use you do not invoke this directly — the repo-root
`.mcp.json` registers both MCP servers and Claude Code spawns them
on session start.

## Tools

| Tool | Wraps | Purpose |
|---|---|---|
| `audit_append` | `AuditLog.append` | Append one event to the hash-chained audit log. |
| `audit_verify` | `AuditLog.verify` | Replay the chain; surface any break. |
| `manifest_finalize` | `build_manifest` + `write_manifest` | Build, sign, and write `run.manifest.json`. Terminal crypto-custody step under Amendment A5. |
| `manifest_verify` | `verify_manifest` | Offline verify (chain + Merkle root + sig presence). |
| `verify_finding` | `verifier.reverify_finding` | Re-run the cited tool call; approve/reject/downgrade. |
| `detect_contradictions` | `contradiction.detect_contradictions` | Pairwise scan Pool A vs Pool B. |
| `judge_findings` | `judge.judge_findings` | Credibility-weighted merge of pool findings. |
| `correlate_findings` | `correlator.correlate` | SOUL.md cross-artifact rule enforcement. |
| `memory_remember` | `MemoryStore.remember` | Hermes-pattern cross-case memory write (A3 §2.2). Never evidence. |
| `memory_recall` | `MemoryStore.recall` | Hermes-pattern cross-case memory query (A3 §2.2). Appends a record that a recall happened. |
| `pool_handoff` | `acp.handoff.handoff` | IBM-ACP agent-to-agent handoff record (A3 §2.3). |
| `expert_miss_capture` | `AuditLog.append` (`expert_miss`) | Append expert edits to the hash-chained miss ledger (`expert_misses.jsonl`). |
| `accuracy_compare` | `accuracy.score` | Read-only ground-truth accuracy diagnostic (TP/FP/FN, precision/recall/F1, hallucination rate) vs a curated golden. A DIAGNOSTIC, never a Finding. |

Each tool has a Pydantic input model with `extra="forbid"` (deny
unknown fields) and a Pydantic output model. JSON schemas are
emitted to the MCP client at `list_tools` time.

## Tests

```bash
uv run --directory services/agent_mcp pytest
```

## End-to-end smoke harness

`scripts/agent-mcp-smoke.py` spawns this server (matching the
`.mcp.json` boot recipe) and drives the full demo flow over stdio
JSON-RPC — `tools/list`, then `audit_append` × 12 chained records,
`audit_verify`, `detect_contradictions`, `judge_findings`,
`correlate_findings`, `manifest_finalize`, `manifest_verify`, plus
a tampered-manifest negative test.

```bash
# Synthetic Findings (default — exercises all 9 tools that don't
# need the Rust DFIR server or network):
uv run --directory services/agent_mcp python ../../scripts/agent-mcp-smoke.py

# Real-evidence regression (loads a real find-evil-auto case dir,
# replays its verdict.json + audit.jsonl + run.manifest.json
# through the agent_mcp surface — proves we still parse production
# output shape after any schema change):
uv run --directory services/agent_mcp python ../../scripts/agent-mcp-smoke.py --real-evidence
```

Both flows run in CI as part of `docker/l1-compose.yml`'s command
sequence (see `.github/workflows/l1-unit.yml`). The synthetic
flow is sufficient to gate merges; the real-evidence flow needs
a populated `tmp/auto-runs/auto-<uuid>/` and is run manually
post-investigation as a regression check.
