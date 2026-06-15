# `docs/sample-run/` — sample run and finding traceability

This directory documents how to reproduce a VERDICT run and trace any Finding
back to the exact tool execution that produced it. It is the entry point for the
"trace any finding to its tool execution" requirement.

Raw run directories (`tmp/auto-runs/<case-id>/`) are intentionally **not**
committed: they carry machine-local absolute paths and bulky reports, and the
project's release hygiene keeps raw run output and evidence out of the public
tree. Instead, a compact, reviewable execution-log trace is committed under
[`docs/release-evidence/`](../release-evidence/README.md), and any analyst can
regenerate a full hash-chained run locally and verify it offline.

## Committed execution-log trace

A compact structured trace from a live EVTX run is committed for review:

- [`docs/release-evidence/evtx-security-log-clear-trace.jsonl`](../release-evidence/evtx-security-log-clear-trace.jsonl)
  — agent messages, typed tool calls, ACP agent-to-agent handoffs, verifier
  replay, finding approval, report QA, and release-gate records, each timestamped.
- [`docs/release-evidence/evtx-security-log-clear-trace-summary.json`](../release-evidence/evtx-security-log-clear-trace-summary.json)
  — reviewer index: run command, case id, evidence hash, `manifest_verify.overall`,
  the token-usage ledger, and the Finding-to-tool-call spot check.

## Reproduce the run

```bash
scripts/verdict evidence/DE_1102_security_log_cleared.evtx --no-dashboard
# outputs land under tmp/auto-runs/<case-id>/
#   audit.jsonl          hash-chained tool-call + agent record
#   verdict.json         the Verdict and Findings
#   run.manifest.json    signed Merkle manifest
#   manifest_verify.json offline custody verification (overall: true)
```

## Trace a Finding offline

`scripts/trace-finding` needs only a Python 3 interpreter — no MCP server, no
network, no virtualenv. Point it at any completed run directory:

```bash
scripts/trace-finding tmp/auto-runs/<case-id>/
```

It re-verifies the hash-chained audit log from scratch (canonical re-serialization,
`seq` monotonicity, `prev_hash` replay), cross-checks the signed manifest, and for
every Finding resolves:

```
verdict word  <-  Finding  <-  tool_call_id  <-  audit.jsonl record  <-  Merkle leaf
```

Exit code is `0` only if the audit chain is intact and every Finding resolves to a
tool execution and a Merkle leaf.

## Spot check (from the committed trace)

| Field | Value |
|---|---|
| Finding | `f-A-evtx-audit-log-cleared` (CONFIRMED, T1070.001) |
| Cited tool call | `tc-002` (`evtx_query`) |
| Trace records | start `seq=3`, output `seq=4`, verifier approval `seq=8`, replay `seq=9`, approved Finding `seq=17` |
| Custody | `manifest_verify.overall = true`, ed25519 signature verified |

The deterministic headless EVTX path records `0` LLM API calls in its token
ledger; the agent loop is exercised over typed tool outputs, and credentials are
checked only during preflight. See the trace summary for the full ledger and
scope limits.
