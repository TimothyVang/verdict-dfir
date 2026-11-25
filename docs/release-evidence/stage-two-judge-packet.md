# Stage Two Judge Packet

This packet is for adversarial Stage Two review. Judges should score from audit
records, tool outputs, verifier replay records, and code references, not from
agent claims or demo narration.

## Primary Clean Run

Use a clean run command for primary evidence:

```bash
scripts/verdict evidence/DE_1102_security_log_cleared.evtx --no-dashboard
```

For a completed clean run directory, the self-score criterion 1 output shape is:

```text
failures=N corrections=N redispatches=N injected_faults=0
```

The optional harness/demo is the only permitted place for `fault_injection`; the
primary packet is clean (`fault_injection=0`) and contains no `fault_injection`
records. The primary packet is traceability evidence, not proof of organic
runtime failure when no organic failure occurred.

## Claim-To-Log Traces

Committed trace source:
`docs/release-evidence/evtx-security-log-clear-trace.jsonl`.

| Claim | Audit seq | `tool_call_id` | Tool | Output hash | Verdict |
|---|---:|---|---|---|---|
| The EVTX evidence was opened and hashed before analysis. | 1-2 | `tc-001` | `case_open` | `a0615707b547a2ac254688fd725c3c590f62440fc9b7947c2843dd40498a39e8` | Custody trace supports the source evidence boundary; it is not a Finding by itself. |
| The Security EVTX was parsed as the active evidence source. | 3-4 | `tc-002` | `evtx_query` | `3d3dd69400552c92c939f1635b9ba781c1ed6847109e293e368c57afc52dd800` | 112 records seen, 112 rows returned, 0 parse errors. |
| The final reportable Finding cites the current-case EVTX tool call. | 17 plus verifier seq 8-10 | `tc-002` | `evtx_query` | `3d3dd69400552c92c939f1635b9ba781c1ed6847109e293e368c57afc52dd800` | `f-A-evtx-audit-log-cleared` is `CONFIRMED`; replay matched exactly and final Verdict is `SUSPICIOUS`. |

Spot-check summary source:
`docs/release-evidence/evtx-security-log-clear-trace-summary.json` records the
same `tool_call_id`, output hash, verifier replay hash, manifest status, and
scope limits.

## Claim-To-Code Traces

| Claim | Code reference | Why it matters |
|---|---|---|
| Self-score separates natural course correction, verifier redispatch, and staged injected faults. | `scripts/self-score.py:119-143`, `scripts/self-score.py:164-168` | Criterion 1 reports `corrections`, `redispatches`, and `injected_faults` as separate counters. |
| The release guard blocks primary readiness packets that include demo-only injected records and checks Stage Two wording when the packet is validated. | `scripts/validate-submission-assets.py:633-648`, `scripts/validate-submission-assets.py:651-701` | Primary release artifacts cannot silently contain demo-only injection records, and packet text must label any injected path as optional harness/demo evidence. |

## Red Flags

- Do not treat the optional harness/demo injection run as organic
  self-correction.
- Do not infer broad host clearance from the clean EVTX packet. The trace covers
  custody, EVTX parsing, verifier replay, and one log-clear Finding only.
- Do not treat memory sidecars, dashboard views, or demo narration as evidence.
  Evidence comes from current-case audit records and tool outputs.
- If a clean run contains no organic runtime failure, score it as clean
  traceability evidence with no organic correction, not as live failure recovery.
- If an appendix clip uses a forced verifier re-dispatch, it must remain labeled
  as optional harness/demo evidence and excluded from organic self-correction
  claims.

## Standout Elements

- Finding-to-tool-call trace is explicit: Finding `f-A-evtx-audit-log-cleared`
  cites `tc-002`, and the verifier replay confirms the same output hash.
- The packet publishes limits instead of hiding them: the EVTX trace is an
  expert-review draft, not customer-releasable output, and it lists unsupplied
  disk/filesystem, memory, network, and Velociraptor coverage.
- Self-score output now makes re-dispatch visible without conflating it with
  staged injection.
- The demo guide now keeps clean primary terminal capture separate from optional
  harness recovery footage.
