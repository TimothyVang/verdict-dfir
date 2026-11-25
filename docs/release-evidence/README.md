# `docs/release-evidence/` — release-validation evidence

This directory holds small, reviewable evidence summaries for two scopes: the
historical `v-submit` L3 fallback packet, and a later Stage One EVTX
execution-log packet. Each file documents what it proves; neither file is raw
customer evidence.

## Files

| File | Purpose |
|---|---|
| `l3-local-sift.json` | Committed local NIST fallback evidence for `v-submit`. It records the NIST Hacking Case image hash, run/readiness state, artifact hashes, and verification commands used when the GitHub KVM runner label had no capacity. It is not SIFT/KVM parity evidence. |
| `evtx-security-log-clear-trace.jsonl` | Compact structured execution trace from a fresh live EVTX run. It includes agent messages, typed tool calls, ACP handoffs, verifier replay, finding approval, report QA, and release-gate records with timestamps. |
| `evtx-security-log-clear-trace-summary.json` | Reviewer index for the EVTX trace: run command, case id, evidence hash, manifest verification result, token usage ledger, and a spot-check mapping from Finding `f-A-evtx-audit-log-cleared` to `evtx_query` tool call `tc-002`. |

## Historical L3 fallback packet

The preferred L3 path is a full SIFT run on a KVM-capable GitHub runner. During
final release, the `ubuntu-latest-4-core-kvm` label had no available jobs, so
this packet recorded the explicit committed local evidence boundary instead of
treating a skipped L3 run as success. It is not a passing L3 recall result.

This is intentionally narrow:

- It does not contain raw evidence, disk images, reports, or case artifacts.
- It records hashes and gate outcomes only.
- It preserves the truth boundary: the packet is `READY_FOR_EXPERT_REVIEW`, not customer-releasable.
- It does not mutate or refresh the GitHub `v-submit` release asset set.

Strict check:

This check is expected to fail the recall threshold while the historical packet
records 7/14 NIST recall (50%) against the 71% bar. (That 7/14 reproduces under the
current hardened matcher on the richer 27-finding runs; leaner 19-finding runs score
**5/14** — run-to-run variance, see `docs/accuracy-report.md`. Either way the packet
is below the bar.) That failure is the point of the packet: the release evidence
remains honest about the L3 gap.

```bash
python3 scripts/validate-l3-evidence.py docs/release-evidence/l3-local-sift.json
```

## Stage One execution-log packet

`evtx-security-log-clear-trace.jsonl` and `evtx-security-log-clear-trace-summary.json`
exist for the Find Evil! self-check item that asks for structured logs showing
the agent communication and tool execution sequence. They were generated from:

```bash
scripts/verdict evidence/DE_1102_security_log_cleared.evtx --no-dashboard
```

Reviewer spot-check:

- Finding: `f-A-evtx-audit-log-cleared`
- Cited tool call: `tc-002`
- Tool: `evtx_query`
- Trace records: start at `seq=3`, output at `seq=4`, verifier approval at
  `seq=8`, replay at `seq=9`, approved Finding at `seq=17`
- Token usage: `0` LLM API calls / `0` input tokens / `0` output tokens for
  this deterministic headless `find-evil-auto` path; credentials are checked
  during preflight, but the EVTX run itself does not call a completion API.
- Manifest note: the `customer_release_gate` trace record is emitted before
  manifest finalization; the summary JSON records the later
  `manifest_verify.overall=true` check.

Trace validation:

```bash
jq -e . docs/release-evidence/evtx-security-log-clear-trace-summary.json >/dev/null
jq -e . docs/release-evidence/evtx-security-log-clear-trace.jsonl >/dev/null
```
