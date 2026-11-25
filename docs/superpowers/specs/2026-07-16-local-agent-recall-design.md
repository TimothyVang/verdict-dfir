# Local Agent High-Signal Recall Design

- Date: 2026-07-16
- Status: Approved for implementation planning
- Scope: beta-native `scripts/verdict --agent`, single-file EVTX only

## Goal

Make the offline DGX Spark agent solve evidence-backed DFIR cases at least as reliably as Claude
Code while preserving VERDICT's existing custody, replay, entailment, and no-fallback guarantees.
The first acceptance case is the fair-fight EID 1102 Security-log-clear sample on which
`gpt-oss:120b` queried the evidence successfully but emitted no finding, while Claude Code emitted
a verifier-approved CONFIRMED T1070.001 finding.

Passing the first case establishes parity on that case only. A claim that the local agent is better
than Claude Code requires a broader fixed EVTX benchmark with repeated runs.

## Current Failure

In native agent mode, each LLM pod may call `evtx_query` and then must call `record_finding` to place
an observation into Pool A or Pool B. The local model made two successful current-case queries but
stopped without calling `record_finding`. The deterministic engine already recognizes EID 1102, but
native agent mode intentionally bypasses that engine and must not silently fall back to it.

The failure is therefore finding-recording recall, not evidence access, MCP dispatch, custody, or
verifier replay.

## Design

### Current-Run Observation Capture

During `_run_agent_pools`, retain each successful `evtx_query` response in memory alongside the
`tool_call_id` assigned by `_record_tool`. This capture does not issue additional tool calls and does
not persist unsealed evidence outside the existing run.

Only successful, advertised, custody-bound calls are eligible. Rejected calls, tool errors, and
responses without a current-run `tool_call_id` cannot produce candidates.

### High-Signal Candidate Recovery

After both LLM pods finish, inspect the captured query rows with a narrow host-side high-signal
extractor. The first supported rule is the existing EID 1102 mapping:

- Windows Security EID 1102
- MITRE T1070.001
- confidence `CONFIRMED`
- `asserted_values` requiring EID 1102 and the Security channel in the same replayed row
- citation to the exact current-run `evtx_query` tool call

If an equivalent agent finding already exists, no candidate is added. Equivalence is based on the
technique and asserted fact, not the model-generated finding UUID.

The recovery step is not a whole-engine fallback: it consumes only evidence the agent already
queried, supports an explicit high-signal allowlist, and cannot convert provider failure or absent
evidence use into a successful run.

### Audit And Reasoning

Every recovered candidate emits an `agent_high_signal_candidate` audit record containing its
finding ID, cited tool call, technique, and rule identifier. The candidate then joins the normal
pool inputs and follows the existing path:

1. finding discipline
2. verifier replay and deterministic entailment
3. judge merge
4. correlator confidence handling
5. report QA
6. manifest finalization and verification

No verifier, judge, report-QA, or manifest rule is relaxed. A replay mismatch or failed entailment
continues to reject the candidate and force honest uncertainty.

### Prompt Reinforcement

The EVTX agent task will include one concise instruction: after inspecting rows, record every
supported high-signal observation before ending the turn. EID-specific facts remain in the host
rule rather than depending on prompt compliance. Prompting is an aid, not the correctness boundary.

## Fail-Closed Behavior

- No successful evidence invocation: keep the existing runtime error; recover nothing.
- Tool error or rejected tool: audit it; recover nothing from it.
- No EID 1102 row: emit no T1070.001 candidate.
- Existing equivalent agent finding: do not duplicate it.
- Candidate lacks current-run citation or asserted facts: reject it before reasoning.
- Verifier replay or entailment failure: reject it through the existing verifier path.
- Provider stops after evidence use with no finding: recovery may add an allowlisted candidate from
  the successful current-run result; this is the intended recall repair.

## Testing

### Unit And Integration Tests

1. A local-model transcript that queries an EID 1102 row but never calls `record_finding` produces
   one candidate citing that query.
2. The candidate is CONFIRMED T1070.001 with the existing same-row asserted-value contract.
3. A benign query result produces no candidate.
4. A failed or unadvertised query produces no candidate.
5. A model-recorded equivalent finding suppresses host-side duplication.
6. A reverse or mismatched replay is rejected by the existing verifier.
7. Native agent provider failure still fails closed and never invokes the deterministic engine.
8. The default deterministic path remains unchanged.

### Fair-Fight Acceptance

Run the pinned EID 1102 evidence with `gpt-oss:120b` on Spark. Acceptance requires:

- verdict `SUSPICIOUS`
- at least one verifier-approved CONFIRMED T1070.001 finding
- citation to a current-run successful `evtx_query`
- golden recall 100 percent and no anti-fact hit
- `manifest_verify.overall == true`
- no deterministic whole-engine fallback

Compare the sealed receipt against the existing Claude fair-fight receipt on the same evidence
hash.

### Broader Superiority Benchmark

Before claiming the local agent is better than Claude Code, create a fixed single-file EVTX battery
covering several high-signal and benign cases. Run both providers repeatedly under identical tool,
step, evidence, and custody constraints. Compare verifier-approved recall, precision, anti-facts,
verdict accuracy, and completion rate. Local must exceed Claude on the aggregate metrics without a
custody regression; one EID 1102 win is insufficient for a general product claim.

## Non-Goals

- Supporting directories, fleet inputs, memory, disk, or network evidence in Phase 4 agent mode
- Replacing the LLM with the full deterministic investigation engine
- Relaxing citation, asserted-value, verifier, report-QA, or manifest requirements
- Public or external model calls from the classified deployment
- Signing or export-policy changes
