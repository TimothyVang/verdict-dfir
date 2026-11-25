---
description: Reason over findings (ACH), verify, and seal a signed verdict manifest
agent: verdict
---

Run the reason/seal phase for the current Case `$1` (full argument string: `$ARGUMENTS`), after both pools have returned Findings from an evidence-type playbook. This is the crypto/custody terminal path — operate read-only on evidence, keep every decision on the hash-chained `audit.jsonl`, and cite the originating `tool_call_id` on every Finding.

Call the actual opencode MCP tools by their exact names (`findevil-agent-mcp_<tool>` for custody/ACH and `findevil-mcp_<tool>` for forensic primitives). Do not type MCP names into shell/bash, do not print JSON examples as substitutes for real calls, and do not invent underscore variants such as `findevil_mcp_manifest_finalize`.

Manifest tools only exist on the Python custody server. Never call
`findevil-mcp_manifest_finalize` or `findevil-mcp_manifest_verify`; call
`findevil-agent-mcp_manifest_finalize` and
`findevil-agent-mcp_manifest_verify`.

Do not accept Findings that only restate suspicious filenames, planted strings, topic notes, archive names, or sinkhole/parked-domain lookups. Those are negative-control leads unless independently corroborated by execution, persistence, credential access, C2, or data movement evidence.

Sequence (all through the Python `findevil-agent-mcp` crypto/ACH/custody tools; each tool call and decision is appended to the chain via `audit_append`):

1. `findevil-agent-mcp_detect_contradictions` — surface Pool A <-> Pool B disagreements. Resolve them, or auto-pass under unattended mode by trusting the higher-credibility pool and logging the decision with `approved_by: "auto"`.
2. **Verifier re-runs cited tool calls.** For each Finding, `findevil-agent-mcp_verify_finding` re-runs the Finding's cited tool and compares SHA-256 against the recorded `output_sha256` — a deterministic replay must reproduce the same hash. The verifier vetoes only Findings without a valid `tool_call_id`. After each verdict, the verifier calls `findevil-agent-mcp_pool_handoff(from_role="verifier", to_role="judge", payload={finding_id, action, replay_record_sha256})` so the judge receives structured input.
3. **Apply Analysis of Competing Hypotheses.** `findevil-agent-mcp_judge_findings` — credibility-weighted merge of the verified Findings (the ACH step).
4. `findevil-agent-mcp_correlate_findings` — enforce the >=2-artifact-class rule; downgrade unsupported Findings. A `CONFIRMED` Finding whose corroboration count is below 2 artifact classes must be auto-downgraded — flag the downgrade explicitly.
5. `findevil-agent-mcp_audit_verify` — replay the hash chain before sealing. If it fails, report `RUN INCOMPLETE / CUSTODY INVALID` and do not finalize.
6. **SEAL.** `findevil-agent-mcp_manifest_finalize` — terminal step: build the Merkle tree over the hash-chained `audit.jsonl` and sign, producing `run.manifest.json`. This seals the Case (no revision after this point). Then `findevil-agent-mcp_manifest_verify` to verify the signed manifest in-run.
7. For CONFIRMED Findings only, the originating pool calls `findevil-agent-mcp_memory_remember(...)` with the IOC/hash/TTP a future investigation should recall (HYPOTHESIS-tier is not remembered).

Emit the scoped verdict word with citations:

- `SUSPICIOUS` — reportable evidence found.
- `INDETERMINATE` — leads or limited coverage prevent a scoped clearance.
- `NO_EVIL` — no reportable Finding in the artifacts actually examined; never a whole-environment clean bill of health.

The run is not complete unless the pipeline reached `findevil-mcp_case_open`, every approved Finding cites a `tool_call_id`, `findevil-agent-mcp_audit_verify` passed, and `findevil-agent-mcp_manifest_verify` reports `overall: true`. If `findevil-agent-mcp_manifest_verify` is missing or `overall` is not `true`, report `RUN INCOMPLETE / CUSTODY INVALID` and do not describe the output as signed or customer-ready. If the evidence vault was modified mid-run, refuse to sign the manifest.
