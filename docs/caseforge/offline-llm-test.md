# Offline VERDICT LLM test — gpt-oss:20b on the DGX Spark

Ran the VERDICT DFIR investigate pipeline fully offline against real EVTX evidence, with
the local LLM agent forced, and graded every run against a machine-readable scorecard.

## Headline (read this first)

**The offline detection floor is complete, but the LLM authored none of it.** Across all
three battery cases the deterministic `find_evil_auto` engine elevated every expected MITRE
technique and CVE (13/13) and produced custody-sealed, `manifest_verify`-PASS cases — but
in all three runs the forced `gpt-oss:20b` agent failed to seal and caseforge **fell back to
the deterministic engine**. Every sealed `verdict.json` carries `agent: "find-evil-auto MVP"`.
So this proves *offline forensic detection works*; it does **not** prove the LLM can drive a
sealed investigation offline. It currently cannot on `gpt-oss:20b`.

## What "offline" means here

Local-only inference on the Spark: `gpt-oss:20b` served by the on-box Ollama at
`http://localhost:11434/v1`, route `local-ollama`, `--privacy local-only`,
`FINDEVIL_OFFLINE_LOCAL=1`, `OPENCODE_PURE=1` + the `OPENCODE_DISABLE_*` set. No cloud, no
Claude credentials, no LAN hop for inference. This is *local-only*, **not air-gapped**: the
Spark had incidental outbound connections during the runs; what is guaranteed offline is the
model-inference path, not the whole host.

## How the LLM was forced

For local EVTX, caseforge's default primary path is the deterministic engine
(`investigate.ts`: "set `CASEFORGE_FORCE_AGENT=1` to force opencode agent"). A plain run
never touches the LLM. Every run here used `CASEFORGE_FORCE_AGENT=1` so `gpt-oss:20b` drove
the investigation via the FindEvil MCP tools; the fallback only fires if the agent fails to
produce a complete sealed run.

## Results (2026-07-10, gpt-oss:20b, forced agent, offline)

| case | expected targets | score | verdict | seal provenance |
|------|------------------|-------|---------|-----------------|
| win-lateral-movement | T1047, T1543.003, CVE-2022-21999 | 3/3 HIT | INDETERMINATE | deterministic-fallback |
| attack-samples | T1070.001, T1078, T1543.003, T1047, CVE-2022-21999 | 5/5 HIT | SUSPICIOUS | deterministic-fallback |
| bench-evtx-2026-07-03 | T1178, T1098, T1003.006, T1134, T1021.002 | 5/5 HIT | INDETERMINATE | deterministic-fallback |

All three sealed with `manifest custody: verified`. The captured `verdict.json` for each run
is checked in under `fixtures/dfir-scorecard/runs/` as the grader's regression fixtures.

## Why the LLM fell back

`gpt-oss:20b` opened the case and ran genuine forensic queries (`findevil-mcp_case_open`,
`findevil-mcp_evtx_query` returning real rows), but repeatedly emitted invalid tool calls —
e.g. `Model tried to call unavailable tool 'invalid'`, `stuck due to repeated invalid tool
calls` — and never reached a sealed manifest. caseforge then ran the deterministic engine to
produce the authoritative, custody-sealed `verdict.json`. This matches the model-roles note
that `gpt-oss:20b` is a weak tool-caller; the failure mode is tool-call protocol, not
forensic reasoning quality.

## The grader

`scripts/score-offline-run.mjs` parses a sealed `verdict.json`, diffs the elevated MITRE
techniques / CVEs against `fixtures/dfir-scorecard/ground-truth.json`
(HIT / PARTIAL / MISS + score), and — critically — reports `llm_provenance` so a passing
detection score is never mistaken for the LLM having done the work.

```
node scripts/score-offline-run.mjs <verdict.json> --case <name> [--require-llm] [--min-score 0.9]
```

`--require-llm` makes the grader exit non-zero when the seal came from the deterministic
fallback rather than the LLM agent — the gate to use once the agent path can actually seal.

Reproduce the offline run on the Spark:

```
CASEFORGE_FORCE_AGENT=1 VERDICT_LLM_MODEL=gpt-oss:20b \
  bash evidence/run-investigate-local.sh evidence/real-evtx-20260708/win-lateral-movement
```

The grader assertions run in CI via `node scripts/selftest.mjs`.
