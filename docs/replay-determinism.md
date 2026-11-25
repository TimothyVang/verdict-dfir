# Replay determinism

Track 3a makes verifier replay evidence explicit without changing Track 3b
severity policy.

## ReplayArtifact

`verify_finding` still returns the legacy top-level fields:

- `replay_tool_name`
- `replay_expected_sha256`
- `replay_actual_sha256`
- `replay_matched`
- `replay_error`

It also returns `replay_artifact` (`schema_version: findevil.replay.v1`) with:

- the cited `tool_call_id` and replayed tool name;
- a deterministic SHA-256 over replay arguments;
- expected and actual output SHA-256 values;
- `matched`, `drift_class`, and `drift_reason`;
- replay error, replay tool-call id, and wall-clock timing when available.

## Drift classes

- `exact_match` — replay output hash matched the audit log.
- `material_drift` — replay succeeded but output hash differed.
- `replay_error` — replay raised an MCP or transport error.
- `missing_citation` — the Finding had no usable `tool_call_id`.
- `missing_audit_record` — the cited `tool_call_id` was not present in the audit index.

The existing verifier behavior is preserved: exact matches approve, replay errors
or missing citations reject, and material drift downgrades one confidence tier.
No Track 3b severity bump is applied here.

## Cache and force-fresh replay

The library exposes `ReplayPool` for callers that want cached and concurrent
replays. Cache keys are deterministic over `(tool_name, arguments)`. Callers can
set `force_fresh_replay` on `verify_finding` or pass the internal engine's
`--force-fresh-replay` flag when debugging replay behavior to bypass cache hints and force re-execution.

## Audit and report surface

The internal automation engine appends a dedicated `kind="replay"` audit event for each
verifier replay alongside the existing `verifier_action` event. Reports show a
per-finding replay chip and a replay determinism appendix when replay artifacts
are present.
