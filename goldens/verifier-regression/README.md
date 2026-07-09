# Verifier-regression corpus

A small, committed corpus of **known-bad findings** the VERDICT verification
pipeline must catch, plus benign **controls** it must leave alone. It backs
`services/agent/tests/test_verifier_regression.py`, which asserts a minimum
catch-rate so a future edit cannot silently weaken a gate.

## What it guards

| Known-bad category | Guardrail (CLAUDE.md / SOUL.md) | Caught by | Action |
|---|---|---|---|
| phantom/nonexistent PID | fact-fidelity — a finding may assert only values present in its cited evidence | verifier (entailment) | rejected |
| attribution overclaim | no attribution/actor identity from host artifacts | verifier (entailment) | rejected |
| single-citation CONFIRMED execution | execution claims need ≥2 artifact classes | correlator (EXECUTION gate) | downgraded |
| exfil-without-staging | exfil needs collection/staging **plus** network evidence | verifier (entailment) | rejected |

The single-citation-execution case is deliberately one the *verifier* approves
(its asserted value really is present); only the *correlator* corroboration gate
flags it. That keeps the corpus honest about which stage does which job.

## How "caught" is decided

Each finding is run through the real, unmodified production stages —
`findevil_agent.verifier.reverify_finding` and
`findevil_agent.correlator.correlate` — with a `MockMcpClient` standing in for the
Rust binary on replay. A finding is "caught" when **either** stage rejects or
downgrades it. The controls must pass clean through both, so the catch-rate
measures real discrimination, not a flag-everything harness.

## Evidence-agnostic

Every value is synthetic (PID 6666, `tool.exe`, `archive.zip`,
`APT-Synthetic-Group`, `jdoe`, `203.0.113.50` from TEST-NET-3). No
image-specific username, hostname, image name, or golden id appears. Each entry
embeds the parsed tool output its cited call reproduces on replay, so the test
needs no live MCP server or real evidence.

## Files

- `known-bad-findings.json` — the corpus (`known_bad`, `controls`, `min_catch_rate`).
- this `README.md`.

To tighten the guard, add a new known-bad entry (naming its `expected_catcher`
and `expected_action`) or raise `min_catch_rate`. Lowering `min_catch_rate` below
`0.75` fails `test_min_catch_rate_floor_stays_strict` on purpose.
