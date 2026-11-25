# Fact-Fidelity — engineering notes & recommendations

Companion to [`fact-fidelity.md`](fact-fidelity.md). That doc explains *what* the
entailment check is; this one records the non-obvious **design decisions**, the
**gotchas** that cost real investigation, and the **recommendations** for
finishing the rollout. Written for whoever extends this next.

## Design decisions (and why)

1. **No separate `submit_finding` tool.** Every finding — deterministic emitter
   or LLM — already flows through `verify_finding`, which validates into the
   `Finding` model (so the schema gate fires) and runs the entailment check. A
   second recording tool would be redundant and would widen the locked 45-tool
   product surface. The gateway already exists; we strengthened it.

2. **The verdict is already load-bearing — no `compute_verdict` surgery.**
   `_apply_verifier_actions` (`scripts/find_evil_auto.py`) drops a `rejected`
   finding and downgrades a `downgraded` one *before* `compute_verdict` runs. So
   a misread that the verifier rejects can never reach a SUSPICIOUS verdict
   without any change to the verdict logic. We almost rewrote the verdict
   function before tracing this.

3. **INFERRED satisfies the gate via `derived_from`, not a forced value.** Many
   INFERRED findings are *cross-fact inferences* (DKOM = `pslist` 0 AND `psscan`
   N>0) drawn from two different cited outputs — they have no single
   re-extractable value. Requiring `asserted_values` on them would force a
   dishonest assertion or silently drop them. The gate requires values for
   CONFIRMED, and values **or** `derived_from` for INFERRED.

4. **`entailment_ok` is a separate signal, not part of `overall`.** It mirrors
   `signature_verified`: an honest status that does not gate the presence-based
   `overall`, so dev/offline stub runs still verify end-to-end. Byte tampering of
   a sealed slice is already caught by the audit chain; `entailment_ok` is the
   *semantic* re-check.

5. **Co-located `record` match.** Binding several fields to one record stops a
   claim being assembled from a value in one row and a damning value in another
   — a gap the flat any-where match could not close.

## Gotchas (each cost real time — read before extending)

1. **`_FINDING_MODEL_FIELDS` silently strips unknown fields.** `finding_for_verifier`
   projects a finding to just the typed `Finding` fields before the verifier
   sees it. `asserted_values` had to be added to that frozenset or it was
   dropped — the entailment check would have **no-op'd forever** and looked
   like it worked. If you add a new evidentiary Finding field, add it there too.

2. **`event_id` (and friends) are normalized — assert against the RAW serialized
   output, not the Python-side value.** The orchestrator reads `event_id` via
   `_event_id_value()` because the *input* EVTX-XML nests it. But the **Rust**
   `evtx_query` parser flattens it to a scalar `u32` *before* serialization, so
   the cited output's `rows[*].event_id` is a clean scalar. The asserted path
   must match the **serialized tool output**, which is what the verifier re-runs
   and hashes — not the bare value the Python iterates, and not the raw input.
   A path that doesn't resolve makes the finding **silently fail entailment**
   (drop), so verify the shape against the Rust tool / a fixture, never guess.

3. **The deterministic emitter path is a guarantee + emitter-bug catcher, not a
   misread catcher.** The code that read the value re-asserts it, so it can't
   "misread" itself. The real teeth are on the **LLM authoring path**, where the
   model cannot record a fact the parser can't find. Frame claims accordingly.

4. **`_cffi_backend` is missing in the dev env — Ed25519 crypto tests fail
   locally, `StubSigner`-path tests pass.** Don't read those 9 failures as
   regressions; they pass in CI's pinned container. Manifest tests that use
   `StubSigner` (not Ed25519) **do** run locally — use that path to test custody
   logic without the backend.

5. **`replay` audit records are hash-chain records but NOT Merkle leaves.** Only
   `tool_call_output` + `finding_approved` become leaves. The sealed entailment
   slice rides on a `replay` record, so it is tamper-evident via the **hash
   chain + `audit_log_final_hash`** (which `verify_manifest` checks), not via the
   Merkle root. That's why the offline re-check adds value the Merkle root alone
   doesn't.

## The honest scope boundary

**Structured-value fidelity, not "hallucination solved."** The check covers
named values typed parsers emit (registry/EVTX/prefetch/MFT/USN/…). Interpretation
("these two artifacts mean lateral movement") has no deterministic oracle — it
stays HYPOTHESIS, needs ≥2 artifact classes, and a human signs off. Pair every
"solved the value-misread" with "did NOT solve inferential judgment." Never let
this become "solved hallucination."

## Recommendations (prioritized)

1. **[HIGH] Flip the gate behind one live run — and consider fail-safe
   downgrade.** Everything is wired + coverage-tested, but flipping
   `FIND_EVIL_REQUIRE_ASSERTED_VALUES=1` by default changes verdict behavior on
   every run; a wrong path on real data would silently drop a real CONFIRMED
   finding → a **false `NO_EVIL`**. Do the live run below first. Stronger still:
   change the gate from *hard-reject* to *downgrade-with-audit-note* on a missing
   declaration, so a missed emitter demotes a finding to a lead (surfaced) rather
   than dropping it — fail-safe instead of fail-closed.

2. **[MED] Persist the full matched output records for true offline
   re-extraction.** Today `manifest_verify` re-checks the sealed matched *values*
   for consistency; it does not re-extract from the original full output (not
   persisted). Persisting the minimal matched *records* would let it re-run the
   real extractor offline, closing the gap between "consistency" and
   "re-extraction".

3. **[MED] Tighten the `record` match to per-field modes.** It currently uses
   substring semantics for every field. Per-field `exact` vs `contains` (e.g.
   `event_id` exact, `data_str` contains) removes the small loosening from the
   flat version.

4. **[LOW] Wire HYPOTHESIS emitters opportunistically.** They are gate-exempt,
   but declaring values still seals their evidence and improves provenance.

5. **[CONDITIONAL] If interactive/Claude-Code mode becomes the shipped product,
   add a typed `submit_finding` as the sole recording path** so verification is
   structurally non-skippable (today it's a guardrail, not a hard gate, on that
   path).

6. **[RESEARCH] Inference cross-check with a different model or rule engine.**
   Pools A/B share a model (per the Estornell 2025 constraint), so they share
   blind spots on *interpretation*. An independent verifier lowers correlated
   error — probabilistically, never "solved." Keep it clearly tiered + human-owned.

## How to flip the gate safely (the live run)

1. `export FIND_EVIL_REQUIRE_ASSERTED_VALUES=1`
2. Run `scripts/verdict <known-evil image with all artifact types>` and a known-benign one.
3. Confirm the verdict and the CONFIRMED finding count are **unchanged** vs a baseline run with the flag off.
4. Grep `audit.jsonl` for any finding rejected/downgraded for a missing or failed `asserted_values` — there should be none on the benign-shape paths.
5. Only then change the default.

## Related

- [`fact-fidelity.md`](fact-fidelity.md) — the mechanism.
- [`replay-determinism.md`](replay-determinism.md) — the custody layer underneath.
- `agent-config/SOUL.md`, `agent-config/TOOLS.md` — the LLM contract this enforces.
