# Fact-Fidelity — the deterministic entailment check

## The gap this closes

VERDICT's verifier already proves a finding **cites reproducible evidence**: it
re-runs the exact tool call the finding points at and confirms the output's
SHA-256 still matches the audit record (see [`replay-determinism.md`](replay-determinism.md)).
That proves the citation is real and unchanged — custody.

It does **not** prove the model **read that evidence correctly**. A model can
look at a real `registry_query` output that says `run_count = 3` and write a
finding claiming `run_count = 8`, attach the genuine `tool_call_id`, and the
SHA still matches. The lie rides on a valid receipt. Reviewers named this
exactly: *validate that the finding's content is entailed by the output, not
just that the citation exists.*

The entailment check closes that gap **deterministically, for structured-value
claims**. No model re-checks the model — something with no shared blind spot
re-extracts the value from the evidence.

## The idea in one line

> A finding declares the structured value(s) it claims. After the cited output
> reproduces, a pure, LLM-free parser re-extracts each declared value from that
> output and confirms it is actually there. A misread — a value not in the
> evidence — is rejected, and the recorded fact is the value the **parser** read,
> not the value the model typed.

## How it works, end to end

```
emitter / LLM            verify_finding (per finding)                  verdict
─────────────            ────────────────────────────                  ──────
declares          ┌──> 1. replay the cited tool_call_id
asserted_values   │       (fresh subprocess, byte-identical)
on the finding ───┘    2. SHA-256 matches the audit record?  ── no ──> drift: reject/downgrade
                       3. check_entailment(asserted_values, output)
                            ├─ every value present?  ── yes ─> APPROVED
                            │      (records the value the parser read)
                            └─ a value missing?      ── no ──> REJECT  (CONFIRMED)
                                                                DOWNGRADE (lower tiers)
                                                                     │
   _apply_verifier_actions drops a rejected finding and lowers a    │
   downgraded one BEFORE compute_verdict runs ──────────────────────┘
   → an unverifiable fact cannot drive a SUSPICIOUS verdict
```

Every finding — whether a deterministic emitter in `scripts/find_evil_auto.py`
or (in interactive mode) the LLM — flows through the **same** `verify_finding`
gateway, so the check applies to both.

### What a finding declares

Each asserted value is `{path, expected, match}`:

| field | meaning |
|---|---|
| `path` | dotted/wildcard path into the cited tool's output JSON, e.g. `entries[*].values[*].name`, `rows[0].FILENAME`, `run_count`. `[*]` matches any element, `[i]` a specific index. A path that resolves to nothing **fails** (it is not silently skipped). |
| `expected` | the value the finding claims is present at `path`. |
| `match` | how to compare (below). |

| `match` | semantics |
|---|---|
| `exact` | whitespace-trimmed string equality |
| `contains` | case-insensitive substring (the asserted value is part of the evidence value) |
| `int` | integer equality, base-aware (`0x..` hex or decimal); booleans rejected |
| `iso_ts` | ISO-8601 timestamp equality (naive treated as UTC) |
| `record` | **co-location** — `path` resolves to a list of records; `expected` is a JSON object of `{field: substring}` constraints that must ALL hold within **one** record |

### Extractive — the recorded fact is server-read

On a pass, the check returns the actual evidence value(s) it matched
(`EntailmentResult.matched`), and the verifier stamps them onto the approval.
For a `contains` match it captures the **full** evidence string, not just the
asserted substring. So the audit chain carries *what the parser read from the
evidence*, not the model's transcription of it.

### Co-location closes the cross-row launder

The `record` match binds several fields to the **same** record. The registry
Run-key finding asserts `name = Updater` **AND** `data_str ~ evil.exe` in one
`entries[].values[]` element — so a claim cannot be assembled from a name in one
row and a damning target in another.

## Who must declare what — the gate

Enforced **by default** (opt out with `FIND_EVIL_REQUIRE_ASSERTED_VALUES=0`; see rollout note):

| tier | requirement | why |
|---|---|---|
| **CONFIRMED** | MUST declare `asserted_values` | it asserts one specific tool-backed value, which is re-extractable |
| **INFERRED** | MUST declare `asserted_values` **OR** cite `derived_from` | it is a *cross-fact inference* (e.g. DKOM = `pslist` 0 AND `psscan` N>0) with no single re-extractable value; its fidelity is the CONFIRMED facts it rests on, each of which is checked. This matches the SOUL.md ≥2-fact rule enforced by `correlate_findings`. |
| **HYPOTHESIS** | exempt | a lead, not an asserted fact |

A finding that declares nothing structured is a no-op for the check (backward
compatible), so the gate is what makes declaration mandatory.

## What this is NOT (read this before claiming anything)

- **Not "hallucination solved."** It covers **structured-value fidelity** —
  registry, EVTX, prefetch, MFT, USN, amcache/shimcache/LNK fields: anything a
  typed parser emits as a named value.
- **Interpretation has no deterministic oracle.** "These two artifacts mean
  lateral movement" cannot be diffed against the evidence. Such claims stay
  `hypothesis:`, require ≥2 artifact classes, and a human signs off. The
  entailment layer makes the *factual substrate* verifiable so the human only
  adjudicates the genuinely-judgment part.
- **On the deterministic emitter path** the check is a *guarantee + emitter-bug
  catcher* (the code that read the value re-asserts it). Its real teeth are on
  the **LLM authoring path**, where the model cannot record a fact the parser
  can't find in the cited output.

The honest one-line claim this earns:

> The AI cannot record a structured fact that isn't in the cited evidence.

Not more than that.

## Prove it yourself

A reproducible "break it on purpose" hook corrupts a finding's asserted value
(not its citation) so only the entailment check rejects it — it is chain-visible
as a `fault_injection` audit record:

```bash
FIND_EVIL_FAULT_INJECT=entailment_misread_once:<finding-id-fragment> \
  scripts/verdict <evidence>
```

A self-contained demo runs the real emitter + verifier (tool re-run stubbed with
the recorded output, so it needs no Rust MCP or evidence) and shows an honest
finding APPROVED then an injected misread REJECTED:

```bash
python3 scripts/entailment-demo.py            # print it
python3 scripts/entailment-demo.py --render clip.mp4   # render a clip
```

Tests: `services/agent/tests/test_entailment.py` (the path/match spec),
`test_verifier.py::TestEntailmentCheck` (reject-on-misread), and
`test_fault_injection.py` (the misread mutation on the real emitter path).

## Where it lives

| component | file |
|---|---|
| `AssertedValue` model + the gate validator | `services/agent/findevil_agent/events.py` |
| the pure checker (path-walker, matchers, extractive result) | `services/agent/findevil_agent/entailment.py` |
| verifier wiring (runs the check at the SHA-match branch) | `services/agent/findevil_agent/verifier.py` |
| emitters declare values; `fault_inject_misread`; the gate flow | `scripts/find_evil_auto.py` |
| the LLM's operating contract | `agent-config/SOUL.md`, `agent-config/TOOLS.md` |

## Falsifiable expectation — the inverse-polarity sibling (opt-in)

`AssertedValue` proves a value the finding **claims is present**; it is refuted
when that value is **absent**. The optional `Finding.expectation` is the inverse:
a refutable **prediction** the pool commits to when it proposes a finding — a
single observation (same `path`/`expected`/`match` shape, reusing the same
path-walker and matchers, no new engine) the verifier checks against the cited
output and that is refuted only when the output reaches that path and holds a
**present-but-conflicting** leaf. Absence is not refutation: if the predicted
path reaches nothing, there is no contradicting evidence, so the finding stands.

A refuted expectation is demoted like a misread — a CONFIRMED finding is rejected
(re-dispatchable once), a lower tier downgraded. It is gated by
`FIND_EVIL_REQUIRE_EXPECTATION=1` and is **default-off**, so it never changes
default verdicts; it is a deliberate operator choice to enforce
counter-evidence-driven refutation on top of the existing entailment check.
Lives in `check_expectation` (`entailment.py`), wired at the SHA-match branch in
`verifier.py`, with `expectation` carried through the emitter projection in
`scripts/find_evil_auto.py`.

## Offline re-verification

The value the parser re-extracted for each assertion (the matched slice) is
sealed into the signed, hash-chained audit log. `manifest_verify` re-runs the
matcher over those sealed values **offline, with no tool re-run**, and reports
`entailment_ok` — a separate honest signal that does NOT gate `overall` (exactly
like `signature_verified`; byte tampering is already caught by the audit chain).
So a third party gets not just "the verifier approved this" but the exact
evidence values it read, tamper-evident and re-checkable offline. Scope: this
re-confirms the sealed slice; it does not re-extract from the original full
output, which is never persisted.

## Committed receipt — the veto firing on real evidence

`docs/release-evidence/sample-run/` is a committed, `/home`-free, offline-verifiable
run on a real `DE_1102_security_log_cleared.evtx` where the entailment check is
**load-bearing, not replay-only**. The `verifier_action` records *"tool re-run
output_sha256 matches audit log; entailment confirmed from evidence: rows[*]=…"*;
the replay artifact carries `entailment.passed: true` with the parser-re-extracted
`{event_id: 1102, channel: Security}` matched at `rows[*]` (`failures: []`); and
[`manifest_verify.json`](release-evidence/sample-run/manifest_verify.json) reports
`overall: true` with `entailment_ok: true`. `scripts/sample-run-trace-smoke.py`
guards this fixture in the local gate, so the receipt cannot silently rot.

## Rollout status (honest)

**Default-ON as of 2026-06-22 (Stage A).** The gate is enforced by default; opt
out with `FIND_EVIL_REQUIRE_ASSERTED_VALUES=0`. Every CONFIRMED emitter declares
its facts (registry Run-key, EVTX EID 1102, the prefetch execution lead) and
every INFERRED finding declares `asserted_values` or cites `derived_from`.

The full-coverage run that gates this flip is committed: `SCHARDT.dd` with the
gate on, `manifest_verify` **overall: true**. Committed recall for this case is
run-dependent and below the 71% bar — **7/14 = 50%** on the richer runs
(`docs/release-evidence/l3-local-sift.json`) and **5/14 = 36%** on leaner runs
(`docs/sample-run/nist-hacking-case-sift/recall-score.json`). The gate governs
fact-fidelity — which structured values a CONFIRMED finding may assert — not
recall, so enabling it did not drop any legitimate finding. The reject path still has teeth
(`test_entailment.py`, `test_verifier.py::TestEntailmentCheck`,
`test_fault_injection.py` pass), and `services/agent/tests/test_gate_coverage.py`
re-checks that run's emitted CONFIRMED/INFERRED findings against the gate.

The component unit suite sets the flag to `0` by default — it exercises
judge/verifier logic, not the gate, and the verifier's own entailment check runs
regardless (see `services/agent/tests/conftest.py`). Gate behavior is covered by
`TestAssertedValuesGate`, the guard test, and the live run above.

Caveat: the committed `docs/sample-run/*/verdict.json` artifacts predate this
work and show the older pre-declaration shape; regenerate them to reflect current
emitter output.

## Related

- [`fact-fidelity-notes.md`](fact-fidelity-notes.md) — engineering notes: design decisions, gotchas, and recommendations for finishing the rollout.
- [`replay-determinism.md`](replay-determinism.md) — the custody layer the check sits on top of.
- [`false-positives.md`](false-positives.md) — the surrounding FP-prevention layers.
- [`verdict-semantics.md`](verdict-semantics.md) — what SUSPICIOUS / INDETERMINATE / NO_EVIL mean.
- `agent-config/SOUL.md` — the epistemic hierarchy this enforces.
