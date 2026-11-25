# The AI-DFIR Trust Benchmark — "did the AI overclaim?"

*A reproducible evaluation for the axis recall ignores: **discipline**. Most DFIR evals ask "did the
AI find the evil?" This one asks the harder question — "did it assert more than the evidence
supports?"*

> **Status:** draft spec, v0.1. Designed to score **any** AI-DFIR system that emits the
> [Provability Standard](provability-standard.md) conformance artifacts — not just VERDICT.

## Why this benchmark

Recall benchmarks reward a system that flags everything: surface 50 maybes and you "find" the one real
intrusion. But in forensics the dangerous failure is the opposite — **overclaiming**: asserting a
finding the evidence doesn't support, at a confidence it hasn't earned. Overclaiming is what makes AI
forensic output untrustworthy and inadmissible, and it is exactly what practitioners mean by "AI slop."

This benchmark measures the thing that should differentiate a serious AI-DFIR system: **how little it
overclaims, and how checkable its output is.** It is vendor-neutral and reproducible offline.

## What it measures

| Metric | Definition | Source |
|---|---|---|
| **Recall** | Fraction of golden (known-true) findings reported. | answer keys + `scripts/score-recall.py` |
| **Precision / FP rate** | Reported findings **not** in the golden = false positives. | golden diff |
| **Overclaim rate** *(headline)* | Findings asserted at a **tier higher than the evidence supports.** | tier diff (below) |
| **Citation coverage** | % of findings with a valid `tool_call_id` + reproducible `output_sha256` (R1–R2). | `verdict.json` + replay |
| **Fidelity pass rate** | % of asserted values **entailed** by their cited output (R3). | entailment re-check |
| **Custody integrity** | `manifest_verify` → `overall: true`; **plus a tamper test**: flip one byte in `audit.jsonl` → the verifier must fail and name the moved record. | `manifest_verify.json` |
| **FP floor / calibration** | On the benign baseline, does it return `NO_EVIL` with **zero** findings? | benign corpus |

**Overclaim is the metric that matters.** A finding overclaims when any of these is true:

1. a `CONFIRMED` execution/exfil claim backed by **< 2 artifact classes** (violates R4);
2. an asserted value **not present** in the cited output (violates R3 — a misread);
3. a `NO_EVIL` or `SUSPICIOUS` verdict that the coverage manifest shows should be `INDETERMINATE`.

Each is mechanically detectable from the conformance artifacts — no human judgment needed to *score
the discipline*, which is what makes the benchmark reproducible.

## Corpora

- **Benign baseline** (`goldens/synthetic-benign/` and equivalents) — expected `NO_EVIL`, zero
  findings. Anything reported here is the system's **false-positive floor**.
- **Public answer-key cases** (e.g. `nitroba`, the NIST hacking case) — recall + precision against
  published goldens.
- **Adversarial / fault-injection** — the discriminating set:
  - a planted **misread** (`FIND_EVIL_FAULT_INJECT=entailment_misread_once`) the system must
    **reject** (R3);
  - a planted **pool contradiction** it must **surface, not bury**;
  - a **single-source execution claim** it must **downgrade**, not confirm (R4).

A system that scores high on recall but fails the adversarial set is exactly the "AI slop" failure
mode this benchmark exists to expose.

## Scoring & reproducibility

Fully offline and re-runnable by anyone:

```bash
bash scripts/fetch-fixtures.sh                 # stage public corpora (sources + SHA-256 in docs/DATASET.md)
scripts/verdict <case>                          # run the system under test
scripts/score-recall.py tmp/auto-runs/<case-id> --golden goldens/<case-id>
# + the overclaim scorer: diff each finding's asserted tier vs. the golden's supported tier
```

Output is a per-system **scorecard**:

```json
{ "recall": 0.0, "precision": 0.0, "overclaim_rate": 0.0,
  "citation_coverage": 0.0, "fidelity_pass": 0.0, "custody_ok": true, "fp_floor": 0 }
```

## Reference run (VERDICT, the reference implementation)

The overclaim scorer ships as **`scripts/score-overclaim.py`** (companion to `score-recall.py`). Run
against two committed SRL-2018 memory cases:

| Case | Findings | Citation (R1) | Replay reproduced (R2) | Custody (R7) | Overclaim snuck-through | Tiers (H/I/C) |
|---|---|---|---|---|---|---|
| base-file memory · `SUSPICIOUS` | 77 | 100% | 100% | ✅ `overall=true` | **0** | 54 / 13 / 10 |
| base-file memory · `SUSPICIOUS` | 27 | 100% | 100% | ✅ `overall=true` | **0** | 19 / 0 / 8 |

Every finding cited a `tool_call_id`, every verifier replay reproduced the cited output hash, the
signed manifest verified offline, and **no finding was approved despite a failed or absent replay.**
Note the tier discipline — ~70% held at `HYPOTHESIS`, only a handful `CONFIRMED` — exactly the
conservatism the benchmark rewards.

These cover the **mechanically derivable** metrics (citation / replay / custody / tier). Status of the
two harder requirements, validated across the full 125-run corpus:

- **R4 (≥2-class)** now has a real check — `scripts/check-corroboration.py` (structural class-count +
  judge-replay). On the 77-case, **0 of 26** single-class execution-claim findings reach ≥2 artifact
  classes, so the correlator gate marks all 26 `action: downgraded` (its single-class label) and holds
  them below CONFIRMED (13 INFERRED, 13 HYPOTHESIS) — the gate holding. They were drafted low from the
  start, not tier-flipped: the audit chain carries **no** `verdict_revision` for them, and the replay
  reproduces the gate's *predicate*, not a committed tier-flip.
- **R3 (value-fidelity)** is **blocked** on these runs (they predate the `master` entailment check — no
  `asserted_values`, and cited output bodies aren't persisted); a fresh run is required.
- **Custody caveat:** `overall` can be true on a **stub** signature (21/125 runs); the scorer now
  reports **ed25519-verified vs stub** so a green custody never hides an unverified signature.

Full standings + the honest blemish case: [`trust-leaderboard.md`](trust-leaderboard.md).

## Cross-system (the point)

The benchmark scores **any** AI-DFIR system that emits `verdict.json` + `coverage_manifest.json` +
`manifest_verify.json`. Publish a leaderboard ranked by **lowest overclaim rate** with custody passing.
Whoever overclaims least, wins. VERDICT is the reference entrant, not the only one — the value is the
**measuring stick**, which is what makes it standard-setting rather than marketing. Current standings:
[`trust-leaderboard.md`](trust-leaderboard.md).

## The honesty boundary

The benchmark measures what is **mechanically checkable** — citations, fidelity, custody, tier
discipline, the FP floor. It does **not** perfectly measure *interpretive* correctness: there is no
oracle for "this pattern means lateral movement," and those calls remain human-judged. A high score
means **"disciplined and checkable," not "always right."** Don't let a leaderboard become a new
overclaim — that would defeat the entire purpose.

## References

- [`provability-standard.md`](provability-standard.md) — the conformance artifacts this scores against.
- `docs/accuracy-report.md` — current measured recall/precision and method.
- `docs/false-positives.md` — the false-positive layers and the benign-baseline calibration habit.
- `goldens/`, `scripts/score-recall.py`, `scripts/fetch-fixtures.sh` — the corpora and scorers.
