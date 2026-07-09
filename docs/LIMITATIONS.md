# VERDICT Limitations And Validation Scope

*What VERDICT's accuracy numbers DO and do NOT show. Read this before quoting any
recall / precision figure: a score is only as strong as the corpus it was measured
on, and a published-walkthrough corpus carries a training-data-contamination
caveat that a private held-out corpus does not.*

This is the honest companion to the [accuracy report](accuracy-report.md) and the
[dataset map](DATASET.md). The scoring core itself lives in
[`services/agent/findevil_agent/accuracy.py`](../services/agent/findevil_agent/accuracy.py)
and now annotates every score with a `validation_class`, a `corpus_identity`
label, and — for public-documented corpora only — a `contamination_caveat`.

## What An Accuracy Score Does NOT Measure

A recall / precision / F1 number from the scoring harness is a measure of how well
a run matched a curated ground-truth golden. It is **not**:

- **Custody integrity.** Whether the run is signed and offline-verifiable is the
  job of `manifest_verify`, not the accuracy score. A high recall on a run whose
  manifest does not verify is `RUN INCOMPLETE / CUSTODY INVALID`, not a win.
- **Generalization.** A score is bounded to the scored corpus and the artifact
  classes present in those cases. It does not extrapolate to unseen evidence.
- **Coverage of absent artifact classes.** A case with no memory image cannot
  score memory recall; the absence is a coverage limit, not a clean result.
- **From-scratch detection on public cases.** When the corpus is a published
  walkthrough, recall can reflect memorization (the analysis may be in the model's
  training data), not independent detection. See the validation classes below.

These same caveats are emitted inline as the `does_not_measure` block in the
`accuracy_compare` diagnostic output, so a reader of the raw score sees them too.

## Validation Classes

Every golden is classified into one of three `validation_class` values. The class
drives how strong its recall number is and whether a contamination caveat applies.

| validation_class | corpus_identity | What it IS | What we DID validate | What we did NOT validate | Contamination caveat |
|---|---|---|---|---|---|
| `synthetic` | `synthetic` | Purpose-built fixtures (e.g. `goldens/synthetic-decoy/expected-findings.json`); no public writeup exists. | False-positive floor and planted-bait avoidance under controlled, adversarially-named inputs. | Real-world recall — synthetic inputs are small and known. | None — the answer cannot be in training data. |
| `public-documented` | `public` | Published, documented cases (e.g. NIST/CTF datasets with public walkthroughs). | Recall against established ground truth and verdict calibration on real evidence. | Whether the run solved it from scratch vs. recalled the public analysis. | **Yes** — recall may reflect memorization; read it as a lower bound on rigor, not proof of generalization. |
| `held-out` | `held-out` | Private / embargoed cases deliberately kept out of public corpora. | The strongest generalization signal of the three — no public writeup to memorize. | Breadth — held-out cases are scarce, so the sample is small. | None — not in any public corpus by construction. |

A golden may declare `validation_class` explicitly. When it does not, the class is
derived conservatively: a golden whose `source_url` is a real http(s) link is
treated as `public-documented` (the contamination-aware default), and anything
else (no URL, or an internal generator note) as `synthetic`. `held-out` must be
declared explicitly — it is never assumed.

## How To Read The Table Honestly

- A strong number on a `synthetic` case proves the false-positive / planted-bait
  discipline holds, not that VERDICT generalizes.
- A strong number on a `public-documented` case is real evidence of capability on
  real artifacts, but the `contamination_caveat` means it is a lower bound on
  independent reasoning, not a generalization proof.
- A strong number on a `held-out` case is the closest thing to a generalization
  signal, weakened only by how few such cases exist.

Per-case scores belong in the [accuracy report](accuracy-report.md), and the full
corpus map with fetch mechanics and data-quality tiers is in [DATASET.md](DATASET.md).
Accuracy is always reported per case and per artifact class — never as a broad,
product-wide clean-bill statement.
