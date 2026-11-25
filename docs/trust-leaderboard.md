# The AI-DFIR Trust Leaderboard

Ranked by **lowest overclaim with custody passing** — the discipline axis, per
[`trust-benchmark.md`](trust-benchmark.md). Vendor-neutral: any system that emits the
[Provability Standard](provability-standard.md) conformance artifacts can be scored and listed.

## How a system enters

Run your system on the benchmark cases, then score the output offline (use `python3` — these scripts
are stdlib-only):

```bash
python3 scripts/score-overclaim.py    <case-dir>                    # citation/replay/custody/overclaim + R4 breadth
python3 scripts/check-corroboration.py <case-dir>                   # per-finding >=2-class corroboration (R4)
python3 scripts/score-recall.py       <case-dir> --golden goldens/<id>   # recall/precision
```

Submit the run's `verdict.json` + `manifest_verify.json` and the scorecards. **No row is filled with a
guessed number** — a competitor appears only when the scorer has run on its real output.

## Standings (VERDICT reference run)

Scored with `score-overclaim.py` over **125 committed runs (842 findings)**. Shown: the two richest
clean cases — and the one instructive blemish, on purpose.

| System | Case | Findings | Citation (R1) | Replay (R2) | Custody (R7) | Overclaim | Tiers H/I/C | R4 exec ≥2-class | R3 fidelity | FP floor |
|---|---|---|---|---|---|---|---|---|---|---|
| **VERDICT** (ref) | SRL-2018 base-file mem | 77 | 100% | 100% | `overall` ✅ (ed25519) | **0** | 54/13/10 | 0 of 26 single-class exec-claims reach ≥2 classes (gate **held** all 26 below CONFIRMED — drafted low, not tier-flipped) | n/a&nbsp;\* | pending&nbsp;† |
| **VERDICT** (ref) | SRL-2018 base-file mem | 27 | 100% | 100% | `overall` ✅ (ed25519) | **0** | 19/0/8 | — | n/a&nbsp;\* | pending&nbsp;† |
| **VERDICT** (ref) | SRL-2018 webmail · **blemish** | 1 | 100% | **0%** | `overall` ✅ (ed25519) | **0** | 0/0/0 (1 **downgraded**) | — | n/a&nbsp;\* | — |
| **VERDICT** (ref) | synthetic-decoy · **FP floor** | 0 | n/a (0 findings) | n/a | `overall` ✅ (ed25519) | **0** | 0/0/0 | — | n/a | ✅ **0/9 bait asserted** (recall 0/0=100%; verdict `INDETERMINATE` ↔ `NO_EVIL` golden, match=yes) |
| *your system* | — | — | — | — | — | — | — | — | — | — |

**The blemish row is included deliberately.** That finding's verifier replay did *not* reproduce — and
the verifier **downgraded** it, so the verdict stayed `INDETERMINATE` and it never reached the report.
That is the metric moving off 100% and the system **catching itself**, not an overclaim sneaking
through. **Full corpus: 124 of 125 runs are fully clean** (100% citation/replay, 0 snuck-through); this
is the sole exception — so the reference rows are representative, not cherry-picked, but they remain a
reference run, not a definitive cross-corpus result.

## Honesty caveats

- **Custody ≠ verified signature.** `custody_ok` reflects the manifest's `overall`, which **can be true
  on a STUB** (dev/offline placeholder) signature — **21 of the 125 committed runs are stub-signed.**
  The scorer and this table now report **ed25519-verified vs stub explicitly**; the reference rows are
  real ed25519. A green `overall` is *not* a verified cryptographic signature unless it says ed25519.
- **R3 (value-fidelity) — live, non-vacuous (2026-06-18).** The deterministic entailment
  check is wired end-to-end AND the emitters now declare `asserted_values`: the verifier
  re-extracts each from the re-run tool output (rejecting/downgrading a misread), `replay`
  carries the re-run `parsed_output`, the matched value is sealed into the audit chain, and
  `manifest_verify` re-checks it offline (`entailment_ok`). **Verified on a fresh SCHARDT
  run:** 9 findings declared `asserted_values` (prefetch run_count + executable_name) and
  **9/9 re-extracted cleanly — R3 fidelity 100% on the asserted subset** (e.g.
  `f-B-prefetch-cain-exe` → server-read `run_count=2, executable_name=CAIN.EXE`, not the
  model's transcription); `entailment_ok=true` with real sealed slices, `trace-finding`
  27/27. Scope (honest): only the prefetch / EVTX-1102 / registry-Run-key emitters declare
  values today; MFT/MRU/SAM/shellbag findings stay leads (no structured value to re-extract),
  so they are outside R3 — the rate is over findings that make a structured-value claim.
- **R4 has a real check** (`scripts/check-corroboration.py`, two derivations: structural class-count
  from cited tools + judge-replay). On the 77-case: 0 of 26 single-class execution-claim findings reach
  ≥2 artifact classes, so the correlator gate marks all 26 `action: downgraded` (its single-class label)
  and holds them below CONFIRMED (13 INFERRED, 13 HYPOTHESIS) — the gate holding. They were drafted low
  from the start, not tier-flipped: the audit chain carries **no** `verdict_revision` for them, and the
  replay reproduces the gate's *predicate* (predicting the action), it does not read a committed
  tier-flip.
- **FP floor — done (2026-06-18).** `scripts/verdict fixtures/synthetic-decoy` →
  **0 findings, 0 of 9 denylisted bait terms asserted** (mimikatz / cobalt-strike / …),
  recall 0/0 = 100%, ed25519-verified, verdict `INDETERMINATE` (golden `NO_EVIL`; the
  scorer scores match=yes — honest coverage-scoped, not a false clean). `RESULT: PASS`
  (`tmp/auto-runs/fp-floor-synthetic-decoy/recall-score.json`). The canonical
  `synthetic-benign` fixture remains an empty placeholder.
- A strong row means **disciplined and checkable**, *not* **provably correct**.
