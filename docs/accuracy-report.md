# VERDICT Accuracy Report

VERDICT is evaluated on two axes:

1. Whether it surfaces known reportable activity when supported artifacts are parsed.
2. Whether it refuses to overclaim when coverage is partial, single-source, or unsupported.

The second axis is as important as recall. A scoped `INDETERMINATE` is the correct
answer when evidence coverage is too thin to corroborate a stronger claim.

## Scoring Harness

`scripts/score-recall.py` compares a completed run's `verdict.json` against an
answer key under `goldens/<case-id>/expected-findings.json`.

The scorer reports:

| Metric | Meaning |
|---|---|
| `expected_n` | Number of expected claims in the answer key. |
| `recalled_n` | Expected claims matched by run findings. |
| `recall_percent` | `recalled_n / expected_n`, rounded. |
| `verdict_match` | Whether the run Verdict is polarity-consistent with the answer key. |
| `pass` | `recall_percent` meets the case bar and the Verdict is consistent. |

Matching is intentionally conservative: the scorer uses distinctive token overlap
and maximum bipartite matching so one verbose run Finding cannot satisfy several
expected claims.

## Current Public Corpus

The repository ships small answer-key JSON files in `goldens/`. Large fixtures are
not committed; `scripts/fetch-fixtures.sh` stages public datasets into `fixtures/`
when the operator wants to run benchmark cases.

| Case | Artifact class | Purpose |
|---|---|---|
| `nitroba` | PCAP | Network-evidence recall without over-attribution. |
| `nist-hacking-case` | Disk | Hacking-tool execution and artifact-corroboration coverage. |
| `synthetic-benign` | Synthetic control | False-positive floor: zero findings should remain `NO_EVIL`. |
| `sans-starter` | Mixed | SANS starter-case answer-key placeholder for local/eventual scoring. |
| Additional public cases | Disk, memory, Android, Linux | Regression corpus for parser expansion and confidence calibration. |

## Reproduce A Score

```bash
bash scripts/fetch-fixtures.sh
scripts/verdict fixtures/<case-path> --no-dashboard
python scripts/score-recall.py tmp/auto-runs/<case-id> --golden goldens/<case-id>
```

For day-to-day development, run focused smokes first:

```bash
python scripts/verdict-policy-smoke.py
python scripts/report-policy-smoke.py
python scripts/path-existence-smoke.py
bash scripts/run-all-smokes.sh
```

## Calibration Rules

- Execution claims require at least two current-case artifact classes.
- Amcache, ShimCache, memory-only process evidence, YARA, Hayabusa, or malfind
  alone is not enough for a confirmed execution claim.
- Network-only activity can surface leads, but it does not identify a human actor.
- Parser failure is a coverage limitation, not evidence of absence.
- Unsupported raw disk coverage must remain custody-only until supported artifacts
  are mounted or extracted.

## Known Limits

- The public source tree does not ship bulky completed case directories or raw
  evidence. Operators produce fresh `tmp/auto-runs/<case-id>/` artifacts locally.
- Some benchmark fixtures require gated or large downloads and may need manual
  staging before scoring.
- Accuracy should be reported per case and per artifact class, not as a broad
  product-wide clean-bill statement.

Related docs: [`DATASET.md`](DATASET.md), [`false-positives.md`](false-positives.md),
[`cryptographic-attestation.md`](cryptographic-attestation.md), and
[`live-test-matrix.md`](live-test-matrix.md).
