# VERDICT Benchmark — local-corpus result (2026-07-01)

Engine commit: (current master). Cases runnable with LOCAL evidence only. **9/9 pass**; aggregate recall **23/27 = 85%** (Tier B, goldens-scored). manifest_verify overall:true on every committed run.

| case | recall | floor | result | run verdict |
|------|-------:|------:|--------|-------------|
| nist-hacking-case | 10/14 (71%) | 71 | PASS | SUSPICIOUS |
| nitroba | 5/5 (100%) | 80 | PASS | INDETERMINATE |
| evtx-attack-samples | 3/3 (100%) | 100 | PASS | SUSPICIOUS |
| synthetic-benign | 0/0 (100%) | 100 | PASS | INDETERMINATE |
| synthetic-decoy | 0/0 (100%) | 100 | PASS | INDETERMINATE |
| security-log-cleared | 1/1 (100%) | 100 | PASS | INDETERMINATE |
| win-lateral-movement | 2/2 (100%) | 100 | PASS | INDETERMINATE |
| wmi-execution | 1/1 (100%) | 100 | PASS | INDETERMINATE |
| service-install-spoolfool | 1/1 (100%) | 100 | PASS | INDETERMINATE |

## Not run — need evidence you'd provide (19 goldens)
alihadi-01/07/09, dfrws-2008-linux, dfrws-2011-android, digitalcorpora-lonewolf, m57-jean, memlabs-lab1/2/3, nist-data-leakage, otrf-apt3-mordor, sans-starter, synthetic-toolless, volatility-cridex. Drop the image in `evidence/` (or via SIFT fixtures) and re-run to add it to the measured set.

## Honest notes
- Several single-finding EVTX cases score recall 100% but issue an INDETERMINATE verdict — the engine correctly stays cautious on single-artifact-class evidence (recall matched; verdict conservative).
- NIST (71%) is the only case at its floor; the 4 remaining misses are real DFIR depth (USB registry / deleted-email carve / thumbcache) — see benchmark-coverage-matrix.md.
- nist-sift + the 2 self-correction demo runs remain stale (SIFT VM / narrative-preserving regen).
