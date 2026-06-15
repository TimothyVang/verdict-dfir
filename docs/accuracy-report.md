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
| `otrf-apt3-mordor` | Windows logs | EVTX/Sysmon/JSON correlation against OTRF's APT3 emulation telemetry. |
| `memlabs-lab1`-`memlabs-lab3` | Windows memory | Volatility-oriented memory extraction coverage using CTF-style objectives without committed flag values. |
| `digitalcorpora-lonewolf` | Windows disk + memory | Large Digital Corpora laptop scenario; records required artifacts and non-scored leads until an authorized teacher guide is available. |
| `synthetic-benign` | Synthetic control | False-positive floor: zero findings should remain `NO_EVIL`. |
| `sans-starter` | Mixed | SANS starter-case answer-key placeholder for local/eventual scoring. |
| Additional public cases | Disk, memory, Android, Linux | Regression corpus for parser expansion and confidence calibration. |

## False Positives

False-positive handling is measured as a first-class outcome, not treated as an
afterthought. The current controls are:

- `synthetic-benign` expects zero Findings and a scoped `NO_EVIL` verdict.
- `alihadi-09-encrypt` is the explicit false-positive control: encryption tools
  can be present without proving malicious activity, so the expected verdict is
  `INDETERMINATE`; an overconfident `SUSPICIOUS` / legacy
  `CONFIRMED_EVIL` result fails the scorer.
- Report QA blocks unsupported execution and exfiltration wording. Network-only
  activity, Amcache-only evidence, ShimCache-only evidence, memory-only process
  evidence, YARA-only hits, Hayabusa-only hits, and malfind-only hits remain
  leads unless corroborated by the required artifact classes.
- The committed EVTX execution trace in
  [`release-evidence/evtx-security-log-clear-trace-summary.json`](release-evidence/evtx-security-log-clear-trace-summary.json)
  records one confirmed Security EID 1102 log-clear Finding and keeps unrelated
  ATT&CK blind spots as warnings rather than negative claims.

The release packet does not claim a global precision score. Precision is reported
per scored case when a trustworthy answer key and completed run output exist.

## Missed Artifacts

Misses are documented explicitly so partial coverage cannot be mistaken for
clearance:

- `nist-hacking-case` currently recalls 7/14 expected claims (50%), below the
  71% bar. The unmatched IDs are `nhc-001`, `nhc-002`, `nhc-003`, `nhc-006`,
  `nhc-012`, `nhc-013`, and `nhc-014`, covering artifacts not yet parsed in the
  committed run: ACMru/search history, USB history, email carving,
  `index.dat`/browser history, XP `.evt`, thumbcache, and named-pipe enum.
- Large or gated datasets remain marked `staged, run pending evidence` until the
  exact fixture is available and scored. No recall number is fabricated for
  those rows.
- Every live run writes `coverage_manifest.json`, which records each artifact
  class as parsed, failed, unsupported, or not supplied. The EVTX trace summary
  records four not-supplied classes (disk/filesystem, `memory`, `network`, and
  `velociraptor`) so reviewers can see what was outside the run scope.

## Hallucinated Claims Found During Testing

The main hallucination class found during testing was not invented IOC text; it
was overclaiming from thin evidence. The controls and observed fixes are:

- The first Nitroba network run returned `NO_EVIL` with 0 Findings because the
  packet cap hid late-case traffic and a truncated final packet caused useful
  stdout to be discarded. The fix raised the packet cap, tolerated partial tshark
  output when stdout is usable, added anonymous-email/cookie timeline extraction,
  and changed the judge grouping so one `pcap_triage` call can produce multiple
  distinct claims.
- The scorer was hardened from symmetric Jaccard matching to expected-coverage
  plus maximum bipartite matching, so a verbose broad Finding cannot satisfy
  multiple expected claims and match order cannot inflate recall.
- Findings without a current-case `tool_call_id` are vetoed. A claim whose cited
  tool output cannot be replayed or whose hash drifts is rejected or downgraded
  before it reaches the final report.
- Prompt-based guidance is not trusted as the final defense. If a model or
  operator wording tries to claim execution from a single weak artifact, report
  QA and the correlator keep that claim at `HYPOTHESIS`, downgrade it, or block
  customer-ready output.

No current release packet includes a hallucinated, uncited Finding as a valid
Finding. When uncertain coverage remains, it is represented as a warning,
limitation, contradiction, or `HYPOTHESIS` instead of a confirmed claim.

## Stage Two Adversarial Checks

Stage Two review is treated as hostile trace review, not as a demo-narrative
exercise. The checks we expect judges to run are:

- **False positives found:** `alihadi-09-encrypt` remains an explicit control for
  benign or dual-use encryption-tool presence. The correct answer is scoped
  `INDETERMINATE`, not a confident suspicious verdict from tool presence alone.
- **Missed artifacts:** the public NIST Hacking Case score is still 7/14 recall.
  The missing ACMru/search history, USB history, email carving, browser history,
  XP `.evt`, thumbcache, and named-pipe artifacts are published as misses rather
  than hidden behind a broad accuracy claim.
- **Hallucination and overclaim classes caught:** uncited Findings, replay hash
  drift, unsupported execution wording, single-source execution claims, and
  unsupported exfiltration claims are vetoed, downgraded, or held as warnings by
  verifier/report-QA/correlator controls before release material is considered.
- **Three-claim trace methodology:** pick any three Findings from a report and
  trace each one to `finding_approved.tool_call_id`, the matching
  `tool_call_start`, its `tool_call_output.output_hash`, verifier replay records,
  and the manifest verification result. The committed EVTX packet is a compact
  public example of this method.
- **Self-correction limitation:** the clean Stage Two packet is traceability
  evidence with `fault_injection=0`. If a clean run has no organic runtime
  failure, it must not be described as organic self-correction. The injected
  verifier re-dispatch run is optional harness/demo evidence only.

## Evidence Integrity

Evidence integrity is enforced architecturally rather than only by prompt text:

- `case_open` SHA-256s the evidence at the start of the Case.
- The product MCP surface has no `execute_shell` and no write verb for evidence.
  Evidence tools open source artifacts read-only; hardened deployments should
  also use a read-only mount / filesystem permissions.
- Each tool output is hashed into `audit.jsonl`, and each audit record links to
  the previous record through `prev_hash`.
- `manifest_finalize` seals the run with a Merkle root over canonical tool
  outputs plus a signature; `manifest_verify` replays the audit chain, leaf
  count, Merkle root, and signature offline.
- Every reportable Finding cites a current-case `tool_call_id`. The verifier
  re-runs the cited tool call and compares the replay output SHA-256 before the
  judge consumes the Finding.

If a prompt-based restriction is ignored, the architectural controls still limit
the damage: there is no raw shell tool to mutate evidence, no uncited Finding can
pass schema/verifier checks, single-source execution wording is blocked by
policy, and `coverage_manifest.json` prevents unsupported areas from being
reported as clean.

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
