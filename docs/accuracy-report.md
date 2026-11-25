# VERDICT Accuracy Report

*Devpost Required Component #9. Consolidates how VERDICT is measured for accuracy: the scoring
method, the recall results against published ground truth, the verdict-calibration / false-positive
posture, and the honest limits. Current source checkouts ship the scoring harness, goldens, and
compact release-evidence summaries; bulky historical run packets are regenerated locally rather
than committed.*

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

The corpus, fetch mechanism, and per-case tiers are in [`DATASET.md`](DATASET.md); the
false-positive architecture is in [`false-positives.md`](false-positives.md). Some golden files
still use the legacy scoring label `CONFIRMED_EVIL`; map that to VERDICT's current top-line
`SUSPICIOUS` when comparing polarity.
Local drop-zone evidence that has a committed answer key is listed separately in
[`evidence-answer-keys.md`](evidence-answer-keys.md); those compact EVTX and fleet-host keys are
calibration cases for fast local live runs, not substitutes for the larger public benchmark batch.

The candidate public corpus backlog in [`DATASET.md`](DATASET.md) is explicitly unscored: a source
does not enter the accuracy table until a specific fixture is pinned, staged, and paired with a
verified expected-findings answer key. Until then, backlog entries are practice, parser-validation,
or needs-walkthrough candidates, not claimed recall coverage.

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

## Scored Results

The golden corpus is **10 scoreable cases** (real published ground truth) + 2 live-run-only
controls. Fixtures and bulky run packets are not committed (license/size);
`scripts/fetch-fixtures.sh` pulls fixtures and `scripts/verdict` regenerates run artifacts. Status
as of this report:

| # | Case | Class | Golden outcome | Recall bar | Result | Status |
|---|---|---|---|---|---|---|
| 1 | `nitroba` | network (pcap) | SUSPICIOUS (legacy label: CONFIRMED_EVIL) | 80% | **5/5 = 100%** · run `INDETERMINATE` | **PASS** in historical run packet; regenerate from fixtures |
| 2 | `nist-hacking-case` | disk (XP) | SUSPICIOUS (legacy label: CONFIRMED_EVIL) | 71% | **7/14 = 50%** · run `SUSPICIOUS` | **FAIL** — narrowed gap, up from 7%; compact receipt in `docs/release-evidence/l3-local-sift.json` |
| 3 | `nist-data-leakage` | disk | SUSPICIOUS (legacy label: CONFIRMED_EVIL) | 60% | — | staged, scheduled (local TSK / SIFT parity) |
| 4 | `alihadi-09-encrypt` | disk (FP control) | **INDETERMINATE** | 50% | — | staged, scheduled (local TSK / SIFT parity) |
| 5 | `alihadi-01-webserver` | disk | SUSPICIOUS (legacy label: CONFIRMED_EVIL) | 60% | — | staged, scheduled (local TSK / SIFT parity) |
| 6 | `dfrws-2008-linux` | memory | SUSPICIOUS (legacy label: CONFIRMED_EVIL) | 50% | — | staged, scheduled |
| 7 | `m57-jean` | disk | SUSPICIOUS (legacy label: CONFIRMED_EVIL) | 60% | — | staged, scheduled (local TSK / SIFT parity) |
| 8 | `alihadi-07-sysinternals` | disk | SUSPICIOUS (legacy label: CONFIRMED_EVIL) | 50% | — | staged, scheduled (local TSK / SIFT parity) |
| 9 | `volatility-cridex` | memory | SUSPICIOUS (legacy label: CONFIRMED_EVIL) | 50% | — | staged, scheduled |
| 10 | `synthetic-benign` | negative control | **NO_EVIL** (0 findings) | 100% | — | staged, scheduled |

**Honest summary:** 1 of 10 fully scored and passing (`nitroba`, 100%); 1 scored and failing but
**measurably improving** (`nist-hacking-case`, **50% = 7/14, up from 7% = 1/14**). The recorded run
now recalls seven of the golden's fourteen canonical claims — hacking-tool execution (Prefetch /
UserAssist, 8 CONFIRMED), on-disk tool artifacts, **shellbag** navigation to staged files,
removable-media **LNK** traces, **Recycle Bin** staging artifacts, the **suspiciously-named account
`Mr. Evil`** (SAM, T1136.001), and the **recently-opened-file MRU**. It still misses the ACMru search
history, USB-history, deleted-email, internet-history, legacy event-log, thumbcache, and named-pipe
artifacts the golden also expects, so it honestly scopes to `SUSPICIOUS` rather than overstate coverage (verdict polarity maps
to the legacy golden's `CONFIRMED_EVIL` label). The receipt is recorded in
`docs/release-evidence/l3-local-sift.json`; to reproduce the score, regenerate a run with
`scripts/verdict` and pass that run directory to `scripts/score-recall.py` with
`--golden goldens/nist-hacking-case`. The
remaining 8 goldens are fixture-staged and pending batch execution — **scheduled, not yet run.** We
publish the gap, and the progress, rather than hide either. The adversarial posture is tracked in
[`red-team-challenge.md`](red-team-challenge.md): unsupported artifact evil, benign admin activity,
single-source execution traps, log clearing, DKOM-vs-smear, exfil-without-network, and parser-failure
cases are expected to pass by staying scoped, preserving limitations, and producing replayable
citations — not by always finding evil.

`nitroba` is the strongest single result, and it is reproducible by rerunning the fixture and
scoring with `--golden goldens/nitroba` (historical result: 5/5 PASS): against a
5-claim network answer key it surfaced all five — anonymous-email contact, source host
`192.168.15.4`, Gmail-cookie attribution, the authenticated Facebook login, and the
send-vs-browsing timeline correlation — at 100% recall over an 80% bar. The run verdict is
`INDETERMINATE` (not a contradiction with 100% recall: recall measures whether the golden *facts*
were surfaced; the verdict measures whether *evil is confirmed* — network metadata yields
`HYPOTHESIS`-level attribution facts, which is honest, so the recall is full while the verdict stays
scoped).

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

- `nist-hacking-case` recalls **7/14 expected claims (50%)** on the standard
  committed runs — six 27-finding SCHARDT runs each reproduce exactly 7/14 under
  the current hardened maximum-bipartite matcher — still below the 71% bar. The
  seven matched: `nhc-004` (hacking-tool files in the MFT), `nhc-005` (prefetch
  execution), `nhc-007` (shellbag staging-share navigation), `nhc-008` (LNK
  removable-media traces), `nhc-009` (Recycle Bin staging), `nhc-010` (SAM account
  "Mr. Evil"), `nhc-011` (OpenSaveMRU installers) — `nhc-008`/`nhc-009` are matched
  at HYPOTHESIS tier. The seven unmatched IDs are `nhc-001`, `nhc-002`, `nhc-003`,
  `nhc-006`, `nhc-012`, `nhc-013`, and `nhc-014`, covering artifacts not yet parsed:
  ACMru/search history, USB history, email carving, `index.dat`/browser history,
  XP `.evt`, thumbcache, and named-pipe enum.
- **Run-to-run variance (disclosed):** NIST recall is run-dependent. Leaner
  19-finding runs (`nist-hacking-case`, `schardt-rescore`) score **5/14 (36%)**
  because they do not emit the HYPOTHESIS-tier LNK (`nhc-008`) and Recycle Bin
  (`nhc-009`) findings; the richer 27-finding runs reach **7/14 (50%)**. Both
  reproduce under the current scorer — the headline number depends on run richness,
  so treat 7/14 as the best committed result and 5/14 as the lower-variance floor.
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
- **Live memory run — the smear-vs-DKOM call on first pass** ([`docs/sample-run/memory-dc/`](sample-run/memory-dc/)):
  a fresh `base-dc-memory.img` run reproduced the exact dangerous signature — `vol_pslist` = 0 vs
  `vol_psscan` = 124 — and held it at **HYPOTHESIS (acquisition smear)** *without* any post-run
  reconciliation. The engine recognized core OS singletons (csrss/lsass/services/smss) recovered
  only by `psscan` and a duplicate `System` (PID 4) as a kernel-read failure a rootkit cannot
  produce, re-sequenced to `vol_psxview` to cross-check, and scoped the verdict to `INDETERMINATE`.
  The supervisor's reasoning is in the audit chain as `agent_message` records, and the run is
  ed25519-signed and offline-verifiable (`scripts/trace-finding docs/sample-run/memory-dc`). This is
  the calibration working in code on a first-pass run, not a doc edit.
- **SRL-2018 22-host fleet** (historical generated report path:
  `docs/reports/2026-04-26-srl2018-dc-investigation.pdf`):
  the same `vol_pslist` = 0 vs `vol_psscan` = 124 divergence
  now stands in the report as **HYPOTHESIS** (acquisition smear). Full honesty about how it got
  there: the original run over-claimed it as confirmed DKOM, and post-run expert review reconciled
  it (commit `cd075c9`) — the caught-hallucination case study below, and the reason the engine now
  carries the smear-disambiguation rule and `vol_psxview`. The live memory run above is the same
  doctrine catching the same trap *before* it reaches the report.
- **Single-class downgrades** — across the correlator's 11 tests
  (`services/agent/tests/test_correlator.py`), an Amcache-only, MFT-only, or EVTX-only execution
  claim is downgraded `CONFIRMED → INFERRED → HYPOTHESIS`; a run-wide *different* artifact class does
  **not** rescue it (corroboration must be the finding's own evidence).

No current release packet includes a hallucinated, uncited Finding as a valid
Finding. When uncertain coverage remains, it is represented as a warning,
limitation, contradiction, or `HYPOTHESIS` instead of a confirmed claim.

## Stage Two Adversarial Checks

Stage Two review is treated as hostile trace review, not as a demo-narrative
exercise. The checks we expect judges to run are:

- **False positives found:** `alihadi-09-encrypt` remains an explicit control for
  benign or dual-use encryption-tool presence. The correct answer is scoped
  `INDETERMINATE`, not a confident suspicious verdict from tool presence alone.
- **Missed artifacts:** the public NIST Hacking Case score is 7/14 recall (50%) on
  the standard committed runs (5/14 on leaner runs — see the run-to-run variance
  note above). The missing ACMru/search history, USB history, email carving, browser
  history, XP `.evt`, thumbcache, and named-pipe artifacts are published as misses
  rather than hidden behind a broad accuracy claim.
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

### Hallucinations caught during testing (specific, not aspirational)

LLM agents confidently assert findings the evidence doesn't support. These are the concrete
instances we caught — each reproducible from a committed artifact, and each honest about *which
layer* did the catching (in-run machinery vs. post-run expert review; both are part of the
product's 99%-automation / 1%-expert-signoff doctrine, `agent-config/EXPERT.md`):

1. **A corrupted verification caught and retried, in-run** — in
   [`docs/sample-run/fault-injection-redispatch/`](sample-run/fault-injection-redispatch/) the
   verifier rejected a deliberately-corrupted replay (`unknown tool: __fault_injected__…`),
   re-dispatched once, and approved on clean evidence — the declared-fault demonstration that the
   catch-and-retry path works on demand.
2. **Honest scope under natural failure, in-run** — in
   [`docs/sample-run/natural-self-correction/`](sample-run/natural-self-correction/) six genuine
   tool failures (truncated `RegBack` hives) ended in a HEARTBEAT-escalated **partial verdict with
   the skipped work named in `analysis_limitations`** — the run records what it did *not* examine
   instead of letting absence of evidence read as absence of evil.
3. **Cross-pool contradictions surfaced before merge, in-run** — the committed `nitroba` chain
   contains **14 `contradiction_resolved` records** (`docs/sample-run/nitroba/audit.jsonl`):
   Pool A vs Pool B disagreements that `detect_contradictions` forced into the open before the
   judge merged. Honest caveat: those committed records carry `contradiction_id: "unknown"` —
   an engine key bug (reading `id` where the tool emits `contradiction_id`) found by our own
   pre-submission audit and since fixed (`4dc81f3`), so newer runs name each contradiction; the
   committed nitroba records prove detection fired, not which pair each record settled.
4. **The SRL-2018 "rootkit" that wasn't — caught by expert review, not in-run.** The original
   fleet investigation **over-claimed**: it headlined the `vol_pslist` = 0 vs `vol_psscan` = 124
   divergence as confirmed DKOM/T1014. Post-run expert review detonated the claim — with
   `KeNumberProcessors` = 0, OS singletons recovered *only* by `psscan`, and a duplicate `System`
   EPROCESS, the evidence is an acquisition smear / kernel-global read failure, which a rootkit
   cannot produce. The report was reconciled to **HYPOTHESIS (acquisition smear)** (commit
   `cd075c9`, ~6 weeks after the run — the git history shows the correction, on purpose), and the
   miss was converted into engine code: the smear-disambiguation rule and the `vol_psxview`
   cross-view tool now in the typed surface, so the same over-claim cannot survive a current run
   Historical generated report path:
   `docs/reports/2026-04-26-srl2018-dc-investigation.pdf`.
   This is precisely the failure mode this report exists to document: a confident wrong answer,
   caught, corrected in the open, and engineered against.

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
