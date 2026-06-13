# VERDICT — Accuracy Report

*Devpost Required Component #9. Consolidates how VERDICT is measured for accuracy: the scoring
method, the recall results against published ground truth, the verdict-calibration / false-positive
posture, and the honest limits. Every number here is reproducible from committed artifacts or the
scoring harness — nothing is asserted without a path you can re-run.*

> **Stance.** VERDICT is graded on two axes at once: **did it surface the real evil** (recall
> against an answer key) **and did it stay honest about coverage** (a scoped-partial run must say
> `INDETERMINATE`, never a false `NO_EVIL` or an over-claimed `SUSPICIOUS`). A high recall with a
> dishonest verdict is a failure; an honest `INDETERMINATE` on a custody-only run is a pass. The
> scorer enforces both.

> **Parser boundary.** If no parser/tool extracts an artifact class, VERDICT cannot reason over it.
> Current runs emit `coverage_manifest.json` and embed the same object in `verdict.json`: each
> artifact class records `available`, `attempted`, `parsed`, `failed`, `unsupported`,
> `not_supplied`, `parse_errors`, `records_seen`, and `rows_returned`. The goal is not to claim
> complete coverage; it is to make incomplete coverage impossible to hide.

---

## 1. How accuracy is measured

`scripts/score-recall.py` grades a finished run's `verdict.json` against a golden
`expected-findings.json` answer key:

- **Recall** — each expected finding is matched to a run finding by **maximum bipartite matching**
  (optimal 1:1 assignment, no double-counting). A match requires **expected-token coverage ≥ 0.5**
  *and* **≥ 3 shared tokens** — the token floor stops generic DFIR vocabulary ("email", "host",
  "http") from producing spurious matches, and MITRE technique is deliberately *not* a shortcut
  (so a case where every finding shares one technique can't inflate recall).
- **Verdict consistency (asymmetric)** — a run that stays NEUTRAL (`INDETERMINATE`/`UNKNOWN`)
  always passes this check (an honest scoped-partial run is a PASS per the live-test gate). A run
  that makes a *definite* call (`SUSPICIOUS`/`NO_EVIL`) against a NEUTRAL golden **fails** — this is
  the false-positive trap. Otherwise polarity must agree.
- **PASS** requires `recall_percent ≥ min_recall_percent` **and** the verdict check. Output lands in
  `<case-dir>/recall-score.json`.

The corpus, fetch mechanism, and per-case tiers are in [`DATASET.md`](DATASET.md); the
false-positive architecture is in [`false-positives.md`](false-positives.md). Some golden files
still use the legacy scoring label `CONFIRMED_EVIL`; map that to VERDICT's current top-line
`SUSPICIOUS` when comparing polarity.

---

## 2. Recall against published ground truth

The golden corpus is **10 scoreable cases** (real published ground truth) + 2 live-run-only
controls. Fixtures are not committed (license/size); `scripts/fetch-fixtures.sh` pulls them. Status
as of this report:

| # | Case | Class | Golden outcome | Recall bar | Result | Status |
|---|---|---|---|---|---|---|
| 1 | `nitroba` | network (pcap) | SUSPICIOUS (legacy label: CONFIRMED_EVIL) | 80% | **5/5 = 100%** · run `INDETERMINATE` | **PASS** (committed: `docs/sample-run/nitroba`) |
| 2 | `nist-hacking-case` | disk (XP) | SUSPICIOUS (legacy label: CONFIRMED_EVIL) | 71% | **5/14 = 36%** · run `SUSPICIOUS` | **FAIL** — narrowed gap, up from 7% (committed: `docs/sample-run/nist-hacking-case`) |
| 3 | `nist-data-leakage` | disk | SUSPICIOUS (legacy label: CONFIRMED_EVIL) | 60% | — | staged, scheduled (SIFT) |
| 4 | `alihadi-09-encrypt` | disk (FP control) | **INDETERMINATE** | 50% | — | staged, scheduled (SIFT) |
| 5 | `alihadi-01-webserver` | disk | SUSPICIOUS (legacy label: CONFIRMED_EVIL) | 60% | — | staged, scheduled (SIFT) |
| 6 | `dfrws-2008-linux` | memory | SUSPICIOUS (legacy label: CONFIRMED_EVIL) | 50% | — | staged, scheduled |
| 7 | `m57-jean` | disk | SUSPICIOUS (legacy label: CONFIRMED_EVIL) | 60% | — | staged, scheduled (SIFT) |
| 8 | `alihadi-07-sysinternals` | disk | SUSPICIOUS (legacy label: CONFIRMED_EVIL) | 50% | — | staged, scheduled (SIFT) |
| 9 | `volatility-cridex` | memory | SUSPICIOUS (legacy label: CONFIRMED_EVIL) | 50% | — | staged, scheduled |
| 10 | `synthetic-benign` | negative control | **NO_EVIL** (0 findings) | 100% | — | staged, scheduled |

**Honest summary:** 1 of 10 fully scored and passing (`nitroba`, 100%); 1 scored and failing but
**measurably improving** (`nist-hacking-case`, **36% = 5/14, up from 7% = 1/14**). The committed run
now recalls five of the golden's fourteen canonical claims — hacking-tool execution (Prefetch,
8 CONFIRMED), on-disk tool artifacts, **shellbag** navigation to staged files, the **suspiciously-named
account `Mr. Evil`** (SAM, T1136.001), and the **recently-opened-file MRU** — after the SAM /
NTUSER-MRU / shellbag artifact lanes landed. It still misses the deleted-email, internet-history,
LNK, recycle-bin, event-log, thumbcache, USB-history, and named-pipe artifacts the golden also
expects, so it honestly scopes to `SUSPICIOUS` rather than overstate coverage (verdict polarity maps
to the legacy golden's `CONFIRMED_EVIL` label). The number is reproducible:
`scripts/score-recall.py docs/sample-run/nist-hacking-case --golden goldens/nist-hacking-case`. The
remaining 8 goldens are fixture-staged and pending a SIFT-VM batch — **scheduled, not yet run.** We
publish the gap, and the progress, rather than hide either. The adversarial posture is tracked in
[`red-team-challenge.md`](red-team-challenge.md): unsupported artifact evil, benign admin activity,
single-source execution traps, log clearing, DKOM-vs-smear, exfil-without-network, and parser-failure
cases are expected to pass by staying scoped, preserving limitations, and producing replayable
citations — not by always finding evil.

`nitroba` is the strongest single result, and it is reproducible from the committed run
(`scripts/score-recall.py docs/sample-run/nitroba --golden goldens/nitroba` → 5/5 PASS): against a
5-claim network answer key it surfaced all five — anonymous-email contact, source host
`192.168.15.4`, Gmail-cookie attribution, the authenticated Facebook login, and the
send-vs-browsing timeline correlation — at 100% recall over an 80% bar. The run verdict is
`INDETERMINATE` (not a contradiction with 100% recall: recall measures whether the golden *facts*
were surfaced; the verdict measures whether *evil is confirmed* — network metadata yields
`HYPOTHESIS`-level attribution facts, which is honest, so the recall is full while the verdict stays
scoped).

---

## 3. Verdict calibration & false-positive posture

False positives waste the analyst's day, so VERDICT is built to *under*-claim rather than over-claim.
Three architectural layers plus the scorer's asymmetric gate enforce it (full detail in
[`false-positives.md`](false-positives.md)):

1. **Narrow, low-FP tool surface** — typed read-only tools; high-FP signals (raw YARA, uncorroborated
   memory scans) are never auto-escalated.
2. **Dual-pool ACH + correlator** — `detect_contradictions` surfaces Pool A vs Pool B disagreement
   *before* merge; `correlate_findings` enforces the **≥2-artifact-class rule** for execution claims.
3. **Strict confidence taxonomy** — `CONFIRMED` > `INFERRED` > `HYPOTHESIS`; a single artifact class
   floors an execution claim at HYPOTHESIS.

**The false-positive control** (`alihadi-09-encrypt`) is designed to catch over-escalation: its golden
verdict is `INDETERMINATE` (encryption tooling is present but doesn't prove evil), so the scorer's
asymmetric gate **fails the run if it escalates** to `SUSPICIOUS` (or the legacy scoring label `CONFIRMED_EVIL`). The
`synthetic-benign` negative control (0 expected findings, `NO_EVIL`) establishes the environment's FP
floor. Both are staged and scheduled.

**Calibration demonstrated in committed runs (real, not hypothetical):**

- **Live memory run — the smear-vs-DKOM call on first pass** ([`docs/sample-run/memory-dc/`](sample-run/memory-dc/)):
  a fresh `base-dc-memory.img` run reproduced the exact dangerous signature — `vol_pslist` = 0 vs
  `vol_psscan` = 124 — and held it at **HYPOTHESIS (acquisition smear)** *without* any post-run
  reconciliation. The engine recognized core OS singletons (csrss/lsass/services/smss) recovered
  only by `psscan` and a duplicate `System` (PID 4) as a kernel-read failure a rootkit cannot
  produce, re-sequenced to `vol_psxview` to cross-check, and scoped the verdict to `INDETERMINATE`.
  The supervisor's reasoning is in the audit chain as `agent_message` records, and the run is
  ed25519-signed and offline-verifiable (`scripts/trace-finding docs/sample-run/memory-dc`). This is
  the calibration working in code on a first-pass run, not a doc edit.
- **SRL-2018 22-host fleet** ([`reports/2026-04-26-srl2018-dc-investigation.pdf`](reports/2026-04-26-srl2018-dc-investigation.pdf)):
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
   ([`reports/2026-04-26-srl2018-dc-investigation.pdf`](reports/2026-04-26-srl2018-dc-investigation.pdf)).
   This is precisely the failure mode this report exists to document: a confident wrong answer,
   caught, corrected in the open, and engineered against.

---

## 4. Confidence distribution & citation coverage (committed runs)

Every committed sample run is offline-verifiable; these are the actual recorded distributions:

| Run | Verdict | Findings | CONFIRMED | INFERRED | HYPOTHESIS | tool_call_id cited | manifest_verify |
|---|---|---|---|---|---|---|---|
| `memory-dc` (live Volatility 3) | INDETERMINATE | 2 | 0 | 0 | 2 | **2/2 (100%)** | `overall=true` |
| `attack-samples-evtx` | SUSPICIOUS | 3 | 1 | 0 | 2 | **3/3 (100%)** | `overall=true` |
| `nist-hacking-case` (local, current engine) | SUSPICIOUS | 19 | 8 | 2 | 9 | **19/19 (100%)** | `overall=true` |
| `nist-hacking-case-sift` (SANS SIFT VM, current engine) | SUSPICIOUS | 19 | 8 | 2 | 9 | **19/19 (100%)** | `overall=true` |
| `fault-injection-redispatch` | SUSPICIOUS | 9 | 8 | 0 | 1 | **9/9 (100%)** | `overall=true` |

- **Citation coverage is 100%** — every finding in every committed run cites a `tool_call_id`. This is
  not aspirational: the verifier vetoes uncited findings and `manifest_finalize` refuses to seal a run
  containing one (see [`cryptographic-attestation.md`](cryptographic-attestation.md)).
- **Confidence is earned** — the 8 CONFIRMED hacking-tool executions in the NIST run each cite *two*
  artifact classes (a `prefetch_parse` **and** a `registry_query`/UserAssist) in their `derived_from`;
  the newer SAM/MRU/shellbag findings are honestly held at HYPOTHESIS/INFERRED. The EVTX-only
  `attack-samples` run confirms only the directly-observed EID 1102 log-clear and holds the weaker
  leads at HYPOTHESIS.
- **Mode parity (exact)** — the local and `--sift` runs of `SCHARDT.dd` produce the **identical**
  19-finding set, the same 8-CONFIRMED / 2-INFERRED / 9-HYPOTHESIS distribution, and the same
  **5/14 = 36% recall**. The `--sift` run executed inside the SANS SIFT VM over SSH (its
  `evidence_path` is the VM's `/home/sansforensics/evidence/SCHARDT.dd`), so a judge gets the same
  result whether they take the easy no-VM path or the full VM — the heavier path buys nothing the
  host path doesn't already deliver on this image.

---

## 5. Audit-trail integrity (every conclusion is provable)

Accuracy is only useful if it's verifiable. All four committed runs pass offline verification with
**zero trust in us**: `scripts/trace-finding <run-dir>` re-derives the hash chain from scratch
(exits non-zero on a single flipped bit), confirms every finding resolves to a `tool_call_id` → audit
record → Merkle leaf, and `manifest_verify` returns `overall=true` (chain + re-derived leaves + count
+ final hash + signature presence). A tail-truncated log or a re-rooted leaf forgery now fails
verification — see [`cryptographic-attestation.md`](cryptographic-attestation.md).

---

## 6. Evidence integrity — the original data cannot be modified

Accuracy claims mean nothing if the agent could have altered what it measured. Evidence
protection here is **architectural, not prompt-based** — there is no instruction saying "don't
modify the evidence"; there is no code path that *can*:

- **No write verbs exist.** The entire product surface is 43 typed, read-only MCP tools — no
  `execute_shell`, no file-write tool, no delete, no mount-rw. A model that "ignores the
  restriction" has nothing to ignore: the destructive call it might hallucinate does not exist in
  the tool schema, so it fails at the JSON-RPC validation boundary before touching anything
  (`services/mcp/src/server.rs`; every tool carries `readOnlyHint` annotations).
- **Originals are opened read-only and fingerprinted.** `case_open` SHA-256s the image before
  anything else; `.e01` originals are opened via libewf read-only. All downstream parsing operates
  on extracted working copies under the case directory — never in place on the evidence path.
- **Every verification re-touches the hash.** Verifier replays re-run the cited tool and compare
  output SHA-256s; a drifted hash rejects the finding (`verify_finding`, with the
  sha256-drift-rejection path exercised by the `verifier_hash_mismatch_once` fault mode).
- **The boundaries were tested for bypass, adversarially.**
  [`services/mcp/tests/bypass_paths.rs`](../services/mcp/tests/bypass_paths.rs) feeds the tool
  surface a shell-injection payload as a *filename* (`evil; touch HACKED && $(rm -rf ~) | nc …`),
  `../../..` traversal paths, and flag-looking paths (`--output=… -rf`): the payload byte-string is
  hashed as a literal file, traversals resolve to typed `NotFound` errors, nothing shells out, and
  the canary file never appears. `vel_collect` arg-key validation blocks flag injection into the
  one subprocess that takes named args, and a malformed-input panic found by this testing (UTF-8
  truncation) was fixed and pinned with a regression test (`405117a`). The documented threat model
  sits at the top of `bypass_paths.rs`.
- **Tampering after the fact is detectable by anyone.** The audit chain + Merkle root + signature
  verify offline (§5); flip one bit in any committed run and `scripts/trace-finding` exits non-zero
  naming the broken record.

## 7. Honest limits

- **Disk classes need the SIFT VM.** A local-mode disk run without SIFT degrades to custody-only and
  returns a scoped verdict (e.g. NIST 5/14 = 36%) — honest, but below the recall bar. Full disk recall
  requires `scripts/verdict --sift`. This is why 8 goldens are pending.
- **Single-source claims floor at HYPOTHESIS.** The ≥2-artifact-class rule is conservative by design;
  it will hold a real-but-uncorroborated execution claim below CONFIRMED. That trades some recall for
  a far lower false-positive rate — the right trade for a forensics tool.
- **Network-only execution wording is QA-blocked.** A finding that implies execution from network
  evidence alone is held in expert review by the report-QA gate.
- **No published DFIR-agent accuracy baseline exists** to compare against (prior tools decline to
  publish accuracy metrics at all). `nitroba` 5/5 and the NIST runs establish an initial, reproducible
  benchmark rather than a comparison.
- **The corpus is not yet fully run.** This report tabulates what is measured and clearly marks what
  is scheduled; it will be updated as the staged fixtures complete under SIFT.

---

## 8. Reproduce it

```bash
scripts/fetch-fixtures.sh                       # stage the scoreable fixtures
scripts/verdict --sift fixtures/<case>          # run a case (disk classes need SIFT)
python scripts/score-recall.py tmp/auto-runs/<case-id>   # recall vs golden -> recall-score.json
scripts/trace-finding docs/sample-run/nist-hacking-case  # verify a committed run offline, zero deps
```

Related: [`DATASET.md`](DATASET.md) (corpus + per-case tiers), [`false-positives.md`](false-positives.md)
(FP architecture), [`cryptographic-attestation.md`](cryptographic-attestation.md) (offline
verification), [`live-test-matrix.md`](live-test-matrix.md) (the done-gate).
