# `docs/sample-run/` — sample runs (self-contained, offline-verifiable execution logs)

These are real, completed VERDICT investigations committed into the repo so a judge who
**clones without running the tool** still gets traceable agent execution logs (Submission
Requirement #8) and can verify the chain of custody **offline**. Every file here is the
byte-for-byte output of an actual run — nothing was edited, because editing any record would
break the hash chain (which is the point).

Seven runs are included, one per evidence class plus the failure-handling showcases. The first is
the network-recall showcase (`nitroba`, 5/5 against the published answer key, reproducible offline);
the next shows catching evil head-on; the third and fourth show the ≥2-artifact-class rule producing
CONFIRMED execution findings on the *same* case — a refreshed pure **local** run (no SIFT VM) and an
older `--sift` reference from inside the SANS SIFT VM. The local run is the current accuracy exhibit
at 7/14 = 50%; the older SIFT reference remains useful as VM execution proof but should not be used
as an exact parity claim until re-run. The fifth proves the **self-correction
loop** end-to-end under a deliberately-injected fault; the sixth shows the same recovery machinery
firing on **natural, un-staged failures** (six real tool errors, six logged course-corrections, and
the documented HEARTBEAT escalation sealing an honest partial verdict); and the seventh is a **live
memory investigation** whose `vol_pslist`=0 / `vol_psscan`=124 divergence is held at HYPOTHESIS as an
acquisition smear, **not** over-claimed as a rootkit — the textbook DKOM caution, demonstrated on a
first-pass run with the supervisor's reasoning in the log:

| Run | Evidence | Verdict | Findings | What it demonstrates |
|---|---|---|---|---|
| [`nitroba/`](nitroba/) | NIST CFReDS `nitroba.pcap` (public), local `tshark` | **INDETERMINATE** | 9 (all `hypothesis:`) | **100% recall, reproducible offline:** against the 5-claim network answer key the engine surfaces all five — the anonymous-email POST to a remailer, the source host `192.168.15.4`, an authenticated Gmail cookie, the Facebook login, and the send-vs-browse timeline — each `tool_call_id`-cited from one deterministic `pcap_triage` call. Network metadata attributes activity to a host but not a person, so every finding is honestly `HYPOTHESIS` and the verdict scopes to `INDETERMINATE` even at full recall. Score it yourself: `scripts/score-recall.py docs/sample-run/nitroba --golden goldens/nitroba` → **5/5 PASS**. |
| [`attack-samples-evtx/`](attack-samples-evtx/) | EVTX attack-sample set | **SUSPICIOUS** | 3 (1 CONFIRMED + 2 `hypothesis:`) | Catching evil head-on: a directly-observed Security **EID 1102 audit-log-clear** (T1070.001) confirmed, with weaker leads honestly held at HYPOTHESIS. |
| [`fault-injection-redispatch/`](fault-injection-redispatch/) | Same NIST `SCHARDT.dd`, local mode, recorded with `FIND_EVIL_FAULT_INJECT=verifier_reject_once:prefetch-cain-exe` | **SUSPICIOUS** | 9 (8 CONFIRMED + 1 HYPOTHESIS) | **Self-correction under an injected fault:** the verifier caught a deliberately-corrupted replay (`unknown tool: __fault_injected__prefetch_parse`), the engine re-dispatched the verify exactly once, the fresh attempt approved, and the verdict is unchanged. The whole loop is in the hash chain, in order: `fault_injection` → `verifier_redispatch` (carrying the first attempt's rejection reason) → `verifier_action: approved`. |
| [`nist-hacking-case/`](nist-hacking-case/) | NIST CFReDS `SCHARDT.dd` (public domain), **local mode** (Prefetch + registry/UserAssist + SAM + NTUSER MRU + shellbags + native LNK/Recycle Bin fallback triage) | **SUSPICIOUS** | 27 (8 CONFIRMED + 19 HYPOTHESIS) | The ≥2-artifact-class rule on the recommended **no-VM path**, *and* the recall gap measurably closing: each hacking-tool execution (cain, netstumbler, mirc, ethereal, lookatlan) is corroborated by Prefetch **and** UserAssist (both `tool_call_id`s in `derived_from`) so it escalates to **CONFIRMED**; the newer artifact lanes add the suspiciously-named account **`Mr. Evil`** (SAM), recently-opened-file **MRU**, **shellbag** navigation to staged files, removable-media **LNK** traces, and **Recycle Bin** staging artifacts. Recall against the published golden is now **7/14 = 50% (up from 7%)** — reproducible: `scripts/score-recall.py docs/sample-run/nist-hacking-case --golden goldens/nist-hacking-case`. Still a FAIL vs the 71% bar, published honestly. |
| [`nist-hacking-case-sift/`](nist-hacking-case-sift/) | Same `SCHARDT.dd`, older run under `--sift` (full SIFT toolchain inside the SANS SIFT VM over SSH; evidence staged into the VM) | **SUSPICIOUS** | 19 (8 CONFIRMED + 2 INFERRED + 9 HYPOTHESIS) | **SIFT execution reference, not current parity proof:** this committed VM run remains ed25519-signed, `manifest_verify overall:true`, and traceable 19/19, but it predates the local LNK / Recycle Bin fallback refresh and still scores **5/14 = 36%**. Re-run and re-score this reference before claiming exact local/SIFT parity. |
| [`memory-dc/`](memory-dc/) | `base-dc-memory.img` (5 GB domain-controller RAM), local Volatility 3 | **INDETERMINATE** | 2 (both `hypothesis:`) | **Live memory lane + the smear-vs-DKOM call, first pass.** All five memory tools ran (`case_open` → `vol_pslist` → `vol_malfind` → `vol_psscan` → `vol_psxview`). `vol_pslist` returned 0 active processes while `vol_psscan` recovered 124 EPROCESS objects — the textbook DKOM/T1014 signature. The engine **refused to claim a rootkit**: core OS singletons (csrss, lsass, services, smss) recovered *only* by `psscan` plus a duplicate `System` (PID 4) point to an **acquisition smear / kernel-global read failure**, which a rootkit cannot produce, so it held the divergence at **HYPOTHESIS** and scoped the verdict to **INDETERMINATE**. The supervisor's reasoning is in the chain as `agent_message` records — *"process views diverge … re-sequencing to cross-validate with vol_psxview before any DKOM claim (divergence can be an acquisition smear, not T1014)."* This is the SRL-2018 caution reproduced as a live, un-reconciled result. |
| [`natural-self-correction/`](natural-self-correction/) | SANS `base-wkstn-01-c-drive.E01` (competition disk image), local mode | **INDETERMINATE** | 1 (`hypothesis:` EID 7045 `mnemosyne` service install, T1543.003) | **Natural self-correction + HEARTBEAT escalation, nothing injected:** the image's `RegBack` hives are genuinely truncated (`hive truncated (header too small)` — a real condition on real evidence, not a fault hook), so six `registry_query` calls fail and each failure is followed by a logged `course_correction` (`narrow: skip this key; continue remaining hive triage`). The failure streak then trips the documented HEARTBEAT escalation (`HEARTBEAT.md`: "2 consecutive failed self-tests → session terminates with partial report"): five `heartbeat_failure` records, one `heartbeat_terminated`, remaining lanes skipped, and the run seals an honestly-scoped partial **INDETERMINATE** with the one defensible lead held at HYPOTHESIS and the skipped work recorded in `analysis_limitations`. The full arc — error → adjusted plan → repeated failure → policy escalation → honest partial verdict — is in the hash chain, in order. |

## Fleet runs (cross-host correlation)

Two committed fleet rollups back the demo's "host by host across the fleet" beat:

- [`fleet-mini/`](fleet-mini/) — a real **3-host** EVTX fleet, each host ed25519-signed and
  offline-verifiable, **3/3 unique Merkle roots**, re-correlatable from a fresh clone
  (`python3 scripts/fleet_correlate.py docs/sample-run/fleet-mini`). The per-host-crypto proof.
- [`fleet-srl2018-22host/`](fleet-srl2018-22host/) — the real **22-host** SRL-2018 memory-fleet
  correlation: 74 cross-host process correlations, 53 temporal clusters, including the exact
  **six-host `Autorunsc.exe` @ `2018-08-15T17:10:32Z`** same-second cluster the video cites.

## Common files in each run

- `audit.jsonl` — the hash-chained, append-only execution log (every `tool_call_start` /
  `tool_call_output` / `finding_approved` / verifier action; each line carries `prev_hash` + `line_hash`
  and a UTC ISO-8601 `ts`). The `acp_handoff` records are the **agent-to-agent message log**: each is
  a timestamped ACP packet between two agent roles (`from_role`/`to_role` in the payload). The
  [`attack-samples-evtx/`](attack-samples-evtx/) run records the **full ACH topology** on the
  record: **supervisor → pool_a** and **supervisor → pool_b** (the dispatch, each carrying its
  opposite hypothesis), **pool_a → judge** and **pool_b → judge** (the merge), and the per-finding
  **verifier → judge** approvals. That is the multi-agent message log a judge can read end to end,
  in the same hash chain as the tool calls.
  `course_correction`, `heartbeat_failure`, and `heartbeat_terminated` records capture real-time
  failure handling (see `natural-self-correction/`).
- `run.manifest.json` — Merkle root over the audit leaves + signature bundle.
- `manifest_verify.json` — the offline-verification result recorded at run time.
- `verdict.json` — the final verdict and every Finding (each citing a `tool_call_id`).
- `REPORT.md` when present — the human-readable investigative narrative. Partial runs can omit it by policy.
- `evidence_inventory.json` (attack-samples only) — artifact classes touched.
- `recall-score.json` (`nitroba`, `nist-hacking-case`) — the committed grading receipt against the
  published golden: nitroba **5/5 = 100% PASS**, nist-hacking-case local **7/14 = 50% FAIL (up from 7%)**,
  and the older nist-hacking-case SIFT reference **5/14 = 36% FAIL**. The FAIL is
  committed on purpose — it is the honest coverage gap `docs/accuracy-report.md` §2 publishes, and
  either file regenerates with
  `python3 scripts/score-recall.py docs/sample-run/<case> --golden goldens/<case>`.

Rendered artifacts are committed only where they are part of the exhibit. For example,
`nist-hacking-case/` includes `REPORT.html`, `REPORT.pdf`, and `figures/`, while leaner
sample directories keep just the sealed run artifacts. A fresh live run may also emit
`REPORT.html`, `REPORT.pdf`, `figures/`, and `timeline.*` in its Case directory.

## Verify it yourself, offline

Each manifest's embedded `audit_log_path` points at the committed log beside it (set at the
2026-06-12 re-seal), so no path override is needed. In a Claude Code session in this repo (the
`findevil-agent-mcp` server auto-spawns), call the `manifest_verify` tool:

```
manifest_verify(
  manifest_path = "docs/sample-run/nist-hacking-case/run.manifest.json",
)
```

All seven runs return `overall: true` — `audit_chain_ok`, `merkle_root_ok`, `leaf_count_ok`, and
`signature_verified` (real ed25519 check) all pass. No network, no trusted third party
(FRE 902(14) self-authentication).

Or, with **nothing but a Python 3 interpreter** (no MCP server, no venv), re-verify the
hash-chained audit log from scratch and trace every finding in one command:

```
scripts/trace-finding docs/sample-run/nist-hacking-case
```

`trace-finding` re-canonicalizes every audit line and replays every `prev_hash` link (it exits
non-zero on a single flipped bit), confirms each declared Merkle leaf resolves to an audit
record, and prints the chain below. `manifest_verify` additionally rebuilds the rs_merkle root
and checks the signature bundle.

## Trace any finding to the tool execution that produced it

Worked example (`attack-samples-evtx/`):

```
Finding  f-A-evtx-audit-log-cleared   (confidence: CONFIRMED)
   └─ cites tool_call_id  tc-002
        └─ audit.jsonl seq 4  tool_call_start  tool = evtx_query
           audit.jsonl seq 5  tool_call_output output_hash = 3d3dd694…
              └─ both tc-002 and the finding_id are leaves in run.manifest.json (8 leaves)
```

So the verdict word ← Finding ← `tool_call_id` ← audit record ← Merkle leaf ← signed manifest,
end to end. `scripts/trace-finding <run-dir> [finding_id]` prints exactly this chain for every
finding (or one), and exits non-zero if any finding fails to resolve.

## Honest caveats

- **The fault-injection run's failure was deliberate — the natural run's was not.**
  `fault-injection-redispatch/` was recorded with `FIND_EVIL_FAULT_INJECT` set, which corrupts
  exactly one verifier replay's tool name for the first attempt. The injection is not hidden: the
  chain's `fault_injection` record declares it before any verifier action, and the engine prints a
  loud banner when the env var is set. It is a harness demonstration that the recovery path works on
  demand; judge the *organic* self-correction on [`natural-self-correction/`](natural-self-correction/),
  whose six failures come from genuinely truncated registry hives on real evidence (no fault hook,
  no `fault_injection` record in its chain — grep it). The recovery code path is the same production
  re-dispatch/course-correction machinery in both.
- **The natural-self-correction run is a partial run on purpose.** It ends with
  `heartbeat_terminated` and ships no `REPORT.md` — that *is* the documented escalation posture
  (HEARTBEAT.md: terminate with a partial, honestly-scoped verdict rather than push on after
  repeated self-test failures). The sealed chain, manifest, and `verdict.json` still verify offline
  like every other run.
- **Signatures are real ed25519, applied at re-seal.** Every committed run is signed with the
  local ed25519 keypair and `manifest_verify` reports `signature_kind: ed25519,
  signature_verified: true` — the signature is cryptographically checked, not just present.
  Disclosure: the runs were originally sealed with the development stub signer and **re-sealed on
  2026-06-12 over the byte-identical audit chains** (each re-seal asserted the Merkle root was
  unchanged before being accepted; the chains themselves were never touched — `audit.jsonl` is
  still the original byte-for-byte run output). The keyless Sigstore/Fulcio+Rekor tier remains the
  customer-release option (`signer="sigstore"`).
- **Absolute paths are left intact** (`/home/sansforensics/SCHARDT.dd`, etc.) on purpose — they are
  hashed into the chain, so rewriting them would break verification. They are run-host paths, not
  secrets.
- **The two NIST runs share evidence, not a case id.** They are independent investigations of
  `SCHARDT.dd` (one local-mode on the host, one inside the SIFT VM), so their `case_id`s, audit
  chains, and Merkle roots differ — each verifies standalone. Their *verdicts and finding sets*
  match, which is the mode-parity point.
- **The ≥2-class rule cuts both ways.** When only one artifact class is parseable, the same
  correlator holds execution claims at INFERRED/HYPOTHESIS instead of CONFIRMED — the aggregate
  counts are in each run's `verdict.json → findings_summary` (`soul_md_kept` /
  `soul_md_downgraded`); runs produced after 2026-06-09 additionally audit the per-finding
  decisions as a `correlation_outcomes` record.
