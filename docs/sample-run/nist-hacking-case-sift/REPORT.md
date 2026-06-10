[VERDICT · DFIR Case File]{.kicker}

# VERDICT — Forensic Investigation Report

[DFIR at machine speed · sigstore-signed chain of custody]{.tagline}

**Case ID:** `782d9a9b-b783-4dee-81cb-a98e11677013`
**Run ID:** `auto-1781102649`
**Started:** 2026-06-10T14:44:09Z
**Finalized:** 2026-06-10T14:44:23Z
**Evidence:** `/home/sansforensics/evidence/SCHARDT.dd`
**Verdict:** **SUSPICIOUS**

> **Cryptographic attestation:**
> Merkle root `3c89e39b42710ff33653df9b3bab036e9d96691f62cabc5bf82090d369d22120`
> Audit log final hash `1936fbb2105c78643786b6764ac4bc2ec9259e4fc873405044be50c638e06425`
> Sigstore signature SHA-256 `ccd360bcee958c378dff7e66daffb3aa302a44201b85e19862368f6134296078`
> Cert fingerprint `bb6201bf2784861f6b28d5de8ce8d4a2cb80b83620a7ca7fa27c0ec298f636c1`

---


## Bottom Line Up Front

::: {.report-fig data-fig="scorecard"}
:::

**Verdict: SUSPICIOUS.** Confirmed: suspicious activity — suspicious activity.

The supplied evidence shows suspicious activity at 2004-08-27T15:33:03Z.

**Scope:** findings span 9 hosts — ETHEREAL.EXE-1C148EEF.pf \(confirmed\); CAIN.EXE-23D61279.pf \(confirmed\); ETHEREAL-SETUP-0.10.6.EXE-1D932600.pf \(confirmed\); NETSTUMBLER.EXE-0BFEE568.pf \(confirmed\); LOOKATLAN.EXE-1F991DD9.pf \(confirmed\); MIRC.EXE-0661EC22.pf \(confirmed\); MIRC612.EXE-02791C37.pf \(confirmed\); CAIN25B45.EXE-056F3A6E.pf \(confirmed\); NETSTUMBLERINSTALLER_0_4_0.EX-0BD9920C.pf \(hypothesis\). Each is assessed separately below; the evidence does not establish them as one incident.

**Assessment:** The cited tool output meets a defined detection rule for this technique. Treat single-source signals as leads until corroborated across artifact classes.

**Certainty:** High — the cited tool output is reproducible \(the verifier re-ran it and the SHA-256 matched\). The confidence is in the artifact, not in intent or actor.

**Key findings:**

* Suspicious activity \(CONFIRMED, T1588.002, cited by tc-010\).
* Suspicious activity \(CONFIRMED, T1588.002, cited by tc-011\).
* Suspicious activity \(CONFIRMED, T1040, cited by tc-020\).
* Suspicious activity \(CONFIRMED, T1040, cited by tc-021\).
* Suspicious activity \(CONFIRMED, T1046, cited by tc-038\).
* Suspicious activity \(CONFIRMED, T1071.001, cited by tc-040\).
* Suspicious activity \(CONFIRMED, T1071.001, cited by tc-041\).
* Suspicious activity \(CONFIRMED, T1046, cited by tc-047\).

* Findings: 9 total — 8 confirmed, 0 inferred, 1 hypothesis.
* Most important next step: Collect Security, Sysmon, and PowerShell Operational EVTX and rerun EVTX/Hayabusa analysis.




## Host Analysis

Findings span more than one host; each is assessed on its own evidence below. The evidence does not establish them as a single incident.

### ETHEREAL.EXE-1C148EEF.pf

*1 finding(s) — 1 confirmed, 0 inferred, 0 hypothesis · 1 events · 2004-08-27T15:34:54Z · source: ETHEREAL.EXE-1C148EEF.pf*

**Other: T1040** `[CONFIRMED]` `tc-021`

The cited tool output meets a defined detection rule for this technique. Treat single-source signals as leads until corroborated across artifact classes.

| Time (UTC) | Event | Account | Tool Call |
|---|---|---|---|
| 2004-08-27T15:34:54Z | prefetch run: ETHEREAL.EXE | — | `tc-021` |
| 2004-08-27T15:46:13Z | UserAssist records execution of cain.exe | — | `tc-085` |
| 2004-08-27T15:46:13Z | UserAssist records execution of cain25b45.exe | — | `tc-085` |
| 2004-08-27T15:46:13Z | UserAssist records execution of ethereal-setup-0.10.6.exe | — | `tc-085` |
| 2004-08-27T15:46:13Z | UserAssist records execution of ethereal.exe | — | `tc-085` |
| 2004-08-27T15:46:13Z | UserAssist records execution of lookatlan.exe | — | `tc-085` |
| 2004-08-27T15:46:13Z | UserAssist records execution of mirc.exe | — | `tc-085` |
| 2004-08-27T15:46:13Z | UserAssist records execution of mirc612.exe | — | `tc-085` |

### CAIN.EXE-23D61279.pf

*1 finding(s) — 1 confirmed, 0 inferred, 0 hypothesis · 9 events · 2004-08-27T15:33:03Z → 2004-08-27T15:46:13Z · source: CAIN.EXE-23D61279.pf*

**Other: T1588.002** `[CONFIRMED]` `tc-010`

The cited tool output meets a defined detection rule for this technique. Treat single-source signals as leads until corroborated across artifact classes.

| Time (UTC) | Event | Account | Tool Call |
|---|---|---|---|
| 2004-08-27T15:33:03Z | prefetch run: CAIN.EXE | — | `tc-010` |
| 2004-08-27T15:46:13Z | UserAssist records execution of cain.exe | — | `tc-085` |
| 2004-08-27T15:46:13Z | UserAssist records execution of cain25b45.exe | — | `tc-085` |
| 2004-08-27T15:46:13Z | UserAssist records execution of ethereal-setup-0.10.6.exe | — | `tc-085` |
| 2004-08-27T15:46:13Z | UserAssist records execution of ethereal.exe | — | `tc-085` |
| 2004-08-27T15:46:13Z | UserAssist records execution of lookatlan.exe | — | `tc-085` |
| 2004-08-27T15:46:13Z | UserAssist records execution of mirc.exe | — | `tc-085` |
| 2004-08-27T15:46:13Z | UserAssist records execution of mirc612.exe | — | `tc-085` |

### ETHEREAL-SETUP-0.10.6.EXE-1D932600.pf

*1 finding(s) — 1 confirmed, 0 inferred, 0 hypothesis · 1 events · 2004-08-27T15:28:36Z · source: ETHEREAL-SETUP-0.10.6.EXE-1D932600.pf*

**Other: T1040** `[CONFIRMED]` `tc-020`

The cited tool output meets a defined detection rule for this technique. Treat single-source signals as leads until corroborated across artifact classes.

| Time (UTC) | Event | Account | Tool Call |
|---|---|---|---|
| 2004-08-27T15:28:36Z | prefetch run: ETHEREAL-SETUP-0.10.6.EXE | — | `tc-020` |
| 2004-08-27T15:46:13Z | UserAssist records execution of cain.exe | — | `tc-085` |
| 2004-08-27T15:46:13Z | UserAssist records execution of cain25b45.exe | — | `tc-085` |
| 2004-08-27T15:46:13Z | UserAssist records execution of ethereal-setup-0.10.6.exe | — | `tc-085` |
| 2004-08-27T15:46:13Z | UserAssist records execution of ethereal.exe | — | `tc-085` |
| 2004-08-27T15:46:13Z | UserAssist records execution of lookatlan.exe | — | `tc-085` |
| 2004-08-27T15:46:13Z | UserAssist records execution of mirc.exe | — | `tc-085` |
| 2004-08-27T15:46:13Z | UserAssist records execution of mirc612.exe | — | `tc-085` |

### NETSTUMBLER.EXE-0BFEE568.pf

*1 finding(s) — 1 confirmed, 0 inferred, 0 hypothesis · 1 events · 2004-08-27T15:12:35Z · source: NETSTUMBLER.EXE-0BFEE568.pf*

**Other: T1046** `[CONFIRMED]` `tc-047`

The cited tool output meets a defined detection rule for this technique. Treat single-source signals as leads until corroborated across artifact classes.

| Time (UTC) | Event | Account | Tool Call |
|---|---|---|---|
| 2004-08-27T15:12:35Z | prefetch run: NETSTUMBLER.EXE | — | `tc-047` |
| 2004-08-27T15:46:13Z | UserAssist records execution of cain.exe | — | `tc-085` |
| 2004-08-27T15:46:13Z | UserAssist records execution of cain25b45.exe | — | `tc-085` |
| 2004-08-27T15:46:13Z | UserAssist records execution of ethereal-setup-0.10.6.exe | — | `tc-085` |
| 2004-08-27T15:46:13Z | UserAssist records execution of ethereal.exe | — | `tc-085` |
| 2004-08-27T15:46:13Z | UserAssist records execution of lookatlan.exe | — | `tc-085` |
| 2004-08-27T15:46:13Z | UserAssist records execution of mirc.exe | — | `tc-085` |
| 2004-08-27T15:46:13Z | UserAssist records execution of mirc612.exe | — | `tc-085` |

### LOOKATLAN.EXE-1F991DD9.pf

*1 finding(s) — 1 confirmed, 0 inferred, 0 hypothesis · 1 events · 2004-08-26T15:06:14Z · source: LOOKATLAN.EXE-1F991DD9.pf*

**Other: T1046** `[CONFIRMED]` `tc-038`

The cited tool output meets a defined detection rule for this technique. Treat single-source signals as leads until corroborated across artifact classes.

| Time (UTC) | Event | Account | Tool Call |
|---|---|---|---|
| 2004-08-26T15:06:14Z | prefetch run: LOOKATLAN.EXE | — | `tc-038` |
| 2004-08-27T15:46:13Z | UserAssist records execution of cain.exe | — | `tc-085` |
| 2004-08-27T15:46:13Z | UserAssist records execution of cain25b45.exe | — | `tc-085` |
| 2004-08-27T15:46:13Z | UserAssist records execution of ethereal-setup-0.10.6.exe | — | `tc-085` |
| 2004-08-27T15:46:13Z | UserAssist records execution of ethereal.exe | — | `tc-085` |
| 2004-08-27T15:46:13Z | UserAssist records execution of lookatlan.exe | — | `tc-085` |
| 2004-08-27T15:46:13Z | UserAssist records execution of mirc.exe | — | `tc-085` |
| 2004-08-27T15:46:13Z | UserAssist records execution of mirc612.exe | — | `tc-085` |

### MIRC.EXE-0661EC22.pf

*1 finding(s) — 1 confirmed, 0 inferred, 0 hypothesis · 1 events · 2004-08-25T16:20:34Z · source: MIRC.EXE-0661EC22.pf*

**Command &amp; Control: T1071.001** `[CONFIRMED]` `tc-040`

The cited tool output meets a defined detection rule for this technique. Treat single-source signals as leads until corroborated across artifact classes.

| Time (UTC) | Event | Account | Tool Call |
|---|---|---|---|
| 2004-08-25T16:20:34Z | prefetch run: MIRC.EXE | — | `tc-040` |
| 2004-08-27T15:46:13Z | UserAssist records execution of cain.exe | — | `tc-085` |
| 2004-08-27T15:46:13Z | UserAssist records execution of cain25b45.exe | — | `tc-085` |
| 2004-08-27T15:46:13Z | UserAssist records execution of ethereal-setup-0.10.6.exe | — | `tc-085` |
| 2004-08-27T15:46:13Z | UserAssist records execution of ethereal.exe | — | `tc-085` |
| 2004-08-27T15:46:13Z | UserAssist records execution of lookatlan.exe | — | `tc-085` |
| 2004-08-27T15:46:13Z | UserAssist records execution of mirc.exe | — | `tc-085` |
| 2004-08-27T15:46:13Z | UserAssist records execution of mirc612.exe | — | `tc-085` |

### MIRC612.EXE-02791C37.pf

*1 finding(s) — 1 confirmed, 0 inferred, 0 hypothesis · 1 events · 2004-08-20T15:09:46Z · source: MIRC612.EXE-02791C37.pf*

**Command &amp; Control: T1071.001** `[CONFIRMED]` `tc-041`

The cited tool output meets a defined detection rule for this technique. Treat single-source signals as leads until corroborated across artifact classes.

| Time (UTC) | Event | Account | Tool Call |
|---|---|---|---|
| 2004-08-20T15:09:46Z | prefetch run: MIRC612.EXE | — | `tc-041` |
| 2004-08-27T15:46:13Z | UserAssist records execution of cain.exe | — | `tc-085` |
| 2004-08-27T15:46:13Z | UserAssist records execution of cain25b45.exe | — | `tc-085` |
| 2004-08-27T15:46:13Z | UserAssist records execution of ethereal-setup-0.10.6.exe | — | `tc-085` |
| 2004-08-27T15:46:13Z | UserAssist records execution of ethereal.exe | — | `tc-085` |
| 2004-08-27T15:46:13Z | UserAssist records execution of lookatlan.exe | — | `tc-085` |
| 2004-08-27T15:46:13Z | UserAssist records execution of mirc.exe | — | `tc-085` |
| 2004-08-27T15:46:13Z | UserAssist records execution of mirc612.exe | — | `tc-085` |

### CAIN25B45.EXE-056F3A6E.pf

*1 finding(s) — 1 confirmed, 0 inferred, 0 hypothesis · 1 events · 2004-08-20T15:05:52Z · source: CAIN25B45.EXE-056F3A6E.pf*

**Other: T1588.002** `[CONFIRMED]` `tc-011`

The cited tool output meets a defined detection rule for this technique. Treat single-source signals as leads until corroborated across artifact classes.

| Time (UTC) | Event | Account | Tool Call |
|---|---|---|---|
| 2004-08-20T15:05:52Z | prefetch run: CAIN25B45.EXE | — | `tc-011` |
| 2004-08-27T15:46:13Z | UserAssist records execution of cain.exe | — | `tc-085` |
| 2004-08-27T15:46:13Z | UserAssist records execution of cain25b45.exe | — | `tc-085` |
| 2004-08-27T15:46:13Z | UserAssist records execution of ethereal-setup-0.10.6.exe | — | `tc-085` |
| 2004-08-27T15:46:13Z | UserAssist records execution of ethereal.exe | — | `tc-085` |
| 2004-08-27T15:46:13Z | UserAssist records execution of lookatlan.exe | — | `tc-085` |
| 2004-08-27T15:46:13Z | UserAssist records execution of mirc.exe | — | `tc-085` |
| 2004-08-27T15:46:13Z | UserAssist records execution of mirc612.exe | — | `tc-085` |

### NETSTUMBLERINSTALLER_0_4_0.EX-0BD9920C.pf

*1 finding(s) — 0 confirmed, 0 inferred, 1 hypothesis · 1 events · 2004-08-27T15:12:11Z · source: NETSTUMBLERINSTALLER_0_4_0.EX-0BD9920C.pf*

**Other: T1046** `[HYPOTHESIS]` `tc-048`

The cited tool output meets a defined detection rule for this technique. Treat single-source signals as leads until corroborated across artifact classes.

| Time (UTC) | Event | Account | Tool Call |
|---|---|---|---|
| 2004-08-27T15:12:11Z | prefetch run: NETSTUMBLERINSTALLER_0_4_0.EX | — | `tc-048` |




## Recommendations

* Collect Security, Sysmon, and PowerShell Operational EVTX and rerun EVTX/Hayabusa analysis.
* Use the disk artifact summary to pivot between Prefetch, Registry, MFT, USN, EVTX, and YARA-target rows without upgrading single-source execution claims.
* Acquire DNS, proxy, firewall, NetFlow, or PCAP telemetry to test C2 and exfiltration hypotheses.




## Limitations

What the supplied evidence cannot establish, and how to resolve it.

* Who operated the activity — this report does not assert attribution; naming an account reflects a record field, not the human behind it.
* Whether the wider environment is affected — this run examined the supplied evidence only.
* Undetermined: command-and-control and exfiltration cannot be assessed without network data. To resolve: collect DNS, proxy, firewall, or NetFlow logs, or a PCAP.
* Undetermined: injected code and hidden processes cannot be examined without a memory image. To resolve: capture RAM and run the volatility process and injection plugins.
* Undetermined: logon, process-creation, and PowerShell activity cannot be reviewed without event logs. To resolve: collect the Security, Sysmon/Operational, and PowerShell/Operational logs.



# Technical Report {.tier-break}

The sections below are the full analyst-grade record: every finding with its
`tool_call_id` and confidence, the complete event timeline, the entity rollup
and indicators, coverage matrices, triage, sources, and the reproducibility and
chain-of-custody appendices.

## Case Summary

* **Total merged findings:** 9
* **By confidence:**
  - CONFIRMED: 8
  - INFERRED:  0
  - HYPOTHESIS: 1
* **Contradictions surfaced (Pool A vs Pool B):** 0
* **SOUL.md correlator:** 9 kept, 0 downgraded

## Detailed Findings

### Finding 1 — confidence: CONFIRMED, pool: B, MITRE: T1588.002, replay: exact_match (match)

cain.exe executed on this host: Windows Prefetch records its execution and the UserAssist key \(per-user GUI execution\) records the same binary. Two independent artifact classes \(prefetch + registry/UserAssist\) corroborate execution.

- `tool_call_id`: `tc-010`
- artifact: `/home/sansforensics/.findevil/cases/782d9a9b-b783-4dee-81cb-a98e11677013/extracted/disk/disk-extract-e3e4a1db-05a9-4a2c-9c69-0e9c2650519f/prefetch/WINDOWS/Prefetch/CAIN.EXE-23D61279.pf`
- confidence: Confirmed — the cited tool output is reproducible; this does not imply attribution or complete scope.

### Finding 2 — confidence: CONFIRMED, pool: B, MITRE: T1588.002, replay: exact_match (match)

cain25b45.exe executed on this host: Windows Prefetch records its execution and the UserAssist key \(per-user GUI execution\) records the same binary. Two independent artifact classes \(prefetch + registry/UserAssist\) corroborate execution.

- `tool_call_id`: `tc-011`
- artifact: `/home/sansforensics/.findevil/cases/782d9a9b-b783-4dee-81cb-a98e11677013/extracted/disk/disk-extract-e3e4a1db-05a9-4a2c-9c69-0e9c2650519f/prefetch/WINDOWS/Prefetch/CAIN25B45.EXE-056F3A6E.pf`
- confidence: Confirmed — the cited tool output is reproducible; this does not imply attribution or complete scope.

### Finding 3 — confidence: CONFIRMED, pool: B, MITRE: T1040, replay: exact_match (match)

ethereal-setup-0.10.6.exe executed on this host: Windows Prefetch records its execution and the UserAssist key \(per-user GUI execution\) records the same binary. Two independent artifact classes \(prefetch + registry/UserAssist\) corroborate execution.

- `tool_call_id`: `tc-020`
- artifact: `/home/sansforensics/.findevil/cases/782d9a9b-b783-4dee-81cb-a98e11677013/extracted/disk/disk-extract-e3e4a1db-05a9-4a2c-9c69-0e9c2650519f/prefetch/WINDOWS/Prefetch/ETHEREAL-SETUP-0.10.6.EXE-1D932600.pf`
- confidence: Confirmed — the cited tool output is reproducible; this does not imply attribution or complete scope.

### Finding 4 — confidence: CONFIRMED, pool: B, MITRE: T1040, replay: exact_match (match)

ethereal.exe executed on this host: Windows Prefetch records its execution and the UserAssist key \(per-user GUI execution\) records the same binary. Two independent artifact classes \(prefetch + registry/UserAssist\) corroborate execution.

- `tool_call_id`: `tc-021`
- artifact: `/home/sansforensics/.findevil/cases/782d9a9b-b783-4dee-81cb-a98e11677013/extracted/disk/disk-extract-e3e4a1db-05a9-4a2c-9c69-0e9c2650519f/prefetch/WINDOWS/Prefetch/ETHEREAL.EXE-1C148EEF.pf`
- confidence: Confirmed — the cited tool output is reproducible; this does not imply attribution or complete scope.

### Finding 5 — confidence: CONFIRMED, pool: B, MITRE: T1046, replay: exact_match (match)

lookatlan.exe executed on this host: Windows Prefetch records its execution and the UserAssist key \(per-user GUI execution\) records the same binary. Two independent artifact classes \(prefetch + registry/UserAssist\) corroborate execution.

- `tool_call_id`: `tc-038`
- artifact: `/home/sansforensics/.findevil/cases/782d9a9b-b783-4dee-81cb-a98e11677013/extracted/disk/disk-extract-e3e4a1db-05a9-4a2c-9c69-0e9c2650519f/prefetch/WINDOWS/Prefetch/LOOKATLAN.EXE-1F991DD9.pf`
- confidence: Confirmed — the cited tool output is reproducible; this does not imply attribution or complete scope.

### Finding 6 — confidence: CONFIRMED, pool: B, MITRE: T1071.001, replay: exact_match (match)

mirc.exe executed on this host: Windows Prefetch records its execution and the UserAssist key \(per-user GUI execution\) records the same binary. Two independent artifact classes \(prefetch + registry/UserAssist\) corroborate execution.

- `tool_call_id`: `tc-040`
- artifact: `/home/sansforensics/.findevil/cases/782d9a9b-b783-4dee-81cb-a98e11677013/extracted/disk/disk-extract-e3e4a1db-05a9-4a2c-9c69-0e9c2650519f/prefetch/WINDOWS/Prefetch/MIRC.EXE-0661EC22.pf`
- confidence: Confirmed — the cited tool output is reproducible; this does not imply attribution or complete scope.

### Finding 7 — confidence: CONFIRMED, pool: B, MITRE: T1071.001, replay: exact_match (match)

mirc612.exe executed on this host: Windows Prefetch records its execution and the UserAssist key \(per-user GUI execution\) records the same binary. Two independent artifact classes \(prefetch + registry/UserAssist\) corroborate execution.

- `tool_call_id`: `tc-041`
- artifact: `/home/sansforensics/.findevil/cases/782d9a9b-b783-4dee-81cb-a98e11677013/extracted/disk/disk-extract-e3e4a1db-05a9-4a2c-9c69-0e9c2650519f/prefetch/WINDOWS/Prefetch/MIRC612.EXE-02791C37.pf`
- confidence: Confirmed — the cited tool output is reproducible; this does not imply attribution or complete scope.

### Finding 8 — confidence: CONFIRMED, pool: B, MITRE: T1046, replay: exact_match (match)

netstumbler.exe executed on this host: Windows Prefetch records its execution and the UserAssist key \(per-user GUI execution\) records the same binary. Two independent artifact classes \(prefetch + registry/UserAssist\) corroborate execution.

- `tool_call_id`: `tc-047`
- artifact: `/home/sansforensics/.findevil/cases/782d9a9b-b783-4dee-81cb-a98e11677013/extracted/disk/disk-extract-e3e4a1db-05a9-4a2c-9c69-0e9c2650519f/prefetch/WINDOWS/Prefetch/NETSTUMBLER.EXE-0BFEE568.pf`
- confidence: Confirmed — the cited tool output is reproducible; this does not imply attribution or complete scope.

### Finding 9 — confidence: HYPOTHESIS, pool: B, MITRE: T1046, replay: exact_match (match)

hypothesis: Windows Prefetch contains NETSTUMBLERINSTALLER_0_4_0.EX with run_count=1; NetStumbler wireless discovery tool is a NIST Hacking Case triage lead. Treat this as a disk-artifact lead that needs corroboration before any standalone activity claim.

- `tool_call_id`: `tc-048`
- artifact: `/home/sansforensics/.findevil/cases/782d9a9b-b783-4dee-81cb-a98e11677013/extracted/disk/disk-extract-e3e4a1db-05a9-4a2c-9c69-0e9c2650519f/prefetch/WINDOWS/Prefetch/NETSTUMBLERINSTALLER_0_4_0.EX-0BD9920C.pf`
- confidence: Hypothesis — a single-source triage lead; corroborate before any response action.





## Full Event Timeline

Normalized timeline events: 573. First 40 rows shown below (consecutive identical events collapsed with an [Nx] count); full data is in `timeline.json` and analyst-friendly `timeline.csv`.

| UTC Time | Artifact | Event | Account | Host | Source IP | Logon | Process/PID | Conf. | Tool Call |
|---|---|---|---|---|---|---|---|---|---|
| 1601-01-01T00:00:00Z | mft | mft entry: $Secure | — | — | — | — | — | — | `tc-004` |
| 1999-04-23T22:22:00Z | mft | mft entry: WIN98/BASE4.CAB | — | — | — | — | — | — | `tc-004` |
| 1999-04-23T22:22:00Z | mft | mft entry: WIN98/BASE5.CAB | — | — | — | — | — | — | `tc-004` |
| 1999-04-23T22:22:00Z | mft | mft entry: WIN98/BASE6.CAB | — | — | — | — | — | — | `tc-004` |
| 1999-04-23T22:22:00Z | mft | mft entry: WIN98/CATALOG3.CAB | — | — | — | — | — | — | `tc-004` |
| 1999-04-23T22:22:00Z | mft | mft entry: WIN98/CHL99.CAB | — | — | — | — | — | — | `tc-004` |
| 1999-04-23T22:22:00Z | mft | mft entry: WIN98/DELTEMP.COM | — | — | — | — | — | — | `tc-004` |
| 1999-04-23T22:22:00Z | mft | mft entry: WIN98/DOSSETUP.BIN | — | — | — | — | — | — | `tc-004` |
| 1999-04-23T22:22:00Z | mft | mft entry: WIN98/DRIVER11.CAB | — | — | — | — | — | — | `tc-004` |
| 1999-04-23T22:22:00Z | mft | mft entry: WIN98/DRIVER12.CAB | — | — | — | — | — | — | `tc-004` |
| 1999-04-23T22:22:00Z | mft | mft entry: WIN98/DRIVER13.CAB | — | — | — | — | — | — | `tc-004` |
| 1999-04-23T22:22:00Z | mft | mft entry: WIN98/DRIVER14.CAB | — | — | — | — | — | — | `tc-004` |
| 1999-04-23T22:22:00Z | mft | mft entry: WIN98/DRIVER15.CAB | — | — | — | — | — | — | `tc-004` |
| 1999-04-23T22:22:00Z | mft | mft entry: WIN98/DRIVER16.CAB | — | — | — | — | — | — | `tc-004` |
| 1999-04-23T22:22:00Z | mft | mft entry: WIN98/DRIVER17.CAB | — | — | — | — | — | — | `tc-004` |
| 1999-04-23T22:22:00Z | mft | mft entry: WIN98/DRIVER18.CAB | — | — | — | — | — | — | `tc-004` |
| 1999-04-23T22:22:00Z | mft | mft entry: WIN98/DRIVER19.CAB | — | — | — | — | — | — | `tc-004` |
| 1999-04-23T22:22:00Z | mft | mft entry: WIN98/DRIVER20.CAB | — | — | — | — | — | — | `tc-004` |
| 1999-04-23T22:22:00Z | mft | mft entry: WIN98/EXTRACT.EXE | — | — | — | — | — | — | `tc-004` |
| 1999-04-23T22:22:00Z | mft | mft entry: WIN98/FORMAT.COM | — | — | — | — | — | — | `tc-004` |
| 1999-04-23T22:22:00Z | mft | mft entry: WIN98/INTL.TXT | — | — | — | — | — | — | `tc-004` |
| 1999-04-23T22:22:00Z | mft | mft entry: WIN98/MINI.CAB | — | — | — | — | — | — | `tc-004` |
| 1999-04-23T22:22:00Z | mft | mft entry: WIN98/NET10.CAB | — | — | — | — | — | — | `tc-004` |
| 1999-04-23T22:22:00Z | mft | mft entry: WIN98/NET7.CAB | — | — | — | — | — | — | `tc-004` |
| 1999-04-23T22:22:00Z | mft | mft entry: WIN98/NET8.CAB | — | — | — | — | — | — | `tc-004` |
| 1999-04-23T22:22:00Z | mft | mft entry: WIN98/NET9.CAB | — | — | — | — | — | — | `tc-004` |
| 1999-04-23T22:22:00Z | mft | mft entry: WIN98/OEMSETUP.BIN | — | — | — | — | — | — | `tc-004` |
| 1999-04-23T22:22:00Z | mft | mft entry: WIN98/OEMSETUP.EXE | — | — | — | — | — | — | `tc-004` |
| 1999-04-23T22:22:00Z | mft | mft entry: WIN98/PRECOPY1.CAB | — | — | — | — | — | — | `tc-004` |
| 1999-04-23T22:22:00Z | mft | mft entry: WIN98/PRECOPY2.CAB | — | — | — | — | — | — | `tc-004` |
| 1999-04-23T22:22:00Z | mft | mft entry: WIN98/SAVE32.COM | — | — | — | — | — | — | `tc-004` |
| 1999-04-23T22:22:00Z | mft | mft entry: WIN98/SCANDISK.EXE | — | — | — | — | — | — | `tc-004` |
| 1999-04-23T22:22:00Z | mft | mft entry: WIN98/SCANDISK.PIF | — | — | — | — | — | — | `tc-004` |
| 1999-04-23T22:22:00Z | mft | mft entry: WIN98/SCANPROG.EXE | — | — | — | — | — | — | `tc-004` |
| 1999-04-23T22:22:00Z | mft | mft entry: WIN98/SCANREG.EXE | — | — | — | — | — | — | `tc-004` |
| 1999-04-23T22:22:00Z | mft | mft entry: WIN98/SETUP.EXE | — | — | — | — | — | — | `tc-004` |
| 1999-04-23T22:22:00Z | mft | mft entry: WIN98/SETUP.TXT | — | — | — | — | — | — | `tc-004` |
| 1999-04-23T22:22:00Z | mft | mft entry: WIN98/SETUP0.WAV | — | — | — | — | — | — | `tc-004` |
| 1999-04-23T22:22:00Z | mft | mft entry: WIN98/SETUP1.WAV | — | — | — | — | — | — | `tc-004` |
| 1999-04-23T22:22:00Z | mft | mft entry: WIN98/SETUP2.WAV | — | — | — | — | — | — | `tc-004` |








## MITRE ATT&CK Coverage

6/12 ATT&CK targets covered by typed-tool output; 1 target(s) produced finding-level evidence; 5 target(s) remain blind spots

| Technique | Tactic | Status | Tools Observed | Gap / Analyst Value |
|---|---|---|---|---|
| T1014 Rootkit | Defense Evasion | blind spot | `none` | missing or untouched artifact classes: memory |
| T1055 Process Injection | Defense Evasion / Privilege Escalation | blind spot | `none` | missing or untouched artifact classes: memory |
| T1059.001 PowerShell | Execution | covered, no finding \(limited\) | `prefetch_parse` | limited coverage — not proof of absence |
| T1021.001 Remote Desktop Protocol | Lateral Movement | blind spot | `none` | missing or untouched artifact classes: evtx |
| T1078 Valid Accounts | Defense Evasion / Persistence / Privilege Escalation | covered, no finding \(limited\) | `registry_query` | limited coverage — not proof of absence |
| T1003 OS Credential Dumping | Credential Access | available, not examined | `none` | required evidence class was available but no target tool ran |
| T1105 Ingress Tool Transfer | Command and Control | covered, no finding \(limited\) | `mft_timeline` | limited coverage — not proof of absence |
| T1071.001 Web Protocols | Command and Control | finding \(CONFIRMED\) | `none` | finding-level evidence exists; preserve cited tool output |
| T1071.004 DNS | Command and Control | blind spot | `none` | missing or untouched artifact classes: network |
| T1041 Exfiltration Over C2 Channel | Exfiltration | blind spot | `none` | missing or untouched artifact classes: network |
| T1547.001 Registry Run Keys / Startup Folder | Persistence / Privilege Escalation | covered, no finding \(limited\) | `mft_timeline, prefetch_parse, registry_query` | limited coverage — not proof of absence |
| T1053.005 Scheduled Task | Execution / Persistence / Privilege Escalation | covered, no finding \(limited\) | `registry_query` | limited coverage — not proof of absence |




## Evidence Coverage

1/5 artifact classes touched; 1/5 directly available from supplied evidence

| Artifact Class | Available | Touched | Tools | Confidence Impact |
|---|:---:|:---:|---|---|
| memory | no | no | `none` | not a memory image; no live-process evidence |
| evtx | no | no | `none` | no event log supplied in this single-evidence run |
| disk/filesystem | yes | yes | `disk_extract_artifacts, disk_mount, mft_timeline, prefetch_parse, registry_query` | disk image registered; deep filesystem parsing requires mounted artifacts |
| network | no | no | `none` | no PCAP, Zeek, firewall, DNS, or proxy logs supplied |
| velociraptor | no | no | `none` | no Velociraptor collection supplied |






## Analysis Coverage by Domain

This table shows which DFIR analysis domains the typed tools exercised on the supplied evidence. Coverage is scope, not assurance.

| Domain | Status | Artifacts Seen | Tools Run | Data Sources | Gaps |
|---|---|---|---|---|---|
| Host &amp; Endpoint Forensics | automated | disk/filesystem | `disk_extract_artifacts, mft_timeline, prefetch_parse, registry_query` | DS0009, DS0022, DS0024 | none |
| Endpoint Telemetry &amp; Live Response | not_covered | none | `none` | none | missing or untouched artifact classes: velociraptor |
| Malware Analysis &amp; Triage | partial | disk/filesystem | `none` | none | missing or untouched artifact classes: memory |
| Memory Forensics | not_covered | none | `none` | none | missing or untouched artifact classes: memory |
| Network Forensics | not_covered | none | `none` | none | missing or untouched artifact classes: network, no PCAP, Zeek, proxy, DNS, firewall, or NetFlow telemetry supplied |
| Windows Event &amp; Account Analysis | not_covered | none | `none` | none | missing or untouched artifact classes: evtx |

**Overclaim guardrails applied:** covered_no_finding is limited coverage, not a clean/cleared claim, Domain coverage describes triage/orchestration across the typed tools that ran, not certified-analyst judgment, visual exhibits do not create findings or upgrade confidence, execution claims still require at least two artifact classes








## Figures

Visual exhibits are generated from parsed tool outputs. They support cited findings but do not replace `tool_call_id`-backed evidence or upgrade confidence by themselves.

### cain.exe executed on this host
* Card: `evidence-card-001`
* Linked findings: `f-B-prefetch-cain-exe`
* Tool call: `tc-010`
* Source records: `prefetch_parse:561`
* Confidence: `CONFIRMED`
* Citations: `CITE-MITRE-ATTACK-DATASOURCES`
* Why suspicious/relevant: This observable is relevant because finding 'f-B-prefetch-cain-exe' is backed by parsed tool output 'tc-010' and should be interpreted with the cited artifact and source caveats.
* Snippet: `cain.exe executed on this host: Windows Prefetch records its execution and the UserAssist key \(per-user GUI execution\) records the same binary. Two independent artifact classes \(prefetch + registry/UserAssist\) corroborate execution.`
* Caveats: Visual exhibit supports the cited finding but does not replace parsed tool output.

### cain25b45.exe executed on this host
* Card: `evidence-card-002`
* Linked findings: `f-B-prefetch-cain25b45-exe`
* Tool call: `tc-011`
* Source records: `prefetch_parse:511`
* Confidence: `CONFIRMED`
* Citations: `CITE-MITRE-ATTACK-DATASOURCES`
* Why suspicious/relevant: This observable is relevant because finding 'f-B-prefetch-cain25b45-exe' is backed by parsed tool output 'tc-011' and should be interpreted with the cited artifact and source caveats.
* Snippet: `cain25b45.exe executed on this host: Windows Prefetch records its execution and the UserAssist key \(per-user GUI execution\) records the same binary. Two independent artifact classes \(prefetch + registry/UserAssist\) corroborate execution.`
* Caveats: Visual exhibit supports the cited finding but does not replace parsed tool output.

### ethereal-setup-0.10.6.exe executed on this host
* Card: `evidence-card-003`
* Linked findings: `f-B-prefetch-ethereal-setup-0-10-6-exe`
* Tool call: `tc-020`
* Source records: `prefetch_parse:559`
* Confidence: `CONFIRMED`
* Citations: `CITE-MITRE-ATTACK-DATASOURCES`
* Why suspicious/relevant: This observable is relevant because finding 'f-B-prefetch-ethereal-setup-0-10-6-exe' is backed by parsed tool output 'tc-020' and should be interpreted with the cited artifact and source caveats.
* Snippet: `ethereal-setup-0.10.6.exe executed on this host: Windows Prefetch records its execution and the UserAssist key \(per-user GUI execution\) records the same binary. Two independent artifact classes \(prefetch + registry/UserAssist\) corroborate e`
* Caveats: Visual exhibit supports the cited finding but does not replace parsed tool output.

### ethereal.exe executed on this host
* Card: `evidence-card-004`
* Linked findings: `f-B-prefetch-ethereal-exe`
* Tool call: `tc-021`
* Source records: `prefetch_parse:562`
* Confidence: `CONFIRMED`
* Citations: `CITE-MITRE-ATTACK-DATASOURCES`
* Why suspicious/relevant: This observable is relevant because finding 'f-B-prefetch-ethereal-exe' is backed by parsed tool output 'tc-021' and should be interpreted with the cited artifact and source caveats.
* Snippet: `ethereal.exe executed on this host: Windows Prefetch records its execution and the UserAssist key \(per-user GUI execution\) records the same binary. Two independent artifact classes \(prefetch + registry/UserAssist\) corroborate execution.`
* Caveats: Visual exhibit supports the cited finding but does not replace parsed tool output.

### lookatlan.exe executed on this host
* Card: `evidence-card-005`
* Linked findings: `f-B-prefetch-lookatlan-exe`
* Tool call: `tc-038`
* Source records: `prefetch_parse:545`
* Confidence: `CONFIRMED`
* Citations: `CITE-MITRE-ATTACK-DATASOURCES`
* Why suspicious/relevant: This observable is relevant because finding 'f-B-prefetch-lookatlan-exe' is backed by parsed tool output 'tc-038' and should be interpreted with the cited artifact and source caveats.
* Snippet: `lookatlan.exe executed on this host: Windows Prefetch records its execution and the UserAssist key \(per-user GUI execution\) records the same binary. Two independent artifact classes \(prefetch + registry/UserAssist\) corroborate execution.`
* Caveats: Visual exhibit supports the cited finding but does not replace parsed tool output.

### mirc.exe executed on this host
* Card: `evidence-card-006`
* Linked findings: `f-B-prefetch-mirc-exe`
* Tool call: `tc-040`
* Source records: `prefetch_parse:542`
* Confidence: `CONFIRMED`
* Citations: `CITE-MITRE-ATTACK-DATASOURCES, CITE-ZEEK-LOGS`
* Why suspicious/relevant: This observable is relevant because finding 'f-B-prefetch-mirc-exe' is backed by parsed tool output 'tc-040' and should be interpreted with the cited artifact and source caveats.
* Snippet: `mirc.exe executed on this host: Windows Prefetch records its execution and the UserAssist key \(per-user GUI execution\) records the same binary. Two independent artifact classes \(prefetch + registry/UserAssist\) corroborate execution.`
* Caveats: Visual exhibit supports the cited finding but does not replace parsed tool output.

### mirc612.exe executed on this host
* Card: `evidence-card-007`
* Linked findings: `f-B-prefetch-mirc612-exe`
* Tool call: `tc-041`
* Source records: `prefetch_parse:517`
* Confidence: `CONFIRMED`
* Citations: `CITE-MITRE-ATTACK-DATASOURCES, CITE-ZEEK-LOGS`
* Why suspicious/relevant: This observable is relevant because finding 'f-B-prefetch-mirc612-exe' is backed by parsed tool output 'tc-041' and should be interpreted with the cited artifact and source caveats.
* Snippet: `mirc612.exe executed on this host: Windows Prefetch records its execution and the UserAssist key \(per-user GUI execution\) records the same binary. Two independent artifact classes \(prefetch + registry/UserAssist\) corroborate execution.`
* Caveats: Visual exhibit supports the cited finding but does not replace parsed tool output.

### netstumbler.exe executed on this host
* Card: `evidence-card-008`
* Linked findings: `f-B-prefetch-netstumbler-exe`
* Tool call: `tc-047`
* Source records: `prefetch_parse:555`
* Confidence: `CONFIRMED`
* Citations: `CITE-MITRE-ATTACK-DATASOURCES`
* Why suspicious/relevant: This observable is relevant because finding 'f-B-prefetch-netstumbler-exe' is backed by parsed tool output 'tc-047' and should be interpreted with the cited artifact and source caveats.
* Snippet: `netstumbler.exe executed on this host: Windows Prefetch records its execution and the UserAssist key \(per-user GUI execution\) records the same binary. Two independent artifact classes \(prefetch + registry/UserAssist\) corroborate execution.`
* Caveats: Visual exhibit supports the cited finding but does not replace parsed tool output.

### hypothesis
* Card: `evidence-card-009`
* Linked findings: `f-B-prefetch-netstumblerinstaller-0-4-0-ex`
* Tool call: `tc-048`
* Source records: `prefetch_parse:553`
* Confidence: `HYPOTHESIS`
* Citations: `CITE-MITRE-ATTACK-DATASOURCES`
* Why suspicious/relevant: This observable is relevant because finding 'f-B-prefetch-netstumblerinstaller-0-4-0-ex' is backed by parsed tool output 'tc-048' and should be interpreted with the cited artifact and source caveats.
* Snippet: `hypothesis: Windows Prefetch contains NETSTUMBLERINSTALLER_0_4_0.EX with run_count=1; NetStumbler wireless discovery tool is a NIST Hacking Case triage lead. Treat this as a disk-artifact lead that needs corroboration before any standalone `
* Caveats: Visual exhibit supports the cited finding but does not replace parsed tool output., HYPOTHESIS confidence requires additional artifact corroboration.




## References

| Citation ID | Title | URL | Supports |
|---|---|---|---|
| `CITE-MITRE-ATTACK-DATASOURCES` | MITRE ATT&amp;CK Data Sources | https://attack.mitre.org/datasources/ | ATT&amp;CK data-source coverage mapping |
| `CITE-MITRE-T1003-001` | MITRE ATT&amp;CK T1003.001 LSASS Memory | https://attack.mitre.org/techniques/T1003/001/ | LSASS credential-dumping interpretation |
| `CITE-MITRE-T1014` | MITRE ATT&amp;CK T1014 Rootkit | https://attack.mitre.org/techniques/T1014/ | DKOM/rootkit process-view divergence interpretation |
| `CITE-NIST-800-61R2` | NIST SP 800-61 Rev. 2 Computer Security Incident Handling Guide | https://csrc.nist.gov/pubs/sp/800/61/r2/final | separation of evidence, analysis, response actions, and gaps |
| `CITE-PLASO` | Plaso/log2timeline documentation | https://plaso.readthedocs.io/ | multi-source forensic timeline normalization |
| `CITE-TIMESKETCH` | Timesketch documentation | https://timesketch.org/ | analyst-oriented forensic timeline review |
| `CITE-VOLATILITY3` | Volatility 3 documentation | https://volatility3.readthedocs.io/ | memory plugin output and process-view validation |
| `CITE-ZEEK-LOGS` | Zeek log documentation | https://docs.zeek.org/en/current/logs/index.html | network log and protocol-semantic coverage |
| `CITE-VELOCIRAPTOR-ARTIFACTS` | Velociraptor artifact documentation | https://docs.velociraptor.app/docs/artifacts/ | artifact-based endpoint collection |
| `CITE-SIGMAHQ` | SigmaHQ rules repository | https://github.com/SigmaHQ/sigma | structured log detection rules as triage leads |
| `CITE-HAYABUSA` | Hayabusa repository | https://github.com/Yamato-Security/hayabusa | Windows EVTX timeline and hunting output |
| `CITE-CAPA` | capa repository | https://github.com/mandiant/capa | malware capability triage limits |






## Recommended Analyst Actions

| Priority | Action | Why | Based On | Expected Evidence |
|---|---|---|---|---|
| P2 | Collect Security, Sysmon, and PowerShell Operational EVTX and rerun EVTX/Hayabusa analysis. | Current findings lack event-log corroboration for logon, process creation, and PowerShell execution hypotheses. | evtx_gap | Security 4624/4625/4688, Sysmon 1/3/7/10/11, PowerShell 4103/4104 |
| P2 | Use the disk artifact summary to pivot between Prefetch, Registry, MFT, USN, EVTX, and YARA-target rows without upgrading single-source execution claims. | Extracted disk artifacts are now summarized as leads and timeline context; execution wording still needs two artifact classes and cited tool_call_id evidence. | disk_artifact_summary | Correlated Prefetch run times, Registry LastWrite, MFT/USN timestamps, EVTX records, and YARA hits |
| P3 | Acquire DNS, proxy, firewall, NetFlow, or PCAP telemetry to test C2 and exfiltration hypotheses. | Network telemetry was not supplied or parsed in this run, so exfiltration and command-and-control coverage remains a blind spot. | network_gap | DNS queries, proxy URLs, firewall sessions, PCAP, Velociraptor network collection |
| P3 | Close ATT&amp;CK blind spots before making closure decisions. | The coverage matrix identifies target techniques with no supporting artifact class in this run. | T1014, T1055, T1021.001, T1071.004, T1041 | Additional evidence classes mapped in attack_coverage.targets\[\].artifact_classes |
| P4 | Pivot from the first and last normalized timeline events into adjacent artifact classes. | Temporal clustering often exposes execution chains that a single artifact class cannot prove alone. | timeline | timeline.csv plus adjacent EVTX, Prefetch, MFT, and network events |




## Reproducibility Appendix

Verifier replay artifacts record whether each cited tool call reproduced the audited output hash. They do not change Track 3b severity policy.

| Finding | Tool | Drift class | Match | Expected SHA | Actual SHA |
|---|---|---|:---:|---|---|
| f-B-prefetch-cain-exe | `prefetch_parse` | `exact_match` | yes | `b2e14c91aaa2` | `b2e14c91aaa2` |
| f-B-prefetch-cain25b45-exe | `prefetch_parse` | `exact_match` | yes | `76ae3ea8345e` | `76ae3ea8345e` |
| f-B-prefetch-ethereal-setup-0-10-6-exe | `prefetch_parse` | `exact_match` | yes | `eba2574fcda2` | `eba2574fcda2` |
| f-B-prefetch-ethereal-exe | `prefetch_parse` | `exact_match` | yes | `cf2fcec98191` | `cf2fcec98191` |
| f-B-prefetch-lookatlan-exe | `prefetch_parse` | `exact_match` | yes | `9a10d59745b3` | `9a10d59745b3` |
| f-B-prefetch-mirc-exe | `prefetch_parse` | `exact_match` | yes | `b035f2359a05` | `b035f2359a05` |
| f-B-prefetch-mirc612-exe | `prefetch_parse` | `exact_match` | yes | `b36f1b611dd3` | `b36f1b611dd3` |
| f-B-prefetch-netstumbler-exe | `prefetch_parse` | `exact_match` | yes | `c912d93baf9b` | `c912d93baf9b` |
| f-B-prefetch-netstumblerinstaller-0-4-0-ex | `prefetch_parse` | `exact_match` | yes | `80850ecc397c` | `80850ecc397c` |


---

## Chain of Custody

![Chain of custody](figures/chain_of_custody.png)

---

## Integrity Verification

This investigation produced a `run.manifest.json` that any third party can
verify offline from the VERDICT repository using the manifest verification
library or the `manifest_verify` MCP tool. There is no standalone
`manifest_verify` shell command in this repo.

```bash
uv run --directory services/agent python -c "from pathlib import Path; from findevil_agent.crypto.manifest import verify_manifest; print(verify_manifest(Path('PATH/TO/run.manifest.json'), audit_log_path=Path('PATH/TO/audit.jsonl')).model_dump_json(indent=2))"
# returns overall=true if the audit chain and Merkle root validate and signature metadata is present
```

The verifier rebuilds:
1. The audit chain by walking `prev_hash` SHA-256 links (catches backdated edits).
2. The Merkle tree from the manifest's `leaves[]` array (catches selective redaction).
3. The signature bundle metadata recorded in the manifest. Full signature and
   transparency-log validation must be performed separately when a production
   signer is used.

A tamper test against this manifest's `merkle_root_hex` was not run automatically.
To execute it, copy the manifest, overwrite `merkle_root_hex` with `ff` repeated
32 times, then run the same Python verification command against the tampered copy.

```bash
python -c "import shutil;shutil.copyfile('run.manifest.json','run.manifest.tamper.json')"
python -c "import json,pathlib;p=pathlib.Path('run.manifest.tamper.json');d=json.loads(p.read_text());d['merkle_root_hex']='ff'*32;p.write_text(json.dumps(d,indent=2,sort_keys=True))"
uv run --directory services/agent python -c "from pathlib import Path; from findevil_agent.crypto.manifest import verify_manifest; print(verify_manifest(Path('PATH/TO/run.manifest.tamper.json'), audit_log_path=Path('PATH/TO/audit.jsonl')).model_dump_json(indent=2))"
```

---

*Produced by `find-evil-auto` (the VERDICT automated investigation orchestrator).
The cryptographic attestation values shown are the actual outputs of this run; every
quantitative claim above is independently verifiable from the artifacts in this
directory (`audit.jsonl`, `run.manifest.json`, `verdict.json`). The automated
QA / expert-signoff gates for this run are in the companion `REPORT-internal` packet.*
