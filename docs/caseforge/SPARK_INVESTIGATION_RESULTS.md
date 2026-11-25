# Spark investigation results — `win-lateral-movement`, run `auto-95f54362`

**Scope first, before any win:** this was a **custody-verified local run on the DGX
Spark**, but its verdict came from caseforge's **deterministic EVTX fallback**, not a
complete sealed gpt-oss agent run, and it **read only 1 of the case's 2 EVTX files**.
The verdict is **INDETERMINATE** — which is the *policy default for single-source
EVTX*, so a "correct" verdict here is **not** evidence the analysis was complete. It is
a real, hash-chained local run; it is **not** a confirmed intrusion and **not** a
full-battery detection.

Machine-readable scorecard: [`spark-scorecard-auto-95f54362.json`](./spark-scorecard-auto-95f54362.json).
Why the gpt-oss agent run never sealed (forcing the fallback) and how to fix it:
[`LOCAL_LLM_SEAL_FAILURE.md`](./LOCAL_LLM_SEAL_FAILURE.md).

## What ran

| Field | Value |
|---|---|
| Host | DGX Spark (GB10, `aarch64`) — entirely on-box, no VM, no network hop |
| Model endpoint | local Ollama `http://localhost:11434/v1` (GB10 GPU) |
| Route / privacy | `local-ollama` / `local-only` |
| Case | `win-lateral-movement` (single host `WIN-77LTAPHIQ1R.example.corp`) |
| Run id / case id | `auto-1783532826` / `auto-95f54362-…` |
| Started | 2026-07-08T17:47:06Z |

### Custody receipt (verified)

`manifest_verify.overall = true` — ed25519 signature present **and** verified,
merkle root ok, audit chain ok (21 audit records), `EXIT_CODE=0`.
`customer_releasable = false`, `packet_state = EXPERT_REVIEW_DRAFT` (correct for an
INDETERMINATE draft). These are quoted from `manifest_verify.json` and
`run.manifest.json` on the run directory.

## Observed vs. expected techniques

Ground truth is the case README's chain: network logons → remote WMI process
execution → service-install persistence, one service carrying the SpoolFool signature.

| Expected | Evidence | In file | Result | Why |
|---|---|---|---|---|
| **T1078** Valid Accounts | 6× Event 4624 | `LM_WMI_…evtx` — **not read** | ❌ MISS | File never parsed; "covered" only via generic `evtx_query`→technique attribution, not a real record (spurious credit). |
| **T1047** WMI remote execution | 2× Event 4688, parent `WmiPrvSE.exe` (→`calc.exe`) | `LM_WMI_…evtx` — **not read** | ❌ MISS | Double miss: file never parsed **and** T1047 is not one of the 12 scored ATT&CK targets. |
| **T1543.003** Windows Service (persistence) | 3× Event 7045 | `LM_Remote_Service02_7045.evtx` — read | ✅ HIT | Finding `f-B-evtx-service-install`, HYPOTHESIS, timeline event emitted. |
| **CVE-2022-21999** SpoolFool (priv-esc) | 7045 service `spoolfool` w/ `cmd.exe` image | `LM_Remote_Service02_7045.evtx` — read | 🟡 PARTIAL | Recognized in narrative (`cves:[CVE-2022-21999]`, named "SpoolFool", with a hunt query) but scored **only** as T1543.003 persistence. |

**Tally:** of 4 expected techniques — **1 full hit, 1 partial, 2 misses**. Only
`T1543.003` reached `observed_techniques`. Overall run stats: 5/12 ATT&CK targets
"covered", **0 finding-level**, 7 blind spots.

## Gap diagnosis (root causes)

The two misses are **both** in the WMI EVTX file, and that file was **never ingested**:

- The run's `evtx_path` / `image_path` / `evidence_path` all resolved to a single
  file, `LM_Remote_Service02_7045.evtx`. `evtx_summary` confirms only **3 records
  seen, all Event 7045, `System` channel**.
- Parsing the unread file out-of-band (python-evtx on the Spark) confirms it holds
  **6× 4624 + 2× 4688 with `WmiPrvSE.exe → calc.exe`** — the entire lateral-movement
  half of the case was present but invisible to the run.

Root causes:

1. **RC1 — single-file evidence scoping (primary).** The case is a *directory* of 2
   EVTX files; the fallback selected exactly one. This zeroed out T1078 and T1047.
2. **RC2 — coverage manifest lacks T1047.** The `WmiPrvSE.exe`-parent remote-WMI
   signature is not among the 12 scored targets, so it earns no credit even if read.
3. **RC3 — thin tool battery on the fallback.** Only `evtx_query` ran (2 `tool_calls`
   incl. `case_open`); `hayabusa_scan` / Sigma never fired — no rule-based detection of
   WMI lateral movement or SpoolFool. This is the "gpt-oss run didn't seal → EVTX
   fallback" path: it grabs one file and runs one query.
4. **RC4 — SpoolFool technique-mapping.** The named CVE is recognized in prose but
   mapped only to persistence (T1543.003), not to its priv-esc technique (e.g. T1068).

## Remediation (proposals — not yet implemented)

1. Fallback evidence scoping should enumerate **every** file in a case directory and
   run `evtx_query` per file (or a merged query), not select one.
2. Add **T1047** (and a `WmiPrvSE.exe`-parent heuristic) to the coverage-manifest targets.
3. Run `hayabusa_scan` / Sigma on the fallback path when the binary is available.
4. Map named CVE signatures (SpoolFool) to their priv-esc technique **in addition to**
   the service-install persistence artifact.

> These four fixes would turn 2 misses into hits and 1 partial into a full hit on this
> case, but the verdict would still be **INDETERMINATE** until a second artifact class
> (disk/memory) corroborates the same host — single-source EVTX stays HYPOTHESIS by design.
