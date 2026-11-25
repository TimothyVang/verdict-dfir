# False-Positive Prevention — Operator's Guide

VERDICT has **three architectural layers** that filter false positives before findings reach the analyst, plus **four operational habits** the analyst applies on top. This document explains both.

---

## The three architectural layers (built in)

### Layer 1 — Tool selection

Some DFIR tools are intrinsically more FP-prone than others. The agent's tool surface is curated to favor low-FP tools, and the playbook (`agent-config/PLAYBOOK.md`) names which tool to reach for in which situation.

| Tool | FP risk | Mitigation in the agent |
|---|---|---|
| `evtx_query` | Very low — exact byte-level Event Log records | None needed |
| `mft_timeline` | Low — `$SI` vs `$FN` MAC-time comparison detects timestomping; agent surfaces both | Built in |
| `prefetch_parse` | Low for *presence*; medium for *absence* — Prefetch can be disabled (`EnablePrefetcher=0`) | Caveat surfaced in tool description per `MEMORY.md` |
| `registry_query` | Low for raw values; medium for *interpretation* (Run keys can be benign software) | Pool A reads and Pool B re-reads with different bias |
| `usnjrnl_query` | Low for events; medium for *gaps* — USN journal is **circular**; gaps are normal | `MEMORY.md` caveat surfaces this |
| `yara_scan` | **High** if community rules used unfiltered; low if YARA-Forge "core" tier only | Agent prefers `core` tier; `extended` tier requires corroboration |
| `hayabusa_scan` | Medium — Sigma rules are tuned conservatively but still flag legit admin activity | Multi-level filter (`min_level: medium` cuts most FPs); rule hits are triage leads until corroborated |
| `vol_pslist` | Medium — *fooled by* DKOM, paging artifacts, kernel build mismatch | Cross-reference with `vol_psscan`; divergence is itself the finding |
| `vol_malfind` | Medium — *misses* hidden injections in DKOM-affected memory | Same — cross-reference with raw YARA scan over `.img` |
| `vel_collect` | Varies by artifact | Velociraptor's per-artifact tuning |

**Rule of thumb:** treat `pslist`/`malfind`/`yara` results as **leads** unless corroborated. Treat `evtx`/`mft`/`registry` as **facts**.

### Layer 2 — Agent-level filtering (ACH dual-pool + correlator)

Three steps remove FPs before the analyst sees the verdict:

1. **`detect_contradictions`** fires when Pool A and Pool B disagree on a finding citing the same `tool_call_id`. The analyst sees the disagreement *before* the judge merges. A finding that BOTH pools agree on is much stronger than one only Pool A claims.
2. **`judge_findings`** applies credibility-weighted merging. A pool that has produced corroborating CONFIRMED findings earlier in the run gains credibility weight; a pool that produced only HYPOTHESIS-tier output gets downweighted.
3. **`correlate_findings`** enforces the SOUL.md ≥2-artifact-class rule: any "this binary RAN" claim must be supported by ≥2 distinct evidence types (Prefetch + Amcache, EDR + memory, EVTX 4688 + MFT, etc.). Single-source claims auto-downgrade `CONFIRMED → INFERRED → HYPOTHESIS`.

### Layer 3 — Confidence taxonomy (epistemic hierarchy)

Every finding carries one of three confidence levels, defined in `agent-config/SOUL.md`:

| Level | Meaning | Action |
|---|---|---|
| `CONFIRMED` | Direct tool output, verified, and corroborated by ≥2 artifact classes if it's an execution claim | Trust; report as fact |
| `INFERRED` | ≥2 confirmed facts logically combined, but no direct tool output asserts the conclusion | Trust with caveat; flag in report |
| `HYPOTHESIS` | Single-source or speculative; the agent prefixes the description with the literal word "hypothesis:" | **Do not act on this without further investigation** |

The agent's `verifier` re-runs the cited tool calls on every finding before merge. A finding whose tool-call output disagrees with the original gets downgraded one tier. Findings without a `tool_call_id` are vetoed entirely.

---

## The four operational habits (analyst applies on top)

### 1. Filter to CONFIRMED-only when triaging

The other tiers are *leads*, not *facts*. When you first read the verdict, look only at CONFIRMED findings. Come back to INFERRED/HYPOTHESIS when you have time to verify them individually.

In the verdict, this is one line:
```bash
jq '.findings[] | select(.confidence == "CONFIRMED") | .description' verdict.json
```

### 2. Read the contradiction surface before the verdict

The judge's `merged` output is a *resolution* of disagreements, not the underlying truth. If `detect_contradictions` returned ≥1, look at the raw Pool A vs Pool B findings before trusting the merged result.

Pattern in the audit log: search for `kind: "contradiction_resolved"` and read the `pool_a` vs `pool_b` description for each. (The in-process wire event is named `ContradictionFound`, but the committed audit-chain record kind is `contradiction_resolved`.)

### 3. Cross-corroborate execution claims by hand

If the agent says "STAGER.EXE ran" based on Prefetch alone, that's INFERRED-tier. Before treating it as fact, run yourself:

* `mft_timeline` on `$MFT` — does the file *exist* on disk? When was it created/modified per `$SI` vs `$FN`?
* `evtx_query` on `Security.evtx` — is there a 4688 (process create) or 4624 (logon) for the time the Prefetch claims it ran?
* `yara_scan` on the binary — does it match a known-bad rule?

If yes to ≥2 of those, upgrade your confidence. If no, leave it as INFERRED.

### 4. Run against the synthetic-benign baseline first

Before running the agent against real evidence, run it against `goldens/synthetic-benign/` (a clean Windows install with no tradecraft). The expected output is **zero findings, verdict NO_EVIL**. If the agent produces any findings against the benign baseline, those represent your environment's *false-positive floor* — file the rule that fired as a known FP and either tune it out or flag any matches against real evidence as suspect.

The benign baseline is the single highest-leverage thing you can do to calibrate the agent. Don't skip it.

---

## Specific FP traps and how to avoid them

### vol_pslist returns 0 → "rootkit!"

**Don't jump.** pslist=0 has at least four benign causes:

1. The memory dump is truncated/corrupt (only first N pages captured)
2. The kernel build doesn't match Vol3's symbol pack (e.g., custom Windows Server build)
3. Paging tables are inconsistent (host was suspended, not powered down before capture)
4. Vol3 version mismatch (a Vol3 minor-version bump can break the `_KPCR` schema lookup)

The DKOM hypothesis is the *fifth* possibility. Before claiming DKOM in your report:

* Run `vol_psscan` — if it also returns 0, the dump is corrupt, not DKOM.
* Run `vol windows.info` — if symbols load and DTB is reasonable, the kernel is intact.
* Run `vol_psxview` — now in the typed MCP surface — to cross-reference process-listing methods. DKOM shows as inconsistency between `pslist` and `psscan` columns; corruption shows as inconsistency across broader views.

The `2026-04-26-srl2018-dc-investigation.md` report is the cautionary example because we *did*
jump, and the correction is in the open: the original run headlined `vol_psscan` = 124 vs
`vol_pslist` = 0 as **confirmed DKOM** — it looks exactly like T1014 at first glance. Post-run
expert review caught the over-claim: `KeNumberProcessors`=0, core OS singletons (e.g. `System`)
recovered *only* by `psscan`, and a duplicate `System` EPROCESS — and a rootkit cannot produce
those. On that image the divergence is an **acquisition smear / kernel-global read failure**, not
T1014, so the report was reconciled to **HYPOTHESIS** (commit `cd075c9`; see the `vol_pslist returns 0`
section above and the [accuracy report](accuracy-report.md)'s Calibration Rules). The escalation checklist above and `vol_psxview`
in the typed surface exist *because of* that miss: a T1014 claim needs ≥2 artifact classes, and
process-list divergence alone — once an acquisition fault is on the table — does not clear that
bar.

### vol_malfind flags a VAD → "injected shellcode!"

**Don't jump.** `vol_malfind` flags any committed, executable, private VAD with no
mapped file — a heuristic that fires on *benign* runtime code far more often than on a
real implant. Before calling a malfind hit injection, classify the region against these
benign classes (deterministic — read the disasm, no LLM needed):

1. **JIT / managed runtimes.** .NET CLR, JScript, Java, and V8 allocate RX private
   memory and emit code there by design. Tell-tales: an MZ/PE header is *absent* (real
   reflective loaders usually carry one), the bytes disassemble as well-formed
   prologues / `jmp` tables, and the owner is a known runtime host (`w3wp.exe`,
   `powershell.exe`, a managed-`.NET` process).
2. **Control-Flow Guard (CFG) thunks / trampolines.** Small RX stubs the loader writes
   for CFG/retpoline are private+executable but short, repetitive, and adjacent to a
   mapped image.
3. **Defender / AV emulation pages.** `MsMpEng.exe` and other scanners allocate RX
   scratch to emulate samples; a malfind hit *inside the scanner* is the scanner, not
   the sample.

A genuine injection signal is the *opposite*: an MZ header in an unexpected location,
egg-hunter / GetPC shellcode stubs, or a trampoline overwriting the head of a legit API.
Treat a bare malfind hit as a **lead** (its tool reliability is ~0.72, per DeepSIFT's
published number): corroborate with a second artifact class — Prefetch/Amcache
execution, an EDR/Sysmon `CreateRemoteThread`, or a `yara_scan` hit on the dumped region
— before any execution/injection claim. The ≥2-artifact-class gate already blocks a
single-class malfind CONFIRMED; this checklist is the analyst reasoning behind that gate.

> **Why this is documentation, not a verdict-time auto-classifier.** A classifier that
> *downgrades* malfind findings programmatically would need real disasm ground truth to
> avoid the opposite error (silencing a real implant); without that corpus it is more
> likely to mis-fire than help. The corroboration discipline above + the ≥2-class gate
> already enforce the right outcome, so this stays analyst guidance — adopted from the
> field (DeepSIFT/project-mantis "benign-discount") without putting a speculative
> classifier on the custody path.

### Hayabusa flags legitimate admin activity

Default Sigma rules flag PowerShell `Invoke-Expression`, `runas` elevation, and other admin tools. These are rare on workstations but routine on RD servers and admin workstations. Mitigation:

* Run with `min_level: high` for noisy Sigma rules.
* Pair every Hayabusa finding with `evtx_query` on the same time window — if Hayabusa flags PowerShell at T0, run `evtx_query` for `Microsoft-Windows-PowerShell/Operational` at T0 and read the actual command. Legitimate admin commands usually don't include obfuscation, b64-encoded payloads, or download cradles.
* Do not treat the rule hit itself as proof of compromise. Confirm the underlying EVTX record and look for a second artifact class before upgrading the claim.

### YARA matches a common byte pattern

YARA rules for "any binary calling `WinExec`" or "binary contains string 'cmd.exe'" will match legitimate Windows binaries. Mitigation:

* Use only `core` tier rules (curated low-FP). Avoid `extended`/`community` tiers without corroboration.
* If a YARA hit is on a Microsoft-signed binary, **the hit is almost certainly a FP** — the rule wasn't tuned to require non-Microsoft signing. Pair with `mft_timeline` for the file: if it's in `\Windows\System32\` and unmodified since OS install, it's legitimate.

### MFT shows files in odd paths

MFT records *all* filenames the entry has ever had. A file moved between directories has multiple `$FN` records. This is normal — not a sign of evasion. Mitigation: read the `is_allocated` field; deleted files have it false.

### EVTX Logon Type 3 looks like remote attacker

Type 3 = Network logon (SMB share, IPC$, etc.). Routine in Windows networks. Mitigation: pair with source IP — if internal RFC1918, almost always benign. Type 10 (RemoteInteractive / RDP) is the one to scrutinize.

### Fleet cross-host correlation: enterprise AV looks like lateral movement

When `fleet_correlate.py` runs across a fleet of enterprise hosts, the McAfee/Trellix endpoint stack (`masvc.exe`, `macmnsvc.exe`, `mcshield.exe`, `mfeann.exe`, `FireSvc.exe`, `HipMgmt.exe`, `ManagementAgent.exe`, etc.) appears on *every* host — at first glance a textbook lateral-movement pattern (same uncommon binary, many machines). It is not. It's the EDR product the organization deployed. Same for VMware Tools (`vmtoolsd.exe`, `VGAuthService.exe`, `vmacthlp.exe`) on virtualized fleets, and the long tail of standard Windows infrastructure (`msdtc.exe`, `dwm.exe`, `LogonUI.exe`, `userinit.exe`, `MemCompression`).

Mitigation: `scripts/fleet_correlate.py` ships a `COMMON_WIN_PROCS` set covering the major enterprise endpoint stacks (McAfee/Trellix, Symantec, CrowdStrike, SentinelOne) plus VMware Tools and Microsoft Defender. Volatility-truncated names (the `ImageFileName` field on EPROCESS is 16 bytes, so `VGAuthService.exe` surfaces as `VGAuthService.`) are matched via a 14-char-truncation normalizer so the filter actually catches them. **What is deliberately NOT filtered:** Sysinternals tools (`Autorunsc.exe`, `psexec.exe`, `procdump.exe`) — cross-host runs of those *are* suspicious, even though the IR team's own forensic sweeps look identical to attacker tooling. The list is in `scripts/fleet_correlate.py` and is the single source of truth that the per-host orchestrator (`scripts/find_evil_auto.py`) imports at runtime to keep the two filters from drifting.

If your fleet ships a different enterprise stack (e.g. CrowdStrike + Microsoft Defender for Endpoint), expect to see those binaries surface as cross-host correlations until you add them to `COMMON_WIN_PROCS`. Don't dismiss them — confirm they're the products you deployed, *then* add them. Adding a binary to the FP list is itself an investigative claim ("we know what this is"); make the claim deliberately.

Every cross-host correlation and temporal cluster the fleet rollup emits carries `epistemic_label: "HYPOTHESIS"` (and the narrative carries the `hypothesis:` prefix) — the same SOUL.md vocabulary the per-host pipeline uses. A fleet correlation is a lead an analyst confirms or kills, never a conclusion the rollup asserts.

---

## What to do when you suspect a false positive

1. **Tag the finding** in your notes as "FP-suspected".
2. **Re-run the cited tool call** with `verify_finding` MCP tool — does the original tool output match what the finding claims?
3. **Cross-corroborate** with one or two artifacts the SOUL.md ≥2 rule would require for upgrade. If they don't show up, the FP suspicion is justified — leave it as HYPOTHESIS in your report.
4. **File a rule note** in `agent-config/MEMORY.md` if the FP is reproducible — future runs benefit from your finding.

---

## What this document is NOT

* Not a substitute for analyst judgment. The agent reduces friction; it doesn't replace expertise.
* Not a complete list of FPs. Every DFIR investigation surfaces new edge cases.
* Not a guarantee. The architecture *reduces* FP rates; it doesn't drive them to zero.

The agent is honest about its limitations by design: every completed run writes
`coverage_manifest.json` and report limitations. When in doubt, downgrade and document.
