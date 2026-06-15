# MEMORY.md — Tier 1 (always loaded)

## Artifact semantics (common misreads)
- Amcache `LastModified` is catalog-registration time, NOT execution time.
- ShimCache (AppCompatCache) is insertion/append-ordered, NOT LRU — position is not recency of use (Mandiant "Caching Out"). Presence != execution; the recorded timestamp is the file's $SI mod-time, and the exec/insert flag was removed on Win10/Server2016+.
- Prefetch disabled on SSDs by some builds/GPOs — absence is not evidence of absence.
- `$MFT` $SI timestamps are trivially stompable (NtSetInformationFile); prefer $FN for tamper detection, but $FN is harder-not-immune (SetMACE chains $SI edits with moves) — cross-validate with $LogFile/$UsnJrnl/Prefetch/LNK.
- UsnJrnl wraps; gaps are normal, not suspicious by themselves.
- EVTX EID 4624 Type 3 = network logon; Type 10 = RemoteInteractive (RDP).
- Sysmon EID 1 ProcessGuid is the correlation key, not PID.
- Sigma/Hayabusa hits are triage leads until the raw EVTX and a corroborating artifact class support the claim.
- Memory-only process or injection evidence does not prove disk execution or exfiltration.
- `covered_no_finding` means scoped tools ran without qualifying evidence; it is not clean, cleared, disproven, or absence of the technique.
- `attck_practitioner_coverage` DFIR analysis-domain lanes describe supplied-evidence/tool coverage only; they do not automate certified-analyst judgment.
- Normalized timeline rows are context or finding support, not findings by themselves.
- Visual evidence cards, screenshots, snippets, and charts support cited tool output; they never replace `tool_call_id` evidence or upgrade confidence alone.
- Auto disk mode is custody-only unless mounted artifacts are supplied; `case_open` alone is an analysis limitation, not a Finding or `NO_EVIL` support.
- Malware triage summaries are IOC/string/memory-region leads only; malfind/YARA previews do not identify who operated code or prove execution by themselves.
- EID 1102 (Security log cleared) is not automatically incident anti-forensics. A clear under a **template/default hostname** (e.g. `WIN10-TEST`, `WINDOWS2012R2`, `MICROSO-*`) by the **local Administrator** at image-build time is range/golden-image build residue; only a clear by a **domain account** at incident time on the deployed (FQDN, domain-joined) host is incident-relevant. Read the `<Computer>` name, the timestamp, and the actor from the `SubjectUserName` field under LogFileCleared user data before classifying. Several "host" images in a corpus may be clones of one template (identical build-time clear) — do not count them as N separate clearings.
- `vol_malfind` RWX VADs are high-false-positive. An RWX private region with **no MZ/PE header and no real code** (zero-filled or allocator-tagged scratch, common in Office/Outlook/.NET-JIT) is a benign allocation, not injection. Dump and inspect/YARA the region before reporting; malfind alone is a lead.
- vol active-list plugins (`vol_pslist`/pstree/`vol_malfind`/banners) returning 0 while `vol_psscan`/`vol_psxview` recover processes — with `KeNumberProcessors=0` / garbage `KdVersionBlock` in `windows.info` — indicates **broken virtual-address translation** (often a truncated/incomplete capture), NOT a missing-symbol problem (symbol download won't fix it). There, `malfind=0` means "not analyzable," not clean; pool-scanning is the reliable coverage. Distinguish this from a true DKOM divergence (which has a healthy `windows.info`).

## Attacker tradecraft priors
- LOLBins to check first: rundll32, regsvr32, mshta, wmic, certutil, bitsadmin.
- Scheduled Tasks in `\Microsoft\Windows\` namespace are a classic hiding spot.
- Run/RunOnce, Services, WMI event subscriptions, Image File Execution Options = persistence top-5.

## Reporting conventions
- All timestamps UTC, ISO-8601, trailing Z.
- Hashes: SHA-256 preferred, MD5 only when tool-limited.
- Never assert attribution.
