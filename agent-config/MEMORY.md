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

## Cross-artifact corroboration gates (correlator)
- The "execution needs >=2 artifact classes" rule is one member of a **family of named, severity-tagged per-technique corroboration gates** in `services/agent/findevil_agent/correlator.py`. Each gate requires an independent artifact-class pair to appear **in the Finding's own text** (other findings in the run do not corroborate); an unmet gate **downgrades one epistemic tier** (CONFIRMED->INFERRED->HYPOTHESIS) and never raises confidence.
  - `EXECUTION` (high): prefetch + a second registry-class execution artifact (Amcache/ShimCache/UserAssist), OR EDR telemetry (Sysmon/EDR/Carbon Black/CrowdStrike). Unchanged from the original gate; Amcache-only stays the catalog-registration downgrade. The opt-in benign-explanation gate still runs on this branch.
  - `LATERAL_MOVEMENT` (high): network + process, OR a remote logon-type record (EID 4624 Type 3/10). MITRE T1021/T1210/T1534/T1550/T1563/T1570.
  - `PERSISTENCE` (medium): a registry/service mechanism + execution evidence the mechanism actually ran. MITRE T1037/T1098/T1136/T1137/T1197/T1505/T1546/T1556/T1574 (the EXECUTION-prefix persistence techniques T1053/T1543/T1547 stay on the execution gate).
  - `PRIVILEGE_ESCALATION` (high): token/process + an event-log corroboration. MITRE T1055/T1068/T1078/T1134/T1484/T1548.
  - `CREDENTIAL_ACCESS` (high): a process/memory class + an event-log/token class. MITRE T1003/T1110/T1555/T1056/T1212. A dedicated `lsass-memory-access-only` ceiling caps an LSASS handle/memory-access claim to INFERRED unless a dump artifact (.dmp/minidump/procdump/comsvcs/ntds.dit) or a 4624/4688 log corroborates — access is not a completed dump.
  - `DEFENSE_EVASION` (high): the event-log class + a second non-event-log class. MITRE T1070/T1112/T1027/T1218/T1562 (e.g. EID 1102 log-clear needs a second corroborating class).
  - `COMMAND_AND_CONTROL` (high): network + process. MITRE T1071/T1090/T1095/T1102/T1572/T1219.
  - The gate family uses a dedicated `_GATE_CLASS_PATTERNS` table (incl. a `memory` class) kept separate from the evidence-weighting `_CLASS_PATTERNS`, so adding gate classes never perturbs `classify_evidence_type` scoring.
- A tactic-gate MITRE prefix takes precedence over execution-verb prose, so a persistence/lateral claim that legitimately cites execution evidence is judged against its tactic's pair. Each fired gate emits a structured WARNING record (`gate`, `severity`, `required_pairs`, `missing_classes`) for the audit trail. Deterministic, downgrade-only — never custody-altering.
- The gate family composes with the rank-4 **confidence ceiling** (also in `correlator.py`): for lateral movement the ceiling is stricter than the gate — it caps any lateral claim to INFERRED unless the destination Logon Type 3/10 is cited, so a gate-satisfying `network+process` lateral finding is still capped (and the ceiling's logon-type reason supersedes the gate's missing-class reason). Stricter rule wins; both only ever lower.
- **Adversarial corroboration prose (anti-spoof).** Class detection keys on the Finding's prose, so attacker-controlled evidence echoed into a description (a filename / registry value / log line, usually quoted) could try to manufacture a second artifact class and stop a downgrade. Two guarantees: (1) the correlator is **downgrade-only**, so no corroboration prose can ever *upgrade* a finding above its engine-set tier (that tier is anchored by the default-on fact-fidelity gate + verifier, not text); (2) opt-in `FIND_EVIL_NEUTRALIZE_QUOTED_CLASSES=1` strips quoted excerpts before class detection (`correlator_gates.strip_quoted_spans`), so a class named only inside a quote cannot satisfy the gate or inflate `classify_evidence_type`. Downgrade-only, deterministic.
- **Temporal-coupling check (`correlator_temporal.py`, opt-in `FIND_EVIL_REQUIRE_TEMPORAL_COUPLING=1`).** Demote-only: an execution-*timing* claim is downgraded one tier when cited execution-time sources (Prefetch last-run, UserAssist, Sysmon/EDR, 4688) disagree beyond 300s, or when the asserted "when it ran" rests ONLY on a catalog/registration timestamp — `$SI` MAC, ShimCache/AppCompatCache, or Amcache `LastModified` (these record cataloging/registration, never execution). Pure timestamp math (clock-wrap aware), never raises, never clears.
- **Counter-evidence FP suppressors (`correlator_suppressors.py`, opt-in `FIND_EVIL_REQUIRE_FP_SUPPRESSORS=1`).** Downgrade/HOLD/NOTE-only "does a boring explanation fit?" pass: (1) a finding whose asserted file hash is on a curated known-good whitelist (built-in trivially-benign content hashes + operator `FIND_EVIL_KNOWN_GOOD_HASHES`) is demoted; (2) a core Windows system binary in its *canonical* system path (e.g. `svchost.exe` in `\Windows\System32`) is the real OS instance → demote, but the same name in a *non-canonical* path is the masquerade tell → left intact; (3) a baseline Windows process subject gets a NOTE only (confidence unchanged). The demoting suppressors NEVER fire on a non-clearable signature (credential-dump / log-clear / destruction / defense-impairment). Evidence-agnostic, custody-neutral. See `docs/false-positives.md`.

## Attacker tradecraft priors
- LOLBins to check first: rundll32, regsvr32, mshta, wmic, certutil, bitsadmin.
- Scheduled Tasks in `\Microsoft\Windows\` namespace are a classic hiding spot.
- Run/RunOnce, Services, WMI event subscriptions, Image File Execution Options = persistence top-5.

## Reporting conventions
- All timestamps UTC, ISO-8601, trailing Z.
- Hashes: SHA-256 preferred, MD5 only when tool-limited.
- Never assert attribution.

## Pre-finalize report-QA coverage gates (additive, downgrade-only)
- `coverage_parse_quality` splits coverage-manifest classes into examined (parser ran without error: parsed/partial/attempted_no_rows) vs failed (status `failed` — the tool errored). A `touched`/tool-invoked class is NOT examined if its parse failed: a tool failure cannot satisfy a clearance. The `clearance_requires_successful_parse` check FAILs a NO_EVIL with no successfully parsed class, WARNs when one class failed but another parsed.
- Reverse coverage audits (`build_coverage_reverse_audits`): an artifact class the evidence contains (available) but no applicable typed tool examined FAILs a NO_EVIL clearance (WARN for other verdicts); indexed-but-uncited tool outputs are disclosed (non-blocking) since uncited output is normal for negative results.
- Conditional key-question rules (`evaluate_key_question_rules`): "if you found X you must have checked Y" (e.g. ingress/download => execution checked; persistence => execution; brute force => successful-logon check; credential access => lateral/logon; log-clearing => second corroborating class; lateral movement => network/source-host). Unmet rules become NAMED limitations (WARN), never a hard clean. All of the above are deterministic and never touch finalize/sign/verify.
