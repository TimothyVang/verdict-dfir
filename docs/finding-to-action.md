# Finding to Action

When the agent returns a verdict, this guide tells you what to do next. Organized by MITRE technique.

---

## Reading the verdict first

`verdict.json` has three top-level verdicts:

| Verdict | Meaning | Your next step |
|---|---|---|
| `SUSPICIOUS` | At least one CONFIRMED finding with a MITRE technique | Treat as a positive — escalate per technique below |
| `INDETERMINATE` | Findings exist but none reached CONFIRMED; or a coverage gap prevents a verdict | Review INFERRED/HYPOTHESIS findings; close coverage gap if evidence is available |
| `NO_EVIL` | All tools ran, no qualifying findings | Document scope; escalate if customer expects an incident |

**Confidence level matters for IR:**
- `CONFIRMED` (≥2 artifact classes corroborated, verifier passed) → act as if real
- `INFERRED` (derived from confirmed facts, labeled) → treat as likely; investigate to confirm or dismiss
- `HYPOTHESIS` (single-source or unverified) → note and monitor; do not action without further corroboration

---

## T1014 — Rootkit (DKOM)

**How the tool detects it:** `vol_pslist` returns 0 for a PID; `vol_psscan` returns >0 for the same EPROCESS block. `vol_psxview` shows which process views miss the recovered process.

**IR actions:**

1. Note the unlinked process name, PID, PPID, and image path from `vol_psscan`.
2. Search `\Windows\System32\drivers\` for `.sys` files modified or created within the compromise window (from MFT timeline).
3. Run YARA against the `\drivers\` directory with rootkit-specific rules (ring-0 DKOM and SSDT hook patterns).
4. Run `vol_malfind` against the recovered process's address space — look for injected code regions.
5. Collect a copy of suspicious `.sys` files for sandbox analysis (out of scope for this tool — escalate).
6. Preserve the full memory image before remediation (volatile evidence).
7. Assume kernel trust is broken on this host — lateral movement and persistence via driver may be present on other hosts.

**Fleet follow-up:** search other hosts in the environment for the same `.sys` hash. A single DKOM rootkit being loaded across multiple systems indicates widespread compromise.

---

## T1055 — Process Injection

**How the tool detects it:** `vol_malfind` returns a region with RWX permissions, an MZ header in unexpected address space, and a YARA hit in the same region.

**IR actions:**

1. Note the target process (the host process the code was injected into), the injected region's VA, and the YARA rule that matched.
2. Extract the injected region bytes (if Volatility's `procdump`/`dlllist` gives you a handle — this may need manual extraction outside this tool's automated scope).
3. Submit the extracted region to a sandbox for behavior analysis.
4. Check the target process's network connections in EVTX 5156 or Zeek conn.log — injected code frequently uses the host process's network access.
5. Correlate the injection time (if available from memory) with EVTX 4688 process-creation events to identify the injector process.
6. Injection + no corresponding disk binary = fileless payload — treat as high-severity.

**Parent process matters:** injection into `explorer.exe`, `svchost.exe`, or `lsass.exe` is higher risk than injection into a user application. Document which process was the target.

---

## T1547.001 — Registry Run Keys / Startup Folder

**How the tool detects it:** `registry_query` returns a non-baseline value under `Run` / `RunOnce`; EVTX 7045 or absence thereof for service-variant; MFT shows the binary exists.

**IR actions:**

1. Record the full registry path, value name, and value data (command line / binary path).
2. Collect the binary at the path listed in the value. Hash it (SHA-256) and compare against threat-intel.
3. Check when the key was last written (registry last-write time) — this gives the installation window, cross-validate with MFT and Prefetch.
4. Check whether the binary has a Prefetch file — confirms it ran at least once.
5. Remove the registry value. Remove the binary. Reboot and verify it does not return (if it does, a second-stage persistence mechanism is present).
6. If the binary is in `\AppData\Roaming\` or `\Temp\` — common attacker staging locations — search for related files created in the same time window via MFT timeline.

---

## T1543.003 — Windows Service

**How the tool detects it:** `registry_query` returns an entry under `HKLM\SYSTEM\CurrentControlSet\Services\` for an unknown service; EVTX 7045 records service installation.

**IR actions:**

1. Record the service name, binary path, start type, and account it runs as.
2. Services running as `SYSTEM` with binaries in `\Temp\`, `\Users\`, or `\ProgramData\` are high-priority.
3. Check the binary hash against threat-intel.
4. Check EVTX 4688 for process-creation events under the service binary.
5. Stop the service (`sc stop`) and disable (`sc config ... start=disabled`) before deleting the binary.
6. Verify no watchdog mechanism re-registers the service after disabling.

---

## T1053.005 — Scheduled Task

**How the tool detects it:** `registry_query` against `TaskCache\Tasks` returns an unexpected task; EVTX 4698 records task creation.

**IR actions:**

1. Record the task name, action (binary or command), trigger (at logon, periodic, on event), and which user account the task runs as.
2. Export the raw XML definition from `\Windows\System32\Tasks\<task-name>`.
3. Hash and check the binary or command referenced in the action.
4. Note the task creation time from EVTX 4698 (if available) — places the attacker's activity in a timeline.
5. Delete the task (`schtasks /delete /tn "<name>" /f`) and remove the binary.

---

## T1546.012 — Image File Execution Options (IFEO) Hijack

**How the tool detects it:** `registry_query` returns a `Debugger` value under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<target.exe>`.

**IR actions:**

1. Note which process is targeted (`<target.exe>`) and what binary is set as the Debugger value.
2. IFEO `Debugger` hijacks cause the Debugger binary to launch every time the target process starts — this achieves persistence and privilege escalation if the target runs as SYSTEM.
3. Also check `SilentProcessExit` under the same registry path — sibling technique.
4. Remove the `Debugger` value. Verify the legitimate process starts normally after removal.

---

## T1070 — Indicator Removal (Timestomping / Log Clearing)

**How the tool detects it:** MFT `$SI.created` is later than `$FN.created` (timestomp); EVTX 1102 (Security log cleared) or 104 (System log cleared).

**IR actions for timestomping:**
1. The `$FN` created time is more reliable — use it to anchor the actual file creation window.
2. Cross-validate against UsnJrnl and Prefetch to build a timeline independent of `$SI`.
3. Timestomping indicates deliberate anti-forensics — assume other artifacts on this host may also have been manipulated. Widen the investigation scope.

**IR actions for log clearing:**
1. EVTX 1102 records who cleared the log (user SID and logon ID) — correlate with EVTX 4624 to identify the session.
2. Clearing the Security log requires SeSecurityPrivilege — typically Administrator. If a non-admin account cleared it, that account is compromised.
3. Clearing is irreversible for the cleared events. Document what time window is now unrecoverable. Look for the same events in alternative sources: Sysmon (if deployed), Zeek, EDR.

---

## T1041 / T1048 — Exfiltration (Network / Alternative Protocol)

**How the tool detects it:** Pool B finds staging files (large archives in `\Temp\` or `\Users\Public\`), `certutil`/`bitsadmin`/`curl` in Prefetch or EVTX 4688, large outbound connections in EVTX 5156 or Zeek conn.log.

**IR actions:**

1. Estimate data volume: staging file sizes from MFT + transfer timestamps from EVTX 5156 / Zeek.
2. Identify destination: IP/hostname from EVTX 5156, Zeek conn.log, or cmdline arguments in EVTX 4688.
3. Check whether the destination is cloud storage (Dropbox, OneDrive, Mega), a file-sharing site, or a raw IP — each implies different attacker infrastructure.
4. Preserve the staging files (if not already deleted). Hash and catalog for scope assessment.
5. If staging files were deleted: look in the unallocated MFT and UsnJrnl for the creation → archive → delete sequence. The archive tool (7z, WinRAR) in Prefetch confirms staging even if the archive itself is gone.
6. Notify legal/DPO if the scope assessment suggests PII or regulated data was staged.

---

## INFERRED and HYPOTHESIS findings — what to do

**INFERRED:** credible but single-source or derived. Prioritize for follow-up:
- Look for the second artifact class that would promote to CONFIRMED
- Example: INFERRED "certutil executed" from EVTX 4688 → find the Prefetch file to confirm

**HYPOTHESIS:** a lead, not a finding. Document and monitor:
- Note the `tool_call_id` and the reason it didn't promote
- Re-run if additional evidence becomes available
- Do not cite HYPOTHESIS-tier findings in a customer report without explicit analyst annotation

---

## Analysis limitations — what the agent couldn't cover

Check `analysis_limitations` in verdict.json for scope gaps. Common ones:

| Limitation | What it means | What to do |
|---|---|---|
| `auto_disk_mode: custody_only` | Disk image was received but not mounted/extracted | Run `disk_mount` + `disk_extract_artifacts`, then re-run the disk-class tools |
| `prefetch_disabled` | No Prefetch files found; SSD or GPO | Compensate with ShimCache + EVTX 4688 for execution evidence |
| `evtx_log_cleared` | EID 1102 or 104 detected | Document the gap; compensate with Sysmon, Zeek, EDR if available |
| `memory_symbols_missing` | Volatility couldn't load symbols for this kernel | Pre-stage symbols or run against a matching symbol pack |
| `no_network_evidence` | No PCAP or Zeek logs provided | Consider requesting network capture from the environment |
