# Artifact Semantics for Analysts

What each artifact type proves and doesn't prove. Read before reviewing agent findings.

---

## Prefetch (`.pf` files)

**Proves:** a binary ran, when (up to the last 8 execution times), how many times.

**Does not prove:** who ran it, whether it ran with malicious intent, that the binary still exists on disk.

**Key fields:**
- `run_count` — total recorded executions (saturates at 128 on older Windows)
- `last_run_times[]` — up to 8 most recent timestamps, UTC
- `loaded_files[]` — DLLs / supporting files loaded at startup (useful for identifying dropped loaders)

**Caveat:** Prefetch is disabled by default on SSDs in some Windows builds and can be disabled via Group Policy. Absence of a Prefetch file does not prove a binary never ran — verify via ShimCache, Amcache, or EVTX 4688 before concluding absence of execution.

---

## Amcache (`Amcache.hve`)

**Proves:** a binary was registered (catalogued) by Windows at some point.

**Does NOT prove execution.** `LastModified` in Amcache is catalog-registration time, not when the binary ran. An installer unpacking a `.exe` to disk triggers Amcache registration without ever executing the file.

**Key fields:**
- `last_modified` — file catalog time, not execution time
- `sha1_hash` — useful for threat-intel lookup (note: it is a SHA-1 of the first 512 KB, not the full file)

**When to use it:** corroborate Prefetch hits (Prefetch = ran; Amcache = was present). Alone it satisfies "file existed" only.

---

## ShimCache (AppCompatCache, `SYSTEM` hive)

**Proves:** a binary was seen by the Application Compatibility infrastructure.

**Does NOT prove execution.** The `exec` flag was removed on Windows 10 / Server 2016+. Entry order is insertion/append order, not last-run order — position in the list is not recency of use (see Mandiant "Caching Out" research).

**Key fields:**
- `path` — full path of the binary
- `last_modified` — the binary's `$SI` last-modified time at the time shimcache saw it (stompable — see MFT section)
- `exec_flag` — only meaningful on Windows 7/Server 2008R2 and earlier

**When to use it:** confirm a binary existed at a path; supplement Amcache. Pair with Prefetch or EVTX 4688 to argue execution.

---

## MFT / NTFS Timestamps (`$SI` vs `$FN`)

**Proves:** a file existed, when it was created/modified/accessed/changed (subject to caveats).

**`$SI` timestamps are stompable.** `NtSetInformationFile` lets any user-mode process set all four `$SI` timestamps to arbitrary values. Attackers routinely timestomp to hide newly dropped binaries among old system files.

**`$FN` timestamps are harder to alter** (require kernel-mode access or indirect moves) but not immune — `SetMACE` chains `$SI` edits with file moves to pull `$FN` along. Prefer `$FN` as the primary timestamp; cross-validate against `$LogFile`, UsnJrnl, Prefetch, and LNK files.

**Timestomp detection:** compare `$SI` created vs `$FN` created. If `$SI.created` is later than `$FN.created`, the `$SI` timestamp was modified after the file was placed on disk — high-confidence timestomp indicator.

**`is_allocated`:** if `False`, the MFT record was marked as deleted. The file content may still be recoverable but is not live on the filesystem.

---

## UsnJrnl (`$Extend\$UsnJrnl`)

**Proves:** the filesystem mutation happened (file created, renamed, deleted, written).

**Does not prove:** intent, who caused the mutation, that the file content was malicious.

**Caveat:** UsnJrnl wraps when it exceeds its configured max size. Gaps in sequence numbers are normal — they do not indicate evidence tampering. Long-running cases on active systems will have gaps.

**When to use it:** corroborate MFT timeline (confirms deletion, rename chains), surface large-file archive-and-delete sequences typical of staging-for-exfil.

---

## EVTX (Windows Event Logs)

**Proves:** Windows logged the described event. The log can be cleared (EID 1102 Security, EID 104 System) but the clearing event itself is recorded.

**Key event IDs:**

| EID | Log | Meaning |
|---|---|---|
| 4624 | Security | Successful logon — **Type 3 = network logon (SMB, often benign on domain); Type 10 = RemoteInteractive (RDP, scrutinize)** |
| 4625 | Security | Failed logon — brute-force indicator in volume |
| 4688 | Security | Process creation (requires audit policy + command-line logging enabled) |
| 4698 / 4702 | Security | Scheduled task created / modified |
| 7045 | System | New service installed |
| 1 | Sysmon (if deployed) | Process create — includes ParentImage, CommandLine, ProcessGuid |
| 5156 | Security | Windows Filtering Platform allowed connection — outbound network |

**Sysmon note:** Sysmon EID 1 `ProcessGuid` is the correlation key across events, not `ProcessId`. PIDs reuse within minutes on busy systems. Always join by `ProcessGuid`, not `PID`.

**Hayabusa / Sigma hits are triage leads, not findings.** A medium-level Sigma rule matching a process name is a reason to look at the raw EVTX record and corroborate with another artifact class — it is not itself CONFIRMED or INFERRED.

---

## Registry

**Proves:** the key/value existed at collection time (or at the hive's last-write time).

**Key persistence locations (Pool A focus):**

| Key | Technique |
|---|---|
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` | T1547.001 — executes on every user login |
| `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` | T1547.001 — user-scope |
| `HKLM\SYSTEM\CurrentControlSet\Services\` | T1543.003 — service persistence |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\` | T1546.012 — IFEO debugger hijack |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\` | T1546.012 — sibling to IFEO |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\` | T1053.005 — scheduled task definition |
| WMI `__EventFilter` / `__EventConsumer` / `__FilterToConsumerBinding` | T1546.003 — WMI subscription |

**Caveat:** registry last-write time is per-key, not per-value. A key modified by a legitimate installer that also contains an attacker value shows the installer's write time, not when the attacker added their value.

---

## Memory — Volatility 3 (`vol_pslist` / `vol_psscan` / `vol_psxview` / `vol_malfind`)

**`vol_pslist`** walks the kernel's `PsActiveProcessHead` doubly-linked list. An attacker with kernel access can unlink an EPROCESS block from this list without removing it from memory (DKOM — Direct Kernel Object Manipulation, T1014).

**`vol_psscan`** signature-scans raw pool memory for EPROCESS structures regardless of the active list. Finds processes unlinked by DKOM.

**The pslist / psscan pair is mandatory.** Run both even on clean-looking pslist output. `pslist=0` for a PID + `psscan>0` for the same EPROCESS = T1014 (Rootkit) DKOM. When the two diverge, run `vol_psxview` next.

**`vol_psxview`** cross-references multiple process views (pslist, psscan, PspCid table, session processes, desktop threads, handles). Identifies which views are missing each recovered process — the combination of misses fingerprints the rootkit's DKOM technique.

**`vol_malfind`** looks for RWX (read-write-execute) Virtual Address Descriptor regions with MZ headers — the classic code-injection footprint (T1055). False-positive rate is moderate on packed legitimate software (video codecs, JVM JIT, some AV). Corroborate via YARA scan and process parentage.

**Memory-only process evidence does NOT prove disk execution.** A process running in memory with no Prefetch file is suspicious but not CONFIRMED execution — it may indicate a fileless payload OR a binary that ran before Prefetch covered the window.

**Symbol resolution:** Volatility 3 downloads Windows debug symbols the first time it processes a memory image for a given kernel version. In SIFT VM without internet access, pre-stage symbols or use the local symbol cache.

---

## YARA

**Proves:** a matching byte pattern or string exists in the scanned target (file or memory region).

**Does not prove:** execution, intent, attribution, or that the sample is currently active.

**Rule tiers:**
- `core` tier — high-specificity rules, low FP rate. Use by default.
- `extended` / `community` tier — broader coverage, higher FP rate. Treat hits as leads, not findings.

**Avoid rules that match Microsoft-signed binaries** without additional context — rules targeting generic PE headers or common packed executables will fire on legitimately signed system components.

**YARA hits from `vol_malfind` memory regions** carry additional weight because the region was already flagged as RWX + MZ. A YARA hit inside a `vol_malfind` region upgrades the injection hypothesis.

---

## Zeek / PCAP

**Proves:** network traffic matching the connection/protocol/payload occurred.

**Key tables:**
- `conn.log` — source IP, destination IP, port, protocol, bytes transferred, duration
- `dns.log` — queries and responses; unusual TLDs, DGA-like labels, long TTLs are leads
- `http.log` — URI, user-agent, response codes; large POSTs on unusual ports are exfil candidates
- `files.log` — extracted file metadata and hashes

**No payload carving without additional scope.** Zeek summarizes; full packet carving for binary extraction requires Wireshark/Scapy and is out of this tool's automated scope — surface it as a gap.

---

## Cross-artifact corroboration rules

The tool enforces the ≥2 artifact-class rule for execution claims before promoting to CONFIRMED. Common valid combinations:

| Claim | Minimum artifact pair |
|---|---|
| Binary X executed | Prefetch + EVTX 4688 |
| Binary X executed | Prefetch + Amcache (registration proves binary existed; Prefetch proves it ran) |
| Binary X executed | EDR telemetry + memory process entry |
| Service Y is persistent | Registry Services key + EVTX 7045 (new service) |
| Scheduled task Z is persistent | Registry TaskCache + EVTX 4698 |
| Code injection into process P | `vol_malfind` RWX+MZ + YARA hit in the same VAD region |
| File deleted to cover tracks | UsnJrnl delete record + MFT `is_allocated=False` |

Amcache alone, ShimCache alone, or a single Sigma/Hayabusa hit does NOT satisfy the ≥2 class rule.
