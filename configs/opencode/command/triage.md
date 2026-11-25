---
description: Triage a mixed evidence case directory (breadth-first)
agent: verdict
---

Investigate the case directory `$1` (full argument string: `$ARGUMENTS`) as the default breadth-first entry point. A mixed case dir — holding a disk image, a memory image, a Velociraptor zip, and EVTX/PCAP files — is how you exercise the whole tool surface in one run.

Operate read-only on evidence through VERDICT forensic MCP tools only. Call the actual opencode tools by their exact names (`findevil-mcp_<tool>` and `findevil-agent-mcp_<tool>`) with structured arguments. Do not type MCP names into shell/bash, do not print JSON examples as substitutes for tool calls, and do not use direct file read/list/grep/glob, write/edit, or ad hoc generated rules to inspect evidence or manufacture proof. SHA-256 every tool output. Cite the originating `tool_call_id` on every Finding. Emit only the scoped verdict words: `SUSPICIOUS` (reportable evidence found), `INDETERMINATE` (leads or limited coverage prevent a scoped clearance), or `NO_EVIL` (no reportable Finding in the artifacts actually examined — never a whole-environment clean bill).

Sequence:

1. Call `findevil-mcp_case_open` on `$1`. Read the returned `image_hash`, `image_size_bytes`, and `id` (the `case_id` you thread through every subsequent tool via its `case_id` argument).
2. Classify every artifact in the directory and dispatch each to its type playbook, stitching the results together under one `case_id`:
   - **memory** (`.mem`/`.raw`/`.dmp`/`.vmem`) -> `findevil-mcp_vol_pslist`, then always `findevil-mcp_vol_psscan`, then `findevil-mcp_vol_psxview` when pslist diverges from psscan, then `findevil-mcp_vol_malfind`, then `findevil-mcp_yara_scan` (Pool B) over the raw image.
   - **disk** (`.e01`/`.dd`/`.raw`/`.aff`) -> `findevil-mcp_disk_mount`, `findevil-mcp_disk_extract_artifacts`, `findevil-mcp_mft_timeline`, `findevil-mcp_prefetch_parse`, `findevil-mcp_usnjrnl_query`, `findevil-mcp_registry_query`, `findevil-mcp_evtx_query`, `findevil-mcp_browser_history`, `findevil-mcp_hayabusa_scan` over the extracted EVTX dir, `findevil-mcp_yara_scan` over extracted yara-targets, then `findevil-mcp_disk_unmount` (finally-block).
   - **evtx** (`.evtx`) -> `findevil-mcp_evtx_query`; add `findevil-mcp_hayabusa_scan` only when an EVTX *directory* (>=2 logs in one folder) is present.
   - **network** (`.pcap`/`.pcapng`/Sysmon-EVTX/Zeek) -> `findevil-mcp_sysmon_network_query`, `findevil-mcp_zeek_summary`, `findevil-mcp_pcap_triage` (each fires only when its artifact class is present).
   - **velociraptor** (`.zip`) -> safely extract supported members (reject zip-slip and oversized members), then re-dispatch each extracted artifact — including memory dumps inside the zip — to the branches above.
3. Run both interpretation pools over the sequence: Pool A (persistence: Run/Services/IFEO/ScheduledTasks/WMI/injected modules; MITRE T1547/T1543/T1546/T1053/T1574) and Pool B (exfil/general malware: staging dirs, `certutil`/`bitsadmin`/`curl`/`wget`/`Invoke-WebRequest`, cloud-sync, USB writes, suspicious outbound endpoints; MITRE T1041/T1567/T1048/T1052/T1110). Where the pools disagree on the same artifact, `findevil-agent-mcp_detect_contradictions` is expected to fire — surface it before the judge.

Stop and ask the analyst when: a tool returns `BinaryNotFound`; two consecutive iterations yield no new Findings and no new contradictions; a `CONFIRMED` Finding has a `correlate_findings` corroboration count below 2 artifact classes; or the evidence vault is modified mid-run.

Do not emit disk-content Findings from `case_open` alone — custody-only disk registration is not a Finding. A single-file input only ever triggers that one type's branch; point this command at a mixed directory for full breadth.

Negative-control gate: suspicious filenames, planted strings, topic notes, archives named "passwords", and sinkhole/parked-domain lookups are non-reportable decoy leads unless independent behavioral evidence exists. Do not turn name/content bait into malware, credential dumping, C2, staging, or exfiltration Findings.

After both pools return Findings, hand off to the reason/seal phase (`verdict` workflow label).
