---
description: Investigate a Velociraptor .zip triage collection — unzip and re-dispatch
agent: verdict
---

Investigate the Velociraptor collection zip `$1` (full argument string: `$ARGUMENTS`). These are triage zips produced by `velociraptor` collection.

Operate read-only on evidence. SHA-256 every tool output. Cite the originating `tool_call_id` on every Finding. Emit only the scoped verdict words: `SUSPICIOUS`, `INDETERMINATE`, or `NO_EVIL` (never a whole-environment clean bill).

Tool sequence (thread `case_id` through every call):

1. `case_open` on `$1` — SHA-256 + `case_id`. Read `image_hash`, `image_size_bytes`, `id`. (both pools)
2. **Velociraptor zip extraction** — safely extract supported contained artifacts to the case work dir. Reject zip-slip and oversized members. Derived staging belongs under the run/output dir, never under the source evidence. (Note: velo zips are unzipped and re-dispatched locally, not via the `vel_collect` tool.) (both)
3. **Per-artifact re-dispatch** — route each extracted artifact to its type playbook, threading the same `case_id`: (both)
   - **memory** -> `vol_pslist`, then always `vol_psscan`, then `vol_psxview` (on divergence), then `vol_malfind`, then `yara_scan`.
   - **EVTX** -> `evtx_query`; add `hayabusa_scan` on folders with >=2 logs.
   - **disk** artifacts -> `mft_timeline`, `usnjrnl_query`, `prefetch_parse`, `registry_query`.
   - **network** -> `sysmon_network_query`, `zeek_summary`, `pcap_triage`.

Run both interpretation pools (Pool A persistence: Run/Services/IFEO/ScheduledTasks/WMI, T1547/T1543/T1546/T1053/T1574; Pool B exfil/malware: staging dirs, LOLBin execution, outbound endpoints, T1041/T1567/T1048/T1052/T1110). Where they disagree on the same artifact, `detect_contradictions` is expected to fire — surface it before the judge.

Execution claims require at least two current-case artifact classes; Hayabusa/YARA/malfind output is a lead until corroborated. A Velociraptor zip commonly carries multiple classes, so use them to reach the two-artifact-class bar rather than lowering it.

Stop and ask when: `BinaryNotFound`; two consecutive iterations yield no new Findings or contradictions; a `CONFIRMED` Finding corroborates across fewer than 2 artifact classes; or the evidence vault is modified mid-run.

After both pools return Findings, hand off to the reason/seal phase (`/verdict`).
