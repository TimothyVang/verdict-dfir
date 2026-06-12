# Fleet investigation report — fleet-20260609T162206Z

**Hosts investigated:** 22
**SUSPICIOUS:** 0 (0%)  **INDETERMINATE:** 22  **NO_EVIL:** 0
**Cross-host process correlations:** 74
**Multi-host temporal clusters:** 53
**Cryptographic integrity:** 0/0 unique Merkle roots (OK — all manifests independent)

---

## Executive summary

This is a fleet-level rollup of 22 per-host investigations executed by `find-evil-auto` against the SRL-2018 SANS HACKATHON-2026 dataset. 0 of 22 hosts (0%) returned the `SUSPICIOUS` verdict — they are the analyst's priority queue.

Each per-host investigation produced its own `run.manifest.json`, audit chain, and verdict; this report is a derivative summary, not a replacement for those primary artifacts. A judge or counter-party who wants to verify must verify each per-host manifest individually via `manifest_verify`.

## Verdict distribution

![Verdict distribution](figures/verdict_distribution.png)

## MITRE ATT&CK technique density

![MITRE technique density](figures/mitre_density.png)

## Cross-host process correlations

*The same uncommon process image name appearing on multiple hosts is a much stronger lateral-movement signal than the same name on one host alone. Below: image names appearing on ≥2 hosts.*

![Cross-host process correlation](figures/cross_host_processes.png)

**34 image names appear on ≥4 hosts.** Pull the corresponding binary off the disk image of any of these hosts and YARA-scan against YARA-Forge core rules:

- `subject_srv.ex` (20 hosts)
- `cmd.exe` (17 hosts)
- `powershell.exe` (15 hosts)
- `rubyw.exe` (14 hosts)
- `ruby.exe` (12 hosts)
- `plasrv.exe` (9 hosts)
- `OUTLOOK.EXE` (8 hosts)
- `find.exe` (8 hosts)
- `java.exe` (8 hosts)
- `msadvapi2_32.e` (8 hosts)
- `msadvapi2_64.e` (8 hosts)
- `ncpa_listener.` (8 hosts)
- `ncpa_passive.e` (8 hosts)
- `prunsrv.exe` (8 hosts)
- `rdpinput.exe` (8 hosts)

## Multi-host temporal clusters (lateral-movement candidates)

![Temporal clusters](figures/temporal_clusters.png)

53 clusters detected. Each cluster is a group of process creations across ≥2 hosts within a 60-second window — the temporal fingerprint of automated tradecraft (PsExec waves, WMI execution chains, scheduled-task pivots).

**Top clusters (by host count):**

### Cluster 1: 6 hosts in 0s

- First event: `2018-08-15T17:10:32+00:00`
- Last event:  `2018-08-15T17:10:32+00:00`
- Sample events:
  - `base-rd-04-memory` PID 2256 `Autorunsc.exe` at 2018-08-15T17:10:32+00:00
  - `base-rd-05-memory` PID 19176 `Autorunsc.exe` at 2018-08-15T17:10:32+00:00
  - `base-wkstn-01-memory` PID 9048 `Autorunsc.exe` at 2018-08-15T17:10:32+00:00
  - `base-wkstn-02-memory` PID 6516 `Autorunsc.exe` at 2018-08-15T17:10:32+00:00
  - `base-wkstn-03-memory` PID 728 `Autorunsc.exe` at 2018-08-15T17:10:32+00:00
  - `base-wkstn-04-memory` PID 7092 `Autorunsc.exe` at 2018-08-15T17:10:32+00:00

### Cluster 2: 5 hosts in 312s

- First event: `2018-06-04T20:18:02+00:00`
- Last event:  `2018-06-04T20:23:14+00:00`
- Sample events:
  - `base-elf-memory` PID 4 `System` at 2018-06-04T20:18:02+00:00
  - `base-elf-memory` PID 4 `System` at 2018-06-04T20:18:02+00:00
  - `base-elf-memory` PID 296 `smss.exe` at 2018-06-04T20:18:02+00:00
  - `base-elf-memory` PID 392 `csrss.exe` at 2018-06-04T20:18:15+00:00
  - `base-elf-memory` PID 472 `smss.exe` at 2018-06-04T20:18:16+00:00
  - `base-elf-memory` PID 504 `wininit.exe` at 2018-06-04T20:18:16+00:00
  - `base-elf-memory` PID 480 `csrss.exe` at 2018-06-04T20:18:16+00:00
  - `base-elf-memory` PID 536 `winlogon.exe` at 2018-06-04T20:18:17+00:00

### Cluster 3: 4 hosts in 211s

- First event: `2018-09-06T17:12:00+00:00`
- Last event:  `2018-09-06T17:15:31+00:00`
- Sample events:
  - `base-rd-02-memory` PID 9028 `sc.exe` at 2018-09-06T17:12:00+00:00
  - `base-rd-02-memory` PID 3744 `cmd.exe` at 2018-09-06T17:12:26+00:00
  - `base-wkstn-02-memory` PID 9172 `SearchFilterHo` at 2018-09-06T17:12:38+00:00
  - `base-rd-02-memory` PID 3524 `sc.exe` at 2018-09-06T17:13:00+00:00
  - `base-rd-02-memory` PID 1164 `find.exe` at 2018-09-06T17:13:00+00:00
  - `base-rd-02-memory` PID 948 `find.exe` at 2018-09-06T17:13:00+00:00
  - `base-hunt-memory` PID 7888 `dllhost.exe` at 2018-09-06T17:13:42+00:00
  - `base-wkstn-01-memory` PID 7488 `conhost.exe` at 2018-09-06T17:13:59+00:00

### Cluster 4: 4 hosts in 82s

- First event: `2018-09-06T18:44:23+00:00`
- Last event:  `2018-09-06T18:45:45+00:00`
- Sample events:
  - `base-wkstn-05-memory` PID 4848 `MSOSYNC.EXE` at 2018-09-06T18:44:23+00:00
  - `base-rd-04-memory` PID 10932 `taskhostw.exe` at 2018-09-06T18:44:52+00:00
  - `base-rd-06-memory` PID 876 `TrustedInstall` at 2018-09-06T18:45:14+00:00
  - `base-rd01-memory` PID 7132 `backgroundTask` at 2018-09-06T18:45:45+00:00

### Cluster 5: 4 hosts in 225s

- First event: `2018-09-06T20:40:00+00:00`
- Last event:  `2018-09-06T20:43:45+00:00`
- Sample events:
  - `base-wkstn-04-memory` PID 2912 `NETSTAT.EXE` at 2018-09-06T20:40:00+00:00
  - `base-wkstn-04-memory` PID 6964 `rubyw.exe` at 2018-09-06T20:40:22+00:00
  - `base-wkstn-04-memory` PID 5588 `find.exe` at 2018-09-06T20:41:00+00:00
  - `base-wkstn-06-memory` PID 5796 `rubyw.exe` at 2018-09-06T20:41:51+00:00
  - `base-wkstn-06-memory` PID 5172 `cmd.exe` at 2018-09-06T20:42:00+00:00
  - `base-rd-05-memory` PID 19364 `NETSTAT.EXE` at 2018-09-06T20:42:00+00:00
  - `base-rd-05-memory` PID 22220 `conhost.exe` at 2018-09-06T20:42:00+00:00
  - `base-rd-05-memory` PID 18912 `cmd.exe` at 2018-09-06T20:42:59+00:00

## Cryptographic attestation

All 0 per-host manifests have **unique Merkle roots** (0/0) — chain integrity intact. Each `run.manifest.json` is independently verifiable via `manifest_verify`.

## Recommended analyst priorities

1. **Triage SUSPICIOUS hosts first** — pull each one's `verdict.json` and `REPORT.pdf` from its case directory.
2. **Investigate the top cross-host process names** (≥4 hosts). Pull the binary off any of those hosts' disk images, YARA-scan, compute SHA-256, check against threat-intel feeds.
3. **Trace temporal clusters back to patient zero**. The first host in each cluster is the entry point candidate — focus deeper analysis (registry, MFT timeline, EVTX 4624/4688) on that host.
4. **For T1014 hosts: check `\Windows\System32\drivers\` on their disk images** for unsigned or non-Microsoft .sys files modified in the suspected compromise window.
5. **Cross-reference timestamps with EVTX logon events** — lateral-movement clusters should align with Logon Type 3 (Network) or Type 10 (RDP) events on the destination hosts.

---

*Produced by `render_fleet_report.py` on 2026-06-10 01:31:34. The authoritative evidence is the per-host `run.manifest.json` in each case directory; this report is a derivative summary.*