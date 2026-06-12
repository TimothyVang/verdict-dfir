# SRL-2018 disk fleet — run through SIFT via one-command auto-staging

Four hosts of the SANS **SRL-2018** corpus, each run with a single command
(`scripts/verdict <disk> --sift`) — the launcher auto-resolved the SIFT VM,
auto-staged the 12–16 GB `.E01` into it, and ran the full pipeline inside the VM.
This complements the earlier **22-host memory fleet** (all INDETERMINATE — single
artifact class): the *disks* are where the anti-forensic activity surfaces.

| Host | Role | Verdict | Findings | Manifest |
|---|---|---|---|---|
| `dmz-ftp` | DMZ FTP server (internet-facing) | **SUSPICIOUS** | 1 CONFIRMED · 1 HYPOTHESIS | ✓ verifies |
| `base-file` | File server | **SUSPICIOUS** | 2 CONFIRMED · 2 HYPOTHESIS | ✓ verifies |
| `base-dc` | Domain controller | INDETERMINATE | 1 HYPOTHESIS | ✓ verifies |
| `base-wkstn-01` | Workstation | INDETERMINATE | 1 HYPOTHESIS | ✓ verifies |

**What the two SUSPICIOUS hosts share:** a **CONFIRMED Windows Security event-log
clear** (EID 1102, anti-forensics / `T1070.001`) — on the two most exposed/valuable
boxes (the DMZ FTP server and the file server). The internal DC and workstation
returned only uncorroborated leads, so the agent kept them at **INDETERMINATE** —
honest about coverage rather than forcing a verdict.

**Restraint, on camera:** on `dmz-ftp` an EID 7045 service install of `vmxnet3`
(a benign VMware NIC driver) was kept a **HYPOTHESIS**, not flagged as evil — the
≥2-artifact-class rule and the verifier doing their job.

Every host: `manifest_verify.overall = true`, every Finding cites a `tool_call_id`.
