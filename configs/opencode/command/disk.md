---
description: Investigate a full disk image (.e01/.dd/.raw/.aff) — deepest evidence path
agent: verdict
---

Investigate the disk image `$1` (full argument string: `$ARGUMENTS`). This is the deepest evidence type — run all the disk-class tools.

Operate read-only on evidence. SHA-256 every tool output. Cite the originating `tool_call_id` on every Finding. Emit only the scoped verdict words: `SUSPICIOUS`, `INDETERMINATE`, or `NO_EVIL` (never a whole-environment clean bill).

Tool sequence (thread `case_id` through every call):

1. `case_open` on `$1` — SHA-256 the image, derive `case_id`. Read `image_hash`, `image_size_bytes`, `id`.
2. `disk_mount` — mount read-only: EWF container via `ewfmount`, then the inner volume via TSK. Local mode mounts the container only; the inner-volume mount needs the SIFT VM (`--sift`). (both pools)
3. `disk_extract_artifacts` — carve MFT/USN/Prefetch/Registry (and yara-targets, if any) to the work dir. (both)
4. `mft_timeline` — `$MFT` timeline; `$SI` vs `$FN` timestomp detection. (both)
5. `prefetch_parse` — per-binary execution evidence (run_count, last 8 run times). (Pool A)
6. `usnjrnl_query` — `$UsnJrnl` change log; corroborates MFT, surfaces deletes. (both)
7. `registry_query` — Run / RunOnce / IFEO / Services / WMI consumers / Scheduled Tasks. (Pool A)
8. `evtx_query` — Security.evtx (4624/4625/4688/7045), System.evtx, Application.evtx. (Pool A)
9. `browser_history` — extracted Chrome/Edge/Firefox browser DBs. (Pool B)
10. `ez_parse` — LNK, JumpLists, Amcache, modern Recycle Bin decoders. (both)
11. `plaso_parse` — legacy EVT, IE index.dat, task, and Recycle Bin timelines. (both)
12. `hayabusa_scan` — Sigma rules over the extracted EVTX **directory** (dir-based). (Pool A)
13. `yara_scan` — YARA over extracted yara-target files. Skipped when extraction yields no yara-targets. (Pool B)
14. `vel_collect` (optional) — additional OS-level artifacts the wrappers don't cover. (both)
15. `disk_unmount` — release the mount (finally-block). (both)

Important deviation: raw disk images are custody-only unless mounted/extracted artifacts are supplied for the typed disk tools. If `disk_mount` / `disk_extract_artifacts` fail or produce no supported parsed artifacts, record the limitation and return `INDETERMINATE`. Never turn `case_open` alone into a disk-content Finding.

Coverage gap (yara on disk): `yara_scan` runs only over files `disk_extract_artifacts` classified as yara-targets — on a stock image that can be 0, so yara is skipped. When a service/driver ImagePath is flagged (e.g. an EID 7045 install), recover and scan that specific file off the mount with an audit-chained tool so it carries a `tool_call_id`; raw shell triage is a lead only. Set `FIND_EVIL_DISK_YARA_RULES` to enable disk-target YARA.

Run both interpretation pools (Pool A persistence: T1547/T1543/T1546/T1053/T1574; Pool B exfil/malware: T1041/T1567/T1048/T1052/T1110); where they disagree on the same artifact, `detect_contradictions` is expected to fire — surface it before the judge.

Stop and ask when: `BinaryNotFound`; two consecutive iterations yield no new Findings or contradictions; a `CONFIRMED` Finding corroborates across fewer than 2 artifact classes; or the evidence vault is modified mid-run.

After both pools return Findings, hand off to the reason/seal phase (`/verdict`).
