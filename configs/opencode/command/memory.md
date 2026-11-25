---
description: Investigate a memory image (.mem/.raw/.dmp/.vmem) — what was running
agent: verdict
---

Investigate the memory image `$1` (full argument string: `$ARGUMENTS`). Memory tells you what was *running*, not just what was *installed*.

Operate read-only on evidence. SHA-256 every tool output. Cite the originating `tool_call_id` on every Finding. Emit only the scoped verdict words: `SUSPICIOUS`, `INDETERMINATE`, or `NO_EVIL` (never a whole-environment clean bill).

Tool sequence (thread `case_id` through every call):

1. `case_open` on `$1` — SHA-256 + `case_id`. Read `image_hash`, `image_size_bytes`, `id`. (both pools)
2. `vol_pslist` — process list from `PsActiveProcessHead` (active-list walk). (both)
3. `vol_psscan` — EPROCESS pool-memory signature scan; finds blocks unlinked from the active list. (both)
4. `vol_psxview` — cross-view process enumeration; identifies which process views miss recovered processes. (both)
5. `vol_malfind` — RWX VADs + MZ headers in unexpected places (code injection). (both)
6. `yara_scan` — YARA over the raw memory image; catches in-memory-only payloads. (Pool B)

The `vol_pslist` + `vol_psscan` pair is mandatory, not optional. Always emit a `vol_psscan` call after `vol_pslist`, even when pslist returns a healthy count, so the audit chain holds both for cross-validation. Divergence between the two outputs IS the forensic finding — `pslist=0` + `psscan>0` is the textbook MITRE ATT&CK T1014 (Rootkit) DKOM signature. When the pair diverges, run `vol_psxview` next to identify which process-enumeration views miss each recovered PID. Keep `vol_pslist`, `vol_psscan`, and `vol_psxview` analytically separate, and rule out acquisition smear before asserting DKOM. A truncated-capture `pslist=0`/`malfind=0` is "not analyzable," not clean.

Treat YARA and malfind output as leads until corroborated. Execution claims require at least two current-case artifact classes — memory-only process evidence, YARA, or malfind alone is not execution proof. If a disk image for the same host is available, cross-reference PIDs from `vol_pslist` against `prefetch_parse` run lists (a memory process with no Prefetch entry signals unprefetched execution); this is an analyst-driven cross-artifact check, not an auto-emitted Finding.

Run both interpretation pools (Pool A persistence: injected modules, LSASS; Pool B exfil/malware: suspicious outbound endpoints in memory). Where they disagree on the same artifact, `detect_contradictions` is expected to fire — surface it before the judge.

Stop and ask when: `BinaryNotFound`; two consecutive iterations yield no new Findings or contradictions; a `CONFIRMED` Finding corroborates across fewer than 2 artifact classes; or the evidence vault is modified mid-run.

After both pools return Findings, hand off to the reason/seal phase (`/verdict`).
