---
description: Investigate a multi-host fleet (many hosts / many disk images) — the scale path
agent: verdict
---

Investigate the multi-host case root `$1` (full argument string: `$ARGUMENTS`) as a fleet. Engage fleet mode when the case root holds a `hosts/` and/or `disks/` subfolder (many machines, not one) — run each host as its own audit-chained Case rather than one host at a time.

Operate read-only on evidence. SHA-256 every tool output. Cite the originating `tool_call_id` on every Finding. Emit only the scoped verdict words: `SUSPICIOUS`, `INDETERMINATE`, or `NO_EVIL` (never a whole-environment clean bill). Custody stays per host — each host carries its own `run.manifest.json` / `manifest_verify`; the fleet correlation report is a derivative summary, never a substitute for per-host verification.

Flow (each host runs its own type-playbook sequence under its own `case_id`):

1. **Validate on one host first.** Run a single representative host end to end (verdict + `manifest_verify.overall=true`) before fanning out, so a pipeline problem surfaces on host 1, not host 7.
2. Run each host as its own audit-chained Case, then cross-host correlation via `fleet_correlate`, then a fleet report via `render_fleet_report`. Fleet runs are resumable — a host whose run-summary already exists is skipped.
3. **SIFT mount-in-place for large images.** When evidence already exists inside the VM (e.g. a read-only shared folder), pass the in-VM path and mount read-only in place — skip copy-staging tens of GB per host.
4. **Manage VM space.** Per-host extracts accumulate; on a small VM, clean a finished host's extracted/mount dirs before the next host. Never delete source evidence or another tool's data without operator approval.
5. **Fuse disk + memory for >=2-class corroboration.** Put a host's disk image and its memory image in one folder so they run as a single cross-artifact Case (memory lane first, disk lane last). Pairing adds a class; it does not lower the two-artifact-class bar.
6. **Close the on-disk YARA gap.** Set `FIND_EVIL_DISK_YARA_RULES` to a ruleset so `yara_scan` runs over extracted yara-targets; when a service/driver ImagePath is flagged (e.g. an EID 7045 install), recover and scan that specific file off the mount with an audit-chained tool (`yara_scan` / typed parse) so the file carries a `tool_call_id`. Raw shell triage (vol/file/sha256sum) is a lead only and will not trace under `manifest_verify` — a "2-artifact-class" claim needs both classes cited in-chain, not one in-chain plus one asserted.

Run both interpretation pools per host (Pool A persistence: T1547/T1543/T1546/T1053/T1574; Pool B exfil/malware: T1041/T1567/T1048/T1052/T1110); where they disagree on the same artifact, `detect_contradictions` is expected to fire — surface it before the judge.

Interpretation traps that bite at scale: EID 1102 build-residue vs incident clears, malfind RWX false positives, and truncated-capture `pslist=0`/`malfind=0` that is "not analyzable," not clean.

Stop and ask when: `BinaryNotFound`; two consecutive iterations yield no new Findings or contradictions; a `CONFIRMED` Finding corroborates across fewer than 2 artifact classes; or an evidence vault is modified mid-run.

For each host, after both pools return Findings, run the reason/seal phase (`/verdict`) so every host is sealed before fleet correlation.
