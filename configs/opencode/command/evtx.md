---
description: Investigate a single Windows event log (.evtx) — the lightweight case
agent: verdict
---

Investigate the Windows event log `$1` (full argument string: `$ARGUMENTS`). This is the lightweight case (matches the `--real-evidence` smoke flow).

Operate read-only on evidence. Call the actual opencode tools by their exact names (`findevil-mcp_<tool>` and `findevil-agent-mcp_<tool>`) with structured arguments. Do not type MCP names into shell/bash, do not print JSON examples as substitutes for tool calls, and do not use direct file read/list/grep/glob, write/edit, or ad hoc generated rules to inspect evidence or manufacture proof. SHA-256 every tool output. Cite the originating `tool_call_id` on every Finding. Emit only the scoped verdict words: `SUSPICIOUS`, `INDETERMINATE`, or `NO_EVIL` (never a whole-environment clean bill).

Tool sequence (thread `case_id` through every call):

1. `findevil-mcp_case_open` on `$1` — SHA-256 + `case_id`. Read `image_hash`, `image_size_bytes`, `id`. (both pools)
2. `findevil-mcp_evtx_query` — parse the log; pull the EID histogram and explicitly query high-signal security events, including 1102 (Security audit log cleared), 4719 (audit policy changed), 4624/4625 (logon success/failure), 4688 (process creation), and 7045 (service install). (both)
3. `findevil-mcp_hayabusa_scan` (optional) — Sigma rule scan; runs ONLY when a `.evtx` **directory** is available. (Pool A)

A single `.evtx` file gets `findevil-mcp_evtx_query` only. For a Security log, Event ID 1102 is reportable anti-forensics evidence: if present, emit `SUSPICIOUS` with a CONFIRMED finding for audit-log clearing, citing the `evtx_query` tool call and its replayable output. Do not conclude `NO_EVIL` until you have explicitly checked for 1102 and 4719. `findevil-mcp_hayabusa_scan` is directory-based (it walks a folder), so it runs only when an EVTX *directory* is supplied — e.g. a Velociraptor zip's `Logs/`, or a mixed case dir with >=2 logs in one folder. To get Sigma coverage on one log, put it in a directory and point the run there; this is a deliberate design choice, not a missing tool.

Execution claims require at least two current-case artifact classes; a single EVTX rarely meets that bar on its own, so an execution/persistence lead from one log stays a lead unless a second class corroborates it. Treat Hayabusa/Sigma output as leads until corroborated.

Run both interpretation pools (Pool A persistence: 7045 service installs, T1547/T1543/T1546/T1053/T1574; Pool B exfil/malware: 4688 command lines for `certutil`/`bitsadmin`/`curl`/`wget`/`Invoke-WebRequest`, T1041/T1567/T1048/T1052/T1110). Where they disagree on the same event, `findevil-agent-mcp_detect_contradictions` is expected to fire — surface it before the judge.

Stop and ask when: `BinaryNotFound`; two consecutive iterations yield no new Findings or contradictions; a `CONFIRMED` Finding corroborates across fewer than 2 artifact classes; or the evidence vault is modified mid-run.

After both pools return Findings, hand off to the reason/seal phase (`verdict` workflow label).
