---
description: Investigate network evidence (.pcap/.pcapng, Sysmon-EVTX, Zeek logs) — what talked to what
agent: verdict
---

Investigate the network evidence `$1` (full argument string: `$ARGUMENTS`). This tells you what talked to what. The engine runs `investigate_network_artifacts`; each tool fires only when its artifact class is present.

Operate read-only on evidence. SHA-256 every tool output. Cite the originating `tool_call_id` on every Finding. Emit only the scoped verdict words: `SUSPICIOUS`, `INDETERMINATE`, or `NO_EVIL` (never a whole-environment clean bill).

Tool sequence (thread `case_id` through every call; each step fires only when its artifact class is present):

1. `case_open` on `$1` — SHA-256 + `case_id`. Read `image_hash`, `image_size_bytes`, `id`. (both pools)
2. `sysmon_network_query` — Sysmon EID 3 network-connection events (needs a Sysmon EVTX). (both)
3. `zeek_summary` — Zeek conn/dns/http summaries (needs Zeek logs). (both)
4. `pcap_triage` — PCAP/PCAPNG triage; can drive Zeek internally for protocol summaries. (both)

Pool B leans on outbound endpoints / exfil patterns (MITRE T1041/T1567/T1048/T1052); Pool A on C2 beaconing (persistence/command-and-control read of the same flows). Where the pools disagree on the same flow or endpoint, `detect_contradictions` is expected to fire — surface it before the judge.

Exfiltration claims require finding-specific collection or staging plus network, tool, or data-movement evidence — a suspicious outbound endpoint alone is a lead, not an exfil Finding. Do not assert attribution, actor identity, or intent from network artifacts.

Stop and ask when: `BinaryNotFound`; two consecutive iterations yield no new Findings or contradictions; a `CONFIRMED` Finding corroborates across fewer than 2 artifact classes; or the evidence vault is modified mid-run.

After both pools return Findings, hand off to the reason/seal phase (`/verdict`).
