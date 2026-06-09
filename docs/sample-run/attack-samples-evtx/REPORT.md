[VERDICT · DFIR Case File]{.kicker}

# VERDICT — Forensic Investigation Report

[DFIR at machine speed · sigstore-signed chain of custody]{.tagline}

**Case ID:** `dir-70ca157294e2094d`
**Run ID:** `auto-1780979644`
**Started:** 2026-06-09T04:34:04Z
**Finalized:** 2026-06-09T04:34:05Z
**Evidence:** `/home/analyst/Desktop/PUG-Projects/sans-hackathon/evidence/attack-samples`
**Verdict:** **SUSPICIOUS**

> **Cryptographic attestation:**
> Merkle root `58bb8c25afafb2011d9bf81af4b164c8d3c0b83e67274be0f45e2a8ae9bb0fa4`
> Audit log final hash `5230ada7577bda529e55caf0d76ace50b24d189f0e35c66a32d194aed6422ba5`
> Sigstore signature SHA-256 `1275ead7e2ea767e5f6e3da1c0eae19da645c5ea9f55dd16b961b1a3b5fa812c`
> Cert fingerprint `667c97009f3d46db808cef0a7598cf84f52984e3ac8198f446b405fdd7d61178`

---

## Case Summary

* **Total merged findings:** 3
* **By confidence:**
  - CONFIRMED: 1
  - INFERRED:  0
  - HYPOTHESIS: 2
* **Contradictions surfaced (Pool A vs Pool B):** 0
* **SOUL.md correlator:** 2 kept, 1 downgraded

---


## Bottom Line Up Front

::: {.report-fig data-fig="scorecard"}
:::

**Verdict: SUSPICIOUS.** Confirmed: a Security audit log clearing on PC01.example.corp under the account EXAMPLE\\user01 — defense evasion / anti-forensics.

The supplied evidence shows a Security audit log clearing on PC01.example.corp under the account EXAMPLE\\user01 at 2019-03-19T23:35:07Z.

**Assessment:** Clearing the Windows Security log removes the local record of what happened before it — logons, privilege use, object access, and process creation. It is a recognized anti-forensic / defense-evasion action. Log clearing is not by itself proof of malicious intent; it also happens during legitimate administration, re-imaging, or backup onboarding. The record proves the clearing occurred and names the account, not who operated it or why.

**Certainty:** High — reproducible from the cited tool call \(the verifier re-runs it and matches the SHA-256\) and sealed in the signed run manifest. This does not authenticate the source artifact upstream of this engine, nor does it prove intent or a breach.

**Key findings:**

* A Security audit log clearing on PC01.example.corp under the account EXAMPLE\\user01 \(CONFIRMED, T1070.001, cited by tc-002\).

* Findings: 3 total — 1 confirmed, 0 inferred, 2 hypothesis.
* Most important next step: Use read-only SIFT disk workflow to extract Prefetch, Registry, MFT, USN Journal, and YARA targets before parsing them with typed tools.






## Timeline

Key events in chronological order, traceable by account, host, and address; each cites the tool call that produced it. The full event ledger is in the technical report below.

::: {.report-fig data-fig="sequence"}
:::

::: {.report-fig data-fig="composition"}
:::

### Key Events

| UTC Time | Event | Account | Host | Source IP | Tool Call |
|---|---|---|---|---|---|
| 2019-03-03T09:20:28Z | Service installed: service 'spoolfool' | — | WIN-77LTAPHIQ1R.example.corp | — | `tc-003` |
| 2019-03-03T09:24:24Z | Service installed: service 'spoolsv' | — | WIN-77LTAPHIQ1R.example.corp | — | `tc-003` |
| 2019-03-18T22:15:36Z | Successful logon: account EXAMPLE\\WIN-77LTAPHIQ1R$, logon Network, from fe80::79bf:8ee2:43 | EXAMPLE\\WIN-77LTAPHIQ1R$ | WIN-77LTAPHIQ1R.example.corp | fe80::79bf:8ee2:433c:2567 | `tc-004` |
| 2019-03-18T22:15:49Z | Successful logon: account EXAMPLE\\Administrator, logon Network, from 10.0.2.17 | EXAMPLE\\Administrator | WIN-77LTAPHIQ1R.example.corp | 10.0.2.17 | `tc-004` |
| 2019-03-18T22:15:49Z | Successful logon: account EXAMPLE\\Administrator, logon Network, from 10.0.2.17, workstatio | EXAMPLE\\Administrator | WIN-77LTAPHIQ1R.example.corp | 10.0.2.17 | `tc-004` |
| 2019-03-18T22:15:49Z | Process created: account EXAMPLE\\WIN-77LTAPHIQ1R$, process C:\\Windows\\System32\\wbem\\WmiPrv | EXAMPLE\\WIN-77LTAPHIQ1R$ | WIN-77LTAPHIQ1R.example.corp | — | `tc-004` |
| 2019-03-18T22:15:49Z | Process created: account EXAMPLE\\WIN-77LTAPHIQ1R$, process C:\\Windows\\System32\\calc.exe | EXAMPLE\\WIN-77LTAPHIQ1R$ | WIN-77LTAPHIQ1R.example.corp | — | `tc-004` |
| 2019-03-18T22:15:49Z | Successful logon: account EXAMPLE\\user01, logon Network, from 10.0.2.17 | EXAMPLE\\user01 | WIN-77LTAPHIQ1R.example.corp | 10.0.2.17 | `tc-004` |
| 2019-03-18T22:16:19Z | Successful logon: account EXAMPLE\\WIN-77LTAPHIQ1R$, logon Network, from ::1 | EXAMPLE\\WIN-77LTAPHIQ1R$ | WIN-77LTAPHIQ1R.example.corp | ::1 | `tc-004` |
| 2019-03-19T00:41:29Z | Service installed: service 'remotesvc' | — | WIN-77LTAPHIQ1R.example.corp | — | `tc-003` |
| 2019-03-19T23:35:07Z | Security audit log clearing by EXAMPLE\\user01 | EXAMPLE\\user01 | PC01.example.corp | — | `tc-002` |
| 2019-03-19T23:35:14Z | Windows event 4663: account NT AUTHORITY\\LOCAL SERVICE, process C:\\Windows\\System32\\svchos | NT AUTHORITY\\LOCAL SERVICE | PC01.example.corp | — | `tc-002` |



## Findings Summary

| Confidence | Pool | MITRE | Finding |
|---|---|---|---|
| CONFIRMED | A | T1070.001 | EVTX contains Security EID 1102 audit-log clear event \(record 1\); this is confirmed event-log evidence of log clearing and requires analyst review. |
| HYPOTHESIS | B | T1543.003 | EVTX EID 7045 records installation of service 'spoolfool' \(image cmd.exe\) \(record 1\); service installation is a durable persistence and lateral-movement mechanism — the image path looks suspicious; corroborate the binary and origin before response. |
| HYPOTHESIS | B | T1047 | EVTX Security EID 4688 shows calc.exe with WmiPrvSE.exe as its parent process, under EXAMPLE\\WIN-77LTAPHIQ1R$ \(record 6\) — consistent with remote WMI activity \(a lateral-movement pattern\); corroborate the source host and process bytes. |


## Recommendations

* Use read-only SIFT disk workflow to extract Prefetch, Registry, MFT, USN Journal, and YARA targets before parsing them with typed tools.
* Acquire DNS, proxy, firewall, NetFlow, or PCAP telemetry to test C2 and exfiltration hypotheses.
* Close ATT&amp;CK blind spots before making closure decisions.




## Limitations

What the supplied evidence cannot establish, and how to resolve it.

* Who operated the activity — this report does not assert attribution; naming an account reflects a record field, not the human behind it.
* Whether the wider environment is affected — this run examined the supplied evidence only.
* Undetermined: What the clearing removed from the log. Reason: records that existed before the clearing are not in this artifact; Event 1102 marks the boundary, it does not preserve what was removed. To resolve: recover from WEF/Windows Event Forwarding or SIEM copies up to the clearing time, EDR telemetry, or a VSS/backup of the EVTX predating it.
* Undetermined: Whether the named account was used by its owner or a thief. Reason: a single Security log cannot separate legitimate-owner use from credential theft. To resolve: review 4624/4625 logon history \(type, source host, time\), 4768/4769 Kerberos, and IdP or EDR sign-in data across hosts.
* Undetermined: Whether the clearing was malicious or routine administration. Reason: Event 1102 carries no intent field — the same record is written by a maintenance script and by an intruder. To resolve: check change-management/ticketing, the account's role, and corroborating 4672/4688 events on forwarded logs.
* Undetermined: execution and persistence cannot be confirmed without disk artifacts. To resolve: parse a triage collection — $MFT, $UsnJrnl, Amcache, ShimCache, Prefetch, and Registry run keys/services/tasks.
* Undetermined: command-and-control and exfiltration cannot be assessed without network data. To resolve: collect DNS, proxy, firewall, or NetFlow logs, or a PCAP.
* Undetermined: injected code and hidden processes cannot be examined without a memory image. To resolve: capture RAM and run the volatility process and injection plugins.
* hayabusa did not complete \(tool error\); raw output is in the run audit log. Resolve the tool's prerequisites and re-run.



# Technical Report {.tier-break}

The sections below are the full analyst-grade record: every finding with its
`tool_call_id` and confidence, the complete event timeline, the entity rollup
and indicators, coverage matrices, triage, sources, and the reproducibility and
chain-of-custody appendices.

## Detailed Findings

### Finding 1 — confidence: CONFIRMED, pool: A, MITRE: T1070.001, replay: exact_match (match)

EVTX contains Security EID 1102 audit-log clear event \(record 1\); this is confirmed event-log evidence of log clearing and requires analyst review.

- `tool_call_id`: `tc-002`
- artifact: `/home/analyst/Desktop/PUG-Projects/sans-hackathon/evidence/attack-samples/DE_1102_security_log_cleared.evtx`
- confidence: Confirmed — the cited tool output is reproducible; this does not imply attribution or complete scope.

### Finding 2 — confidence: HYPOTHESIS, pool: B, MITRE: T1543.003, replay: exact_match (match)

hypothesis: EVTX EID 7045 records installation of service 'spoolfool' \(image cmd.exe\) \(record 1\); service installation is a durable persistence and lateral-movement mechanism — the image path looks suspicious; corroborate the binary and origin before response.

- `tool_call_id`: `tc-003`
- artifact: `/home/analyst/Desktop/PUG-Projects/sans-hackathon/evidence/attack-samples/LM_Remote_Service02_7045.evtx`
- confidence: Hypothesis — a single-source triage lead; corroborate before any response action.

### Finding 3 — confidence: HYPOTHESIS, pool: B, MITRE: T1047, replay: exact_match (match)

hypothesis: EVTX Security EID 4688 shows calc.exe with WmiPrvSE.exe as its parent process, under EXAMPLE\\WIN-77LTAPHIQ1R$ \(record 6\) — consistent with remote WMI activity \(a lateral-movement pattern\); corroborate the source host and process bytes.

- `tool_call_id`: `tc-004`
- artifact: `/home/analyst/Desktop/PUG-Projects/sans-hackathon/evidence/attack-samples/LM_WMI_4624_4688_TargetHost.evtx`
- confidence: Hypothesis — a single-source triage lead; corroborate before any response action.





## Full Event Timeline

Normalized timeline events: 127. First 16 rows shown below (consecutive identical events collapsed with an [Nx] count); full data is in `timeline.json` and analyst-friendly `timeline.csv`.

| UTC Time | Artifact | Event | Account | Host | Source IP | Logon | Process/PID | Conf. | Tool Call |
|---|---|---|---|---|---|---|---|---|---|
| 2019-03-03T09:20:28Z | evtx | Service installed: service 'spoolfool' | — | WIN-77LTAPHIQ1R.example.corp | — | — | — | HYPOTHESIS | `tc-003` |
| 2019-03-03T09:24:24Z | evtx | Service installed: service 'spoolsv' | — | WIN-77LTAPHIQ1R.example.corp | — | — | — | — | `tc-003` |
| 2019-03-18T22:15:36Z | evtx | Successful logon: account EXAMPLE\\WIN-77LTAPHIQ1R$, logon Network, from fe80::79bf:8ee2:433c:2567 | EXAMPLE\\WIN-77LTAPHIQ1R$ | WIN-77LTAPHIQ1R.example.corp | fe80::79bf:8ee2:433c:2567 | Network | 0x0 | — | `tc-004` |
| 2019-03-18T22:15:49Z | evtx | \[2x\] Successful logon: account EXAMPLE\\Administrator, logon Network, from 10.0.2.17 | EXAMPLE\\Administrator | WIN-77LTAPHIQ1R.example.corp | 10.0.2.17 | Network | 0x0 | — | `tc-004` |
| 2019-03-18T22:15:49Z | evtx | Successful logon: account EXAMPLE\\Administrator, logon Network, from 10.0.2.17, workstation PC01 | EXAMPLE\\Administrator | WIN-77LTAPHIQ1R.example.corp | 10.0.2.17 | Network | 0x0 | — | `tc-004` |
| 2019-03-18T22:15:49Z | evtx | Process created: account EXAMPLE\\WIN-77LTAPHIQ1R$, process C:\\Windows\\System32\\wbem\\WmiPrvSE.exe | EXAMPLE\\WIN-77LTAPHIQ1R$ | WIN-77LTAPHIQ1R.example.corp | — | — | C:\\Windows\\System32\\wbem\\WmiPrvSE.exe \(0xae8\) | — | `tc-004` |
| 2019-03-18T22:15:49Z | evtx | Process created: account EXAMPLE\\WIN-77LTAPHIQ1R$, process C:\\Windows\\System32\\calc.exe | EXAMPLE\\WIN-77LTAPHIQ1R$ | WIN-77LTAPHIQ1R.example.corp | — | — | C:\\Windows\\System32\\calc.exe \(0x424\) | HYPOTHESIS | `tc-004` |
| 2019-03-18T22:15:49Z | evtx | Successful logon: account EXAMPLE\\user01, logon Network, from 10.0.2.17 | EXAMPLE\\user01 | WIN-77LTAPHIQ1R.example.corp | 10.0.2.17 | Network | 0x0 | — | `tc-004` |
| 2019-03-18T22:16:19Z | evtx | Successful logon: account EXAMPLE\\WIN-77LTAPHIQ1R$, logon Network, from ::1 | EXAMPLE\\WIN-77LTAPHIQ1R$ | WIN-77LTAPHIQ1R.example.corp | ::1 | Network | 0x0 | — | `tc-004` |
| 2019-03-19T00:41:29Z | evtx | Service installed: service 'remotesvc' | — | WIN-77LTAPHIQ1R.example.corp | — | — | — | — | `tc-003` |
| 2019-03-19T23:35:07Z | evtx | Security audit log clearing by EXAMPLE\\user01 | EXAMPLE\\user01 | PC01.example.corp | — | — | — | CONFIRMED | `tc-002` |
| 2019-03-19T23:35:08Z | evtx | Windows event 5156 | — | PC01.example.corp | — | — | — | — | `tc-002` |
| 2019-03-19T23:35:14Z | evtx | \[110x\] Windows event 4663: account NT AUTHORITY\\LOCAL SERVICE, process C:\\Windows\\System32\\svchost.exe | NT AUTHORITY\\LOCAL SERVICE | PC01.example.corp | — | — | C:\\Windows\\System32\\svchost.exe \(0x5a8\) | — | `tc-002` |
| 2020-09-09T13:18:23Z | evtx | Failed logon: account MSEDGEWIN10\\IEUser, logon Interactive, workstation MSEDGEWIN10, process C:\\Program Files | MSEDGEWIN10\\IEUser | MSEDGEWIN10 | — | Interactive | C:\\Program Files \(x86\)\\Google\\Chrome\\Application\\chrome.exe \(0x1358\) | — | `tc-001` |
| 2020-09-09T13:18:25Z | evtx | Successful logon: account NT AUTHORITY\\SYSTEM, logon Service, process C:\\Windows\\System32\\services.exe | NT AUTHORITY\\SYSTEM | MSEDGEWIN10 | — | Service | C:\\Windows\\System32\\services.exe \(0x25c\) | — | `tc-001` |
| 2020-09-09T13:18:27Z | evtx | \[2x\] Successful logon: account MSEDGEWIN10\\IEUser, logon Interactive, workstation MSEDGEWIN10, process C:\\Program F | MSEDGEWIN10\\IEUser | MSEDGEWIN10 | — | Interactive | C:\\Program Files \(x86\)\\Google\\Chrome\\Application\\chrome.exe \(0x1358\) | — | `tc-001` |




## Observed Hosts, Accounts & Processes

Every account, host, address, and process observed across the timeline, with where it first and last appears and which findings cite it.

### Accounts

| Value | Events | First Seen | Last Seen | Findings |
|---|---:|---|---|---|
| NT AUTHORITY\\LOCAL SERVICE | 110 | 2019-03-19T23:35:14Z | 2019-03-19T23:35:15Z | — |
| EXAMPLE\\WIN-77LTAPHIQ1R$ | 4 | 2019-03-18T22:15:36Z | 2019-03-18T22:16:19Z | f-B-evtx-wmi-exec |
| EXAMPLE\\Administrator | 3 | 2019-03-18T22:15:49Z | 2019-03-18T22:15:49Z | — |
| MSEDGEWIN10\\IEUser | 3 | 2020-09-09T13:18:23Z | 2020-09-09T13:18:27Z | — |
| EXAMPLE\\user01 | 2 | 2019-03-18T22:15:49Z | 2019-03-19T23:35:07Z | f-A-evtx-audit-log-cleared |
| NT AUTHORITY\\SYSTEM | 1 | 2020-09-09T13:18:25Z | 2020-09-09T13:18:25Z | — |

### Hosts

| Value | Events | First Seen | Last Seen | Findings |
|---|---:|---|---|---|
| PC01.example.corp | 112 | 2019-03-19T23:35:07Z | 2019-03-19T23:35:15Z | f-A-evtx-audit-log-cleared |
| WIN-77LTAPHIQ1R.example.corp | 11 | 2019-03-03T09:20:28Z | 2019-03-19T00:41:29Z | f-B-evtx-service-install, f-B-evtx-wmi-exec |
| MSEDGEWIN10 | 4 | 2020-09-09T13:18:23Z | 2020-09-09T13:18:27Z | — |

### Workstations

| Value | Events | First Seen | Last Seen | Findings |
|---|---:|---|---|---|
| MSEDGEWIN10 | 3 | 2020-09-09T13:18:23Z | 2020-09-09T13:18:27Z | — |
| PC01 | 1 | 2019-03-18T22:15:49Z | 2019-03-18T22:15:49Z | — |

### Source IPs

| Value | Events | First Seen | Last Seen | Findings |
|---|---:|---|---|---|
| 10.0.2.17 | 4 | 2019-03-18T22:15:49Z | 2019-03-18T22:15:49Z | — |
| ::1 | 1 | 2019-03-18T22:16:19Z | 2019-03-18T22:16:19Z | — |
| fe80::79bf:8ee2:433c:2567 | 1 | 2019-03-18T22:15:36Z | 2019-03-18T22:15:36Z | — |

### Processes

| Value | Events | First Seen | Last Seen | Findings |
|---|---:|---|---|---|
| C:\\Windows\\System32\\svchost.exe | 110 | 2019-03-19T23:35:14Z | 2019-03-19T23:35:15Z | — |
| C:\\Program Files \(x86\)\\Google\\Chrome\\Application\\chrome.exe | 3 | 2020-09-09T13:18:23Z | 2020-09-09T13:18:27Z | — |
| C:\\Windows\\System32\\calc.exe | 1 | 2019-03-18T22:15:49Z | 2019-03-18T22:15:49Z | f-B-evtx-wmi-exec |
| C:\\Windows\\System32\\services.exe | 1 | 2020-09-09T13:18:25Z | 2020-09-09T13:18:25Z | — |
| C:\\Windows\\System32\\wbem\\WmiPrvSE.exe | 1 | 2019-03-18T22:15:49Z | 2019-03-18T22:15:49Z | — |

### Services

| Value | Events | First Seen | Last Seen | Findings |
|---|---:|---|---|---|
| remotesvc | 1 | 2019-03-19T00:41:29Z | 2019-03-19T00:41:29Z | — |
| spoolfool | 1 | 2019-03-03T09:20:28Z | 2019-03-03T09:20:28Z | f-B-evtx-service-install |
| spoolsv | 1 | 2019-03-03T09:24:24Z | 2019-03-03T09:24:24Z | — |




## Indicators of Compromise (IOCs)

Observed artifacts pulled from the timeline and findings; validate or corroborate before detection deployment or blocking.

| Type | Values |
|---|---|
| Accounts | EXAMPLE\\Administrator, EXAMPLE\\WIN-77LTAPHIQ1R$, EXAMPLE\\user01, MSEDGEWIN10\\IEUser, NT AUTHORITY\\LOCAL SERVICE, NT AUTHORITY\\SYSTEM |
| Hosts / Workstations | MSEDGEWIN10, PC01, PC01.example.corp, WIN-77LTAPHIQ1R.example.corp |
| IP addresses | 10.0.2.17, ::1, fe80::79bf:8ee2:433c:2567 |
| Processes | C:\\Program Files \(x86\)\\Google\\Chrome\\Application\\chrome.exe, C:\\Windows\\System32\\calc.exe, C:\\Windows\\System32\\services.exe, C:\\Windows\\System32\\svchost.exe, C:\\Windows\\System32\\wbem\\WmiPrvSE.exe |
| Services | remotesvc, spoolfool, spoolsv |
| File paths | calc.exe, cmd.exe |




## MITRE ATT&CK Coverage

5/12 ATT&CK targets covered by typed-tool output; 0 target(s) produced finding-level evidence; 7 target(s) remain blind spots

| Technique | Tactic | Status | Tools Observed | Gap / Analyst Value |
|---|---|---|---|---|
| T1014 Rootkit | Defense Evasion | blind spot | `none` | missing or untouched artifact classes: memory |
| T1055 Process Injection | Defense Evasion / Privilege Escalation | blind spot | `none` | missing or untouched artifact classes: memory |
| T1059.001 PowerShell | Execution | covered, no finding \(limited\) | `evtx_query, hayabusa_scan` | limited coverage — not proof of absence |
| T1021.001 Remote Desktop Protocol | Lateral Movement | covered, no finding \(limited\) | `evtx_query, hayabusa_scan` | limited coverage — not proof of absence |
| T1078 Valid Accounts | Defense Evasion / Persistence / Privilege Escalation | covered, no finding \(limited\) | `evtx_query, hayabusa_scan` | limited coverage — not proof of absence |
| T1003 OS Credential Dumping | Credential Access | covered, no finding \(limited\) | `evtx_query, hayabusa_scan` | limited coverage — not proof of absence |
| T1105 Ingress Tool Transfer | Command and Control | blind spot | `none` | missing or untouched artifact classes: disk/filesystem, network |
| T1071.001 Web Protocols | Command and Control | blind spot | `none` | missing or untouched artifact classes: network |
| T1071.004 DNS | Command and Control | blind spot | `none` | missing or untouched artifact classes: network |
| T1041 Exfiltration Over C2 Channel | Exfiltration | blind spot | `none` | missing or untouched artifact classes: network |
| T1547.001 Registry Run Keys / Startup Folder | Persistence / Privilege Escalation | blind spot | `none` | missing or untouched artifact classes: disk/filesystem |
| T1053.005 Scheduled Task | Execution / Persistence / Privilege Escalation | covered, no finding \(limited\) | `evtx_query, hayabusa_scan` | limited coverage — not proof of absence |




## Evidence Coverage

1/5 artifact classes touched; 1/5 directly available from supplied evidence

| Artifact Class | Available | Touched | Tools | Confidence Impact |
|---|:---:|:---:|---|---|
| memory | no | no | `none` | not a memory image; no live-process evidence |
| evtx | yes | yes | `evtx_query, hayabusa_scan` | Windows event evidence available |
| disk/filesystem | no | no | `none` | no disk image supplied; execution/persistence corroboration is limited |
| network | no | no | `none` | no PCAP, Zeek, firewall, DNS, or proxy logs supplied |
| velociraptor | no | no | `none` | no Velociraptor collection supplied |






## Analysis Coverage by Domain

This table shows which DFIR analysis domains the typed tools exercised on the supplied evidence. Coverage is scope, not assurance.

| Domain | Status | Artifacts Seen | Tools Run | Data Sources | Gaps |
|---|---|---|---|---|---|
| Host &amp; Endpoint Forensics | not_covered | none | `none` | none | missing or untouched artifact classes: disk/filesystem |
| Endpoint Telemetry &amp; Live Response | not_covered | none | `none` | none | missing or untouched artifact classes: velociraptor |
| Malware Analysis &amp; Triage | not_covered | none | `none` | none | missing or untouched artifact classes: disk/filesystem, memory |
| Memory Forensics | not_covered | none | `none` | none | missing or untouched artifact classes: memory |
| Network Forensics | not_covered | none | `none` | none | missing or untouched artifact classes: network, no PCAP, Zeek, proxy, DNS, firewall, or NetFlow telemetry supplied |
| Windows Event &amp; Account Analysis | automated | evtx | `evtx_query, hayabusa_scan` | DS0003, DS0009, DS0017, DS0019, DS0028 | none |

**Overclaim guardrails applied:** covered_no_finding is limited coverage, not a clean/cleared claim, Domain coverage describes triage/orchestration across the typed tools that ran, not certified-analyst judgment, visual exhibits do not create findings or upgrade confidence, execution claims still require at least two artifact classes






## Windows Event Log Summary

* Records seen: 8
* Rows returned: 8
* Parse errors: 0
* Channels: Security
* Top Event IDs: EID 4624 x6, EID 4688 x2
* Verdict contribution: finding — high-signal event semantics produced finding-level evidence




## Figures

Visual exhibits are generated from parsed tool outputs. They support cited findings but do not replace `tool_call_id`-backed evidence or upgrade confidence by themselves.

### EVTX contains Security EID 1102 audit-log clear event
* Card: `evidence-card-001`
* Linked findings: `f-A-evtx-audit-log-cleared`
* Tool call: `tc-002`
* Source records: `evtx_query:record_id=1;event_id=1102, evtx_query:record_id=2;event_id=5156, evtx_query:record_id=3;event_id=4663;pid=0x5a8`
* Confidence: `CONFIRMED`
* Citations: `CITE-MITRE-ATTACK-DATASOURCES`
* Why suspicious/relevant: This observable is relevant because finding 'f-A-evtx-audit-log-cleared' is backed by parsed tool output 'tc-002' and should be interpreted with the cited artifact and source caveats.
* Snippet: `EVTX contains Security EID 1102 audit-log clear event \(record 1\); this is confirmed event-log evidence of log clearing and requires analyst review.`
* Caveats: Visual exhibit supports the cited finding but does not replace parsed tool output.

### hypothesis
* Card: `evidence-card-002`
* Linked findings: `f-B-evtx-service-install`
* Tool call: `tc-003`
* Source records: `evtx_query:record_id=1;event_id=7045, evtx_query:record_id=2;event_id=7045, evtx_query:record_id=3;event_id=7045`
* Confidence: `HYPOTHESIS`
* Citations: `CITE-MITRE-ATTACK-DATASOURCES`
* Why suspicious/relevant: This observable is relevant because finding 'f-B-evtx-service-install' is backed by parsed tool output 'tc-003' and should be interpreted with the cited artifact and source caveats.
* Snippet: `hypothesis: EVTX EID 7045 records installation of service 'spoolfool' \(image cmd.exe\) \(record 1\); service installation is a durable persistence and lateral-movement mechanism — the image path looks suspicious; corroborate the binary and ori`
* Caveats: Visual exhibit supports the cited finding but does not replace parsed tool output., HYPOTHESIS confidence requires additional artifact corroboration.

### hypothesis
* Card: `evidence-card-003`
* Linked findings: `f-B-evtx-wmi-exec`
* Tool call: `tc-004`
* Source records: `evtx_query:record_id=1;event_id=4624;pid=0x0, evtx_query:record_id=2;event_id=4624;pid=0x0, evtx_query:record_id=3;event_id=4624;pid=0x0`
* Confidence: `HYPOTHESIS`
* Citations: `CITE-MITRE-ATTACK-DATASOURCES`
* Why suspicious/relevant: This observable is relevant because finding 'f-B-evtx-wmi-exec' is backed by parsed tool output 'tc-004' and should be interpreted with the cited artifact and source caveats.
* Snippet: `hypothesis: EVTX Security EID 4688 shows calc.exe with WmiPrvSE.exe as its parent process, under EXAMPLE\\WIN-77LTAPHIQ1R$ \(record 6\) — consistent with remote WMI activity \(a lateral-movement pattern\); corroborate the source host and process`
* Caveats: Visual exhibit supports the cited finding but does not replace parsed tool output., HYPOTHESIS confidence requires additional artifact corroboration.




## References

| Citation ID | Title | URL | Supports |
|---|---|---|---|
| `CITE-MITRE-ATTACK-DATASOURCES` | MITRE ATT&amp;CK Data Sources | https://attack.mitre.org/datasources/ | ATT&amp;CK data-source coverage mapping |
| `CITE-MITRE-T1003-001` | MITRE ATT&amp;CK T1003.001 LSASS Memory | https://attack.mitre.org/techniques/T1003/001/ | LSASS credential-dumping interpretation |
| `CITE-MITRE-T1014` | MITRE ATT&amp;CK T1014 Rootkit | https://attack.mitre.org/techniques/T1014/ | DKOM/rootkit process-view divergence interpretation |
| `CITE-NIST-800-61R2` | NIST SP 800-61 Rev. 2 Computer Security Incident Handling Guide | https://csrc.nist.gov/pubs/sp/800/61/r2/final | separation of evidence, analysis, response actions, and gaps |
| `CITE-PLASO` | Plaso/log2timeline documentation | https://plaso.readthedocs.io/ | multi-source forensic timeline normalization |
| `CITE-TIMESKETCH` | Timesketch documentation | https://timesketch.org/ | analyst-oriented forensic timeline review |
| `CITE-VOLATILITY3` | Volatility 3 documentation | https://volatility3.readthedocs.io/ | memory plugin output and process-view validation |
| `CITE-ZEEK-LOGS` | Zeek log documentation | https://docs.zeek.org/en/current/logs/index.html | network log and protocol-semantic coverage |
| `CITE-VELOCIRAPTOR-ARTIFACTS` | Velociraptor artifact documentation | https://docs.velociraptor.app/docs/artifacts/ | artifact-based endpoint collection |
| `CITE-SIGMAHQ` | SigmaHQ rules repository | https://github.com/SigmaHQ/sigma | structured log detection rules as triage leads |
| `CITE-HAYABUSA` | Hayabusa repository | https://github.com/Yamato-Security/hayabusa | Windows EVTX timeline and hunting output |
| `CITE-CAPA` | capa repository | https://github.com/mandiant/capa | malware capability triage limits |






## Recommended Analyst Actions

| Priority | Action | Why | Based On | Expected Evidence |
|---|---|---|---|---|
| P2 | Use read-only SIFT disk workflow to extract Prefetch, Registry, MFT, USN Journal, and YARA targets before parsing them with typed tools. | Execution and persistence claims need disk-backed corroboration; memory-only observations are not enough for final execution claims. | disk_gap | ewfmount read-only mount, Sleuth Kit file extraction, Prefetch, Amcache/ShimCache, Run keys, services, scheduled tasks, MFT/USN entries |
| P3 | Acquire DNS, proxy, firewall, NetFlow, or PCAP telemetry to test C2 and exfiltration hypotheses. | Network telemetry was not supplied or parsed in this run, so exfiltration and command-and-control coverage remains a blind spot. | network_gap | DNS queries, proxy URLs, firewall sessions, PCAP, Velociraptor network collection |
| P3 | Close ATT&amp;CK blind spots before making closure decisions. | The coverage matrix identifies target techniques with no supporting artifact class in this run. | T1014, T1055, T1105, T1071.001, T1071.004 | Additional evidence classes mapped in attack_coverage.targets\[\].artifact_classes |
| P4 | Pivot from the first and last normalized timeline events into adjacent artifact classes. | Temporal clustering often exposes execution chains that a single artifact class cannot prove alone. | timeline | timeline.csv plus adjacent EVTX, Prefetch, MFT, and network events |
| P4 | Verify run.manifest.json with manifest_verify before sharing or archiving results. | The audit chain and Merkle root are the reproducibility boundary for judge and analyst review. | custody | run.manifest.json, audit.jsonl, verdict.json, timeline.csv |




## Reproducibility Appendix

Verifier replay artifacts record whether each cited tool call reproduced the audited output hash. They do not change Track 3b severity policy.

| Finding | Tool | Drift class | Match | Expected SHA | Actual SHA |
|---|---|---|:---:|---|---|
| f-A-evtx-audit-log-cleared | `evtx_query` | `exact_match` | yes | `3d3dd6940055` | `3d3dd6940055` |
| f-B-evtx-service-install | `evtx_query` | `exact_match` | yes | `c02ce481d2f1` | `c02ce481d2f1` |
| f-B-evtx-wmi-exec | `evtx_query` | `exact_match` | yes | `51f6fa751e99` | `51f6fa751e99` |


---

## Chain of Custody

![Chain of custody](figures/chain_of_custody.png)

---

## Integrity Verification

This investigation produced a `run.manifest.json` that any third party can
verify offline from the VERDICT repository using the manifest verification
library or the `manifest_verify` MCP tool. There is no standalone
`manifest_verify` shell command in this repo.

```bash
uv run --directory services/agent python -c "from pathlib import Path; from findevil_agent.crypto.manifest import verify_manifest; print(verify_manifest(Path('PATH/TO/run.manifest.json'), audit_log_path=Path('PATH/TO/audit.jsonl')).model_dump_json(indent=2))"
# returns overall=true if the audit chain and Merkle root validate and signature metadata is present
```

The verifier rebuilds:
1. The audit chain by walking `prev_hash` SHA-256 links (catches backdated edits).
2. The Merkle tree from the manifest's `leaves[]` array (catches selective redaction).
3. The signature bundle metadata recorded in the manifest. Full signature and
   transparency-log validation must be performed separately when a production
   signer is used.

A tamper test against this manifest's `merkle_root_hex` was not run automatically.
To execute it, copy the manifest, overwrite `merkle_root_hex` with `ff` repeated
32 times, then run the same Python verification command against the tampered copy.

```bash
python -c "import shutil;shutil.copyfile('run.manifest.json','run.manifest.tamper.json')"
python -c "import json,pathlib;p=pathlib.Path('run.manifest.tamper.json');d=json.loads(p.read_text());d['merkle_root_hex']='ff'*32;p.write_text(json.dumps(d,indent=2,sort_keys=True))"
uv run --directory services/agent python -c "from pathlib import Path; from findevil_agent.crypto.manifest import verify_manifest; print(verify_manifest(Path('PATH/TO/run.manifest.tamper.json'), audit_log_path=Path('PATH/TO/audit.jsonl')).model_dump_json(indent=2))"
```

---

*Produced by `find-evil-auto` (the VERDICT automated investigation orchestrator).
The cryptographic attestation values shown are the actual outputs of this run; every
quantitative claim above is independently verifiable from the artifacts in this
directory (`audit.jsonl`, `run.manifest.json`, `verdict.json`). The automated
QA / expert-signoff gates for this run are in the companion `REPORT-internal` packet.*
