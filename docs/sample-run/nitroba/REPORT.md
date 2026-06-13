[VERDICT · DFIR Case File]{.kicker}

# VERDICT — Forensic Investigation Report

[DFIR at machine speed · signed, replayable chain of custody]{.tagline}

**Case ID:** `3dec6921-0d8f-4dbc-bb0e-135a560a47a9`
**Run ID:** `auto-1781197622`
**Started:** 2026-06-11T17:07:02Z
**Finalized:** 2026-06-11T17:07:25Z
**Evidence:** `/home/analyst/Desktop/PUG-Projects/sans-hackathon/evidence/nitroba.pcap`
**Verdict:** **INDETERMINATE**

> **Cryptographic attestation:**
> Merkle root `160be4dd293b83b3045ab704cb67c6be7f62bb8070d60e19fb5bd34e914cb430`
> Audit log final hash `91aed184ba46f722bc96df2bd8053223d068b5b6a5164484e3d62a84d857effc`
> Sigstore signature SHA-256 `c51309a893715f9676f582c612eeae60ac293ef153d3d5de2b51abfc30d99fc0`
> Cert fingerprint `7f0a7966906a2b48aba2e397fd7ec8637f994b00007124c846d1332ac5c722a2`

---


## Bottom Line Up Front

::: {.report-fig data-fig="scorecard"}
:::

**Verdict: INDETERMINATE.** Triage lead: suspicious activity — suspicious activity.

The supplied evidence shows suspicious activity.

**Assessment:** The cited tool output meets a defined detection rule for this technique. Treat single-source signals as leads until corroborated across artifact classes.

**Certainty:** Low — a single-source lead; a direction to pursue, not a conclusion.

**Key findings:**

* The run produced only triage-level leads; read each cited tool call in the findings detail before acting.

* Findings: 9 total — 0 confirmed, 0 inferred, 9 hypothesis.
* Most important next step: Review notable external conversations for protocol semantics, byte counts, session timing, and host ownership.




## Host Analysis

### nitroba.pcap

*9 finding(s) — 0 confirmed, 0 inferred, 9 hypothesis · 0 events · time not recorded · source: nitroba.pcap*

**Command &amp; Control: T1071.001** `[HYPOTHESIS]` `tc-002`

The cited tool output meets a defined detection rule for this technique. Treat single-source signals as leads until corroborated across artifact classes.

**Command &amp; Control: T1071.001** `[HYPOTHESIS]` `tc-002`

The cited tool output meets a defined detection rule for this technique. Treat single-source signals as leads until corroborated across artifact classes.

**Command &amp; Control: T1071.001** `[HYPOTHESIS]` `tc-002`

The cited tool output meets a defined detection rule for this technique. Treat single-source signals as leads until corroborated across artifact classes.

**Command &amp; Control: T1071.001** `[HYPOTHESIS]` `tc-002`

The cited tool output meets a defined detection rule for this technique. Treat single-source signals as leads until corroborated across artifact classes.

**Command &amp; Control: T1071.001** `[HYPOTHESIS]` `tc-002`

The cited tool output meets a defined detection rule for this technique. Treat single-source signals as leads until corroborated across artifact classes.

**Command &amp; Control: T1071.001** `[HYPOTHESIS]` `tc-002`

The cited tool output meets a defined detection rule for this technique. Treat single-source signals as leads until corroborated across artifact classes.

**Command &amp; Control: T1071.001** `[HYPOTHESIS]` `tc-002`

The cited tool output meets a defined detection rule for this technique. Treat single-source signals as leads until corroborated across artifact classes.

**Command &amp; Control: T1071.001** `[HYPOTHESIS]` `tc-002`

The cited tool output meets a defined detection rule for this technique. Treat single-source signals as leads until corroborated across artifact classes.

**Command &amp; Control: T1071.001** `[HYPOTHESIS]` `tc-002`

The cited tool output meets a defined detection rule for this technique. Treat single-source signals as leads until corroborated across artifact classes.




## Recommendations

* Review notable external conversations for protocol semantics, byte counts, session timing, and host ownership.
* Collect Security, Sysmon, and PowerShell Operational EVTX and rerun EVTX/Hayabusa analysis.
* Use the disk artifact summary to pivot between Prefetch, Registry, MFT, USN, EVTX, and YARA-target rows without upgrading single-source execution claims.




## Limitations

What the supplied evidence cannot establish, and how to resolve it.

* Who operated the activity — this report does not assert attribution; naming an account reflects a record field, not the human behind it.
* Whether the wider environment is affected — this run examined the supplied evidence only.
* Undetermined: injected code and hidden processes cannot be examined without a memory image. To resolve: capture RAM and run the volatility process and injection plugins.
* Undetermined: logon, process-creation, and PowerShell activity cannot be reviewed without event logs. To resolve: collect the Security, Sysmon/Operational, and PowerShell/Operational logs.



# Technical Report {.tier-break}

The sections below are the full analyst-grade record: every finding with its
`tool_call_id` and confidence, the complete event timeline, the entity rollup
and indicators, coverage matrices, triage, sources, and the reproducibility and
chain-of-custody appendices.

## Case Summary

* **Total merged findings:** 9
* **By confidence:**
  - CONFIRMED: 0
  - INFERRED:  0
  - HYPOTHESIS: 9
* **Contradictions surfaced (Pool A vs Pool B):** 14
* **SOUL.md correlator:** 9 kept, 0 downgraded

## Detailed Findings

### Finding 1 — confidence: HYPOTHESIS, pool: A, MITRE: T1071.001, replay: exact_match (match)

hypothesis: pcap_triage observed a notable external conversation to 69.59.235.129:10224 \(external destination on uncommon port 10224\). Treat as network triage context for C2 or transfer hypotheses only; do not claim data loss without separate collection/staging plus tool or data-movement evidence.

- `tool_call_id`: `tc-002`
- artifact: `/home/analyst/Desktop/PUG-Projects/sans-hackathon/evidence/nitroba.pcap`
- confidence: Hypothesis — a single-source triage lead; corroborate before any response action.

### Finding 2 — confidence: HYPOTHESIS, pool: A, MITRE: T1071.001, replay: exact_match (match)

hypothesis: Timeline correlation: the anonymous/harassing-email sends from internal host 192.168.15.4 \(first at 2008-07-22T06:01:26Z\) fall within the same browsing session as that host's authenticated web activity \(2008-07-22T04:29:53Z to 2008-07-22T06:03:44Z\) — the harassing-email send times correlate in time with the suspect host's browsing activity. Cross-flow timing link only; do not name a person from network metadata alone.

- `tool_call_id`: `tc-002`
- artifact: `/home/analyst/Desktop/PUG-Projects/sans-hackathon/evidence/nitroba.pcap`
- confidence: Hypothesis — a single-source triage lead; corroborate before any response action.

### Finding 3 — confidence: HYPOTHESIS, pool: B, MITRE: T1071.001, replay: exact_match (match)

hypothesis: Authenticated webmail session to 'mail.google.com' from internal host 192.168.15.4 \(HTTP session cookie present\) — attributes the web/email activity on 192.168.15.4 to a specific webmail account, corroborating the source host's identity. Account ownership still requires provider records.

- `tool_call_id`: `tc-002`
- artifact: `/home/analyst/Desktop/PUG-Projects/sans-hackathon/evidence/nitroba.pcap`
- confidence: Hypothesis — a single-source triage lead; corroborate before any response action.

### Finding 4 — confidence: HYPOTHESIS, pool: B, MITRE: T1071.001, replay: exact_match (match)

hypothesis: Authenticated social-media login to facebook \('www.facebook.com'\) from internal host 192.168.15.4 \(HTTP session cookie present\) — ties the activity on 192.168.15.4 to a named social-media account and corroborates the suspect's identity. Account ownership still requires provider records; do not name a person from network metadata alone.

- `tool_call_id`: `tc-002`
- artifact: `/home/analyst/Desktop/PUG-Projects/sans-hackathon/evidence/nitroba.pcap`
- confidence: Hypothesis — a single-source triage lead; corroborate before any response action.

### Finding 5 — confidence: HYPOTHESIS, pool: B, MITRE: T1071.001, replay: exact_match (match)

hypothesis: Internal host 192.168.15.4 submitted a request \(HTTP POST\) to anonymous/self-destructing email service 'www.sendanonymousemail.net' \(sendanonymousemail\) over HTTP — consistent with sending an anonymous or harassing message, and identifies 192.168.15.4 as the originating source host. Corroborate the message body/recipient before naming a person; do not assert attribution from network metadata alone.

- `tool_call_id`: `tc-002`
- artifact: `/home/analyst/Desktop/PUG-Projects/sans-hackathon/evidence/nitroba.pcap`
- confidence: Hypothesis — a single-source triage lead; corroborate before any response action.

### Finding 6 — confidence: HYPOTHESIS, pool: B, MITRE: T1071.001, replay: exact_match (match)

hypothesis: Authenticated webmail session to 'b.mail.google.com' from internal host 192.168.15.4 \(HTTP session cookie present\) — attributes the web/email activity on 192.168.15.4 to a specific webmail account, corroborating the source host's identity. Account ownership still requires provider records.

- `tool_call_id`: `tc-002`
- artifact: `/home/analyst/Desktop/PUG-Projects/sans-hackathon/evidence/nitroba.pcap`
- confidence: Hypothesis — a single-source triage lead; corroborate before any response action.

### Finding 7 — confidence: HYPOTHESIS, pool: B, MITRE: T1071.001, replay: exact_match (match)

hypothesis: Authenticated webmail session to 'mail.live.com' from internal host 192.168.15.4 \(HTTP session cookie present\) — attributes the web/email activity on 192.168.15.4 to a specific webmail account, corroborating the source host's identity. Account ownership still requires provider records.

- `tool_call_id`: `tc-002`
- artifact: `/home/analyst/Desktop/PUG-Projects/sans-hackathon/evidence/nitroba.pcap`
- confidence: Hypothesis — a single-source triage lead; corroborate before any response action.

### Finding 8 — confidence: HYPOTHESIS, pool: B, MITRE: T1071.001, replay: exact_match (match)

hypothesis: Authenticated webmail session to 'chatenabled.mail.google.com' from internal host 192.168.1.64 \(HTTP session cookie present\) — attributes the web/email activity on 192.168.1.64 to a specific webmail account, corroborating the source host's identity. Account ownership still requires provider records.

- `tool_call_id`: `tc-002`
- artifact: `/home/analyst/Desktop/PUG-Projects/sans-hackathon/evidence/nitroba.pcap`
- confidence: Hypothesis — a single-source triage lead; corroborate before any response action.

### Finding 9 — confidence: HYPOTHESIS, pool: B, MITRE: T1071.001, replay: exact_match (match)

hypothesis: Internal host 192.168.15.4 contacted anonymous/self-destructing email service 'www.willselfdestruct.com' \(willselfdestruct\) over HTTP — consistent with sending an anonymous or harassing message, and identifies 192.168.15.4 as the originating source host. Corroborate the message body/recipient before naming a person; do not assert attribution from network metadata alone.

- `tool_call_id`: `tc-002`
- artifact: `/home/analyst/Desktop/PUG-Projects/sans-hackathon/evidence/nitroba.pcap`
- confidence: Hypothesis — a single-source triage lead; corroborate before any response action.









## Indicators of Compromise (IOCs)

Observed artifacts pulled from the timeline and findings; validate or corroborate before detection deployment or blocking.

| Type | Values |
|---|---|
| IP addresses | 192.168.1.64, 192.168.15.4, 69.59.235.129 |
| Domains | b.mail.google.com, chatenabled.mail.google.com, facebook.com, mail.google.com, mail.live.com, sendanonymousemail.net, willselfdestruct.com |




## MITRE ATT&CK Coverage

4/12 ATT&CK targets covered by typed-tool output; 1 target(s) produced finding-level evidence; 8 target(s) remain blind spots

| Technique | Tactic | Status | Tools Observed | Gap / Analyst Value |
|---|---|---|---|---|
| T1014 Rootkit | Defense Evasion | blind spot | `none` | missing or untouched artifact classes: memory |
| T1055 Process Injection | Defense Evasion / Privilege Escalation | blind spot | `none` | missing or untouched artifact classes: memory |
| T1059.001 PowerShell | Execution | blind spot | `none` | missing or untouched artifact classes: evtx |
| T1021.001 Remote Desktop Protocol | Lateral Movement | blind spot | `none` | missing or untouched artifact classes: evtx |
| T1078 Valid Accounts | Defense Evasion / Persistence / Privilege Escalation | blind spot | `none` | missing or untouched artifact classes: evtx |
| T1003 OS Credential Dumping | Credential Access | blind spot | `none` | missing or untouched artifact classes: evtx, memory |
| T1105 Ingress Tool Transfer | Command and Control | covered, no finding \(limited\) | `pcap_triage` | limited coverage — not proof of absence |
| T1071.001 Web Protocols | Command and Control | finding \(HYPOTHESIS\) | `pcap_triage` | finding-level evidence exists; preserve cited tool output |
| T1071.004 DNS | Command and Control | covered, no finding \(limited\) | `pcap_triage` | limited coverage — not proof of absence |
| T1041 Exfiltration Over C2 Channel | Exfiltration | covered, no finding \(limited\) | `pcap_triage` | limited coverage — not proof of absence |
| T1547.001 Registry Run Keys / Startup Folder | Persistence / Privilege Escalation | blind spot | `none` | missing or untouched artifact classes:  |
| T1053.005 Scheduled Task | Execution / Persistence / Privilege Escalation | blind spot | `none` | missing or untouched artifact classes: evtx |




## Evidence Coverage

2/5 artifact classes touched; 1/5 directly available from supplied evidence

| Artifact Class | Available | Touched | Tools | Confidence Impact |
|---|:---:|:---:|---|---|
| memory | no | no | `none` | not a memory image; no live-process evidence |
| evtx | no | no | `none` | no event log supplied in this single-evidence run |
| disk/filesystem | no | yes | `none` | no disk image supplied; execution/persistence corroboration is limited |
| network | yes | yes | `pcap_triage` | network telemetry available for C2/exfiltration triage |
| velociraptor | no | no | `none` | no Velociraptor collection supplied |






## Analysis Coverage by Domain

This table shows which DFIR analysis domains the typed tools exercised on the supplied evidence. Coverage is scope, not assurance.

| Domain | Status | Artifacts Seen | Tools Run | Data Sources | Gaps |
|---|---|---|---|---|---|
| Host &amp; Endpoint Forensics | partial | disk/filesystem | `none` | none | none |
| Endpoint Telemetry &amp; Live Response | not_covered | none | `none` | none | missing or untouched artifact classes: velociraptor |
| Malware Analysis &amp; Triage | partial | disk/filesystem | `none` | none | missing or untouched artifact classes: memory |
| Memory Forensics | not_covered | none | `none` | none | missing or untouched artifact classes: memory |
| Network Forensics | automated | network | `pcap_triage` | DS0029 | none |
| Windows Event &amp; Account Analysis | not_covered | none | `none` | none | missing or untouched artifact classes: evtx |

**Overclaim guardrails applied:** covered_no_finding is limited coverage, not a clean/cleared claim, Domain coverage describes triage/orchestration across the typed tools that ran, not certified-analyst judgment, visual exhibits do not create findings or upgrade confidence, execution claims still require at least two artifact classes








## Figures

Visual exhibits are generated from parsed tool outputs. They support cited findings but do not replace `tool_call_id`-backed evidence or upgrade confidence by themselves.

### hypothesis
* Card: `evidence-card-001`
* Linked findings: `f-A-pcap_triage-external-conversation`
* Tool call: `tc-002`
* Source records: `tc-002`
* Confidence: `HYPOTHESIS`
* Citations: `CITE-MITRE-ATTACK-DATASOURCES, CITE-ZEEK-LOGS`
* Why suspicious/relevant: This observable is relevant because finding 'f-A-pcap_triage-external-conversation' is backed by parsed tool output 'tc-002' and should be interpreted with the cited artifact and source caveats.
* Snippet: `hypothesis: pcap_triage observed a notable external conversation to 69.59.235.129:10224 \(external destination on uncommon port 10224\). Treat as network triage context for C2 or transfer hypotheses only; do not claim data loss without separa`
* Caveats: Visual exhibit supports the cited finding but does not replace parsed tool output., HYPOTHESIS confidence requires additional artifact corroboration.

### hypothesis
* Card: `evidence-card-002`
* Linked findings: `f-A-pcap-timeline-192.168.15.4`
* Tool call: `tc-002`
* Source records: `tc-002`
* Confidence: `HYPOTHESIS`
* Citations: `CITE-MITRE-ATTACK-DATASOURCES, CITE-ZEEK-LOGS`
* Why suspicious/relevant: This observable is relevant because finding 'f-A-pcap-timeline-192.168.15.4' is backed by parsed tool output 'tc-002' and should be interpreted with the cited artifact and source caveats.
* Snippet: `hypothesis: Timeline correlation: the anonymous/harassing-email sends from internal host 192.168.15.4 \(first at 2008-07-22T06:01:26Z\) fall within the same browsing session as that host's authenticated web activity \(2008-07-22T04:29:53Z to 2`
* Caveats: Visual exhibit supports the cited finding but does not replace parsed tool output., HYPOTHESIS confidence requires additional artifact corroboration.

### hypothesis
* Card: `evidence-card-003`
* Linked findings: `f-B-pcap-webmail-mail.google.com`
* Tool call: `tc-002`
* Source records: `tc-002`
* Confidence: `HYPOTHESIS`
* Citations: `CITE-MITRE-ATTACK-DATASOURCES, CITE-ZEEK-LOGS`
* Why suspicious/relevant: This observable is relevant because finding 'f-B-pcap-webmail-mail.google.com' is backed by parsed tool output 'tc-002' and should be interpreted with the cited artifact and source caveats.
* Snippet: `hypothesis: Authenticated webmail session to 'mail.google.com' from internal host 192.168.15.4 \(HTTP session cookie present\) — attributes the web/email activity on 192.168.15.4 to a specific webmail account, corroborating the source host's `
* Caveats: Visual exhibit supports the cited finding but does not replace parsed tool output., HYPOTHESIS confidence requires additional artifact corroboration.

### hypothesis
* Card: `evidence-card-004`
* Linked findings: `f-B-pcap-social-facebook`
* Tool call: `tc-002`
* Source records: `tc-002`
* Confidence: `HYPOTHESIS`
* Citations: `CITE-MITRE-ATTACK-DATASOURCES, CITE-ZEEK-LOGS`
* Why suspicious/relevant: This observable is relevant because finding 'f-B-pcap-social-facebook' is backed by parsed tool output 'tc-002' and should be interpreted with the cited artifact and source caveats.
* Snippet: `hypothesis: Authenticated social-media login to facebook \('www.facebook.com'\) from internal host 192.168.15.4 \(HTTP session cookie present\) — ties the activity on 192.168.15.4 to a named social-media account and corroborates the suspect's i`
* Caveats: Visual exhibit supports the cited finding but does not replace parsed tool output., HYPOTHESIS confidence requires additional artifact corroboration.

### hypothesis
* Card: `evidence-card-005`
* Linked findings: `f-B-pcap-anon-email-www.sendanonymousemail.net`
* Tool call: `tc-002`
* Source records: `tc-002`
* Confidence: `HYPOTHESIS`
* Citations: `CITE-MITRE-ATTACK-DATASOURCES, CITE-ZEEK-LOGS`
* Why suspicious/relevant: This observable is relevant because finding 'f-B-pcap-anon-email-www.sendanonymousemail.net' is backed by parsed tool output 'tc-002' and should be interpreted with the cited artifact and source caveats.
* Snippet: `hypothesis: Internal host 192.168.15.4 submitted a request \(HTTP POST\) to anonymous/self-destructing email service 'www.sendanonymousemail.net' \(sendanonymousemail\) over HTTP — consistent with sending an anonymous or harassing message, and `
* Caveats: Visual exhibit supports the cited finding but does not replace parsed tool output., HYPOTHESIS confidence requires additional artifact corroboration.

### hypothesis
* Card: `evidence-card-006`
* Linked findings: `f-B-pcap-webmail-b.mail.google.com`
* Tool call: `tc-002`
* Source records: `tc-002`
* Confidence: `HYPOTHESIS`
* Citations: `CITE-MITRE-ATTACK-DATASOURCES, CITE-ZEEK-LOGS`
* Why suspicious/relevant: This observable is relevant because finding 'f-B-pcap-webmail-b.mail.google.com' is backed by parsed tool output 'tc-002' and should be interpreted with the cited artifact and source caveats.
* Snippet: `hypothesis: Authenticated webmail session to 'b.mail.google.com' from internal host 192.168.15.4 \(HTTP session cookie present\) — attributes the web/email activity on 192.168.15.4 to a specific webmail account, corroborating the source host'`
* Caveats: Visual exhibit supports the cited finding but does not replace parsed tool output., HYPOTHESIS confidence requires additional artifact corroboration.

### hypothesis
* Card: `evidence-card-007`
* Linked findings: `f-B-pcap-webmail-mail.live.com`
* Tool call: `tc-002`
* Source records: `tc-002`
* Confidence: `HYPOTHESIS`
* Citations: `CITE-MITRE-ATTACK-DATASOURCES, CITE-ZEEK-LOGS`
* Why suspicious/relevant: This observable is relevant because finding 'f-B-pcap-webmail-mail.live.com' is backed by parsed tool output 'tc-002' and should be interpreted with the cited artifact and source caveats.
* Snippet: `hypothesis: Authenticated webmail session to 'mail.live.com' from internal host 192.168.15.4 \(HTTP session cookie present\) — attributes the web/email activity on 192.168.15.4 to a specific webmail account, corroborating the source host's id`
* Caveats: Visual exhibit supports the cited finding but does not replace parsed tool output., HYPOTHESIS confidence requires additional artifact corroboration.

### hypothesis
* Card: `evidence-card-008`
* Linked findings: `f-B-pcap-webmail-chatenabled.mail.google.com`
* Tool call: `tc-002`
* Source records: `tc-002`
* Confidence: `HYPOTHESIS`
* Citations: `CITE-MITRE-ATTACK-DATASOURCES, CITE-ZEEK-LOGS`
* Why suspicious/relevant: This observable is relevant because finding 'f-B-pcap-webmail-chatenabled.mail.google.com' is backed by parsed tool output 'tc-002' and should be interpreted with the cited artifact and source caveats.
* Snippet: `hypothesis: Authenticated webmail session to 'chatenabled.mail.google.com' from internal host 192.168.1.64 \(HTTP session cookie present\) — attributes the web/email activity on 192.168.1.64 to a specific webmail account, corroborating the so`
* Caveats: Visual exhibit supports the cited finding but does not replace parsed tool output., HYPOTHESIS confidence requires additional artifact corroboration.

### hypothesis
* Card: `evidence-card-009`
* Linked findings: `f-B-pcap-anon-email-www.willselfdestruct.com`
* Tool call: `tc-002`
* Source records: `tc-002`
* Confidence: `HYPOTHESIS`
* Citations: `CITE-MITRE-ATTACK-DATASOURCES, CITE-ZEEK-LOGS`
* Why suspicious/relevant: This observable is relevant because finding 'f-B-pcap-anon-email-www.willselfdestruct.com' is backed by parsed tool output 'tc-002' and should be interpreted with the cited artifact and source caveats.
* Snippet: `hypothesis: Internal host 192.168.15.4 contacted anonymous/self-destructing email service 'www.willselfdestruct.com' \(willselfdestruct\) over HTTP — consistent with sending an anonymous or harassing message, and identifies 192.168.15.4 as th`
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
| P1 | Review notable external conversations for protocol semantics, byte counts, session timing, and host ownership. | External connections on uncommon ports or with large byte counts are leads that need protocol and endpoint corroboration. | f-A-pcap_triage-external-conversation | Full flow records, PCAP carve/reassembly, Zeek conn/http/dns/tls logs, endpoint owner and process context |
| P2 | Collect Security, Sysmon, and PowerShell Operational EVTX and rerun EVTX/Hayabusa analysis. | Current findings lack event-log corroboration for logon, process creation, and PowerShell execution hypotheses. | evtx_gap | Security 4624/4625/4688, Sysmon 1/3/7/10/11, PowerShell 4103/4104 |
| P2 | Use the disk artifact summary to pivot between Prefetch, Registry, MFT, USN, EVTX, and YARA-target rows without upgrading single-source execution claims. | Extracted disk artifacts are now summarized as leads and timeline context; execution wording still needs two artifact classes and cited tool_call_id evidence. | disk_artifact_summary | Correlated Prefetch run times, Registry LastWrite, MFT/USN timestamps, EVTX records, and YARA hits |
| P3 | Close ATT&amp;CK blind spots before making closure decisions. | The coverage matrix identifies target techniques with no supporting artifact class in this run. | T1014, T1055, T1059.001, T1021.001, T1078 | Additional evidence classes mapped in attack_coverage.targets\[\].artifact_classes |
| P4 | Build a broader timeline with disk and event-log artifacts before closing the case. | No normalized timeline events were available from the supplied evidence. | timeline_gap | EVTX timestamps, process creation times, MFT/USN entries, Prefetch last-run times |




## Reproducibility Appendix

Verifier replay artifacts record whether each cited tool call reproduced the audited output hash. They do not change Track 3b severity policy.

| Finding | Tool | Drift class | Match | Expected SHA | Actual SHA |
|---|---|---|:---:|---|---|
| f-A-pcap_triage-external-conversation | `pcap_triage` | `exact_match` | yes | `644b816b9307` | `644b816b9307` |
| f-A-pcap-timeline-192.168.15.4 | `pcap_triage` | `exact_match` | yes | `644b816b9307` | `644b816b9307` |
| f-B-pcap-webmail-mail.google.com | `pcap_triage` | `exact_match` | yes | `644b816b9307` | `644b816b9307` |
| f-B-pcap-social-facebook | `pcap_triage` | `exact_match` | yes | `644b816b9307` | `644b816b9307` |
| f-B-pcap-anon-email-www.sendanonymousemail.net | `pcap_triage` | `exact_match` | yes | `644b816b9307` | `644b816b9307` |
| f-B-pcap-webmail-b.mail.google.com | `pcap_triage` | `exact_match` | yes | `644b816b9307` | `644b816b9307` |
| f-B-pcap-webmail-mail.live.com | `pcap_triage` | `exact_match` | yes | `644b816b9307` | `644b816b9307` |
| f-B-pcap-webmail-chatenabled.mail.google.com | `pcap_triage` | `exact_match` | yes | `644b816b9307` | `644b816b9307` |
| f-B-pcap-anon-email-www.willselfdestruct.com | `pcap_triage` | `exact_match` | yes | `644b816b9307` | `644b816b9307` |


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
uv run --directory services/agent python -c "from pathlib import Path; from findevil_agent.crypto.manifest import verify_manifest; print(verify_manifest(Path('PATH/TO/run.manifest.json'), audit_log_path=Path('PATH/TO/audit.jsonl')))"
# returns overall=True if the audit chain and Merkle root validate and signature metadata is present
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
uv run --directory services/agent python -c "from pathlib import Path; from findevil_agent.crypto.manifest import verify_manifest; print(verify_manifest(Path('PATH/TO/run.manifest.tamper.json'), audit_log_path=Path('PATH/TO/audit.jsonl')))"
```

---

*Produced by `find-evil-auto` (the VERDICT automated investigation orchestrator).
The cryptographic attestation values shown are the actual outputs of this run; every
quantitative claim above is independently verifiable from the artifacts in this
directory (`audit.jsonl`, `run.manifest.json`, `verdict.json`). The automated
QA / expert-signoff gates for this run are in the companion `REPORT-internal` packet.*
