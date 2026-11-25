# EXPERT.md - Expert Signoff Doctrine

## Goal

Move Find Evil toward 99% DFIR automation with a human expert handling the
final 1% signoff. The agent does the mechanical investigation, correlation,
timeline building, report drafting, and self-review. The expert reviews the
final PDF, checks confidence and limitations, then decides whether it is safe
to send to a company.

## Operating model

Signoff model: the agent prepares an evidence-bound signoff packet; the
human expert remains final authority for customer release.

The SOUL.md confidence hierarchy controls every claim: CONFIRMED is backed
by current-case tool output, INFERRED is derived from two or more confirmed
facts, and HYPOTHESIS is explicitly labeled as such. The expert does not
upgrade a claim because the PDF reads well; the evidence tier must already
support it.

1. Automate the repeatable work.
2. Keep every claim tied to current-case evidence.
3. Refuse unsafe certainty when scope or artifacts are missing.
4. Escalate instead of guessing.
5. Treat the PDF as a signoff packet, not an unquestionable forensic truth.

## Signoff question

Every case ends with one expert question:

> Would I send this report to a company without rewriting it?

If the answer is no, convert the required edit into one of:

- a new typed evidence connector;
- a stronger playbook step;
- a machine-checkable expert rule;
- a report QA check;
- an explicit escalation condition.

## Scope tiers

### Autonomous today

- `windows_memory` - memory process and injection review.
- `windows_evtx` - EVTX parsing and high-signal event findings.
- `disk_custody_registration` - custody registration for disk images.
- `timeline_normalization` - timeline exports from parsed artifacts.
- `evidence_backed_pdf_reporting` - Findings, verdicts, evidence cards, and
  PDF report drafting.
- `miss-feedback-loop` - expert corrections are captured as a typed,
  hash-chained improvement ledger.

### Partial today

- `disk_content_analysis_without_mount` - disk-content conclusions when only
  raw disk images are supplied.
- `exfiltration_without_network_telemetry` - exfiltration conclusions without
  network, DNS, proxy, firewall, PCAP, or EDR telemetry.
- `malware_capability_without_reverse_engineering` - malware capability claims
  beyond malfind/YARA/string triage.
- `identity_compromise_from_single_log_source` - identity compromise
  conclusions from single EVTX sources.

### Escalation-only today

- `legal_notification` - legal notification decisions.
- `attribution` - actor attribution.
- `unsupported_cloud_or_saas` - Cloud/SaaS compromise without dedicated
  connectors.
- `mobile_forensics` - mobile forensics.
- `ot_ics_forensics` - OT/ICS forensics.
- `failed_report_qa` - any case where the report QA gate fails.

## Expert evidence rules

- Every Finding cites a `tool_call_id` that exists in the case tool-call list.
- Timeline rows support Findings; they do not become Findings by themselves.
- Visual evidence cards and charts explain evidence; they never raise confidence.
- Execution claims require at least two current-case artifact classes.
- Amcache, ShimCache, memory-only process evidence, YARA, Hayabusa, and malfind
  are not standalone execution proof.
- Exfiltration claims require both collection/staging evidence and network,
  tool, or data-movement evidence.
- `NO_EVIL` means no reportable Finding in the scoped artifacts examined; it is
  not a clean bill of health.
- Disk auto mode is custody-only unless mounted or extracted artifacts are
  supplied.
- Prior-case memory is a prioritization signal, not current-case proof.
- Never assert attribution.

## Report standard

The report must let the expert answer the signoff question quickly:

- What happened, in plain English.
- What evidence supports it.
- Which Findings are CONFIRMED, INFERRED, or HYPOTHESIS.
- Which artifact classes were touched.
- Which important artifact classes were missing or blind spots.
- What the company should do next.
- What the agent cannot prove from the supplied evidence.
- Whether the report is ready for expert signoff or blocked.

## Replacement metric

The system is improving only when routine cases produce reports the expert can
send with fewer edits. Track misses as rule, connector, playbook, QA, or report
defects, not as one-off human cleanup.

Every expert edit to the auto-drafted PDF must be filed via
`expert_miss_capture` before the corrected packet ships. Captured misses become
the improvement ledger: connector gaps, playbook holes, weak rules, missing QA
gates, missing escalation triggers, and forbidden-language hits. Uncaptured
edits are an audit gap and a QA defect because the next case cannot surface
those failure modes.

Captured misses must also appear in report metadata and the expert signoff
packet as `feedback_items`. Each item routes to one improvement class:
connector, playbook step, detection rule, QA check, escalation trigger, or
report-copy fix.

## Forbidden-language rationale

- `clean` / `cleared` - implies environment-wide assurance from scoped evidence.
- `disproven` / `absent` / `absence of compromise` / `absence of the technique`
  - treats limited coverage as proof of nonexistence.
- `no compromise` - overstates a `NO_EVIL` verdict beyond examined artifacts.
- `attributed to` / `malware operator` / `the attacker` - asserts actor identity
  or intent from host artifacts.
- `is malware` - converts triage signals into a capability conclusion without
  reverse-engineering support.
- `breach confirmed` - collapses technical Findings into a legal/business
  conclusion the agent cannot make alone.
- `customer-ready` / `customer ready` - bypasses the report QA, sigstore,
  manifest verification, and explicit expert-approval release gates.
