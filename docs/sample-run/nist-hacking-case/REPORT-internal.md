[VERDICT · Internal QA & Release Gates]{.kicker}

# VERDICT — Internal QA & Release Gates

[Expert-signoff packet · not customer narrative]{.tagline}

**Case ID:** `b639fdda-146c-48ec-9080-1e144ec7ceae`
**Run ID:** `auto-1781289206`
**Verdict:** **SUSPICIOUS**

> These sections are the automated expert-review packet's internal gates. They are
> not part of the customer report (`REPORT.html`); they exist so a human expert can
> see the machine QA status, release blockers, and the doctrine the engine enforced
> before approving customer release.

---

## Analysis Doctrine

The agent prepares an evidence-bound signoff packet; the human expert remains final authority for customer release.

| Rule | Severity | Requirement |
|---|---|---|
| `finding_tool_call_required` | blocker | Every Finding must cite a non-empty tool_call_id that exists in the case tool-call list. |
| `verify_finding_replay_embedded` | blocker | Customer-ready reports must embed verifier replay evidence for each Finding and every replay must match the audited tool output. |
| `verify_finding_replay_failures` | blocker | A verifier rejection or replay failure must force INDETERMINATE or blocked customer release, never NO_EVIL. |
| `execution_requires_two_current_artifact_classes` | blocker | Execution claims require at least two current-case artifact classes. Prefetch is preferred; Amcache, ShimCache, memory-only process evidence, YARA, Hayabusa, and malfind are not standalone execution proof. |
| `exfiltration_requires_staging_and_movement` | blocker | Exfiltration claims require staging or collection evidence plus network, tool, or data-movement evidence. |
| `no_evil_is_scoped` | warning | NO_EVIL means no reportable Finding in the artifact classes examined. It must not imply environment-wide assurance. |
| `disk_auto_mode_custody_only` | blocker | Raw disk auto mode is custody-only unless mounted or extracted artifacts are supplied and parsed. |
| `visuals_do_not_upgrade_confidence` | warning | Charts, evidence cards, screenshots, and PDF exhibits support cited tool output but never create Findings or raise confidence. |



## QA / Expert Signoff

* Overall QA status: `FAIL`
* Packet state: `BLOCKED_MANUAL_INVESTIGATION`
* Ready for expert signoff: `False`
* Customer-release candidate from automated QA: `False`
* Customer releasable after expert approval: `False`
* Expert decision: `pending`
* Expert review estimate: `manual investigation required`
* Signoff question: `Would I send this report to a company without rewriting it?`

| Check | Status | Summary |
|---|---|---|
| `finding_tool_call_required` | PASS | All 19 Finding\(s\) cite current-case tool calls. |
| `execution_requires_two_current_artifact_classes` | FAIL | Execution wording appears without per-Finding current-case corroboration from two acceptable artifact classes. |
| `exfiltration_requires_staging_and_movement` | FAIL | Exfiltration wording appears without both staging/collection and network/tool/data-movement coverage. |
| `disk_auto_mode_custody_only` | PASS | No custody-only disk overclaim detected. |
| `no_evil_is_scoped` | PASS | Verdict wording remains scoped to supplied evidence. |
| `timeline_source_refs_present` | PASS | Timeline includes 626 normalized event\(s\) with source references. |
| `verify_finding_replay_failures` | PASS | No verifier replay failures were recorded as analysis limitations. |
| `verify_finding_replay_embedded` | PASS | Every Finding carries embedded verifier replay evidence, or there are no Findings to replay. |
| `limitations_visible` | WARN | Analysis limitations must remain visible before customer release. |
| `no_forbidden_unqualified_language` | PASS | No forbidden unqualified language detected in Findings or customer-visible report text. |
| `attack_coverage_blind_spots` | WARN | ATT&amp;CK coverage includes blind spots that require expert awareness. |



## Customer Release Gate

This gate is written after `manifest_finalize` and `manifest_verify`; it is a post-finalize linkage artifact, not a replacement for the audited `verdict.json` hash committed before manifest finalization.

* QA status: `FAIL`
* Packet state: `BLOCKED_MANUAL_INVESTIGATION`
* Manifest verified: `False`
* Manifest signature present: `False`
* Signer: `ed25519`
* Expert approved: `False`
* Customer releasable: `False`

### Release Blockers

* Execution wording appears without per-Finding current-case corroboration from two acceptable artifact classes.
* Exfiltration wording appears without both staging/collection and network/tool/data-movement coverage.
* customer release requires an effective manifest_finalize signer=sigstore \(identity + transparency log\); ed25519 proves integrity offline but not identity, and stub signatures are dev/offline only
* explicit human expert approval is required before customer release
* finalized manifest signature metadata must be present before customer release
* manifest_verify must pass before customer release



## Readiness State

* Packet state: `BLOCKED_MANUAL_INVESTIGATION`
* Ready for expert review/signoff: `False`
* Expert-review status: `pending`
* Ready for customer PDF: `False`
* Customer releasable: `False`

### Blockers

* Execution wording appears without per-Finding current-case corroboration from two acceptable artifact classes.
* Exfiltration wording appears without both staging/collection and network/tool/data-movement coverage.
* customer release requires an effective manifest_finalize signer=sigstore \(identity + transparency log\); ed25519 proves integrity offline but not identity, and stub signatures are dev/offline only
* explicit human expert approval is required before customer release
* finalized manifest signature metadata must be present before customer release
* manifest_verify must pass before customer release

### Failed Checks

* execution_requires_two_current_artifact_classes
* exfiltration_requires_staging_and_movement

### Warnings

* limitations_visible
* attack_coverage_blind_spots


