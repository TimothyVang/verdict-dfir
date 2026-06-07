# Practical SANS DFIR Completion Prompt

Date: 2026-05-04

Use this prompt in a coding-agent session to finish Find Evil! as a practical SANS DFIR investigation tool. It intentionally mirrors the rigor of a large milestone execution prompt: parallel discovery, vertical slices, real validation, a measurable definition of done, and a final evidence table.

This prompt is explicitly not an attestation or ledger milestone. Treat existing audit logs and run manifests as reproducibility metadata that current code may already emit; do not add, redesign, or polish evidence-signing or external timestamping features. A5-removed timestamping tools stay removed.

## Copy/Paste Prompt

You are a senior DFIR engineer and senior staff software engineer finishing the Find Evil! SANS hackathon submission.

Repo:

```text
C:\Users\newbi\Desktop\PUG Projects\SANS-Hackathon
```

Context:

Find Evil! is a Claude Code driven DFIR agent for Windows evidence. The product surface is the investigation workflow judges run: the one command scripts/verdict (preflight, investigate, live dashboard, signed verdict and report), interactive Claude Code via scripts/find-evil, and SIFT-VM tools via the --sift flag (scripts/find-evil-sift helper). scripts/find-evil-auto is the internal headless engine that verdict calls.

Current architecture constraints:

- Claude Code is the primary interface under Amendment A2.
- Rust MCP server exposes typed DFIR tools only.
- Python MCP server exposes support tools for ACH, memory, handoff, and existing audit/run metadata.
- Evidence is read-only.
- AGPL/GPL DFIR tools remain subprocess-only.
- No execute_shell MCP tool.
- No fake evidence, fake findings, or fabricated demos.
- Every finding must cite a tool_call_id.
- Execution claims require at least two artifact classes.
- Confidence labels must follow CONFIRMED, INFERRED, HYPOTHESIS.
- Do not assert attribution.
- Do not add attestation work. Preserve existing audit and run-metadata behavior only where required by current code and tests.

Current practical target:

Make the project judge-ready as a practical SANS DFIR tool. Prioritize investigation usefulness over architecture polish.

Research-backed DFIR baseline:

Reference inputs for this prompt: [SANS SIFT Workstation](https://www.sans.org/tools/sift-workstation/), [AppliedIR/Valhuntir](https://github.com/AppliedIR/Valhuntir), [Volatility 3](https://github.com/volatilityfoundation/volatility3), [Hayabusa](https://github.com/Yamato-Security/hayabusa), [Velociraptor](https://github.com/Velocidex/velociraptor), [Sigma](https://github.com/SigmaHQ/sigma), [Plaso/log2timeline](https://github.com/log2timeline/plaso), and [Timesketch](https://github.com/google/timesketch).

- SANS SIFT Workstation is the judge-aligned environment: a maintained open-source DFIR workstation for file systems, evidence images, memory, event logs, Plaso/log2timeline, Volatility, Sleuth Kit, libewf, and related incident-response tooling. The prompt should drive evidence triage in SIFT, not unrelated platform work.
- SANS explicitly describes Protocol SIFT as experimental research, not court-validated forensic reliability. The product should be honest: useful for triage and analyst acceleration, with human review and corroboration before final claims.
- Valhuntir's public guidance is a useful quality bar: AI can accelerate evidence ingestion, timelines, findings, and report generation, but a trained human must guide and verify the investigation. Do not let the agent approve its own conclusions.
- Volatility 3 is the memory baseline: use runtime-state plugins such as pslist, psscan, psxview, malfind, and symbol/readiness errors to reason about process visibility, DKOM, and injection. Memory output is evidence; attacker intent is an inference.
- Hayabusa and Sigma are event-log triage baselines: fast Windows EVTX timelines, log metrics, logon summaries, Base64 extraction, Sigma alerting, and tuning reduce time-to-pivot. Sigma/Hayabusa hits are leads for analyst review, not automatic proof of compromise.
- Velociraptor is the collection baseline: when supplied as collections or zip output, treat it as endpoint state evidence and connect collected artifacts to timeline and ATT&CK coverage instead of ignoring it.
- Plaso/log2timeline and Timesketch are timeline baselines: practical DFIR output should produce normalized, importable timelines that analysts can pivot, tag, annotate, and correlate across artifact classes.

Fix-first order:

1. Benign EVTX must not become SUSPICIOUS solely because records parsed successfully.
2. Correlator downgrade/keep results must affect final findings and verdict input, not only summary counters.
3. vol_psxview must trigger on pslist/psscan PID or process-set divergence, not count only.
4. agent-config/TOOLS.md argument names must match actual MCP schemas.
5. Report caveats must prevent overclaiming Sigma hits, memory-only execution, missing disk/network evidence, and covered_no_finding coverage.

Additional blockers to verify before 100 percent:

- docs/false-positives.md must not say psxview is absent from MCP.
- docs/verdict-semantics.md must not describe multi-host recurrence as two artifact classes.
- If existing reproducibility/tamper examples remain, they must not mutate original outputs in place; copy outputs before any tamper demonstration.
- Untracked files must be reviewed before commit; private onboarding or team-only notes should not ship accidentally.

Non-negotiable outcome:

At the end of the session, a SANS judge or DFIR reviewer must be able to run the documented command against memory, EVTX, or disk evidence and answer these questions from the generated output, report, and docs without manually reading raw logs:

- What evidence type was supplied?
- Which DFIR tools ran?
- Which artifact classes were available and touched?
- What suspicious behavior was found?
- Which ATT&CK techniques are implicated?
- Which exact tool_call_id supports each finding?
- What evidence is missing?
- What confidence tier applies and why?
- What false-positive caveats apply?
- What does the normalized timeline show?
- Where are timeline.json and timeline.csv?
- What are the next analyst actions in SIFT or the interactive agent?
- How do I reproduce the run?

Definition of practical SANS DFIR completion:

Operators must be able to inspect, validate, and continue a case across:

- memory process views and injection artifacts
- EVTX event-log activity
- disk artifact limitations and next manual steps
- cross-artifact confidence rules
- ATT&CK coverage and blind spots
- normalized timelines
- analyst reports
- false-positive prevention guidance
- reproducible validation commands

For this prompt, 100 percent does not mean every disk artifact parser is fully automated in headless mode. It means memory and EVTX are automated and tested; disk evidence is either handled through existing typed tools when mounted/extracted artifacts are available, or reported honestly as case_open-only with concrete read-only SIFT next actions for deep disk review. Full disk deep dive may remain an interactive/SIFT workflow, but the report must make that boundary explicit.

Do not claim 100 percent complete unless implementation, docs, tests, validation, final review, and the disk-scope rule above are satisfied.

Execution mode:

- Finish this milestone in one continuous pass if technically possible.
- Do not stop after each task for approval.
- Use parallel subagents immediately after the initial repo inspection to compress discovery and reduce missed integration points.
- The main agent owns final architecture decisions, code integration, validation, docs, commit decision, and final response.
- Subagents may research and propose implementation details, but the main agent must verify all findings against the codebase before editing.
- If a subagent reports uncertainty, inspect the relevant files directly before deciding.
- Only ask the user for clarification if there is a real DFIR product ambiguity or destructive action risk.
- Keep implementation minimal. Prefer existing MCP tools, scripts/find_evil_auto.py, scripts/render_report.py, agent-config playbooks, and existing smoke tests before adding new tools, tables, services, or dependencies.
- A milestone is not done when output looks good. It is done only when output is backed by real tool results, tests pass, docs are updated, and validation evidence exists.

One-pass operating rule:

Work like a mission controller. Use subagents for discovery and risk reduction, then centralize implementation decisions in the main agent. Do not split into research now and implementation later unless blocked by missing evidence, missing VM/tool binaries with no fallback, or an explicit user stop.

If your agent platform has a Task/subagent tool, launch all six subagents in one parallel batch. If it does not, perform the six research workstreams yourself before editing and label the findings with the same section names.

Do not use subagents to make commits. Do not let subagents independently edit overlapping files. The main agent integrates all code changes.

No-premature-stop contract:

- Do not produce a final answer while any global definition-of-done item is unchecked.
- Do not end with next steps for work required by this prompt. Do the work instead.
- Do not say mostly done, foundation complete, or ready for follow-up unless the completion score is below 100 and the final response starts with Not complete:.
- If you discover missing work during final review, return to implementation mode immediately and fix it before responding.
- If a validation command fails, fix the failure and rerun it. Do not summarize the failure as a caveat unless it is a true external blocker with no available fallback.
- If tests pass but docs are missing, keep working.
- If docs are done but report output or timeline verification is missing, keep working.
- If implementation is done but validation has not run, keep working.
- Do not commit unless the current user request explicitly authorizes a commit. If this prompt is pasted with commit authorization, create one final commit only after validation passes.

Hard completion gate algorithm:

```text
while true:
  inspect git status and current todo/checklist
  run or verify all focused tests for completed slices
  run the full validation suite or documented feasible subset
  calculate the 100-point completion score
  if score == 100 and validation passed and docs are updated and commit policy is satisfied:
      produce final response
      stop
  if there is a true external blocker:
      document exact blocker, fallback proof, incomplete score, and ask/stop only if user action is required
      stop
  otherwise:
      implement the missing/failing item
      rerun affected tests
      continue loop
```

True external blockers are limited to:

- Required evidence is missing and no fixture/smoke path can validate behavior.
- Required SIFT VM or DFIR binary is unavailable and no unit/smoke fallback can validate the behavior.
- Required credentials are missing and no local/dev path exists.
- Docker/OS/toolchain failure prevents validation and cannot be fixed from the repo.
- User approval is required for a destructive action, force push, paid dependency, evidence deletion, or major product decision outside this prompt.

Everything else is an implementation problem to fix, not a reason to stop.

Start by inspecting:

```text
git status --short --branch
git diff
CLAUDE.md
README.md
QUICKSTART.md
CHANGELOG.md
agent-config/SOUL.md
agent-config/PLAYBOOK.md
agent-config/TOOLS.md
agent-config/MEMORY.md
agent-config/JUDGING.md
docs/false-positives.md
docs/verdict-semantics.md
docs/runbooks/ci-smoke-checklist.md
scripts/find_evil_auto.py
scripts/render_report.py
scripts/verdict-policy-smoke.py
scripts/rust-mcp-smoke.py
scripts/divergence-smoke.py
scripts/path-existence-smoke.py
services/mcp/src/server.rs
services/mcp/src/tools/
services/mcp/tests/
services/agent_mcp/tests/test_stdio_smoke.py
```

Do not revert or overwrite user or other-agent changes.

Quality bar:

- Build vertical working slices instead of broad scaffolding.
- Prefer readable boring code over clever abstractions.
- Keep new names and new tools to the minimum needed.
- Write tests against behavior, not implementation details.
- Do not add a new MCP tool unless existing typed tools cannot cover the evidence need.
- Do not expand attestation. Keep reproducibility practical: commands run, output paths, and existing run metadata.
- Treat generated reports, timelines, and evidence outputs as local artifacts unless explicitly intended for docs.
- Keep production runtime independent from test-only fixtures.

## Parallel Subagent Protocol

After the initial inspection, launch these subagents concurrently. Ask each subagent to return concise findings with file paths, recommended edits, risks, and test targets. Do not let subagents edit or commit.

Required subagent output contract:

Each subagent must return exactly these sections:

1. Existing facts: files/functions/tools/docs found, with paths.
2. Minimal implementation: smallest set of edits that satisfies this workstream.
3. Tests to add/update: exact test files and assertions.
4. Risks/blockers: only real blockers, not speculative concerns.
5. Do-not-do list: changes that would overbuild or violate constraints.

The main agent must summarize each subagent finding into working notes before implementation. If any required section is missing, directly inspect the relevant files and fill the gap yourself.

Subagent dependency map:

- Subagent A informs Tasks 1, 2, and 3 because memory process views are the strongest differentiator.
- Subagent B informs Tasks 1, 4, 6, and 7 because event logs and Windows caveats affect confidence tiers.
- Subagent C informs Tasks 1, 5, and 7 because disk artifacts are required for execution and persistence corroboration.
- Subagent D depends on A, B, and C for timeline event shapes and ATT&CK technique coverage.
- Subagent E depends on D for report structure and on all artifact subagents for false-positive caveats.
- Subagent F depends on all findings for validation and documentation, but can research CI and runbooks independently.

Main-agent synthesis requirements:

Before editing code, write a concise internal synthesis with:

- current worktree summary and files that appear user/other-agent owned
- chosen evidence output contract for verdict.json
- selected timeline export strategy
- selected ATT&CK coverage strategy
- selected false-positive caveat strategy
- selected report sections
- docs to update
- tests to add or adjust
- validation commands to run
- commit decision based on explicit user authorization

If the synthesis says a new MCP tool is needed, justify why existing typed tools are insufficient. Prefer not adding tools.

Subagent A: Memory DFIR and Volatility

Prompt:

```text
Research the Find Evil memory investigation path. Focus on scripts/find_evil_auto.py, services/mcp/src/tools/vol_pslist.rs, vol_psscan.rs, vol_psxview.rs if present, vol_malfind.rs, services/mcp/src/server.rs, services/mcp/tests, scripts/rust-mcp-smoke.py, agent-config/PLAYBOOK.md, and docs/reports examples. Return a minimal plan to make memory triage practical for SANS: Volatility readiness/symbol errors, pslist/psscan/psxview DKOM coverage, PID/process-set divergence, malfind T1055 coverage, timeline extraction, confidence labels, and false-positive caveats. Do not modify files.
```

Subagent B: EVTX and Windows Event Logs

Prompt:

```text
Research the EVTX investigation path. Focus on evtx_query, hayabusa_scan, scripts/find_evil_auto.py, agent-config/MEMORY.md, agent-config/PLAYBOOK.md, docs/false-positives.md, and tests/smokes that cover EVTX behavior. Return a minimal plan to improve event-log summaries, Hayabusa/Sigma hit handling, log metrics, Event ID metrics, logon summaries, Base64/PowerShell pivots, timeline events, ATT&CK mapping, logon caveats, benign-EVTX verdict behavior, and next analyst actions without overclaiming. Do not modify files.
```

Subagent C: Disk Artifacts and Execution Corroboration

Prompt:

```text
Research disk and filesystem artifact support. Focus on mft_timeline, usnjrnl_query, registry_query, prefetch_parse, yara_scan, current disk behavior in scripts/find_evil_auto.py, agent-config/PLAYBOOK.md, agent-config/MEMORY.md, docs/false-positives.md, and docs/verdict-semantics.md. Return a minimal plan for practical disk evidence handling, read-only E01/raw mount workflows, Plaso/log2timeline or bodyfile-style timeline handoff, current automation limitations, manual SIFT next steps, and execution-claim safeguards. Do not modify files.
```

Subagent D: Timeline, ATT&CK Coverage, and Evidence Gaps

Prompt:

```text
Research timeline and ATT&CK output. Focus on scripts/find_evil_auto.py, scripts/render_report.py, scripts/verdict-policy-smoke.py, docs/reports, docs/verdict-semantics.md, and README/QUICKSTART output descriptions. Return a minimal design for timeline.json, timeline.csv, Timesketch/Timeline Explorer friendly CSV fields, attack_coverage, case_completeness, next_actions, and tests. Keep it backed by real tool outputs. Do not modify files.
```

Subagent E: Report Quality and False-Positive Controls

Prompt:

```text
Research analyst report quality. Focus on scripts/render_report.py, docs/false-positives.md, agent-config/SOUL.md, agent-config/JUDGING.md, docs/reports, and README. Return a minimal plan to make the report useful to a SANS judge: findings, evidence support, timeline, ATT&CK coverage, missing evidence, next actions, and false-positive caveats. Do not modify files.
```

Subagent F: Docs, Validation, and SIFT Judge Workflow

Prompt:

```text
Research operator docs and validation. Focus on README.md, QUICKSTART.md, CHANGELOG.md, docs/README.md, docs/runbooks/ci-smoke-checklist.md, docs/demo-script-a2.md, scripts/run-all-smokes.sh, cargo/ruff/Python smoke commands, and packaging docs. Return a doc update plan grounded in SIFT, Volatility, Hayabusa/Sigma, Velociraptor, Plaso/log2timeline, Timesketch, and Valhuntir-style human review lessons; include final validation checklist, likely local blockers, and a reviewer demo path. Do not modify files.
```

Ready-to-copy parallel launch instruction:

If your coding environment supports launching multiple subagents/tasks in one tool call, launch all six subagents above together. If it requires separate calls, issue them back-to-back before reading any results. Use descriptions like:

```text
Memory DFIR research
EVTX research
Disk artifact research
Timeline ATT&CK research
Report FP research
Docs validation research
```

Each subagent should be told: research only, do not edit, do not commit, return the required five-section output contract.

Merge protocol:

- Wait for all subagents before substantial edits unless a finding is clearly independent and low-risk.
- Build one integrated implementation plan from the subagent reports.
- Prefer the smallest correct implementation that satisfies the global definition of done.
- Avoid adding tools or dependencies if existing MCP tools and scripts can satisfy the milestone.
- If two subagents conflict, inspect the files directly and choose the simpler DFIR-safe path.
- Track work with a todo list and keep one active implementation task at a time after the parallel research phase.
- Run focused tests after each major slice, then broader validation at the end.
- Do not start a second architecture path in parallel. Pick one implementation path and complete it end to end.
- If disk evidence is not fully automated, document the current limit clearly and provide concrete SIFT next steps instead of faking coverage.
- If a KPI-style or UI feature is tempting, reject it unless it directly improves DFIR investigation output.

Suggested implementation order after subagents return:

1. Tool surface consistency and vol_psxview completion.
2. Memory playbook correctness and findings confidence.
3. EVTX summaries and timeline extraction.
4. Disk-path limits and manual next actions.
5. Case completeness, ATT&CK coverage, and evidence gaps.
6. Timeline JSON/CSV export.
7. Report rendering and false-positive caveats.
8. Operator docs and reviewer demo path.
9. Full validation and final response.
10. Commit only if explicitly authorized.

Single-pass completion loop:

Repeat this loop until the global definition of done passes:

1. Implement the smallest next vertical slice.
2. Run the narrowest relevant tests.
3. Fix failures immediately.
4. Update docs for the slice.
5. Move to the next slice only when the current slice works.
6. After all slices, run the full feasible validation suite.
7. If validation fails, fix and rerun the failed command plus affected earlier commands.
8. Commit only if the user explicitly authorized committing and only after validation passes or a true external blocker is documented with fallback proof.

Hard stop conditions:

- Stop and ask before destructive git operations, deleting evidence, rewriting history, force pushing, adding a new MCP shell surface, adding paid/cloud dependencies, or introducing a new evidence-signing or timestamping mechanism.
- Do not stop for routine test failures, typing errors, formatting failures, missing helper functions, stale docs, or local code integration issues. Fix them.

Failure recovery playbook:

- If Rust tests fail: inspect the specific tool module, MCP registration, and smoke expectations; fix code or expected counts consistently.
- If Volatility command parsing fails: inspect plugin output shape and update the parser/test fixtures without weakening validation.
- If EVTX parsing fails: preserve parse error counts and degrade gracefully; do not fabricate rows.
- If timeline export fails: test pure helper behavior first, then integration.
- If report rendering fails due to Pandoc/Chrome missing: compile Markdown generation and document the local binary blocker; do not claim PDF validation passed.
- If SIFT VM is unavailable: run MCP unit tests, smoke tests, and pure orchestrator policy tests as fallback; document that end-to-end evidence execution was not possible.
- If path-existence smoke fails: fix the path reference or avoid backtick-quoted runtime placeholders in docs.
- If divergence-smoke fails: update stale active docs or smoke patterns only when the new shipped behavior is truly different.
- If tests need data: use existing fixtures or create test-only fixtures. Do not add fake production evidence or fake findings.
- If a subagent returns an overbuilt plan: use the facts, reject the overbuild, and proceed with the minimal DFIR-safe path.

Anti-overbuild constraints:

- Do not add new UI polish for this milestone.
- Do not add n8n, Temporal, LangGraph, or managed-agent runtime work.
- Do not add new evidence-signing systems, external timestamping systems, receipts, or attestations.
- Do not add an execute_shell tool.
- Do not add a broad generic shell runner under another name.
- Do not add fake demo data or synthetic malicious findings to production docs.
- Do not rewrite the architecture.
- Do not create multiple partial commits.
- Do not edit external reference clones.
- Do not stage generated reports, evidence, VM images, target, node_modules, tmp, or local state.

Preferred architecture for this milestone:

- Source of truth: typed MCP tool outputs and current run metadata already produced by the investigation path.
- Memory evidence: vol_pslist, vol_psscan, vol_psxview, vol_malfind.
- EVTX evidence: evtx_query and hayabusa_scan where available.
- Disk evidence: mft_timeline, usnjrnl_query, registry_query, prefetch_parse, yara_scan where available; otherwise explicit current-limit language.
- Operator output: verdict.json, timeline.json, timeline.csv, REPORT.md, REPORT.html, REPORT.pdf when local renderer exists.
- Analyst guidance: ATT&CK coverage, evidence gaps, false-positive caveats, and next actions.
- Audit/run metadata: preserve existing behavior only; do not expand it.

Concrete file map:

Expect most implementation to land in these areas. Inspect first, then keep edits as small as possible.

```text
Auto-run and report:
  scripts/find_evil_auto.py
  scripts/render_report.py
  scripts/verdict-policy-smoke.py

Rust MCP tool surface:
  services/mcp/src/server.rs
  services/mcp/src/lib.rs
  services/mcp/src/tools/mod.rs
  services/mcp/src/tools/vol_pslist.rs
  services/mcp/src/tools/vol_psscan.rs
  services/mcp/src/tools/vol_psxview.rs
  services/mcp/src/tools/vol_malfind.rs
  services/mcp/tests/

Smoke and drift guards:
  scripts/rust-mcp-smoke.py
  scripts/divergence-smoke.py
  scripts/smoke-regex-tests.py
  scripts/path-existence-smoke.py
  scripts/run-all-smokes.sh

Runtime agent identity and DFIR caveats:
  agent-config/SOUL.md
  agent-config/PLAYBOOK.md
  agent-config/TOOLS.md
  agent-config/MEMORY.md
  agent-config/JUDGING.md

Operator docs:
  README.md
  QUICKSTART.md
  CHANGELOG.md
  docs/README.md
  docs/false-positives.md
  docs/verdict-semantics.md
  docs/demo-script-a2.md
  docs/runbooks/ci-smoke-checklist.md
```

Concrete output targets:

Prefer these names unless existing naming patterns strongly suggest better local names.

```text
Verdict fields:
  case_completeness
  attack_coverage
  next_actions
  timeline_summary

Host artifacts:
  audit.jsonl if emitted by the existing path
  run.manifest.json if emitted by the existing path
  verdict.json
  timeline.json
  timeline.csv
  REPORT.md
  REPORT.html
  REPORT.pdf when renderer is available

Report sections:
  Summary
  Findings overview
  Next 5 Analyst Actions
  Case Completeness
  ATT&CK Coverage
  Unified Timeline
  Findings detail
  False-positive caveats where relevant
  Reproducibility instructions limited to existing behavior
```

Suggested verdict output contract:

```json
{
  "case_id": "string",
  "run_id": "string",
  "evidence_path": "string",
  "evidence_type": "memory|evtx|disk|unknown",
  "verdict": "SUSPICIOUS|INDETERMINATE|NO_EVIL",
  "findings_summary": {},
  "findings": [],
  "case_completeness": {},
  "attack_coverage": {},
  "next_actions": [],
  "timeline_summary": {}
}
```

Suggested timeline event contract:

```json
{
  "ts": "ISO-8601 UTC string",
  "source": "tool name",
  "artifact_class": "memory|evtx|disk/filesystem|network",
  "description": "short analyst-readable event",
  "tool_call_id": "tc-###",
  "details": {}
}
```

Suggested ATT&CK coverage contract:

```json
{
  "summary": "string",
  "covered_target_count": 0,
  "finding_target_count": 0,
  "blind_spot_count": 0,
  "observed_techniques": [],
  "targets": [
    {
      "technique_id": "T1014",
      "technique_name": "Rootkit",
      "tactic": "Defense Evasion",
      "status": "finding|covered_no_finding|available_not_examined|blind_spot",
      "finding_confidence": "CONFIRMED|INFERRED|HYPOTHESIS|null",
      "tools_expected": [],
      "tools_observed": [],
      "artifact_classes": [],
      "artifact_classes_observed": [],
      "gap": "string",
      "analyst_value": "string"
    }
  ]
}
```

Allowed practical shortcuts:

- If an end-to-end SIFT VM run is unavailable, validate with Rust unit tests, MCP smoke tests, and pure Python policy/report tests, and document the missing VM as an external blocker.
- If PDF rendering is unavailable because Pandoc or Chrome is missing, validate Markdown generation and HTML/PDF command path where possible, and document the local binary blocker.
- If disk image deep parsing is not implemented in auto mode, explicitly state case_open-only behavior and provide SIFT manual next actions instead of pretending disk coverage is complete.
- If a metric cannot be honestly derived from supplied evidence, return a gap/null reason rather than a fake number.
- If a finding is supported by one artifact class only, keep it HYPOTHESIS or INFERRED as appropriate and state what corroboration is missing.

DFIR red lines:

- Never claim execution from Amcache alone.
- Never treat ShimCache ordering as execution proof without caveats.
- Never conflate EVTX Logon Type 3 with interactive RDP Logon Type 10.
- Never turn a process name anomaly into malware attribution without corroboration.
- Never call DKOM/T1014 CONFIRMED solely from one process view.
- Never claim exfiltration without network or equivalent corroborating evidence.
- Never describe covered_no_finding as clean, not malicious, disproven, cleared, or absence of the technique; it only means available tools ran and found no qualifying evidence under current coverage.
- Never expose raw secrets, credentials, API keys, tokens, or evidence-local sensitive data in docs.

Task 1: Tool Surface and Drift Cleanup

Goal:

Ensure the typed DFIR tool surface is consistent and judge-facing docs match shipped behavior.

Implement:

- Confirm Rust MCP tool count is 19.
- Confirm Python MCP tool count is 12.
- Confirm total MCP tool count is 31.
- Confirm vol_psxview is registered, listed, dispatched, exported, tested, and documented.
- Remove stale active references to old Rust tool counts, old total tool counts, old Python tool counts, and A5-removed timestamping tools.

Checklist:

- Existing active docs match shipped tool counts.
- Rust smoke expects the correct tool count.
- Divergence smoke catches old counts.
- No execute_shell or equivalent shell pass-through exists.

Deliverables:

- Minimal code/docs/smoke updates.
- Rust tests or smoke tests.

Acceptance tests:

- cargo test for findevil-mcp passes.
- rust-mcp-smoke lists 13 tools and includes vol_psxview.
- divergence-smoke passes.

Task 2: Memory DFIR Vertical Slice

Goal:

Make memory image investigation useful for process hiding, injection, and timeline triage.

Implement:

- Run vol_pslist and record process start timeline events.
- Run vol_psscan and record recovered process object timeline events.
- Run vol_psxview when pslist and psscan counts, PIDs, or process sets disagree, or document why it is conditional.
- Run vol_malfind and synthesize T1055 findings carefully.
- Ensure DKOM/T1014 findings cite the strongest cross-view tool_call_id.
- Preserve confidence-tier distinctions between confirmed tool output and inferred attacker behavior.

Checklist:

- pslist/psscan divergence is visible.
- Same-count but different-PID divergence still triggers cross-view review.
- psxview evidence is included when needed.
- malfind findings distinguish suspicious VADs from final malware conclusions.
- Timeline events include source, artifact class, description, and tool_call_id.

Deliverables:

- Auto-run updates if needed.
- Tests or smoke coverage.
- Report output updates if needed.

Acceptance tests:

- verdict-policy-smoke covers T1014/T1055 verdict behavior.
- py_compile and ruff pass for changed scripts.
- Rust MCP tests pass for vol_psxview if touched.

Task 3: EVTX Vertical Slice

Goal:

Make EVTX investigation useful without overclaiming.

Implement:

- Record EVTX rows as normalized timeline events when timestamps exist.
- Summarize records_seen, parse_errors, distinct event IDs, and top event IDs.
- Ensure a benign EVTX with parsed records does not become SUSPICIOUS solely because parsing succeeded.
- Treat Hayabusa/Sigma hits as triage leads that require review, tuning, and corroboration.
- Preserve single-source caveat for EVTX-only claims.
- Add next actions for Security, Sysmon, and PowerShell Operational logs when missing.
- Map relevant gaps to ATT&CK targets where practical.

Checklist:

- EVTX tool output is represented in timeline_summary.
- Parse errors remain visible.
- Benign-event-log policy is covered by verdict-policy-smoke or equivalent tests.
- Single-source event-log observations remain caveated.
- Logon Type 3 vs 10 caveat remains documented.

Deliverables:

- Auto-run/report updates if needed.
- Tests or policy smoke updates.
- Docs updates if needed.

Acceptance tests:

- verdict-policy-smoke passes.
- py_compile and ruff pass for changed scripts.

Task 4: Disk Artifact Vertical Slice

Goal:

Make disk evidence handling honest and useful even if full E01 deep parsing is not automated.

Implement:

- Keep disk evidence read-only.
- If auto mode remains case_open-only for disk, state that clearly in verdict/report/docs.
- If mounted/extracted disk artifacts are available, prefer existing typed tools for MFT, USN, Registry, Prefetch, and YARA before adding new tooling.
- If full-disk automation is deferred, document a read-only SIFT workflow using libewf/ewfmount, Sleuth Kit, Plaso/log2timeline, and targeted artifact extraction.
- Provide concrete next actions for MFT, USN Journal, Prefetch, Registry, Amcache/ShimCache, YARA, and mounted artifact paths.
- Ensure execution/persistence claims require disk corroboration or stay downgraded.

Checklist:

- Disk path does not pretend to parse unavailable artifacts.
- Report tells analyst what to do next in SIFT.
- Case completeness marks disk/filesystem availability and touched state honestly.
- Timeline guidance tells analysts how to continue in Plaso/Timesketch or spreadsheet tooling.

Deliverables:

- Auto-run next actions and report wording.
- Docs updates.

Acceptance tests:

- verdict-policy-smoke or pure helper tests cover evidence gaps.
- docs path smoke passes.

Task 5: Case Completeness, ATT&CK Coverage, and Evidence Gaps

Goal:

Make missing evidence explicit before a judge trusts the verdict.

Implement:

- Add or verify case_completeness in verdict.json.
- Add or verify attack_coverage in verdict.json.
- Add or verify next_actions in verdict.json.
- Include blind spots for unavailable or untouched artifact classes.
- Ensure coverage is derived from actual tools run and actual findings, not fake assumptions.
- Distinguish tool execution from enough evidence to make absence-of-evil claims.

Checklist:

- Memory, EVTX, disk/filesystem, and network evidence classes are represented.
- ATT&CK status distinguishes finding, covered_no_finding, available_not_examined, and blind_spot.
- covered_no_finding is explained as limited coverage, never as not malicious, clean, cleared, disproven, or absence of the technique.
- Next actions are capped and prioritized.

Deliverables:

- Pure helper code if needed.
- Tests in verdict-policy-smoke or dedicated tests.
- Report rendering updates.

Acceptance tests:

- Coverage helper marks T1014/T1055 findings correctly.
- Coverage helper marks exfil/network as blind spot when no network telemetry exists.
- Next actions are capped at five.

Task 6: Unified Timeline JSON and CSV

Goal:

Produce analyst-friendly timeline artifacts for spreadsheet and report use.

Implement:

- Persist timeline.json in host auto-run directory.
- Persist timeline.csv in host auto-run directory.
- Include timeline_summary in verdict.json.
- Include first_ts, last_ts, event_count, artifact_classes, and exports list.
- Ensure CSV includes details_json with stable JSON serialization.

Checklist:

- Timeline sorting is deterministic.
- Invalid timestamps are skipped safely.
- CSV is UTF-8 and spreadsheet-friendly.
- Report points to both JSON and CSV when CSV exists.

Deliverables:

- Auto-run export helper.
- Tests or smoke coverage.
- QUICKSTART output docs.

Acceptance tests:

- Pure CSV helper test verifies header and details_json.
- py_compile and ruff pass.

Task 7: Analyst Report and False-Positive Controls

Goal:

Make the generated report readable and decision-useful for SANS DFIR review.

Implement:

- Render Next 5 Analyst Actions.
- Render Case Completeness.
- Render ATT&CK Coverage.
- Render Unified Timeline with timeline.csv reference.
- Render Findings detail with confidence, pool, MITRE, tool_call_id, and artifact path.
- Add false-positive caveats where relevant, either in report text or linked docs.
- If existing report reproducibility/tamper examples remain, make them non-destructive: copy files before tamper experiments.

Checklist:

- Report does not bury evidence gaps.
- Report uses DFIR vocabulary.
- Report does not overclaim execution, exfiltration, or attribution.
- Report does not treat Sigma/Hayabusa hits as final compromise proof.
- Report remains usable if no timeline events exist.

Deliverables:

- render_report.py updates.
- Compile/lint checks.
- Docs updates if report contract changes.

Acceptance tests:

- py_compile passes for render_report.py.
- ruff passes.
- path-existence-smoke passes for docs references.

Task 8: Operator Docs and SIFT Judge Runbook

Goal:

A judge should know how to run the tool, where outputs appear, and how to interpret the results.

Update docs:

- README.md
- QUICKSTART.md
- CHANGELOG.md
- docs/README.md if adding docs
- docs/false-positives.md if caveats change
- docs/verdict-semantics.md if verdict policy changes
- docs/runbooks/ci-smoke-checklist.md if validation commands change

Document:

- how to run interactive mode
- how to run find-evil-auto
- how to run SIFT mode
- expected output files
- how to read verdict.json
- how to use timeline.csv
- how to interpret ATT&CK coverage
- how to interpret case completeness
- what evidence gaps mean
- what manual SIFT steps are next
- local setup blockers and fallbacks

Validation:

Run required docs and smoke checks:

```text
python scripts/divergence-smoke.py
python scripts/path-existence-smoke.py
python scripts/smoke-regex-tests.py
```

Task 9: Validation and Final Review

Goal:

Prove the project is practically ready or document the exact external blocker.

Focused validation commands:

```text
cargo test -p findevil-mcp --locked
cargo clippy -p findevil-mcp --all-targets -- -D warnings
python scripts/rust-mcp-smoke.py
python scripts/verdict-policy-smoke.py
python scripts/divergence-smoke.py
python scripts/smoke-regex-tests.py
python scripts/path-existence-smoke.py
ruff check scripts/find_evil_auto.py scripts/render_report.py scripts/verdict-policy-smoke.py
ruff format --check scripts/find_evil_auto.py scripts/render_report.py scripts/verdict-policy-smoke.py
python -m py_compile scripts/find_evil_auto.py scripts/render_report.py scripts/verdict-policy-smoke.py
```

Broader validation commands:

```text
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
ruff check .
ruff format --check .
python scripts/divergence-smoke.py
python scripts/path-existence-smoke.py
python scripts/smoke-regex-tests.py
python scripts/verdict-policy-smoke.py
python scripts/rust-mcp-smoke.py
uv run --directory services/agent_mcp python ../../scripts/agent-mcp-smoke.py
```

Optional if Node/web files changed:

```text
pnpm install --frozen-lockfile
pnpm --filter @findevil/web typecheck
pnpm --filter @findevil/web test
pnpm --filter @findevil/web build
```

If bash is available and prerequisites are built:

```text
bash scripts/run-all-smokes.sh
```

Validation discipline:

- Run fast focused tests during implementation, but final proof must include the broader validation list above or exact external blockers with fallback proof.
- If SIFT VM end-to-end execution is not available, do not claim end-to-end evidence execution. Claim only the validated unit/smoke/policy coverage.
- If no real SIFT/evidence run was possible, do not score the milestone as 100 unless the user explicitly accepts that external blocker.
- If Rust release binary is missing for rust-mcp-smoke, build it or document exact build blocker.
- If uv is missing for agent-mcp smoke, document exact error and run available Python tests/fallbacks.
- If ruff format fails, format and rerun.
- If mypy is not part of this repo's current canonical validation, do not invent it as a blocker.

Minimum focused test matrix:

Before final response, ensure tests or smokes cover:

```text
Rust MCP:
  - vol_psxview appears in tool list
  - vol_psxview dispatch validates input/error path
  - no execute_shell exists

Auto-run helpers:
  - evidence type dispatch policy
  - verdict policy for CONFIRMED, INFERRED T1014/T1055, and HYPOTHESIS
  - benign EVTX with parsed records does not produce SUSPICIOUS solely from successful parsing
  - correlator downgrade/keep outcomes affect final findings and verdict input
  - ATT&CK coverage statuses
  - next actions cap and priority
  - timeline.csv export

Docs/smokes:
  - no stale 11/12 Rust tool-count references in active docs
  - no stale active references to A5-removed timestamping tools
  - all backtick-quoted doc paths resolve or are allow-listed
```

Evidence requirements:

The final response must include evidence, not just claims:

- exact validation commands run and pass/fail result
- new or changed output fields
- new or changed report sections
- new or changed docs
- whether SIFT end-to-end was run or what external blocker prevented it
- commit hash if committed
- push status
- final completion score from the 100-point scorecard

Completion evidence table:

The final response must include a table like this, with real evidence filled in:

```text
Requirement | Status | Evidence
Parallel subagents launched | pass/fail | subagent summaries reconciled
Tool surface consistency | pass/fail | 19 Rust + 12 Python + smoke output
Memory DFIR slice | pass/fail | vol_pslist/psscan/psxview/malfind tests or code refs
EVTX slice | pass/fail | evtx timeline/summary behavior and tests
Disk artifact honesty | pass/fail | case_open limit + SIFT next actions documented
Case completeness | pass/fail | verdict field + report section
ATT&CK coverage | pass/fail | verdict-policy-smoke or helper test
Timeline JSON/CSV | pass/fail | artifact path + helper test
Report quality | pass/fail | report sections + compile/lint proof
False-positive controls | pass/fail | SOUL/MEMORY/docs/report references
Docs/runbook | pass/fail | doc paths
Ruff | pass/fail | command output
Format check | pass/fail | command output
Rust tests | pass/fail | command output
Clippy | pass/fail | command output
Python smokes | pass/fail | command output
SIFT end-to-end | pass/fail | command output or exact external blocker
Generated artifacts ignored | pass/fail | git status proof
Commit | pass/fail | commit hash or explicit no-commit policy
Completion score | pass/fail | 100/100 required
```

If any row is fail, the agent must not use a normal completion response. Continue working, or start the final response with Not complete: if a true external blocker prevents completion.

If a command cannot run because a binary is missing, include:

- command attempted
- exact error
- fallback command used
- why fallback is sufficient or insufficient for this milestone

Completion scorecard:

Use this scorecard before claiming completion. The milestone is not complete below 100/100 unless the final response starts with Not complete: and documents a true external blocker.

```text
10 pts: parallel subagent research completed and reconciled
10 pts: tool surface consistency complete and tested
10 pts: memory DFIR slice complete and tested
10 pts: EVTX/disk evidence handling honest and documented
15 pts: case completeness, ATT&CK coverage, next actions complete and tested
10 pts: timeline.json and timeline.csv complete and tested
10 pts: report renders analyst-useful sections and caveats
10 pts: operator docs and SIFT judge workflow updated
10 pts: focused and broader validation pass, including real SIFT/evidence execution when available; exact external blocker keeps score below 100 unless user accepts it
5 pts: commit policy satisfied, with commit hash if authorized
```

Global definition of done:

- Parallel subagents were launched for memory, EVTX, disk, timeline/ATT&CK, report/FP, and docs/validation.
- Subagent findings were reconciled into one integrated implementation before final edits.
- Rust MCP surface is 19 tools.
- Python MCP surface is 12 tools.
- Total MCP surface is 25 tools.
- vol_psxview is integrated, tested, and documented.
- Memory playbook produces useful process/injection findings and timeline events.
- EVTX playbook produces useful summaries and timeline events.
- Benign EVTX does not become SUSPICIOUS solely because records parsed.
- Correlator kept/downgraded outcomes affect final findings and verdict input.
- Disk evidence path is honest about current automation limits and manual next steps.
- verdict.json includes case_completeness, attack_coverage, next_actions, and timeline_summary.
- Host artifacts include timeline.json and timeline.csv.
- Report includes findings, next actions, case completeness, ATT&CK coverage, unified timeline, and false-positive caveats or links.
- Confidence labels follow SOUL.md.
- No execution claim relies on one artifact class only.
- No new attestation or timestamping work was added.
- No A5-removed timestamping runtime claims were reintroduced.
- No execute_shell or shell-equivalent MCP surface was added.
- No fake production findings or fake evidence were added.
- Ruff passes.
- Format check passes.
- Rust tests pass.
- Clippy passes.
- Python smokes pass.
- Docs drift guards pass.
- Generated artifacts and evidence are not staged.
- Commit policy is satisfied.
- Do not push unless explicitly asked.

Final self-review before final response or commit:

- Search changed files for TODO, mock, fake, execute_shell, A5-removed timestamping vocabulary, old Rust tool-count claims, old total tool-count claims, and old Python tool-count claims.
- Remove or explicitly justify test-only usage where applicable.
- Check git diff --stat and ensure the scope matches this milestone.
- Check git diff --check.
- Check git status --short.
- Verify generated artifacts are ignored and not staged.
- Verify no secrets, evidence files, VM images, or local state files are staged.
- Verify docs describe exactly how an operator uses the practical DFIR outputs.
- Verify final response includes the completion evidence table.

Reviewer demo script:

Before final response, prepare a short operator demo path in docs or final output:

1. Start in the repo root.
2. Run the interactive command or headless command from QUICKSTART.
3. Open the generated host output directory.
4. Inspect verdict.json for verdict, findings, case_completeness, attack_coverage, next_actions, and timeline_summary.
5. Open timeline.csv in a spreadsheet or text viewer.
6. Open REPORT.md, REPORT.html, or REPORT.pdf if renderer is available.
7. Confirm every finding cites tool_call_id.
8. Continue manually in SIFT using the listed next actions.

This does not need to create fake evidence. If no local evidence exists, document how to use existing fixtures or the SIFT VM path.

Commit:

Only commit if the user explicitly authorized committing in this session or included a commit requirement when pasting this prompt.

If authorized, create one accurate commit only after the full definition of done passes, for example:

```text
feat(dfir): improve practical investigation outputs
```

Do not create partial commits. Do not push unless explicitly asked.

Final response format:

1. What changed
2. Practical DFIR value
3. Proof/validation output
4. Remaining caveats, if any
5. Commit hash or no-commit policy
6. Push status
7. Completion score out of 100
8. Completion evidence table

If the completion score is not 100/100, the final response must start with Not complete: and explain exactly what remains.

Forbidden final-response patterns before 100/100:

- This is ready for the next phase.
- The foundation is done.
- Most of the work is complete.
- Remaining work: followed by required checklist items.
- I could not run X without exact blocker evidence and fallback validation.

If you are about to write one of those, stop writing the final answer and continue implementation instead.
