---
name: verdict
description: Run VERDICT DFIR end to end from Claude Code. Use when the operator says /verdict, run verdict, investigate evidence end to end, is there evil here, or wants a signed Verdict and report. The skill verifies setup, uses SIFT mode when available, falls back honestly when it is not, and reports dashboard/report paths without treating optional automation as evidence.
---

# VERDICT DFIR

Use this skill to run the public VERDICT workflow from Claude Code. It is a guided entrypoint over the repository scripts and MCP tools; it is not a second product path.

## Safety Rules

- Evidence is read-only. Never mutate source evidence, mounted evidence, or original Case files.
- Every Finding must cite a current-case `tool_call_id`.
- Run `verify_finding` for each Finding and record each verifier decision with `pool_handoff` before `judge_findings` consumes the Findings.
- `report_qa` must be audited before `manifest_finalize`; a failed or missing report QA gate blocks customer-ready output and requires expert review.
- Optional n8n, grounding, browser, dashboard, and memory sidecars are operator aids only. They are never evidence and never create Findings.
- Do not assert attribution, actor identity, legal breach status, or business impact.
- Do not inflate limited coverage to `NO_EVIL`, clean, cleared, no compromise, or proof of no evil.
- Disk images are content-scoped: local Sleuth Kit/libewf or SIFT can extract supported artifacts for parsing; if mount/extract produces no supported artifacts, the raw image remains custody-only.
- If the pipeline stops before `case_open`, no Verdict exists. Report the failing line instead of summarizing evidence.

## Steps

### 1. Resolve Evidence

If the operator supplied a path, use that exact path. If no path was supplied, use `scripts/verdict --watch` and ask the operator to drop evidence into `evidence/`.

Do not choose between multiple unrelated evidence files silently.

### 2. Preflight And Setup

Run the setup helper first:

```bash
bash scripts/verdict-setup.sh
```

Read its output, especially:

```text
FIND_EVIL_GUEST_IP=<ip>
SIFT_OK=<0|1>
```

This helper builds missing MCP servers through `scripts/install.sh`, checks optional n8n/grounding availability, and attempts SIFT VM discovery when possible. Missing optional automation is non-fatal. Missing core runtime dependencies must be reported plainly.

### 3. Run The Case

If `SIFT_OK=1`, run SIFT mode:

```bash
ARTIFACT="/mnt/hgfs/evidence/example.E01"
FIND_EVIL_GUEST_IP="<ip>" bash scripts/verdict "${ARTIFACT}" --sift
```

For host-local evidence that is not guest-mounted, configure an explicit guest-visible case staging root instead of falling back to legacy VM evidence directories:

```bash
HOST_EVIDENCE="/path/to/evidence.E01"
CASE_ID="auto-$(python3 -c 'import uuid; print(uuid.uuid4())')"
FINDEVIL_SIFT_CASE_STAGING_ROOT="/home/sansforensics/find-evil/tmp/auto-runs/${CASE_ID}/staging/sift" \
FIND_EVIL_GUEST_IP="<ip>" \
bash scripts/verdict "${HOST_EVIDENCE}" --sift --case-id "${CASE_ID}"
```

If `SIFT_OK=0`, run local mode:

```bash
EVIDENCE="/path/to/evidence"
bash scripts/verdict "${EVIDENCE}"
```

In local mode, state the scope honestly: memory, EVTX, PCAP, Velociraptor collections, and extracted artifacts can still be useful; raw disk images need local Sleuth Kit/libewf support to produce parsed artifacts, and remain custody-only if mount/extract fails or yields no supported artifacts.

Use default parallel execution. Pass `--no-dashboard` only when the operator explicitly does not want browser/dashboard behavior.

SIFT mode should prefer read-only guest-mounted evidence paths such as `/mnt/hgfs/evidence/<artifact>`; these are referenced directly and are not copied. If the operator supplies a host-only path in `--sift` mode, the launcher fails closed unless `FINDEVIL_SIFT_CASE_STAGING_ROOT` points to a guest-visible project case staging directory, typically ending in `staging/sift`. Current-run SIFT staging is marker-guarded and removed after a successful run unless `--keep-sift-staging` is set. Do not ask the operator to manually remove current-run staging after a successful `scripts/verdict --sift` run; if disk pressure remains, distinguish automatic current-run cleanup from legacy root-level staging that predates this lifecycle and requires explicit approval before deletion.

Keep `--run-summary` outputs outside evidence paths. Use `tmp/...` or another non-evidence output directory; the launcher rejects summary paths inside the evidence directory or configured host evidence roots.

### 4. Locate Case Outputs

Use the case path printed by `scripts/verdict`. Prefer the case-local run summary:

```text
tmp/auto-runs/<case-id>/summaries/run-summary.json
```

Then inspect the referenced Case directory under:

```text
tmp/auto-runs/<case-id>/
```

Generated sidecars are grouped under the same case directory, including `summaries/`, `logs/`, `staging/`, `artifacts/`, and `evidence/` reference metadata when present.

Only read `tmp/verdict-last-run.json` when it was explicitly requested with `--run-summary tmp/verdict-last-run.json`; otherwise it may be stale from a prior compatibility run.

Read the relevant outputs when present:

- `verdict.json` - Verdict, confidence, Findings, and coverage.
- `manifest_verify.json` - custody verification; `overall` must be `true` for a completed manifest.
- `coverage_manifest.json` - artifact classes available, attempted, parsed, failed, unsupported, or not supplied.
- `automation.json` - optional post-verdict workflow status.
- `grounding.json` - optional post-verdict claim-grounding status.

### 5. Report One Status Block

If `manifest_verify.json` is missing or `overall` is not `true`, report `RUN INCOMPLETE / CUSTODY INVALID`, do not describe the output as signed, and do not present Findings as valid until custody is fixed.

Otherwise use this shape:

```text
Verdict   : <SUSPICIOUS | INDETERMINATE | NO_EVIL> (confidence <value>)
Findings  : <N> (all Findings cite tool_call_id: <yes|no>)
Custody   : manifest_verify.overall = true
Coverage  : <short scope statement from coverage_manifest/verdict limitations>
Automation: n8n <reachable/recorded | skipped | unavailable> -> automation.json if present
Grounding : <claims researched | skipped | unavailable> -> grounding.json if present
Case      : tmp/auto-runs/<case-id>/
Report    : REPORT.html / REPORT.pdf if present
```

If any Finding lacks `tool_call_id`, call that out as invalid instead of presenting it as a valid Finding.

### 6. Open Dashboard And Report When Available

If a browser MCP is available and `--no-dashboard` was not requested, open:

- Dashboard URL printed by `scripts/verdict`, usually `http://localhost:3000/?case=<case-dir>`.
- `tmp/auto-runs/<case-id>/REPORT.html`.

Always print paths even when a browser cannot be opened.

## Notes

- `scripts/verdict <evidence>` is the canonical one-shot product launcher.
- `scripts/find-evil` or `claude` plus `investigate <path>` is the interactive path.
- SIFT mode is recommended for disk images because it supplies the forensic workstation baseline for read-only mount and extraction.
- n8n and grounding are opt-in operator workflow layers. Report whether they ran, but never use them as evidence or confidence boosters.
- A scoped `INDETERMINATE` is an honest result when coverage is thin. Do not convert it into reassurance.
