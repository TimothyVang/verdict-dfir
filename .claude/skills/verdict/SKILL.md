---
name: verdict
description: Run the whole VERDICT pipeline on evidence in one go and report what fired. Use when the operator says /verdict, "run verdict", "investigate <path> end to end", "is there evil here", or asks to run the full investigation + automation + report and SEE every workflow that ran. Runs scripts/verdict --parallel, then surfaces the Verdict, the n8n automation, and the grounding sidecar in one status block.
---

# VERDICT — one-shot investigation + a unified "what ran" report

Use this skill when the operator wants the full pipeline in a single command and wants
to *see* every tool fire — including the n8n automation and grounding workflows that the
plain run executes silently.

## Safety rules (do not violate)

- **Evidence is read-only.** Never mutate the evidence; the pipeline opens it read-only.
- **Never cross the memory/automation boundary.** n8n automation and the grounding sidecar
  are post-verdict, operator-side aids — never evidence, never a Finding, never in the
  hash-chained audit chain. Read their sidecars to *report* them; never treat them as
  evidence.
- **Do not change the MCP surface** or add broad MCP servers.
- Use DFIR vocabulary: **Case**, **Finding**, **Verdict**, **Confidence**.

## Steps

### 1. Resolve the evidence
- If the operator gave a path, use it. Otherwise use the newest file in `evidence/`
  (the launcher does this for you when no path is passed).

### 2. Pre-check the automation stack (so it visibly fires, not silently skips)
- Check n8n: `curl -fsS --max-time 3 http://127.0.0.1:5678/healthz`.
- If it is **down**, tell the operator the grounding + finding-to-action workflows will be
  skipped, and *offer* to start n8n first (do not start it without asking). The
  investigation + signed Verdict still run fully without n8n.

### 3. Run the pipeline (parallel, one go)
- Run: `bash scripts/verdict <evidence> --parallel`
  - `--parallel` overlaps the independent tool calls (verify re-runs + disk-artifact
    parses); the Verdict and the audit chain are unchanged.
  - Add `--workers N` (default 4) — lower it on a low-RAM host; each lane is its own
    findevil-mcp process.
  - Add `--no-dashboard` only if the operator does not want the browser opened.
- Stream the launcher's stage output. It now prints a line when n8n posts and when
  grounding is written or skipped — surface those to the operator as they happen.

### 4. Locate the Case outputs
- Read `tmp/verdict-last-run.json` to get the `case_id` / case directory.
- The Case dir is `tmp/auto-runs/<case-id>/`. Read whichever of these exist:
  - `verdict.json` — the Verdict, confidence, findings, tool-call count.
  - `manifest_verify.json` — `overall` must be `true` (offline-verifiable custody).
  - `automation.json` — the n8n finding-to-action result (workflow name, reachability).
  - `grounding.json` — the grounding research (claims researched, sources).

### 5. Print ONE unified status block
Summarize, in this shape:

```
Verdict   : <SUSPICIOUS | INDETERMINATE | NO_EVIL>  (confidence <…>)
Findings  : <N>  (each citing a tool_call_id)  ·  tool calls: <N>
Custody   : manifest_verify.overall = <true|false>
Automation: n8n <fired: workflow <name> | skipped (down)>  →  automation.json
Grounding : <K claims researched | skipped>  →  grounding.json
Case      : tmp/auto-runs/<case-id>/   ·   REPORT.html / REPORT.pdf
```

- Be honest about coverage: an `INDETERMINATE` on a custody-only or thin Case is a correct,
  honest result — never inflate it to `NO_EVIL`/"safe".

### 6. Offer to open the artifacts
- Offer to open the live dashboard (`http://localhost:3000/?case=<case-dir>`) and the
  `REPORT.html` via the browser MCP (`mcp__playwright__browser_navigate`) — offer, don't
  auto-open beyond what the launcher already opens.

## Notes
- `--sift` runs the DFIR tools inside the SANS SIFT VM; in that mode the n8n/grounding steps
  are skipped by design.
- If `scripts/verdict` stops before `case_open`, report the exact failing line — do not
  claim a Verdict that was not produced.
