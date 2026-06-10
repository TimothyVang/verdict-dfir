---
name: verdict
description: Turnkey end-to-end DFIR — type /verdict <evidence> and it bootstraps everything (builds the MCP servers, brings up n8n, prepares the SIFT VM) then runs the full pipeline with no flags. Use when the operator says /verdict, "run verdict", "investigate <path> end to end", "is there evil here", or wants the whole investigation + automation + report in one go. Auto-selects the SIFT VM (full forensic toolchain) so disk images fully extract, fires n8n + grounding, and surfaces the Verdict + every workflow that ran.
---

# VERDICT — turnkey one-shot DFIR + a unified "what ran" report

The operator types `/verdict <evidence>` (or just `/verdict`) and gets the **whole** pipeline
with no setup and no flags: this skill bootstraps the environment, auto-uses the SIFT VM so disk
images actually extract, runs the parallel investigation to a signed Verdict, fires the n8n
automation + grounding workflows, and shows the dashboard + report — then reports everything that
fired.

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

### 2. Bootstrap everything (no manual installs, no flags for the operator)
- Run `bash scripts/verdict-setup.sh` and read its two stdout lines:
  `FIND_EVIL_GUEST_IP=<ip>` and `SIFT_OK=<0|1>`.
- It builds the MCP servers (via `install.sh`) if missing, brings up n8n, and prepares the
  SIFT VM — resolves its **current** DHCP IP (the hardcoded default is often stale), powers it
  on if it is off, and confirms the forensic toolchain (`ewfmount` etc.). The SIFT VM is where
  Volatility/Hayabusa/ewfmount/TSK live pre-installed, so this is how "install everything" is
  satisfied without installing forensic binaries on the host.
- Surface its progress lines to the operator. It is non-fatal: a missing n8n just means
  automation is skipped; a missing VM falls back to local mode.

### 3. Run the full pipeline — auto-SIFT, parallel, n8n + grounding, all in one go
The operator types only `/verdict <evidence>`; **this skill adds the right flags.**
- If `SIFT_OK=1`, run:
  `FIND_EVIL_GUEST_IP=<ip> bash scripts/verdict <evidence> --sift`
  → DFIR tools run **in the SIFT VM** (the only way to fully extract a disk image) → signed
  verdict + manifest → **n8n finding-to-action fires** → **grounding fires** → dashboard + report.
- If `SIFT_OK=0` (no reachable VM), run `bash scripts/verdict <evidence>` locally and tell the
  operator a **disk image is custody-only** without the VM (memory/EVTX/network still work if
  their tools are present).
- Parallel is the **default** (`--workers 2`); pass `--no-parallel` only to force serial, and
  `--no-dashboard` only if the operator does not want the browser opened.
- Stream the launcher's stage output — it prints when n8n posts and when grounding is
  written/skipped; surface those as they happen.

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

### 6. Show the dashboard AND the report at the end
Unless the operator passed `--no-dashboard`, surface both:
- **Dashboard:** `scripts/verdict` already auto-opens the live dashboard deep-linked to
  the Case (`http://localhost:3000/?case=<case-dir>`). If it did not open (headless, or
  the dev server was slow), open it via the browser MCP
  (`mcp__playwright__browser_navigate`).
- **Report:** open the generated `REPORT.html` from the Case dir
  (`tmp/auto-runs/<case-id>/REPORT.html`) via the browser MCP so the operator sees the
  full analyst report, not just the status block. (`REPORT.pdf` is alongside it.)
- Always also print the paths — dashboard URL, `REPORT.html`/`REPORT.pdf`, `verdict.json`
  — so they are reachable even when no browser MCP is wired.
- If `--no-dashboard` was passed, skip opening but still print the paths.

## Notes
- `--sift` runs the DFIR tools inside the SANS SIFT VM over SSH (needed for full disk
  extraction — local mode can only mount the EWF container, not the inner volume). The
  post-verdict n8n automation + grounding now fire in `--sift` mode too (host-side, after the
  case dir syncs back), so `--sift` gives you the full pipeline in one go.
- The SIFT VM IP default (`192.168.197.143`) can be stale; if `--sift` can't reach the VM,
  set `FIND_EVIL_GUEST_IP` to the current IP (e.g. via `vmrun getGuestIPAddress`).
- If `scripts/verdict` stops before `case_open`, report the exact failing line — do not
  claim a Verdict that was not produced.
