# VERDICT — see it run

The whole workflow, end to end: **install → invoke → investigate → watch → verdict.**
Every capture below is a real run (NIST/EVTX evidence), not a mockup. Home paths are
shown as `~` for privacy; nothing else is edited.

## 1 · Install — one preflight, then green

`scripts/doctor.sh` checks the whole toolchain in seconds and prints an honest summary.

![Install / preflight doctor](install-doctor.gif)

## 2 · Invoke — one command in Claude Code

VERDICT *is* a Claude Code agent (Amendment A2). You type one line — `investigate <evidence>`
— and the agent scopes the case and takes over.

![Claude Code investigating evidence](claude-code-live-run.png)

## 3 · Investigate — the DFIR pipeline solves the case

`case_open` SHA-256s the evidence, forks Pool A (persistence) + Pool B (exfil), runs the typed
DFIR tools (EVTX, Hayabusa, prefetch, …), a verifier re-checks every finding, the judge merges
them, and the run is sealed into a signed manifest — ending on the verdict and `manifest_verify = PASS`.

![End-to-end investigation](investigation.gif)

## 4 · Watch it live — the dashboard

Every tool call and finding streams to the dashboard the moment it lands, each tagged
`CONFIRMED` / `INFERRED` / `HYPOTHESIS` and citing the exact `tool_call_id` behind it.

![Live dashboard](dashboard-live.gif)

## 5 · The verdict + the report

A signed, evidence-bound verdict (`SUSPICIOUS` / `INDETERMINATE` / `NO_EVIL`) and a full analyst
report — every finding traceable to a tool call, the whole chain verifiable offline.

| Verdict | Tool-cited findings | Analyst report |
|---|---|---|
| ![hero](dashboard-hero.png) | ![findings](dashboard-findings.png) | ![report](report.png) |

---

Reproduce any of these with the recipes in
[`scripts/make-demo-video/CAPTURE.md`](../../scripts/make-demo-video/CAPTURE.md), or just run
`scripts/verdict <evidence>` yourself.
