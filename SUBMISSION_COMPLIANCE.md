# SANS Find Evil! 2026 — Submission Compliance Checklist

This file exists for one reason: **make it trivially easy for judges to verify every required
submission component without hunting through the repo.** Each item below names the requirement,
states whether it is satisfied, and gives the exact path or URL.

---

## 1. Public Code Repository

**Requirement:** Provide a URL to your code repository for judging and testing.

**STATUS: SATISFIED**

> **Repository:** https://github.com/TimothyVang/verdict-dfir
>
> The repository is public. Clone and run in three commands — see §4 below.

---

## 2. Open-Source License (MIT or Apache 2.0)

**Requirement:** The repository must be public and open source by including an MIT or Apache 2.0
open source license file.

**STATUS: SATISFIED**

> **License file:** [`LICENSE`](LICENSE) — Apache License, Version 2.0
>
> The submission tree contains only Apache-2.0 and MIT code. AGPL/GPL tools (Hayabusa,
> Volatility3, Velociraptor, YARA, Chainsaw) are invoked as subprocesses only — they are
> never linked into the submission binary, keeping the Apache-2.0 tree clean per SANS rules.

---

## 3. README with Setup Instructions

**Requirement:** The repository must contain a README with setup instructions.

**STATUS: SATISFIED**

> **Primary README:** [`README.md`](README.md)
>
> **Quickstart (three steps):** [`QUICKSTART.md`](QUICKSTART.md)
>
> **One-command entry point after setup:**
> ```bash
> scripts/verdict <path-to-evidence>
> ```
> `scripts/verdict` runs the full one-command workflow: preflight → investigate →
> open the live dashboard → signed verdict + report. `QUICKSTART.md` covers three
> environments:
> - Local (SIFT tools on host) — the default
> - SANS SIFT VM (`scripts/verdict <path> --sift`)
> - Headless / automated (`scripts/verdict <path> --no-dashboard`)

---

## 4. Live Deployment or Step-by-Step Instructions

**Requirement:** Include either a live deployment URL or step-by-step instructions.

**STATUS: SATISFIED**

> **Step-by-step:** [`QUICKSTART.md`](QUICKSTART.md)
>
> Minimal steps:
> ```bash
> # 1. Install
> bash scripts/install.sh
>
> # 2. Run pre-flight check
> bash scripts/doctor.sh
>
> # 3. Investigate evidence
> scripts/verdict /path/to/evidence
> # or open Claude Code and type: investigate /path/to/evidence
> ```
>
> Full walkthroughs (local / SIFT VM / headless) are in `QUICKSTART.md`.

---

## 5. Text Description — Features and Functionality

**Requirement:** Include a text description that should explain the features and functionality
of your Project.

**STATUS: SATISFIED**

> **Full description:** [`README.md`](README.md) — see sections:
> - *What you get* and *Capabilities* (the differentiators + disk/memory/fleet coverage)
> - *How it works* (the typed tool surface, cryptographic custody, ACH agent topology, six trust boundaries)
> - *Accuracy — measured, and honest about the gap* (reproducible recall vs published goldens)
>
> **Short summary:**
> Find Evil! is a Claude Code DFIR agent that investigates Windows host evidence (memory
> images, EVTX logs, disk artifacts) and produces a cryptographically signed verdict any
> third party can verify offline. It exposes 32 narrow typed MCP tools (20 Rust DFIR +
> 12 Python crypto/ACH/memory) — no `execute_shell`. Two competing-hypothesis agent pools
> (persistence-biased Pool A + exfil-biased Pool B) investigate in parallel; disagreements
> are surfaced as first-class `kind=contradiction` audit records before the judge merges.
> A standalone maintainer tool (`scripts/self-score.py`) grades a completed run against the
> SANS rubric *before* submission, writing `<case>/self-score.json` without touching the
> sealed audit chain — it is not part of the investigation pipeline.

---

## 6. Demonstration Video

**Requirement:** Include a demonstration video of your Project.

**STATUS: SATISFIED — rendered, hosted on YouTube, published (2026-06-12)**

> **The hosted cut.** The full 4:35 film (10 beats, voiceover, real-footage exhibits) is
> public on YouTube, with the mp4 mirrored as a release asset:
>
> **Hosted URL (YouTube):** <https://youtu.be/4RQnVden6L8>
>
> **mp4 mirror (release asset):** <https://github.com/TimothyVang/verdict-dfir/releases/download/v-submit/find-evil-demo.mp4>
>
> **Real exhibits in the cut (genuine capture, not animation):**
> 1. **Beat 2** — an actual asciinema capture of a live investigation, slowed to 0.3× and
>    trimmed to end held on the verifier self-correction (`verify_finding rejected … —
>    re-dispatching once` → `recovered … on re-dispatch ✓`, with the declared fault
>    injection noted in the audit chain).
> 2. **Beat 6** — a fresh localhost dashboard capture (current brand, live finding stream,
>    a held hover on a finding's `tool_call_id` provenance line).
> 3. **Beat 7** — the offline tamper proof, recorded per
>    [`CAPTURE.md`](scripts/make-demo-video/CAPTURE.md) Slot 3: `scripts/trace-finding`
>    passes on the committed sample run, one hex character is flipped in a `/tmp` copy, and
>    the verifier fails naming the exact broken record (`seq 97: prev_hash break`).
>
> Narration canon is [`beats-data.ts`](scripts/make-demo-video/src/beats/beats-data.ts);
> re-render with `pnpm render` (output goes to `/tmp`, not the repo — the mp4 ships on
> YouTube + as a release-asset mirror, never in the tree). The Devpost form's video field
> carries the same YouTube URL.

---

## 7. Architecture Diagram

**Requirement:** Include an Architecture Diagram.

**STATUS: SATISFIED**

> **Architecture document:** [`docs/architecture.md`](docs/architecture.md)
>
> Contains:
> - Mermaid flowchart of all six trust boundaries
> - Runtime architecture (evidence vault → SIFT subprocesses → MCP servers → Claude Code)
> - Audit chain data-flow diagram
> - Relationship to Protocol SIFT (coexistence table)
> - Prompt-based vs. architectural guardrails comparison (required by SANS rules §3)
>
> The Mermaid diagrams render directly on GitHub — open
> [`docs/architecture.md`](docs/architecture.md) for the rendered trust-boundary flowchart,
> the runtime architecture, and the audit-chain data-flow diagram.

---

## 8. Evidence Dataset Documentation

**Requirement:** Include Evidence Dataset Documentation.

**STATUS: SATISFIED**

> **Dataset documentation:** [`docs/DATASET.md`](docs/DATASET.md)
>
> Documents:
> - NIST CFReDS Hacking Case (`SCHARDT.001`) — public domain, SHA-256, source URL
> - SANS HACKATHON-2026 SRL-2018 dataset (DC investigation, 22-host fleet)
> - OTRF Security-Datasets (APT3 EVTX fixtures)
> - Volatility Foundation cridex.vmem (memory image)
> - Synthetic benign baseline (generated by `scripts/fetch-fixtures.sh`)
>
> Download / stage all fixtures:
> ```bash
> bash scripts/fetch-fixtures.sh
> ```

---

## 9. Accuracy Report

**Requirement:** Include an Accuracy Report.

**STATUS: SATISFIED**

> **Consolidated accuracy report:** [`docs/accuracy-report.md`](docs/accuracy-report.md) — the
> scoring method (bipartite recall + asymmetric verdict gate), the recall table against published
> ground truth (nitroba 5/5 = 100%, reproducible from `docs/sample-run/nitroba`; NIST 1/14 = 7%;
> 8 staged + scheduled), 100% `tool_call_id`
> citation across committed runs, the false-positive posture (3 FP layers + the alihadi-09 control),
> and the honest limits. Every number is reproducible from a committed artifact (run
> `scripts/score-recall.py docs/sample-run/<case> --golden goldens/<case>`).
>
> **Full investigation report (PDF):**
> [`docs/reports/2026-04-26-srl2018-dc-investigation.pdf`](docs/reports/2026-04-26-srl2018-dc-investigation.pdf)
>
> **HTML version:**
> [`docs/reports/2026-04-26-srl2018-dc-investigation.html`](docs/reports/2026-04-26-srl2018-dc-investigation.html)
>
> **Markdown source:**
> [`docs/reports/2026-04-26-srl2018-dc-investigation.md`](docs/reports/2026-04-26-srl2018-dc-investigation.md)
>
> Key accuracy metrics — **NIST CFReDS Hacking Case** (`SCHARDT.001` golden):
> - **Recall target:** ≥ 71% of 14 canonical findings (per golden at
>   `goldens/nist-hacking-case/expected-findings.json`)
>
> Key findings — **SRL-2018 DC** (the showcase report, a different dataset):
> - **Process-enumeration divergence** (`vol_pslist`=0 vs `vol_psscan`=124) stands as a
>   **HYPOTHESIS** (acquisition smear / kernel-global read failure: `KeNumberProcessors`=0, core
>   OS singletons recovered only by `psscan`, duplicate `System` EPROCESS), not confirmed DKOM.
>   Stated plainly: the original run over-claimed this as confirmed T1014 and post-run expert
>   review reconciled it (commit `cd075c9`) — the documented caught-hallucination case study in
>   [`docs/accuracy-report.md`](docs/accuracy-report.md) §3, and the origin of the engine's
>   smear-disambiguation rule + `vol_psxview`. Corroborable leads: `subject_srv.exe` (T1543.003)
>   + service-spawned `cmd.exe` (T1059.003).
> - Fleet accuracy summary: §9.1 of the report (22-host SRL-2018 rollup)

---

## 10. Agent Execution Logs

**Requirement:** Include Agent Execution Logs.

**STATUS: SATISFIED**

> **Committed sample runs (self-contained on a fresh clone):**
> [`docs/sample-run/`](docs/sample-run/) ships seven real, completed investigations — their
> `audit.jsonl`, `run.manifest.json`, `verdict.json`, `manifest_verify.json`, and `REPORT.md`.
> All verify **offline** (`manifest_verify` returns `overall: true`), and
> [`docs/sample-run/README.md`](docs/sample-run/README.md) walks a single finding all the way
> back to the tool execution and Merkle leaf that produced it. Every live investigation also
> produces the same `audit.jsonl` in its case run directory.
>
> **Multi-agent message logs:** the `acp_handoff` records in each `audit.jsonl` are the
> agent-to-agent messages, timestamped and hash-chained with the tool executions — the
> inter-agent log required of multi-agent submissions is in the same verifiable chain, not a
> side file. The [`attack-samples-evtx/`](docs/sample-run/attack-samples-evtx/) run records the
> full ACH topology: **supervisor → pool_a / pool_b** (dispatch, opposite hypotheses),
> **pool_a / pool_b → judge** (merge), and per-finding **verifier → judge** approvals — the
> `from_role`/`to_role` payload fields make each one explicit.
>
> **Real-time self-correction in the logs:**
> [`docs/sample-run/natural-self-correction/`](docs/sample-run/natural-self-correction/) shows
> six genuine tool failures (truncated registry hives on real evidence — no fault hook) each
> answered by a logged `course_correction`, then the documented HEARTBEAT escalation sealing an
> honestly-scoped partial verdict. Trace it yourself:
> `scripts/trace-finding docs/sample-run/natural-self-correction`.
>
> **Format:** Hash-chained JSONL — each line contains `seq`, `kind`, `ts` (UTC ISO-8601),
> `payload`, `line_hash`, and `prev_hash`. The chain is verified by the
> `audit_verify` MCP tool and by `manifest_verify`.
>
> **Viewing logs from a run:**
> ```bash
> # After any investigation:
> cat $FINDEVIL_HOME/cases/<case-id>/audit.jsonl | python3 -m json.tool | head -50
>
> # Or via the live dashboard:
> pnpm --filter @findevil/web dev   # then open http://localhost:3000/debug
> ```
>
> **Committed sample run layout** (`docs/sample-run/<case>/`; a full live run additionally
> emits `REPORT.html`, `REPORT.pdf`, `figures/`, and `timeline.*`):
> ```
> docs/sample-run/<case>/
> ├── audit.jsonl          # hash-chained execution log (every tool call, finding, verdict)
> ├── verdict.json         # final verdict with confidence and MITRE mappings
> ├── run.manifest.json    # Merkle root + signature metadata
> ├── manifest_verify.json # offline verification result (overall: true)
> └── REPORT.md            # human-readable investigation report
> ```

---

## Quick Reference Table

| # | Requirement | File / URL | Status |
|---|-------------|------------|--------|
| 1 | Code repository URL | https://github.com/TimothyVang/verdict-dfir | SATISFIED |
| 2 | Apache 2.0 / MIT license file | [`LICENSE`](LICENSE) | SATISFIED |
| 3 | README with setup instructions | [`README.md`](README.md) · [`QUICKSTART.md`](QUICKSTART.md) | SATISFIED |
| 4 | Deployment / step-by-step instructions | [`QUICKSTART.md`](QUICKSTART.md) | SATISFIED |
| 5 | Feature / functionality description | [`README.md`](README.md) | SATISFIED |
| 6 | Demonstration video | [YouTube (4:35)](https://youtu.be/4RQnVden6L8) · [mp4 mirror](https://github.com/TimothyVang/verdict-dfir/releases/download/v-submit/find-evil-demo.mp4) · [`beats-data.ts`](scripts/make-demo-video/src/beats/beats-data.ts) (narration canon) | SATISFIED (4:35 cut, real exhibits — see §6) |
| 7 | Architecture diagram | [`docs/architecture.md`](docs/architecture.md) | SATISFIED |
| 8 | Evidence dataset documentation | [`docs/DATASET.md`](docs/DATASET.md) | SATISFIED |
| 9 | Accuracy report | [`docs/accuracy-report.md`](docs/accuracy-report.md) (incl. §6 evidence integrity + named caught hallucinations) · [`docs/reports/2026-04-26-srl2018-dc-investigation.pdf`](docs/reports/2026-04-26-srl2018-dc-investigation.pdf) | SATISFIED (best: nitroba 100% recall, reproducible; NIST 7% — honest coverage gap) |
| 10 | Agent execution logs | [`docs/sample-run/`](docs/sample-run/) (7 committed runs — one per evidence class, verify offline; `acp_handoff` = agent-to-agent log) | SATISFIED |

---

*Last verified: 2026-06-12 — execution-log deliverable (#10) now ships seven committed,
offline-verifiable runs under [`docs/sample-run/`](docs/sample-run/); all return
`manifest_verify overall: true`. The two NIST SCHARDT runs (Prefetch-only INDETERMINATE vs.
`--sift` Prefetch+UserAssist CONFIRMED) show the ≥2-artifact-class rule cutting both ways, and
`natural-self-correction/` adds the un-staged failure-recovery arc (six `course_correction`
records + HEARTBEAT escalation), and `memory-dc/` adds a live Volatility 3 run that holds a
pslist/psscan divergence at HYPOTHESIS (acquisition smear, not DKOM) on first pass — both
ed25519-signed and offline-traceable.*
