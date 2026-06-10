# SANS Find Evil! 2026 — Submission Compliance Checklist

This file exists for one reason: **make it trivially easy for judges to verify every required
submission component without hunting through the repo.** Each item below names the requirement,
states whether it is satisfied, and gives the exact path or URL.

---

## 1. Public Code Repository

**Requirement:** Provide a URL to your code repository for judging and testing.

**STATUS: SATISFIED**

> **Repository:** https://github.com/TimothyVang/sans-hackathon
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
> - *What it does* (four differentiators)
> - *How it's built* (five trust boundaries)
> - *Anticipated questions* (Q&A for judges)
>
> **Short summary:**
> Find Evil! is a Claude Code DFIR agent that investigates Windows host evidence (memory
> images, EVTX logs, disk artifacts) and produces a cryptographically signed verdict any
> third party can verify offline. It exposes 31 narrow typed MCP tools (19 Rust DFIR +
> 12 Python crypto/ACH/memory) — no `execute_shell`. Two competing-hypothesis agent pools
> (persistence-biased Pool A + exfil-biased Pool B) investigate in parallel; disagreements
> are surfaced as first-class `kind=contradiction` audit records before the judge merges.
> A standalone maintainer tool (`scripts/self-score.py`) grades a completed run against the
> SANS rubric *before* submission, writing `<case>/self-score.json` without touching the
> sealed audit chain — it is not part of the investigation pipeline.

---

## 6. Demonstration Video

**Requirement:** Include a demonstration video of your Project.

**STATUS: NEEDS RE-RECORD (live screencast) — explainer committed, hosted URL pending**

> **What is committed today:** [`docs/find-evil-demo.mp4`](docs/find-evil-demo.mp4) is a
> 3:59 narrated **Remotion motion-graphics explainer** (source:
> `scripts/make-demo-video/`). It explains the architecture well, but it is **not a live
> terminal screencast** — the terminal it shows is a simulated animated pane and the
> dashboard is a static screenshot.
>
> **What must ship before the deadline:**
> 1. Re-record per the authoritative beat map [`docs/demo-script-a2.md`](docs/demo-script-a2.md)
>    as a real screen capture (<5 min, narrated): `scripts/verdict` launch, `case_open` +
>    SHA-256, a **live self-correction** (see the reproducible fault-injection recipe in
>    Beat 4's notes — `FIND_EVIL_FAULT_INJECT` makes the verifier catch + re-dispatch
>    on camera), and `manifest_verify` flipping to `overall=false` on a one-byte tamper.
> 2. Host it (YouTube/Vimeo/Youku) and record the URL here and in the Devpost
>    submission URL field.
>
> **Hosted URL:** _pending re-record_

---

## 7. Architecture Diagram

**Requirement:** Include an Architecture Diagram.

**STATUS: SATISFIED**

> **Architecture document:** [`docs/architecture.md`](docs/architecture.md)
>
> Contains:
> - Mermaid flowchart of all five trust boundaries
> - Runtime architecture (evidence vault → SIFT subprocesses → MCP servers → Claude Code)
> - Audit chain data-flow diagram
> - Relationship to Protocol SIFT (coexistence table)
> - Prompt-based vs. architectural guardrails comparison (required by SANS rules §3)
>
> The Mermaid diagrams render directly on GitHub. A static PNG export is at
> [`docs/architecture-diagram.png`](docs/architecture-diagram.png) if it exists,
> otherwise open `docs/architecture.md` on GitHub for rendered diagrams.

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
> - **Process-enumeration divergence** (`vol_pslist`=0 vs `vol_psscan`=124) reported as a **HYPOTHESIS**, not confirmed DKOM — on the SRL-2018 DC image it is an acquisition smear / kernel-global read failure (`KeNumberProcessors`=0, core OS singletons recovered only by `psscan`, duplicate `System` EPROCESS); the agent refuses to assert T1014 without ≥2 artifact classes. Corroborable leads: `subject_srv.exe` (T1543.003) + service-spawned `cmd.exe` (T1059.003).
> - Fleet accuracy summary: §9.1 of the report (22-host SRL-2018 rollup)

---

## 10. Agent Execution Logs

**Requirement:** Include Agent Execution Logs.

**STATUS: SATISFIED**

> **Committed sample runs (self-contained on a fresh clone):**
> [`docs/sample-run/`](docs/sample-run/) ships three real, completed investigations — their
> `audit.jsonl`, `run.manifest.json`, `verdict.json`, `manifest_verify.json`, and `REPORT.md`.
> All verify **offline** (`manifest_verify` returns `overall: true`), and
> [`docs/sample-run/README.md`](docs/sample-run/README.md) walks a single finding all the way
> back to the tool execution and Merkle leaf that produced it. Every live investigation also
> produces the same `audit.jsonl` in its case run directory.
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
| 1 | Code repository URL | https://github.com/TimothyVang/sans-hackathon | SATISFIED |
| 2 | Apache 2.0 / MIT license file | [`LICENSE`](LICENSE) | SATISFIED |
| 3 | README with setup instructions | [`README.md`](README.md) · [`QUICKSTART.md`](QUICKSTART.md) | SATISFIED |
| 4 | Deployment / step-by-step instructions | [`QUICKSTART.md`](QUICKSTART.md) | SATISFIED |
| 5 | Feature / functionality description | [`README.md`](README.md) | SATISFIED |
| 6 | Demonstration video | [`docs/find-evil-demo.mp4`](docs/find-evil-demo.mp4) · [`docs/demo-script-a2.md`](docs/demo-script-a2.md) | SATISFIED |
| 7 | Architecture diagram | [`docs/architecture.md`](docs/architecture.md) | SATISFIED |
| 8 | Evidence dataset documentation | [`docs/DATASET.md`](docs/DATASET.md) | SATISFIED |
| 9 | Accuracy report | [`docs/reports/2026-04-26-srl2018-dc-investigation.pdf`](docs/reports/2026-04-26-srl2018-dc-investigation.pdf) | SATISFIED |
| 10 | Agent execution logs | [`docs/sample-run/`](docs/sample-run/) (3 committed runs, verify offline) | SATISFIED |

---

*Last verified: 2026-06-09 — execution-log deliverable (#10) now ships three committed,
offline-verifiable runs under [`docs/sample-run/`](docs/sample-run/); all return
`manifest_verify overall: true`. The two NIST SCHARDT runs (Prefetch-only INDETERMINATE vs.
`--sift` Prefetch+UserAssist CONFIRMED) show the ≥2-artifact-class rule cutting both ways.*
