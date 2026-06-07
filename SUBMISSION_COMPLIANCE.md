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
> bash scripts/find-evil-run --evidence <path-to-evidence>
> ```
> `QUICKSTART.md` covers three environments:
> - Local mode (SIFT tools on host)
> - SIFT VM mode (`scripts/find-evil-sift`)
> - Headless/automated mode (`scripts/find-evil-auto`)

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
> bash scripts/find-evil-run --evidence /path/to/evidence
> # or open Claude Code and type: investigate /path/to/evidence
> ```
>
> Full mode walkthroughs (local / SIFT VM / headless) are in `QUICKSTART.md`.

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
> The agent self-scores against the SANS rubric inside the signed manifest.

---

## 6. Demonstration Video

**Requirement:** Include a demonstration video of your Project.

**STATUS: SEE BELOW**

> **Video file in repo:** [`docs/find-evil-demo.mp4`](docs/find-evil-demo.mp4)
>
> **Video script / beat map:** [`docs/demo-script-a2.md`](docs/demo-script-a2.md)
> (5-minute structured walkthrough — 6 beats, each timed)
>
> The video shows:
> - Beat 1: `scripts/find-evil` launched, `.mcp.json` auto-spawns both MCP servers
> - Beat 2: `case_open` + SHA-256 verification, Pool A/B forked in parallel
> - Beat 3: Memory image investigation — `vol_pslist` vs `vol_psscan` DKOM divergence
> - Beat 4: Contradiction surface + resolution, `verify_finding` replay
> - Beat 5: `manifest_finalize` — 3-tier chain signed, `manifest_verify` run offline
> - Beat 6: Fleet rollup (22-host SRL-2018 dataset), leaderboard diff
>
> If the mp4 is not yet in the repo (pending recording), the Devpost submission URL
> field will contain the hosted video link. The demo script at `docs/demo-script-a2.md`
> is the authoritative beat map.

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

> **Sample audit log:** [`docs/reports/`](docs/reports/) — every investigation produces
> an `audit.jsonl` in the case run directory.
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
> **Sample run output directory structure:**
> ```
> tmp/auto-runs/<case-id>/
> ├── audit.jsonl          # hash-chained execution log (every tool call, finding, verdict)
> ├── verdict.json         # final verdict with confidence and MITRE mappings
> ├── run.manifest.json    # Merkle root + signature metadata
> ├── manifest_verify.json # offline verification result
> ├── REPORT.md            # human-readable investigation report
> ├── REPORT.html          # styled HTML version
> └── REPORT.pdf           # PDF (if Chrome/pandoc available)
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
| 6 | Demonstration video | [`docs/find-evil-demo.mp4`](docs/find-evil-demo.mp4) · [`docs/demo-script-a2.md`](docs/demo-script-a2.md) | SEE §6 |
| 7 | Architecture diagram | [`docs/architecture.md`](docs/architecture.md) | SATISFIED |
| 8 | Evidence dataset documentation | [`docs/DATASET.md`](docs/DATASET.md) | SATISFIED |
| 9 | Accuracy report | [`docs/reports/2026-04-26-srl2018-dc-investigation.pdf`](docs/reports/2026-04-26-srl2018-dc-investigation.pdf) | SATISFIED |
| 10 | Agent execution logs | `tmp/auto-runs/<case-id>/audit.jsonl` · [`docs/reports/`](docs/reports/) | SATISFIED |

---

*Last verified: 2026-06-07 against commit `b2dbc71` (master, `v-submit` tag).*
