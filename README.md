# Find Evil!

> **Judges: verify all 10 required submission components in one place →
> [`SUBMISSION_COMPLIANCE.md`](SUBMISSION_COMPLIANCE.md)**

**SANS Find Evil! 2026 hackathon submission.**

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
![Status: v-submit released](https://img.shields.io/badge/status-v--submit%20released-brightgreen.svg)
![Rust 1.88](https://img.shields.io/badge/rust-1.88-orange.svg)
![Python 3.11](https://img.shields.io/badge/python-3.11-blue.svg)

> **Deadline:** 2026-06-15 22:45 CDT · **Reference bar:** [AppliedIR / Valhuntir](https://github.com/AppliedIR/Valhuntir) (Rob Lee, MIT)

---

## What it is

**Find Evil!** is a Claude Code agent that automates repeatable Windows host DFIR mechanics for memory images, EVTX logs, mounted/extracted disk artifacts, and raw disk-image custody registration. It produces an evidence-bound verdict (`SUSPICIOUS` / `INDETERMINATE` / `NO_EVIL`) and expert-signoff packet with a cryptographic chain of custody any third party can verify offline. Raw disk images supplied alone are custody-registered today; disk-content conclusions require mounted or extracted artifacts.

Four claims, all exercised on every CI run:

1. **A typed MCP tool surface, no `execute_shell`.** 31 narrow Pydantic-validated tools — 19 Rust DFIR (`case_open`, `disk_mount`/`disk_extract_artifacts`/`disk_unmount`, `evtx_query`, `vol_pslist`/`vol_psscan`/`vol_psxview`, `vol_malfind`, `mft_timeline`, `hayabusa_scan`, `yara_scan`, `usnjrnl_query`, `registry_query`, `prefetch_parse`, `vel_collect`, `sysmon_network_query`, `zeek_summary`, `pcap_triage`) plus 12 Python crypto/ACH/memory/handoff/expert-feedback tools. EVTX parsed in-process via the omerbenamram/evtx Rust crate; AGPL/GPL tools (Hayabusa, Volatility3, Velociraptor) invoked as subprocesses only — Apache-2.0 submission tree stays clean.

2. **Cryptographic chain of custody with FRE 902(14) framing.** Three composed primitives: hash-chained audit JSONL (`prev_hash` per record) → `rs_merkle` Merkle root over canonical-JSON tool outputs → manifest signature metadata. Production signing can use Sigstore/Rekor; local offline automation may use a clearly identified stub signer and is not customer-releasable without expert approval. `manifest_verify` verifies the audit chain and Merkle root offline. (Pre-A5 the chain tail-anchored to Bitcoin via OpenTimestamps; removed because judges scoring offline can't exercise the network call or wait for Bitcoin attestation maturation. Trade-off documented in [`docs/cryptographic-attestation.md`](docs/cryptographic-attestation.md).)

3. **Analysis of Competing Hypotheses as agent topology.** Two pools investigate the same evidence with opposing priors (persistence-biased vs. exfil-biased). Disagreements emit as `kind=contradiction` audit records *before* the judge merges — surfaced as first-class output, not hidden in consensus. The report also includes case-completeness and ATT&CK coverage matrices, `timeline.json` / `timeline.csv` normalized from tool outputs, and the next 5 analyst actions so analysts can see what evidence was missing before trusting the verdict. Heuer's 1970s intelligence-analysis framework applied as live agent architecture, not a rebrand of single-agent voting.

4. **Self-score inside the cryptographic attestation.** The agent emits 6 `kind=judge_selfscore` audit records (one per SANS rubric criterion) *before* `manifest_finalize`. Because they land before the Merkle tree closes, the agent's own self-assessment is part of the signed manifest — `grep '"kind":"judge_selfscore"' audit.jsonl` and you have the agent's own score against the same rubric you're using.

**Submission artifacts:** [`v-submit`](https://github.com/TimothyVang/sans-hackathon/releases/tag/v-submit) contains the release report and validated submission bundle. The demo video is [`docs/find-evil-demo.mp4`](docs/find-evil-demo.mp4). The local SIFT L3 fallback evidence used when GitHub KVM capacity was unavailable is documented under [`docs/release-evidence/`](docs/release-evidence/README.md).

**The showcase:** [`docs/reports/2026-04-26-srl2018-dc-investigation.md`](docs/reports/2026-04-26-srl2018-dc-investigation.md) (PDF: 1.3 MB) — a real end-to-end investigation of the SANS HACKATHON-2026 *SRL-2018 Compromised Enterprise Network* dataset, and a demonstration of epistemic discipline: the `vol_pslist`=0 / `vol_psscan`>0 process-enumeration divergence on 11 of 22 hosts is treated as a **HYPOTHESIS** (a likely shared acquisition-smear / kernel-global read failure — core OS singletons recovered only by `psscan` and duplicate `System` EPROCESS, which a rootkit cannot produce), **not** 11 confirmed DKOM rootkits. The corroborable findings are the service implants (`subject_srv.exe`, T1543.003) and service-spawned `cmd.exe` bursts (T1059.003), plus the textbook automated-recon-sweep signature — 6 hosts ran `Autorunsc.exe` at the exact same second.

---

## Try it

Three steps, no other config.

```bash
git clone https://github.com/TimothyVang/sans-hackathon.git
cd sans-hackathon

# Pre-flight + Rust+Python build (detects the three Claude credential modes
# from CLAUDE.md "Credential modes (Amendment A1)" — pick whichever you have).
bash scripts/install.sh

# Open Claude Code in the repo. .mcp.json auto-spawns both MCP servers
# (Rust + Python) on session start.
claude
# (or, equivalently, bash scripts/find-evil — same thing with a friendlier
# error message if claude isn't on PATH.)

# Then prompt the agent: "investigate <case path>"
```

Headless single-shot:

```bash
bash scripts/find-evil-auto /mnt/hgfs/evidence/extracted/<host>/<host>-memory.img --unattended
# Or point it at a mixed case directory containing memory, EVTX, disk artifacts,
# network logs, and Velociraptor collection zips.
bash scripts/find-evil-auto /mnt/hgfs/evidence/cases/<host>/ --unattended

# Optional machine-readable pointer file for automation/readiness gates.
bash scripts/find-evil-auto /mnt/hgfs/evidence/cases/<host>/ --unattended --run-summary tmp/run-summary.json
```

`--run-summary` writes JSON without changing human stdout. The file records the `run_id`, `case_id`, evidence path, local run directory, artifact paths (`audit.jsonl`, `verdict.json`, `run.manifest.json`, `manifest_verify.json`, reports, timelines), report QA/release-gate/expert-signoff state, signer, `readiness_state`, blockers, warnings, and the final result when the run reaches completion.

Per-mode walkthrough + SIFT-VM setup recipe lives in [QUICKSTART.md](QUICKSTART.md). Trust-boundary diagrams in [docs/architecture.md](docs/architecture.md). Pre-emptive judge Q&A is the [Anticipated questions](#anticipated-questions) section below.

**Protocol SIFT coexistence:** Find Evil! runs on the same SIFT VM after `protocol-sift install`, with a deliberately narrow MCP surface (31 typed tools, no `execute_shell`) that coexists alongside Protocol SIFT's broader gateway. Neither requires nor conflicts with the other; judges choose which interface to use per investigation. See [docs/architecture.md](docs/architecture.md#relationship-to-protocol-sift) for the full positioning.

Codex operator support is documented in [docs/codex-compatibility.md](docs/codex-compatibility.md). The web dashboard also has a local Codex prompt cockpit at `/codex`; it is an operator aid, not a new product-default MCP surface.

---

## Required downloads & install files

Large binaries (the SIFT VM, evidence images) are **not** committed — they are SANS-licensed and/or far larger than GitHub's file limit. Download them from the links below. `bash scripts/install.sh` handles the toolchain (Rust + Python) automatically; the table marks what you still fetch by hand. A machine-readable companion to these tables lives in [`requirements.txt`](requirements.txt) — `pip install -r requirements.txt` installs the host DFIR Python tooling (Volatility 3), and the comments enumerate every non-pip download (starting with the SANS SIFT OVA).

### Core (every mode)

| Item | Link | Notes |
|---|---|---|
| Claude Code CLI | <https://docs.anthropic.com/en/docs/claude-code/install> | The agent runtime. `claude` must be on PATH. |
| Rust 1.88 (rustup) | <https://rustup.rs> | Pinned in `rust-toolchain.toml`. `install.sh` builds the Rust MCP server. |
| uv (Python tool) | <https://docs.astral.sh/uv/getting-started/installation/> | Python env/lockfile manager. Python 3.11. |

### SIFT-VM mode (Path A — matches the SANS judging environment)

| Item | Link | Notes |
|---|---|---|
| SANS SIFT Workstation OVA | <https://www.sans.org/tools/sift-workstation/> | ~9.3 GB. Save as `sift-2026.03.24.ova` in the repo root. Gitignored (`*.ova`); never committed. |
| VMware Workstation | <https://www.vmware.com/products/desktop-hypervisor.html> | Provides `vmrun` + `ovftool` used by `scripts/sift-vm-bootstrap.sh`. VMware-only today. |

Then run `bash scripts/sift-vm-bootstrap.sh` (see [QUICKSTART.md](QUICKSTART.md#path-a--sift-vm-recommended-matches-the-sans-judging-environment)).

### Local-host mode (Path B — DFIR binaries on the host)

| Item | Link | Notes |
|---|---|---|
| Volatility 3 | <https://github.com/volatilityfoundation/volatility3> | `pip install volatility3`. Powers `vol_*`. |
| Hayabusa | <https://github.com/Yamato-Security/hayabusa/releases> | Sigma engine over EVTX (`hayabusa_scan`). |
| Velociraptor | <https://github.com/Velocidex/velociraptor/releases> | Artifact collection (`vel_collect`). |
| YARA-X | bundled | Ships in the Rust crate; no separate install. |

### Evidence to investigate

| Item | Link | Notes |
|---|---|---|
| SANS Find Evil! starter case data | <https://findevil.devpost.com/resources> | The primary golden the judges test against. Drop into `evidence/` (local) or `/mnt/hgfs/evidence/` (SIFT). |
| Fixture corpora (NIST CFReDS / OTRF) | see [docs/DATASET.md](docs/DATASET.md) | Pulled by the L3 scripts at CI time; per-fixture links + SHA-256 in the dataset doc. |

Local-mode evidence goes in the repo's [`evidence/`](evidence/README.md) directory by default — `bash scripts/find-evil-auto` with no path argument investigates whatever is there (override with `$FINDEVIL_EVIDENCE_ROOT`).

### Optional

| Item | Link | Notes |
|---|---|---|
| Engram memory MCP server | [docs/runbooks/engram-memory-integration.md](docs/runbooks/engram-memory-integration.md) | Standalone Apache-2.0 knowledge/memory tool, wired in optionally; not bundled. |

---

## Repository layout

```
.
├── agent-config/             — runtime DFIR agent identity (SOUL/AGENTS/PLAYBOOK/
│                               TOOLS/MEMORY/HEARTBEAT/JUDGING)
├── services/mcp/             — Rust MCP server (19 typed DFIR tools)
├── services/agent_mcp/       — Python MCP server (12 crypto/ACH/memory/ACP/expert-feedback tools)
├── services/agent/           — findevil_agent package (M2 crypto + M4 ACH primitives)
├── services/swarm/           — overnight build swarm (Option B per Amendment A1)
├── scripts/                  — find-evil / find-evil-sift / find-evil-auto launchers,
│                               fleet pipeline (fleet_*.py + render_fleet_report.py),
│                               smoke harnesses (rust-mcp-smoke + agent-mcp-smoke +
│                               run-all-smokes), readiness gates, report renderer
├── packer/                   — L3 sandbox: warm-qcow2 build from sift-2026.03.24.ova
├── docker/                   — L1/L2 sandbox: docker compose specs + Dockerfiles
├── docs/
│   ├── README.md             — canonical doc INDEX (read first)
│   ├── architecture.md       — five trust boundaries + Mermaid diagrams
│   ├── cryptographic-attestation.md  — three-link chain + FRE 902(14)
│   ├── verdict-semantics.md  — what SUSPICIOUS / INDETERMINATE / NO_EVIL mean
│   ├── false-positives.md    — three architectural FP layers + four habits
│   ├── demo-script-a2.md     — 5-minute Devpost video script
│   ├── reports/              — analyst-facing investigation reports (real evidence)
│   ├── release-evidence/     — small validated release evidence summaries, no raw data
│   ├── specs/                — 9 architecture specs (master + 4 amendments + 4 subsystems)
│   ├── plans/                — active launch checklist + retired TDD plans
│   └── archive/              — non-authoritative research and parked design artifacts
└── .mcp.json                 — Claude Code auto-spawn registry for both MCP servers
```

---

## Anticipated questions

**"Why no real-world end-to-end run in the demo video?"**
The demo video shows a Tesla-mode investigation against a real memory image (Beat 3 of [`docs/demo-script-a2.md`](docs/demo-script-a2.md)) and a 22-host fleet rollup against the SANS HACKATHON-2026 SRL-2018 dataset (Beat 6). Full report: [`docs/reports/2026-04-26-srl2018-dc-investigation.md`](docs/reports/2026-04-26-srl2018-dc-investigation.md) (PDF: 1.3 MB; fleet rollup at §9.1). Fleet artifacts: `tmp/fleet-runs/fleet-20260426T055440Z/`.

**"Why doesn't the dashboard have real sprites?"**
Sprite components live in [`apps/web/components/sprites/`](apps/web/components/sprites/), and the shipped dashboard surface is the SSE audit-tail/debug viewer. The AuditBeadString chrome described in [Amendment A3](docs/specs/2026-04-26-amendment-a3-agent-army-and-dashboard.md) Phase 6 remains a design artifact until implemented in `apps/web/`.

**"What happens if I install on Windows?"**
Windows-friendly throughout. Use `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/run-all-smokes.ps1` for the native local smoke gate so Windows-installed `uv`, cargo, ruff, and `findevil-mcp.exe` are used directly; `bash scripts/run-all-smokes.sh` remains the POSIX/Git Bash path. The `find-evil` family of launchers is bash, runs cleanly under Git Bash / WSL. The Tesla-mode orchestrator SSHes into a SIFT VM regardless of host OS, so the host platform does not need DFIR tools installed. Hypervisor: VMware Workstation only today (`scripts/find-evil-sift` lines 10–12).

**"How do I build a readiness packet?"**
Use the Windows gate for the current packet-producing flow: `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/readiness-gate.ps1 -Mode Full -EvidencePath <path-inside-sift-vm> -RunL1Docker`. It runs the local build lane, runs or accepts a completed `find-evil-auto` evidence run, verifies the manifest, checks report QA/expert-signoff release blockers, copies the customer-review artifacts into `tmp/readiness-gates/<run-id>/packet/`, writes `readiness-summary.json` and `readiness-packet-manifest.json`, then creates `readiness-packet.zip`. If you pass a fixed `-RunId`, reruns refresh generated packet contents and may use a fresh `<run-id>-build-<timestamp>` local-build child run when the original child run already exists. `READY_FOR_EXPERT_REVIEW` means the packet is ready for human expert review; it is not customer-releasable. `READINESS_BLOCKED` means the summary's `blockers` list must be resolved first. The POSIX `scripts/readiness-gate.sh` is a strict legacy/check-only gate; it does not assemble the packet ZIP.

**"Where's the LangGraph supervisor / FastAPI service / in-container CLI?"**
Dropped per [Amendment A2](docs/specs/2026-04-25-amendment-a2-claude-code-primary-interface.md) §2.1. Claude Code IS the orchestrator; the streaming UX is Claude Code's terminal; the entry point is `scripts/find-evil` (or `claude` directly). Re-introduction guarded by the L0 `amendment-a2-guard` GHA job.

**"Why no Bitcoin anchor on the crypto chain?"**
Removed under Amendment A5 (2026-04-30). The pre-A5 design tail-anchored to Bitcoin via OpenTimestamps; that tier required network reach to a calendar server plus a multi-hour wait for Bitcoin attestation maturation, neither of which a judge scoring offline can exercise. The orchestrator never called `ots_stamp` in the first place — it was listed as "(Optional) Step 10" in `find_evil_auto.py`'s docstring with no code path invoking it. Production signing can use Sigstore/Rekor; stub-signed offline runs remain expert-review packets, not customer-releasable custody artifacts. Trade-off: [`docs/cryptographic-attestation.md`](docs/cryptographic-attestation.md) §"What FRE 902(14) requires."

**"`Cargo.lock` is committed — is that a mistake?"**
No — `findevil-mcp` ships as a binary (not a library), so the lockfile is committed deliberately. [`.gitignore`](.gitignore) carries an explicit comment to that effect; documented in [`CLAUDE.md`](CLAUDE.md) §"Spec/code divergences."

---

## License & attribution

Apache-2.0. See [LICENSE](LICENSE).

The vendored reference clones in `openclaw/`, `hermes-agent/`, `Linear-Coding-Agent-Harness/`, and `.playwright-mcp/` are research-only and gitignored — they do not ship in the submission.

---

## Status

This is a submitted hackathon project, not a maintained product. The code, test suite, agent-config, demo asset, release workflow, and readiness packet path are stable. The cryptographic chain-of-custody and the typed MCP tool surface are the load-bearing claims — both are exercised end-to-end on CI. Automated readiness stops at `READY_FOR_EXPERT_REVIEW`; customer release still requires human expert approval.

> **For Claude Code agents:** read [CLAUDE.md](CLAUDE.md) first. It encodes the document hierarchy, the non-negotiable invariants, the Karpathy 4 principles, and the spec/code divergence list.

> **For Codex-compatible agents:** read [AGENTS.md](AGENTS.md), then [docs/codex-compatibility.md](docs/codex-compatibility.md). Codex support uses the same two narrow MCP servers; it is not an invitation to add broad external MCP defaults.
