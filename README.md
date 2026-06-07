<p align="center">
  <img src="assets/logo/logo.png" alt="VERDICT — DFIR at machine speed." width="560">
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="License"></a>
  <img src="https://img.shields.io/badge/rust-1.88-orange.svg" alt="Rust 1.88">
  <img src="https://img.shields.io/badge/python-3.11-blue.svg" alt="Python 3.11">
  <img src="https://img.shields.io/badge/node-20-green.svg" alt="Node 20">
</p>

<p align="center"><b>Digital forensics &amp; incident response at machine speed — with a verdict you can prove.</b></p>

---

**VERDICT** automates the repeatable mechanics of a Windows-host DFIR investigation — memory
images, EVTX logs, disk artifacts, and network captures — and produces an evidence-bound verdict
(`SUSPICIOUS` / `INDETERMINATE` / `NO_EVIL`) backed by a **cryptographic chain of custody any third
party can verify offline**. It runs as a [Claude Code](https://claude.com/claude-code) agent over a
narrow, typed tool surface, so every conclusion cites the exact tool call that produced it.

## What you get

Every run writes a self-contained case directory:

| Artifact | What it is |
|---|---|
| `audit.jsonl` | Append-only, **hash-chained** log of every tool call and finding (`prev_hash` per record) |
| `verdict.json` | The evidence-bound verdict + findings, each citing a `tool_call_id` and a confidence tier |
| `run.manifest.json` | Merkle root over canonical tool outputs + signature metadata — verifiable offline |
| `report.html` | Analyst report: findings, ATT&CK coverage, normalized timeline, next analyst actions |

## How it works

Three ideas, exercised end-to-end on every CI run:

1. **A typed MCP tool surface — no `execute_shell`.** 31 narrow, schema-validated tools: 19 Rust
   DFIR tools (`case_open`, `vol_pslist`/`psscan`/`psxview`, `mft_timeline`, `evtx_query`,
   `hayabusa_scan`, `yara_scan`, `registry_query`, `prefetch_parse`, `pcap_triage`, …) + 12 Python
   crypto/analysis tools. AGPL/GPL engines (Volatility, Hayabusa, Velociraptor) are invoked as
   subprocesses only, so the Apache-2.0 tree stays license-clean.

2. **A cryptographic chain of custody.** Hash-chained audit log → `rs_merkle` Merkle root over
   canonical-JSON tool outputs → a manifest signature (Sigstore/Rekor in production; a clearly
   labeled stub signer for offline runs). `manifest_verify` checks the chain + root offline. Framed
   for FRE 902(14) self-authenticating evidence — see [`docs/cryptographic-attestation.md`](docs/cryptographic-attestation.md).

3. **Analysis of Competing Hypotheses as agent topology.** Two pools investigate the same evidence
   with opposing priors (persistence-biased vs. exfil-biased). Their disagreements are emitted as
   first-class `kind=contradiction` records *before* a credibility-weighted **judge** merges them —
   surfaced, not hidden in consensus. Heuer's intelligence-analysis method as live architecture.

Findings follow a strict epistemic hierarchy — **CONFIRMED** (≥2 corroborating artifact classes,
verifier-passed) > **INFERRED** (derived from confirmed facts) > **HYPOTHESIS** — and execution
claims require at least two artifact classes. Evidence is opened read-only.

## Hi, I'm new

New here? You have two equivalent ways to get a working setup. Both install the full toolchain
(Rust, uv, Node, pnpm), build the `findevil-mcp` server, sync the Python agent-mcp venv, and
install the host DFIR tools.

- **From a terminal:** run `bash scripts/setup`. It installs everything, re-checks what is
  still missing, and prints a green/red summary. Safe to re-run.
- **From Claude Code:** open the repo with `claude` and type `setup` (or `i'm new`). The agent
  runs the same install, then — for any asset behind a registration form, EULA, or login (such
  as the SANS SIFT VM) — drives a browser to fetch it and moves it into place for you. If the
  download site cannot be automated, the agent opens the page and walks you through it.

When setup is green, point VERDICT at evidence: `scripts/verdict <path-to-evidence>`, or open
`claude` and prompt `investigate <path>`. Per-environment setup (local DFIR tools vs. the SANS
SIFT VM) is in [QUICKSTART.md](QUICKSTART.md); what the in-agent `setup` trigger does is in
[docs/onboarding.md](docs/onboarding.md).

## Quickstart

```bash
git clone https://github.com/TimothyVang/sans-hackathon.git verdict
cd verdict
bash scripts/setup          # one-shot: preflight + build + DFIR tools + honest summary
# or, just the build step:
bash scripts/install.sh     # preflight + build (Rust MCP server + Python env)
```

**One command, one workflow.** `verdict` runs the whole thing — preflight → investigate → opens the
live dashboard at the case → signed verdict + report:

```bash
scripts/verdict <path-to-evidence>
#   --sift          run the DFIR tools inside the SANS SIFT VM (default: local host)
#   --no-dashboard  don't auto-open the browser
```

Point it at a single image or a mixed case directory (memory + EVTX + disk + network +
Velociraptor). Output lands in `tmp/auto-runs/<case-id>/`, and the dashboard
(`http://localhost:3000`) streams the run live as it happens.

**Prefer to drive it yourself?** Open Claude Code in the repo (`claude`) and prompt
`investigate <path>` — same tools, interactive.

**No evidence yet?** Evidence files are never committed (they're gitignored), so a fresh clone
ships with none. Stage public test datasets with `bash scripts/fetch-fixtures.sh` (sources +
SHA-256 in [docs/DATASET.md](docs/DATASET.md)), or drop your own image into `evidence/` and run
`scripts/verdict --watch`. Every run is a **live test**: confirm `tmp/auto-runs/<case-id>/verdict.json`
carries a real verdict and `manifest_verify.json` reports `overall: true`.

Per-environment setup (local DFIR binaries vs. the SANS SIFT VM) and evidence placement live in
[QUICKSTART.md](QUICKSTART.md). Trust-boundary diagrams are in [docs/architecture.md](docs/architecture.md).

## Repository layout

```
.
├── agent-config/        — runtime agent identity (SOUL / AGENTS / PLAYBOOK / TOOLS / MEMORY)
├── services/mcp/        — Rust MCP server (19 typed DFIR tools)
├── services/agent_mcp/  — Python MCP server (12 crypto / ACH / memory tools)
├── services/agent/      — findevil_agent package (crypto chain + ACH primitives)
├── apps/web/            — Next.js dashboard (live audit-stream viewer + design system)
├── scripts/             — verdict launcher (find-evil/-auto shims), report renderer, CI smoke runners
├── docs/                — architecture, crypto attestation, verdict semantics, reports
└── .mcp.json            — Claude Code auto-spawn registry for both MCP servers
```

## Documentation

- [docs/README.md](docs/README.md) — canonical documentation index
- [docs/architecture.md](docs/architecture.md) — the five trust boundaries
- [docs/cryptographic-attestation.md](docs/cryptographic-attestation.md) — the chain of custody + FRE 902(14)
- [docs/verdict-semantics.md](docs/verdict-semantics.md) — what `SUSPICIOUS` / `INDETERMINATE` / `NO_EVIL` mean
- [docs/false-positives.md](docs/false-positives.md) — how VERDICT avoids over-claiming

> **For coding agents:** read [CLAUDE.md](CLAUDE.md) first — it encodes the document hierarchy, the
> non-negotiable invariants, and the coding principles for this repo.

## License

Apache-2.0. See [LICENSE](LICENSE). Vendored reference clones (`openclaw/`, `hermes-agent/`, …) are
research-only and gitignored — they do not ship.

<sub>VERDICT began as an entry in the SANS <i>Find Evil!</i> 2026 hackathon; internal identifiers
(<code>findevil-mcp</code>, <code>@findevil/web</code>, <code>scripts/find-evil</code>) retain that
name.</sub>
