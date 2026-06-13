# Find Evil! — ${RELEASE_TAG}

**Submission for the SANS Find Evil! hackathon** ([findevil.devpost.com](https://findevil.devpost.com/)) — a Claude Code agent that investigates Windows host evidence and produces a signed verdict any third party can verify offline.

**Demo video:** ${DEMO_VIDEO_URL}

**Accuracy on NIST CFReDS Hacking Case:** ${ACCURACY}%

**Release date:** ${DATE}

**License:** Apache-2.0

---

## What it does

Find Evil! automates repeatable Windows host DFIR mechanics for memory captures, EVTX logs, mounted/extracted disk artifacts, and raw disk-image custody registration. It produces an evidence-bound verdict (`SUSPICIOUS` / `INDETERMINATE` / `NO_EVIL`) plus an expert-signoff packet with four load-bearing properties. Raw disk images supplied alone are custody-registered today; disk-content conclusions require mounted or extracted artifacts.

1. **A typed MCP tool surface, no `execute_shell`.** 43 narrow schema-validated product tools — 31 Rust DFIR (`case_open`, `disk_mount`/`disk_extract_artifacts`/`disk_unmount`, `evtx_query`, `vol_pslist`/`vol_psscan`/`vol_psxview`, `vol_run`, `ez_parse`, `plaso_parse`, `mac_triage`, `cloud_audit`, `mft_timeline`, `hayabusa_scan`, `yara_scan`, `usnjrnl_query`, `registry_query`, `prefetch_parse`, `vel_collect`, `browser_history`, `sysmon_network_query`, `zeek_summary`, `pcap_triage`, and the Linux/network/NTFS single-purpose wraps) plus 12 Python crypto/ACH/memory/handoff/expert-feedback tools. EVTX parsed in-process via the omerbenamram/evtx Rust crate (~1600× faster than python-evtx); AGPL/GPL tools (Hayabusa, Volatility3, Velociraptor) invoked through subprocess boundaries only — Apache-2.0 submission tree stays clean.

2. **Cryptographic chain of custody supporting a FRE 902(14) self-authenticating-evidence claim.** Three composed primitives: hash-chained audit JSONL (`prev_hash` per record) → `rs_merkle` Merkle root over canonical-JSON tool outputs → manifest signature metadata. Local automation defaults to a real Ed25519 signature that verifies offline; Sigstore/Rekor is the identity + transparency-log tier; the stub signer is explicit dev fallback and is not customer-releasable without expert approval. `manifest_verify` verifies the audit chain and Merkle root offline. (Pre-A5 the chain tail-anchored to Bitcoin via OpenTimestamps; removed because judges scoring offline can't exercise the network call. Trade-off: `docs/cryptographic-attestation.md`.)

3. **Analysis of Competing Hypotheses as agent topology.** Two pools investigate the same evidence with opposing priors (persistence-biased vs. exfil-biased). Disagreements emit as `kind=contradiction` audit records *before* the judge merges — surfaced as first-class output, not hidden in consensus. Heuer's 1970s intelligence-analysis framework applied as live agent architecture.

4. **Pre-submission self-score, separate from the sealed chain.** A standalone maintainer tool, `scripts/self-score.py`, grades a *completed* run against the six SANS rubric criteria before submission. It reads the case's `audit.jsonl`, reconstructs the criterion signals, and writes `<case>/self-score.json` — it does **not** emit records into the investigation pipeline or touch the sealed audit chain. The self-score is a maintainer QA artifact, not part of the signed manifest. (The Pool A/B `judge_findings` MERGE agent is unrelated and unaffected.)

## How it's built

Five trust boundaries (see `docs/architecture.md` for Mermaid diagrams):

```
Evidence vault (read-only .e01)
  → SIFT tool subprocesses (unprivileged, sandboxed)
  → Two typed MCP servers
      • findevil-mcp (Rust)         — 31 DFIR tools, no execute_shell
      • findevil-agent-mcp (Python) — 12 crypto/ACH/memory/ACP/expert-feedback tools
  → Claude Code agent loop (supervisor + forked Pool A/B subagents
    + verifier + judge + correlator + contradiction surface)
  → Crypto chain-of-custody (audit hash chain + rs_merkle + signed manifest)
```

**Architectural approach per SANS rules:** **Direct Agent Extension (§1) + Custom MCP Server (§2).** Claude Code IS the agent; the typed MCP surface is the only verb set it has. There is no `execute_shell`, anywhere.

## Install

The tool accepts three credential modes; pick whichever you have:

```bash
# 1. Claude Code long-lived token (recommended for non-interactive judging)
export CLAUDE_CODE_OAUTH_TOKEN=<token>  # generated via 'claude setup-token'

# 2. Claude Code interactive session
claude auth login

# 3. Anthropic API key
export ANTHROPIC_API_KEY=sk-ant-...   # from console.anthropic.com; <$1/run

# Any of the above, then:
curl -fsSL https://raw.githubusercontent.com/<OWNER>/<REPO>/master/scripts/install.sh | bash
```

`scripts/install.sh` detects credentials in priority order and fails fast with a clear error listing all three options if none are present.

## Run

```bash
# THE ONE COMMAND: preflight → investigate → open the live dashboard →
# signed verdict + report. .mcp.json auto-spawns both MCP servers
# (findevil-mcp + findevil-agent-mcp) over stdio.
scripts/verdict fixtures/nist-hacking-case/SCHARDT.001

# Flags: --sift (run DFIR tools in the SANS SIFT VM — auto-resolves the VM's IP
#        and auto-stages ANY host evidence path into it, so it stays one
#        command), --no-dashboard, --skip-build, --dry-run, --run-summary <path>.

# Interactive equivalent — open Claude Code from this repo's root:
claude
# … then prompt: "investigate fixtures/nist-hacking-case/SCHARDT.001"
# The agent calls case_open → fork Pool A/B subagents → run DFIR tools →
# detect_contradictions → judge → correlate → manifest_finalize.

# Verify a completed run's chain-of-custody offline:
# Drive the manifest_verify MCP tool from any MCP client (Claude Desktop,
# Claude Code, ChatGPT) — no network, no third-party servers.
```

`scripts/verdict` calls the internal headless engine (`scripts/find-evil-auto`) under the hood; `find-evil-run` and `find-evil-live` are deprecated shims that forward to `verdict`, and `find-evil-sift` is the SIFT-VM helper. Add `--run-summary <path>` to write a machine-readable JSON pointer to the run directory, artifact paths, report QA, release-gate/expert-signoff state, readiness state, blockers, and warnings. Multi-host fleet: `python scripts/fleet_investigate.py && python scripts/fleet_correlate.py && python scripts/render_fleet_report.py`.

For expert-review packaging on native Windows, run `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/readiness-gate.ps1 -Mode Full -EvidencePath <path-inside-sift-vm> -RunL1Docker`. It writes `readiness-summary.json` and `readiness-packet.zip` under `tmp/readiness-gates/<run-id>/`, with `packet/readiness-packet-manifest.json` listing copied artifacts. Fixed `-RunId` reruns refresh generated packet contents and may use a timestamped local-build child run. `READY_FOR_EXPERT_REVIEW` means human expert review can begin; automation does not mark customer release ready.

## Accuracy report

Self-reported per SANS rules, from the L3 nightly goldens CI workflow:

- **NIST CFReDS Hacking Case:** ${ACCURACY}% recall on 14 canonical findings
- **Synthetic benign baseline:** 0 findings (correct — negative control passes)
- **Hallucination rate:** tracked per run via verifier-rejected-finding count

See `goldens/<fixture>/expected-findings.json` for ground-truth declarations and `fixtures/` for source datasets (not bundled — pulled via `scripts/fetch-fixtures.sh`).

## Links

- Repository: https://github.com/<OWNER>/<REPO>
- Architecture deep-dive: `docs/architecture.md`
- Doc INDEX (status badge per file): `docs/README.md`
- Cryptographic attestation deep-dive: `docs/cryptographic-attestation.md`
- Showcase investigation report: `docs/reports/2026-04-26-srl2018-dc-investigation.md`
- Dataset documentation: `docs/DATASET.md`

## License

Apache-2.0 — see `LICENSE`. Submission + all original code MIT/Apache-2.0 compatible per SANS rules. AGPL/GPL tools (Hayabusa, Chainsaw, Volatility3, Velociraptor) are invoked as subprocesses only; they are not linked into the submission binaries.
