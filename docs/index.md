# VERDICT DFIR

VERDICT is **DFIR for agents** — the typed, read-only, audit-chained forensic
tool surface AI agents plug into and drive. It exposes 45 MCP tools across
memory, disk, EVTX, and network; VERDICT's own reference agent (Claude Code)
opens a Case, drives the surface, verifies every Finding, and emits a signed
Verdict plus report. The scope is intentionally narrow: the strongest claim is
that the cited artifacts were examined through replayable tools, not that an
entire system is clean.

"DFIR for agents" means forensic tools that agents *operate* — not forensics of
what an agent did.

## Start Here

| Need | Read |
|---|---|
| Install from a cold clone | [Install Guide](https://github.com/TimothyVang/verdict-dfir-beta/blob/main/INSTALL.md) |
| Run in three commands | [Quickstart](https://github.com/TimothyVang/verdict-dfir-beta/blob/main/QUICKSTART.md) |
| Run every mode and flag | [Running VERDICT](using/running-verdict.md) |
| Understand trust boundaries | [Architecture](architecture.md) |
| Verify custody claims | [Cryptographic Attestation](cryptographic-attestation.md) |
| See why a finding can't lie about a value | [Fact-Fidelity (entailment check)](fact-fidelity.md) |
| Interpret verdict words | [Verdict Semantics](verdict-semantics.md) |
| Check measured accuracy | [Accuracy Report](accuracy-report.md) |
| Inspect the tool surface | [MCP Servers and Tools](reference/mcp-and-tools.md) |
| Use the visual system | [VERDICT Brand](brand.md) |

## Canonical Repository

The public release repository is
[`TimothyVang/verdict-dfir`](https://github.com/TimothyVang/verdict-dfir). The
older `TimothyVang/dev-verdict-github` repository is the historical development
remote and should not be treated as a separate product release channel.

## Verification Model

Every reportable Finding must cite a current-case `tool_call_id`. The verifier
re-runs the cited tool, compares output hashes, and blocks uncited or drifting
Findings before the final Verdict is signed.

## Visual System

The v2 brand bible is `VERDICT_DFIR_SVG_Assets_v2/verdict-brand-board-reconstructed.png`.
Dashboard, report, GitHub, and video surfaces should use the production assets
and palette documented in [VERDICT Brand](brand.md). Visual styling is presentation
only and never upgrades confidence or creates Findings.
