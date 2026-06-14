# VERDICT DFIR

VERDICT is a DFIR agent that opens a Case, drives a narrow typed MCP tool
surface, verifies every Finding, and emits a signed Verdict plus report. The
scope is intentionally narrow: the strongest claim is that the cited artifacts
were examined through replayable tools, not that an entire system is clean.

## Start Here

| Need | Read |
|---|---|
| Install and run | [Running VERDICT](using/running-verdict.md) |
| Understand trust boundaries | [Architecture](architecture.md) |
| Verify custody claims | [Cryptographic Attestation](cryptographic-attestation.md) |
| Interpret verdict words | [Verdict Semantics](verdict-semantics.md) |
| Check measured accuracy | [Accuracy Report](accuracy-report.md) |
| Inspect the tool surface | [MCP Servers and Tools](reference/mcp-and-tools.md) |

## Canonical Repository

The public release repository is
[`TimothyVang/verdict-dfir`](https://github.com/TimothyVang/verdict-dfir). The
older `TimothyVang/sans-hackathon` repository is the historical development
remote for the SANS Find Evil! entry and should not be treated as a separate
product release channel.

## Verification Model

Every reportable Finding must cite a current-case `tool_call_id`. The verifier
re-runs the cited tool, compares output hashes, and blocks uncited or drifting
Findings before the final Verdict is signed.
