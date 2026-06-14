# docs/ — Public Documentation Index

The root `README.md` is the public landing page. This directory contains the
operator, analyst, and trust-model documentation that should remain useful from a
fresh clone of `TimothyVang/verdict-dfir`.

## Start Here

| Need | Read |
|---|---|
| Install from a cold clone | [`../INSTALL.md`](../INSTALL.md) |
| Pick a run mode | [`../QUICKSTART.md`](../QUICKSTART.md) |
| Run every `scripts/verdict` mode and flag | [`using/running-verdict.md`](using/running-verdict.md) |
| Understand trust boundaries | [`architecture.md`](architecture.md) |
| Verify signed outputs | [`cryptographic-attestation.md`](cryptographic-attestation.md) |
| Interpret Verdict words safely | [`verdict-semantics.md`](verdict-semantics.md) |
| Inspect the MCP/tool surface | [`reference/mcp-and-tools.md`](reference/mcp-and-tools.md) |
| Check release evidence policy | [`release-surface.md`](release-surface.md) |

## Core Docs

| File | Purpose |
|---|---|
| `architecture.md` | Runtime architecture, trust boundaries, and prompt-vs-structural guardrails. |
| `artifact-semantics.md` | What each artifact type can and cannot prove. |
| `cryptographic-attestation.md` | Audit hash chain, Merkle root, signature, and offline verification model. |
| `false-positives.md` | Conservative confidence taxonomy and overclaim prevention. |
| `investigation-phases.md` | Case lifecycle from `case_open` through report finalization. |
| `red-team-challenge.md` | Adversarial cases VERDICT should handle without overclaiming. |
| `replay-determinism.md` | Replay and verifier stability expectations. |
| `troubleshooting.md` | Failure modes, detectors, and fixes. |
| `verdict-semantics.md` | `SUSPICIOUS`, `INDETERMINATE`, and `NO_EVIL` semantics. |

## Operator Guides

| File | Purpose |
|---|---|
| `using/running-verdict.md` | Canonical command reference for `scripts/verdict`. |
| `using/evidence-intake.md` | Evidence staging and evidence-type routing. |
| `using/fleet-analysis.md` | Multi-host fleet workflow. |
| `using/reports.md` | Report rendering and re-rendering. |
| `reference/dependencies.md` | Dependency and tool version matrix. |
| `reference/environment-variables.md` | Environment variable surface. |
| `reference/mcp-and-tools.md` | Registered MCP servers and product tools. |

## Runtime Agent Config

The investigation agent reads `agent-config/` during operation:

| File | Purpose |
|---|---|
| `agent-config/SOUL.md` | Mission, epistemic hierarchy, and refusal rules. |
| `agent-config/AGENTS.md` | Supervisor, pools, verifier, judge, and correlator roles. |
| `agent-config/PLAYBOOK.md` | Evidence-type tool sequences. |
| `agent-config/TOOLS.md` | Typed product tool catalog. |
| `agent-config/MEMORY.md` | DFIR caveats and artifact interpretation traps. |
| `agent-config/EXPERT.md` | Expert signoff and report-QA doctrine. |
| `agent-config/HEARTBEAT.md` | Liveness and prompt-injection self-checks. |

## What Is Not Shipped

Historical implementation plans (`docs/plans/`), raw sample-run outputs
(`docs/sample-run/`), generated reports (`docs/reports/`), historical specs,
templates, legacy docs, bulky forensic evidence, operator memory vaults, and
submission-only material are intentionally omitted from the public source tree.
See [`release-surface.md`](release-surface.md) for the release boundary.
