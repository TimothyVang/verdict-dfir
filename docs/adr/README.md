# Architecture Decision Records

This directory records accepted and superseded architecture decisions for VERDICT using a
lightweight Nygard format. ADRs describe why a decision was made; current operating instructions
remain in `CLAUDE.md`, `AGENTS.md`, and `docs/architecture.md`.

## Index

| ADR | Status | Decision |
|---|---|---|
| [0001](0001-phase-4-native-agent-runtime.md) | Accepted | Phase 4 authoritative offline runtime is the beta-native `scripts/verdict --agent` loop |

Use [template.md](template.md) for new decisions. Do not rewrite an accepted ADR to reverse its
decision; add a new ADR that supersedes it.
