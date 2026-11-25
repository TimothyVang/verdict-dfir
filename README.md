# VERDICT — REA for DFIR

> **One local-first DFIR monorepo combining VERDICT (`findevil-mcp` + cryptographic custody), CaseForge (fail-closed privacy & model routing), and the REA (`morluto/rea`) MCP/Evidence architecture.**

**The LLM is not the forensic source of truth.** Every reportable finding must cite verified `evidence_id` records from the append-only session ledger, satisfy schema-encoded forensic rules (`>=2` artifact classes for confirmation, explicit Amcache caveats), and survive Skeptic challenge. Real evidence stays local by default (`--privacy local-only`).

## Monorepo Layout

```text
verdict/
├── packages/
│   ├── verdict-mcp/       # REA-for-DFIR MCP server: Evidence envelope, retained views, unknowns, Mulder citation gate
│   ├── verdict-cli/       # Unified `verdict` CLI: doctor, setup, models, intake, verify, serve
│   ├── caseforge-sdk/     # Fail-closed privacy router, model router, structured findings, custody validator
│   ├── caseforge-cli/     # Legacy `caseforge` CLI (preserved & workspace-linked)
│   └── caseforge-tui/     # Read-only Ink operator workbench TUI
├── services/
│   ├── mcp/               # Rust `findevil-mcp` (34 read-only forensic tools)
│   ├── agent_mcp/         # Python `findevil-agent-mcp` (14 Ed25519 custody/Merkle tools)
│   └── agent/             # Deterministic 0-LLM DFIR engine & orchestrators
├── crates/
│   ├── caseforge-fleet/   # Rust multi-host fleet runner
│   └── caseforge-ingest/  # Rust high-speed evidence ingest
├── .agents/skills/verdict-dfir/      # Portable agent skill + reference playbooks
├── .claude-plugin/ .codex-plugin/ .cursor-plugin/
├── configs/               # Privacy/model/ingest/OCR configs + OpenCode profiles
├── goldens/ & fixtures/   # Synthetic/public DFIR verification fixtures
└── docs/
    ├── ARCHITECTURE.md         # REA-for-DFIR architecture + winning-apps merge roadmap
    └── CONSOLIDATION_MAP.md    # Exact inventory of all old scattered repos & local dirs
```

## Quickstart

```bash
npm install
npm run build:core
npm test

# Host readiness across Rust findevil-mcp, SIFT tools, REA bridge, and local LLMs
node packages/verdict-cli/dist/src/cli.js doctor

# Verify fail-closed privacy routing (cloud denied by default on sensitive evidence)
node packages/verdict-cli/dist/src/cli.js models --privacy local-only --evidence sensitive

# Target-free intake with REA-style summary + portable authenticated bundle
node packages/verdict-cli/dist/src/cli.js intake ./fixtures --evidence-output /tmp/bundle.json --json

# Print read-only MCP setup plan for Claude Code / Codex / Cursor / OpenCode
node packages/verdict-cli/dist/src/cli.js setup --client all

# Launch unified MCP stdio server
node packages/verdict-cli/dist/src/cli.js serve
```

## Build Rust & Python Components

```bash
cargo check --workspace
cargo build --release -p findevil-mcp
```

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — Unified REA-for-DFIR architecture and winning-apps merge matrix (Mulder, TRUDI, SIFT++, FindEvil, Camel, DFIR-Companion patterns, Malvex, REA-Argonaut).
- [`docs/CONSOLIDATION_MAP.md`](docs/CONSOLIDATION_MAP.md) — Exact map of every legacy GitHub repo and local folder consolidated here (and what stays strictly outside git).
- [`docs/caseforge/`](docs/caseforge/) — Preserved CaseForge PRD, model routing, DGX Spark runbooks, and security docs.
- [`.agents/skills/verdict-dfir/SKILL.md`](.agents/skills/verdict-dfir/SKILL.md) — Portable agent workflow instructions.

## License

Apache-2.0. See `LICENSE` and `docs/caseforge/THIRD_PARTY_NOTICES.md`.
