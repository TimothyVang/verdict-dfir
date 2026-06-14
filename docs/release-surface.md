# Release Surface

This document keeps the public release surface explicit so the release
repository does not drift into an unbounded development dump.

## Canonical Release Channel

- Canonical repo: `https://github.com/TimothyVang/verdict-dfir`
- Historical dev repo: `https://github.com/TimothyVang/sans-hackathon`
- Public docs: `https://timothyvang.github.io/verdict-dfir/`
- Release tags: prefer semantic versions such as `v0.1.0`; `v-submit` remains a
  historical SANS Find Evil! submission tag.

## Ships In Source

These directories are intentionally part of the public source tree because they
are needed to build, operate, or audit VERDICT from a clone:

| Path | Why it ships |
|---|---|
| `agent-config/` | Runtime DFIR guardrails, roles, playbook, and tool catalog. |
| `services/` | Product MCP servers and Python verification primitives. |
| `scripts/` | Install, preflight, run, smoke, scoring, and release tooling. |
| `apps/web/` | Local dashboard and offline report renderer. |
| `docs/` | Operator, architecture, accuracy, and release evidence docs. |
| `.github/workflows/` | CI, release, docs, and reproducibility gates. |
| `.mcp.json` / `.mcp.json.sift` | Claude Code MCP launch configuration for local and SIFT modes. |

## Excluded From Archive Exports

The repository keeps several operator/development surfaces in git for day-to-day
work, but they are not part of a clean source archive or judge/customer bundle.
`.gitattributes` marks these with `export-ignore`:

| Path | Reason |
|---|---|
| `.agents/` | Harness compatibility and local agent skills, not runtime product code. |
| `.claude/` | Claude Code project configuration; useful locally, noisy in release archives. |
| `obsidian-mind/` | Development/operator memory framework; never evidence and never audit-chain input. |
| `evidence/` | Placeholder only; real evidence is excluded by `.gitignore`. |
| `goldens/` | Test scoring data, not required for end-user runtime. |
| `packer/` | SIFT image build scaffolding, not required for normal install/run. |
| `docs/plans/` | Historical implementation plans; useful for archaeology, not runtime docs. |
| `docs/specs/` | Historical architecture specs; curated public pages link only current decisions. |
| `docs/legacy/` | Retired material kept for git history context. |
| evidence extensions and runtime state | `*.E01`, `*.dd`, `*.mem`, `*.evtx`, `*.pcap*`, `.env*`, `tmp/`, `fixtures/`, and `test-forensics/` are archive-excluded as defense in depth. |

Release ZIPs produced for submissions should remain small, deterministic, and
limited to the assets listed by the release workflow or submission packager.
