# Release Surface

This document keeps the public release surface explicit so the release
repository does not drift into an unbounded development dump.

## Canonical Release Channel

- Canonical public repo (clone, run, contribute): `https://github.com/TimothyVang/verdict-dfir-beta`
- Release assets (prebuilt MCP binaries, demo videos) and the published docs are
  hosted on the original release repo `https://github.com/TimothyVang/verdict-dfir`:
  `https://timothyvang.github.io/verdict-dfir/`
- Release tags: prefer semantic versions such as `v0.2.0-beta.1`; `v-submit` remains a
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
| `VERDICT_DFIR_SVG_Assets_v2/` | Canonical v2 brand bible, production SVGs, usage guide, and asset QA report. |
| `goldens/` | Small answer-key JSON files for recall scoring. |
| `packer/` | SIFT warm-image build recipe used by L3 workflows. |
| `.claude/skills/` | Claude Code slash-skill entrypoints such as `/verdict`. |
| `.github/workflows/` | CI, release, docs, and reproducibility gates. |
| `.mcp.json` / `.mcp.json.sift` | Claude Code MCP launch configuration for local and SIFT modes. |

## Excluded From Archive Exports

The repository keeps several operator/development surfaces in git for day-to-day
work, but they are not part of a clean source archive or judge/customer bundle.
`.gitattributes` marks these with `export-ignore`:

| Path | Reason |
|---|---|
| local harness config | Local agent-harness commands, settings, and workflows are operator surfaces, not product runtime. |
| operator memory vault | Optional local memory vaults are never evidence and never audit-chain input. |
| `evidence/` | Placeholder only; real evidence is excluded by `.gitignore`. |
| `docs/plans/` | Historical implementation plans; useful for archaeology, not runtime docs. |
| `docs/specs/` | Historical architecture specs; curated public pages link only current decisions. |
| `docs/templates/` | Historical planning/spec/template archives; curated public pages link only current decisions. |
| `docs/legacy/` | Retired material kept for git history context. |
| `docs/sample-run/` | Historical run packets are large generated artifacts; current source ships compact release-evidence summaries and rerun commands instead, and operators generate fresh case directories under `tmp/auto-runs/`. |
| `docs/reports/` | Generated reports and figures are release artifacts, not required for a clean source checkout. |
| rendered demo videos | `docs/find-evil-demo.mp4` and `docs/verdict-*.mp4` are hosted release/video assets; source beats and generator scripts ship instead. |
| evidence extensions and runtime state | `*.E01`, `*.dd`, `*.mem`, `*.evtx`, `*.pcap*`, `.env*`, `tmp/`, `fixtures/`, and `test-forensics/` are archive-excluded as defense in depth. |

Release ZIPs produced for submissions should remain small, deterministic, and
limited to the assets listed by the release workflow or submission packager.

## Brand Surface

The canonical visual system is documented in `docs/brand.md` and sourced from
`VERDICT_DFIR_SVG_Assets_v2/`. Public README, GitHub badges or imagery, report
CSS, dashboard UI, and Remotion/video output should use the v2 assets and palette.
Visual assets are never evidence and do not change the scoped meaning of a
Verdict or Finding confidence tier.
