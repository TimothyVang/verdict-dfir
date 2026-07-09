# Repo Layout

How files are organized in this repository, and the one rule that keeps the root
clean. The goal is simple: **everything lives in one project folder with a place for
each thing** — the repo root holds only configuration and the load-bearing top-level
docs; everything else lives in a named directory.

This layout is **machine-enforced** by `scripts/repo-layout-smoke.py`, which runs as
part of `bash scripts/run-all-smokes.sh`. A stray file or folder at the root — a loose
scratch note, a duplicate asset folder, an un-homed output dir — fails the gate until
it is filed correctly.

## What may live at the repo root

Only two kinds of things:

1. **Config / manifest files** — build and tooling manifests that tools expect at the
   root: `Cargo.toml`, `Cargo.lock`, `pnpm-workspace.yaml`, `pnpm-lock.yaml`,
   `rust-toolchain.toml`, `requirements.txt`, `mkdocs.yml`, `Dockerfile`,
   `.dockerignore`, `.mcp.json`, `.mcp.json.sift`, `.gitignore`, `.gitattributes`,
   `.yamllint`, and the bootstrap `install.sh`.
2. **Public top-level docs** — the documents readers expect at the root of a project:
   `README.md`, `INSTALL.md`, `QUICKSTART.md`, `CHANGELOG.md`, `LICENSE`, `NOTICE`,
   `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`, `SECURITY.md`, plus the agent operating
   contracts `CLAUDE.md`, `AGENTS.md`, and `llms.txt`.

Everything else belongs in a directory.

## Top-level directories

| Directory | Holds |
|-----------|-------|
| `agent-config/` | Runtime DFIR agent rules (SOUL, AGENTS, PLAYBOOK, TOOLS, ...). |
| `apps/` | Web dashboard and UI surfaces. |
| `services/` | MCP servers and agent backends (Rust + Python). |
| `scripts/` | Build, run, smoke, and tooling scripts. |
| `docs/` | Product documentation (this file included). |
| `assets/` | Small shared assets. |
| `VERDICT_DFIR_SVG_Assets_v2/` | The **canonical** brand asset package (see `docs/brand.md`). |
| `goldens/` | Golden / benchmark expected-findings data. |
| `packer/` | SIFT VM image build configuration. |
| `ci/` | CI helper configuration. |
| `docker/` | Container compose definitions. |
| `evidence/` | Default evidence drop dir (ships as README + `.gitkeep`; contents are gitignored). |
| `.github/` | GitHub workflows and templates. |
| `.githooks/` | Repo-managed git hooks (e.g. the publish pre-push guard). |
| `.claude/` | Claude Code config; only `.claude/skills/` ships, the rest is gitignored. |

## Self-contained runtime: `.project-local/`

Everything the MCP servers and forensic tools produce at runtime is contained
inside the project under `.project-local/` (gitignored), so nothing escapes the
folder. `scripts/lib/project-env.sh` is sourced by every MCP launcher
(`scripts/run-mcp-*.sh`) and by `scripts/verdict`, and exports project-local
defaults for the standard escape hatches:

| Variable | Redirects | Lands in |
|----------|-----------|----------|
| `TMPDIR` | tool scratch (`std::env::temp_dir()`, `tempfile`) | `.project-local/tmp` |
| `FINDEVIL_HOME` | case store + `memory.sqlite` + signing key | `.project-local/findevil` |
| `XDG_DATA_HOME` / `HAYABUSA_RULES_BASE` | hayabusa rules, tool data | `.project-local/share` |
| `XDG_STATE_HOME` / `XDG_CACHE_HOME` | tool state / cache | `.project-local/state`, `.project-local/cache` |
| `npm_config_cache` | npx package cache (convenience MCPs) | `.project-local/npm` |
| `PLAYWRIGHT_BROWSERS_PATH` / `PUPPETEER_CACHE_DIR` | browser downloads | `.project-local/ms-playwright`, `.project-local/puppeteer` |
| `CARGO_HOME` / `RUSTUP_HOME` | Rust crate cache + toolchains | `.project-local/toolchain/cargo`, `.project-local/toolchain/rustup` |
| `UV_CACHE_DIR` / `UV_PYTHON_INSTALL_DIR` | uv wheel cache + interpreters | `.project-local/toolchain/uv-cache`, `.project-local/toolchain/uv-python` |
| `PNPM_HOME` / `npm_config_store_dir` | pnpm content-addressable store | `.project-local/toolchain/pnpm-store` |

The language toolchain dirs hold **project-local copies** seeded from the
machine-wide caches (`~/.cargo`, `~/.rustup`, `~/.cache/uv`, `~/.local/share/pnpm`),
which are left intact so other projects keep working. This project then builds
entirely from in-folder state.

Each export honours a pre-set value (`${VAR:-default}`), so an operator can
still override any single location. The convenience MCP servers (`n8n-mcp`,
`playwright`, `puppeteer`) run through `scripts/run-mcp-{n8n,playwright,puppeteer}.sh`
so their npx/browser bytes also land in `.project-local/` — never committed,
preserving the "convenience servers are never bundled" release rule.

## Runtime and local output (gitignored — out of scope for the guard)

These never enter git, so the layout guard ignores them. They are produced by runs or
local tooling and documented here only so their presence at the root is expected:

- `tmp/`, `target/`, `node_modules/`, `release-assets/`, `fixtures/` — build / run output.
- `*.ova`, `*.E01`, `*.dd`, `*.mem`, `*.evtx`, `*.pcap*` — evidence and VM images.
- `log2timeline-*.log*` / `psort-*.log*` — plaso writes a timestamped run log into the
  current working directory on every invocation; these are transient and gitignored.
- `graphify-out/`, `obsidian-mind/`, `n8n-references/` — optional local operator tooling.

## Real-time guard for AI agents (Claude Code / Codex)

The smoke catches stray root entries *after* they exist. To stop them being
created in the first place, `scripts/hooks/guard-root-writes.py` is a PreToolUse
hook: when an agent tries to write a new file or folder at the repo root that
isn't sanctioned, the hook blocks the write and tells the agent where the file
should go. It reuses the same `ROOT_ALLOWLIST`, so the hook and the smoke never
drift.

Wire it into Claude Code (e.g. `.claude/settings.local.json`):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Write",
        "hooks": [
          { "type": "command",
            "command": "python3 \"$CLAUDE_PROJECT_DIR/scripts/hooks/guard-root-writes.py\"" }
        ]
      }
    ]
  }
}
```

Codex and other agents read the same rule from `AGENTS.md` ("Keep the repo root
clean") and `CLAUDE.md`.

## Adding a new sanctioned root entry

If a new file or folder genuinely belongs at the root (rare), add its **exact name** to
`ROOT_ALLOWLIST` in `scripts/repo-layout-smoke.py` with a one-line justification
comment — the same convention as `ALLOW_PATTERNS` in `scripts/path-existence-smoke.py`.
Otherwise, do one of:

- **Move it** into a sanctioned subtree (`scripts/`, `docs/`, `assets/`, `services/`, ...).
- **Ignore it** in `.gitignore` if it is local-only output.

Then re-run the guard:

```bash
python3 scripts/repo-layout-smoke.py
```
