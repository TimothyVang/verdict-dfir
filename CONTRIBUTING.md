# Contributing to VERDICT

Thanks for helping improve VERDICT. This guide covers how to build, test, and submit changes. New
to the project? Start with [INSTALL.md](INSTALL.md); for the design, read
[CLAUDE.md](CLAUDE.md) and [docs/architecture.md](docs/architecture.md).

VERDICT is a DFIR agent where **Claude Code is the engine** (Amendment A2). It is three subsystems:
a Rust MCP server (`services/mcp/`, 20 DFIR tools), a Python MCP server
(`services/agent_mcp/`, 12 crypto/ACH/memory tools), and a Next.js dashboard (`apps/web/`).

---

## Before you start — the non-negotiable invariants

These are load-bearing for the project's security story and judging narrative. A PR that breaks one
will be blocked. Full list: [CLAUDE.md §3](CLAUDE.md).

- **No `execute_shell` MCP tool, ever.** The narrow typed surface *is* the pitch.
- **Every Finding cites a `tool_call_id`.** The verifier vetoes any that doesn't.
- **Evidence is read-only;** the audit log is append-only and hash-chained.
- **Claude Code is the orchestrator** — do not reintroduce `findevil_agent.cli` or `scripts/build-deb.sh`
  (the L0 `amendment-a2-guard` job and `divergence-smoke.py` will fail CI if you do).
- **AGPL/GPL DFIR tools are subprocess-only, never linked** (keeps the tree Apache-2.0).
- When spec and code disagree, **code + committed pin files win** ([CLAUDE.md §8](CLAUDE.md)).

---

## Build and test

Install the toolchain once with `bash scripts/setup` (see [INSTALL.md](INSTALL.md)). The commands
below mirror exactly what CI runs, so green locally means green in CI.

### Rust (`services/mcp/`) — Rust 1.88 (pinned in `rust-toolchain.toml`)

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

### Python (`services/agent/`, `services/agent_mcp/`) — Python 3.11, uv

```bash
ruff check .
ruff format --check .                       # ruff 0.7.4 (pinned in CI)
uv run --directory services/agent_mcp pytest
uv run --directory services/agent pytest
```

### Node (`apps/web/`) — Node 20, pnpm

```bash
pnpm install --frozen-lockfile
pnpm -r exec tsc --noEmit
pnpm -r lint
pnpm test
```

### Shell

All `scripts/*.sh` must pass `shellcheck` (the L0 `shellcheck` job runs it at `severity: error`).

---

## The two verification bars

1. **CI predictor (fast).** `bash scripts/run-all-smokes.sh` (POSIX/Git Bash) or
   `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/run-all-smokes.ps1` (Windows). These
   mirror what L1 runs; they print the current smoke tally (do not hard-code it). A smoke run is a
   *predictor*, not the real bar.
2. **The "done" gate is a live test.** Run a real investigation:

   ```bash
   scripts/verdict evidence/<file>
   ```

   It passes when `tmp/auto-runs/<case-id>/verdict.json` carries a real Verdict, every Finding cites
   a `tool_call_id`, and `manifest_verify.json` reports `overall: true`. An honest `INDETERMINATE`
   on thin evidence is a PASS. Full matrix: [docs/live-test-matrix.md](docs/live-test-matrix.md).

New behavior follows **TDD**: write the failing test (RED), implement (GREEN), refactor. See
[docs/troubleshooting.md](docs/troubleshooting.md) when something breaks.

---

## CI tiers

| Tier | Workflow | What it gates |
|---|---|---|
| **L0** | `l0-static.yml` | lint (shellcheck/ruff/clippy/fmt/tsc), docs-consistency, the A2 guard. Fast, **required**. |
| **L1** | `l1-unit.yml` | `cargo test` / `pytest` / `pnpm build+test` in a pinned container. **Required**. |
| **L2** | `l2-sift-lite.yml` | DFIR-tool smoke. **Advisory** (does not block). |
| **L3** | `l3-nightly.yml` | full-SIFT golden run. **Blocks releases.** |

---

## Submitting changes

- **Branch** off `master`; never commit to `master` directly.
- **Conventional Commits.** `feat(scope):`, `fix(scope):`, `test(scope):`, `docs(scope):`,
  `chore(scope):`, `refactor(scope):`. Active scopes include `mcp`, `agent`, `verdict`, `fleet`,
  `sandbox`, `ci`, `tooling`, `deps`, `plan`. One logical change per commit.
- **Never** use `--no-verify`, `--no-gpg-sign`, or `git commit --amend`. If a hook fails, fix the
  root cause and make a new commit.
- **DFIR vocabulary, not software vocabulary**: Case (not session/run), Observable (not file),
  Task (not step), Finding (not result), Verdict (not conclusion), Confidence (not score). See
  [CLAUDE.md §7](CLAUDE.md) for the carve-outs.
- **Surgical diffs.** Touch only what the change requires; match the surrounding style; don't
  refactor adjacent code.
- Open a PR with a clear summary and a test plan. Ensure L0 + L1 are green and the branch is current
  with `master` before requesting review.

Unsure about a term? See [docs/glossary.md](docs/glossary.md).
