# Runbook: Local Smoke Gate

**Status: ACTIVE**
**Script:** `scripts/run-all-smokes.sh` (POSIX/Git Bash) or `scripts/run-all-smokes.ps1` (native Windows)

Run this as a **CI predictor**: it mirrors the L1 Docker gate (`docker/l1-compose.yml`) but runs
locally without containers for a faster iteration loop, so a green local run predicts a green L1.
It is **not** a live test — the dev "done" gate is a passing live test (`scripts/verdict` against
real evidence; see `CLAUDE.md` "Running A Case"). Run the smoke runners to predict CI; run a live test to prove
the app actually works.

---

## Prerequisites

| Requirement | How to install |
|---|---|
| Rust 1.88 | `rustup update` — `rust-toolchain.toml` pins the version |
| `cargo build --release -p findevil-mcp` | run once before first smoke; the Rust smoke resolves the release binary |
| `uv` | `pip install uv` or `curl -LsSf https://astral.sh/uv/install.sh \| sh` |
| `uv sync --directory services/agent_mcp` | run once after `uv` is installed; the agent_mcp smoke spawns the Python MCP server |
| `pnpm` (optional — for web smokes) | `npm install -g pnpm` |
| `ruff` (optional — skips cleanly if absent) | `pip install ruff` or `uv tool install ruff` |
| `python3` on PATH | Python 3.11+ |

Optional tools (`ruff`, `cargo`, `powershell`/`pwsh`) are detected via `command -v`. If absent,
their smoke steps print `SKIP` rather than `FAIL`.

---

## Run it

```bash
bash scripts/run-all-smokes.sh
```

On native Windows (no Git Bash):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/run-all-smokes.ps1
```

Exit code 0 = all smokes passed (or skipped); non-zero = at least one failed.

---

## What each smoke covers

| # | Smoke | Covers |
|---|---|---|
| 1 | `rust-mcp-smoke` | 32-tool JSON-RPC catalog + core error paths for the Rust MCP server |
| 2 | `agent-mcp-smoke` | Synthetic Findings through the full M2 crypto chain (audit → Merkle → signed manifest) |
| 3 | `verdict-policy-smoke` | `compute_verdict` + `detect_evidence_type` policy lock |
| 4 | `fleet-policy-smoke` | `fleet_correlate` normalize/filter/cluster/density/uniqueness/aggregate |
| 4b | `report-policy-smoke` | Report QA + expert signoff + visual evidence policy |
| 4c | `readiness-gate-smoke` | PacketOnly packaging + fail-closed blockers (skips if no PowerShell) |
| 5 | `launcher-smoke` | `bash -n` syntax + `claude` binary on PATH + no positional-dot invocations |
| 6 | `divergence-smoke` | Active CLAUDE.md divergences not reintroduced in live files |
| 7 | `path-existence-smoke` | Every backtick-quoted path in operator docs resolves to a real file/dir |
| 8 | `smoke-regex-tests` | Synthetic +/- cases against audit-smoke regex/helper policies |
| L | `ruff check .` | Python lint clean (skips if ruff absent) |
| L | `ruff format --check .` | Python formatter clean (skips if ruff absent) |
| L | `cargo fmt --all --check` | Rust formatter clean (skips if cargo absent) |
| L | `cargo clippy --deny warnings` | Rust lint clean (skips if cargo absent) |
| L | `cargo test --workspace --locked` | Full Rust test suite — set `SKIP_SLOW_RUST=1` to skip during fast iteration |

---

## Common failure modes and fixes

### `SKIP: prerequisite not met ([ -x target/release/findevil-mcp ])`

The Rust release binary hasn't been built yet.

```bash
cargo build --release -p findevil-mcp
```

### `uv: command not found` (agent-mcp-smoke fails)

```bash
pip install uv
uv sync --directory services/agent_mcp
```

### `ModuleNotFoundError: findevil_agent_mcp` (agent-mcp-smoke fails)

The agent_mcp env is not synced.

```bash
uv sync --directory services/agent_mcp --extra dev
```

### `cargo: command not found` (Rust smokes skip or fail)

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Then reload your shell and retry.

### `ruff: command not found` (lint smokes skip)

Not a failure — the smoke gate `SKIP`s correctly. Install ruff if you want the lint gate:

```bash
uv tool install ruff
```

### `path-existence-smoke` fails on a new doc you just wrote

The smoke checks every backtick-quoted path in operator docs. If you added a backtick path
in a new document that doesn't resolve, either fix the path or temporarily skip by not quoting
it with backticks until the referenced file exists.

### Smoke passes locally but fails in L1 Docker

Check toolchain versions. The Docker gate (`docker/l1-compose.yml`) uses Ubuntu 22.04 with
Rust 1.88 (per `rust-toolchain.toml`) and Python 3.11. If your local toolchain diverges:

```bash
# Rust version:
rustup show active-toolchain

# Python version in agent_mcp venv:
uv run --directory services/agent_mcp python --version
```

---

## Speed tips

- Skip the slow Rust test suite during inner-loop iteration: `SKIP_SLOW_RUST=1 bash scripts/run-all-smokes.sh`
- The Rust binary build is cached by `cargo`; subsequent `cargo build --release` runs are fast once the initial build completes.
- The Python smokes (`agent-mcp-smoke`, `verdict-policy-smoke`, etc.) run in under 5 seconds each after the first `uv sync`.
