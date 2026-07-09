# Installing VERDICT

The single canonical install path: **clone → install → verify → first run**. For the project
pitch see [README.md](README.md); for run modes and every flag see
[docs/using/running-verdict.md](docs/using/running-verdict.md).

VERDICT runs as a [Claude Code](https://claude.com/claude-code) agent. Installation builds the two
product MCP servers and the host DFIR toolchain; Claude Code auto-spawns the servers from
`.mcp.json` on session start. The product surface is 48 tools total: 34 Rust DFIR tools in
`findevil-mcp` plus 14 Python crypto/ACH/memory/ACP/expert-feedback tools in
`findevil-agent-mcp`.

---

## Prerequisites

Install the required OS tools and configure one Claude credential first. The first-run setup can
bootstrap the C toolchain (`build-essential` on Debian/Ubuntu), missing cargo/uv via their official
installers, and Node 20 via `fnm` when needed (best-effort, since Node is optional):
`bash scripts/setup` calls `scripts/install.sh --bootstrap`. For fail-closed CI/judge checks, run
`bash scripts/install.sh` without `--bootstrap`; it reports missing tools instead of installing them.

| Tool | Version | Why | Required? |
|---|---|---|---|
| Rust + Cargo | 1.88 (pinned in `rust-toolchain.toml`) | builds `findevil-mcp` (34 DFIR tools) | **yes** |
| uv | latest | syncs the Python `findevil-agent-mcp` env (14 tools) | **yes** |
| Python | 3.11–3.12 | runs the Python `findevil-agent-mcp` + smoke/score tooling | **yes** |
| git | recent | clones the repo; used by the smokes | **yes** |
| unzip | any | extracts Velociraptor `.zip` collections + fixtures | **yes** |
| Node | 20 | the live dashboard (`apps/web`) | optional |
| pnpm | latest | dashboard package manager | optional |
| A Claude credential | one of three (below) | the agent cannot run without it | **yes** |

**Claude credential — one of three modes** (full detail in [CLAUDE.md §8](CLAUDE.md)):

1. `CLAUDE_CODE_OAUTH_TOKEN` env var (from `claude setup-token`) — best for CI/automation.
2. A logged-in Claude Code session (`~/.claude/` present) — the dev default.
3. `ANTHROPIC_API_KEY` env var — direct metered API.

### Two hard floors (stated plainly, not bugs)

- **The Claude credential is required** for the investigating agent (one of the three modes above).
- **Disk-image inner-volume extraction needs Sleuth Kit/libewf locally or the SANS SIFT VM** (a
  ~9.3 GB browser-gated download — see [QUICKSTART.md](QUICKSTART.md) "Path A"). Local-host mode
  fully handles memory, EVTX, PCAP, and Velociraptor evidence; raw `.E01`/`.dd` disks are custody-only
  when mount/extract prerequisites are absent or no supported artifacts are produced.

---

## Step 1 — Clone

```bash
git clone --depth 1 https://github.com/TimothyVang/verdict-dfir-beta.git verdict   # --depth 1 keeps the clone small + fast
cd verdict
```

## Step 2 — Install

```bash
bash scripts/setup
```

This runs `scripts/install.sh` (builds `findevil-mcp` with `cargo build --release` — **5–10 min on
the first run**, then cached — syncs the Python MCP env with `uv`, and installs the host DFIR tools
— Volatility3, Hayabusa, Chainsaw, Velociraptor, pandoc — into `~/.local/bin`, no sudo), then
`scripts/doctor.sh` for a preflight summary. It is **idempotent** — safe to re-run.

**Skip the compile (when release binaries exist).** Once a tagged release publishes prebuilt
binaries, set `FINDEVIL_MCP_PREBUILT=1 FINDEVIL_MCP_VERSION=<tag>` before `scripts/install.sh` to
download a checksum-verified `findevil-mcp` for your platform instead of compiling. Any
unavailable/unverified asset falls back to the normal build, so this is always safe to set.

## Step 3 — Verify

```bash
bash scripts/doctor.sh          # human-readable, color table + remedies
bash scripts/doctor.sh --json   # machine-readable: {"ready":true,...}
```

`ready:true` (and no red required rows) means the toolchain, both MCP servers, and a Claude
credential are present. DFIR-tool and reporting rows are **advisory** — a missing optional binary
surfaces at runtime as `BinaryNotFound -32602` and the agent pivots; it does not block a run.
Failure modes and fixes: [docs/troubleshooting.md](docs/troubleshooting.md).

## Step 4 — First run

Point VERDICT at evidence. Output lands in `tmp/auto-runs/<case-id>/`, and the live dashboard at
`http://localhost:3000` streams the run.

```bash
# Your own evidence (memory / EVTX / PCAP / Velociraptor work locally; disk needs local Sleuth Kit/libewf or --sift):
scripts/verdict evidence/<your-file>

# No evidence yet? Stage public test datasets (into fixtures/, never evidence/):
bash scripts/fetch-fixtures.sh         # sources + SHA-256 in docs/DATASET.md
scripts/verdict fixtures/<staged-path>
```

A run is a **live test**, not a smoke run: confirm `tmp/auto-runs/<case-id>/verdict.json` carries a
real Verdict (`SUSPICIOUS` / `INDETERMINATE` / `NO_EVIL`), every Finding cites a `tool_call_id`, and
`manifest_verify.json` reports `overall: true`.

You can also drive it interactively — open `claude` (or `scripts/find-evil`) in the repo and prompt
`investigate <path>` — or use the turnkey `/verdict <path>` skill, which also bootstraps n8n and the
SIFT VM. See [docs/using/running-verdict.md](docs/using/running-verdict.md).

---

## Where to read next

- [QUICKSTART.md](QUICKSTART.md) — environment choice (SIFT VM vs. local) and run modes
- [docs/using/running-verdict.md](docs/using/running-verdict.md) — every flag, output layout
- [docs/reference/dependencies.md](docs/reference/dependencies.md) — the full dependency + version matrix
- [docs/troubleshooting.md](docs/troubleshooting.md) — failure mode → detector → fix
- [docs/architecture.md](docs/architecture.md) — the six trust boundaries
