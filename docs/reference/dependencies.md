# Dependencies & Version Matrix — canonical inventory

> **Status: ACTIVE.** Mirrors what `scripts/doctor.sh` checks and `scripts/install-dfir-tools.sh`
> installs. When this file and the scripts disagree, **the scripts win** (code is authoritative)
> — fix this file. Exact versions below are the shipped defaults as of this writing; the scripts
> print the live values, so re-run `bash scripts/doctor.sh --json` to confirm.

There are four dependency layers. Only the first two are required to run an EVTX-only
investigation in-process; the external DFIR binaries are needed for memory/disk/PCAP/Sigma work.

---

## 1. Host toolchain (REQUIRED — `doctor.sh` blocks without these)

| Tool | Pin | Why | Install |
|---|---|---|---|
| `claude` CLI | latest | The agent IS the engine (A2) | `npm i -g @anthropic-ai/claude-code` |
| Rust | **1.88** (`rust-toolchain.toml`) | builds `findevil-mcp` | `rustup` |
| `cargo` | with Rust 1.88 | build/test | rustup |
| C toolchain (`cc`) | system | links Rust crates (rustup does not install it) | `build-essential` (Debian/Ubuntu) · `xcode-select --install` (macOS) |
| `uv` + Python | **3.11** | `findevil-agent-mcp` venv | `curl -LsSf https://astral.sh/uv/install.sh \| sh` |
| Node | **20** | `apps/web` dashboard | nodejs.org / nvm |
| `pnpm` | 9.x | workspace install | `corepack enable` |
| `git`, `unzip` | any | clone, extract release zips | OS package |

> **Node-version note:** the product/dashboard are pinned to **Node 20**. The optional
> `qmd` MCP launcher is inert unless `FINDEVIL_ENABLE_QMD=1` is set and an operator
> supplies a local `obsidian-mind/` vault plus matching Node/QMD toolchain. The optional
> **obsidian-mind memory layer** (QMD + lifecycle hooks) needs **Node 22+** — installed
> side-by-side via nvm and used only for that layer. Reduced source checkouts may omit the
> obsidian-mind runbook; it is optional operator memory, never evidence, and never audit-chain
> input.

### Credential modes (Amendment A1 — one of three, detected by `install.sh`)

1. `CLAUDE_CODE_OAUTH_TOKEN` env var (from `claude setup-token`) — non-interactive, preferred.
2. Interactive Claude Code login (`~/.claude/`) — dev default.
3. `ANTHROPIC_API_KEY` env var — direct metered API.

---

## 2. External DFIR tools (subprocess-only — never linked; license-clean by design)

Installed by `scripts/install-dfir-tools.sh` into `~/.local/bin` (idempotent, best-effort,
non-fatal). The SANS SIFT OVA bundles all of these, so `--sift` mode needs none of them on the
host. Each version below is the script's **default** and is overridable by env var
(`HAYABUSA_VERSION=2.20.0 bash scripts/install-dfir-tools.sh`).

| Tool | Default pin | License | Backs (MCP tool) | Missing → behavior |
|---|---|---|---|---|
| `volatility3` | **see note** | Volatility Software License (BSD-2-style) | `vol_pslist/psscan/psxview/malfind` | BinaryNotFound |
| `hayabusa` | `2.19.0` | AGPL-3.0 | `hayabusa_scan` | BinaryNotFound (Sigma scan skipped) |
| `chainsaw` | `2.13.0` | Elastic License 2.0 | optional EVTX hunting (not a core tool) | n/a |
| `velociraptor` | `0.74.6` | Apache-2.0 | `vel_collect` | BinaryNotFound |
| `sleuthkit` (`fls`/`icat`/`mmls`) | system pkg | IPL-1.0 / CPL-1.0 | `disk_extract_artifacts` reads `.e01`/`.dd` content directly; `mmls` resolves the partition offset | disk evidence stays custody-only (no registry/MFT/prefetch) |
| `pandoc` | `3.1.11.1` | GPL-2.0 | report HTML/PDF (`render_report.py`) | HTML/PDF render skipped |
| `tshark` | system pkg | GPL-2.0 | `pcap_triage` (preferred) | falls back to zeek |
| `zeek` | system pkg | BSD-3-Clause | `zeek_summary`, `pcap_triage` (fallback) | env-limit, not evidence-absence |
| `yara-x` | `1.12.0` (Rust crate) | BSD-3-Clause / Apache-2.0 | `yara_scan` | n/a — **in-process, not a subprocess** |

> **volatility3 version — a real spec/code divergence to know about.** Two install paths pin
> different versions:
> - `requirements.txt` (pip host-tool path) pins **`volatility3==2.27.0`** — "to match the SIFT
>   Workstation 2026.03.24 build."
> - `scripts/install-dfir-tools.sh` defaults to **`VOLATILITY_VERSION=2.11.0`** (overridable).
>
> Both are "code," so per the repo's code-wins rule neither is wrong; the pip path is the one
> aligned to SIFT parity. If you need a specific version, install via `requirements.txt`
> (`uv pip install -r requirements.txt`) or override `VOLATILITY_VERSION`. This divergence is
> tracked here rather than silently resolved.

Binary overrides (env-var first, then PATH): `VOLATILITY_BIN`, `HAYABUSA_BIN`,
`VELOCIRAPTOR_BIN`, `TSHARK_BIN`, `ZEEK_BIN`. See [`environment-variables.md`](environment-variables.md).

---

## 3. Rust crate pins (`services/mcp/Cargo.toml`, locked in `Cargo.lock`)

App, not library → `Cargo.lock` is committed. Exact pins are spec-locked; do not bump without a
spec amendment.

| Crate | Pin | Used by |
|---|---|---|
| `evtx` | `=0.11.2` | `evtx_query`, `sysmon_network_query` (~1600× faster than python-evtx) |
| `frnsc-prefetch` | `=0.13.3` | `prefetch_parse` |
| `forensic-rs` | `=0.13` | prefetch FS abstraction |
| `mft` | `=0.6.1` | `mft_timeline` (0.7+ needs rustc 1.90; we're locked at 1.88) |
| `yara-x` (+ `-macros`/`-parser`/`-proto`) | `1.12.0` | `yara_scan` (in-process) |
| `usnjrnl-forensic` | `0.6.0` | `usnjrnl_query` |
| `sha2` | `0.10` | output SHA-256 over canonical JSON |
| `uuid` | `1.x` | `case_id` |
| `serde` / `serde_json` / `schemars` | 1.x / 1.x / 1.x | typed I/O + JSON schema |
| `tokio` / `chrono` / `tracing` / `hex` / `thiserror` | 1.x / 0.4 / 0.1 / 0.4 / 1.0 | runtime, time, logging |

> Registry hive parsing is **in-tree** (`src/tools/regf.rs`), not a crate: `frnsc-hive` panicked
> on XP-era `lf`/`li`/`ri` cells and `notatin` doesn't build under rustc 1.88.
> `rmcp` (the MCP SDK) is **deliberately not activated** — the server in `src/server.rs` is a
> hand-rolled stdio JSON-RPC 2.0 implementation pinned to MCP 2024-11-05.

---

## 4. Python dependencies

`services/agent_mcp/pyproject.toml` (+ `uv.lock`), importing `services/agent/` as a path dep:

| Package | Pin | Role |
|---|---|---|
| `mcp` | `>=1.0,<2.0` | MCP server SDK |
| `pydantic` | `>=2.7,<3.0` | typed tool I/O |
| `structlog` | `>=24.4` | structured logging |
| `python-dotenv` | `>=1.0,<1.2` | env loading |
| `findevil-agent` | path dep | crypto chain + ACH primitives |
| `anthropic` | `0.97.0` | LLM client (judge/correlator helpers) |
| `pytest` / `pytest-asyncio` / `pytest-cov` / `ruff` / `mypy` | dev | test + lint + types |

Crypto stack (in `services/agent/`): Ed25519 (the offline-verifiable default manifest signer),
`sigstore` (opt-in identity/transparency signer tier), plus a hand-rolled `rs_merkle`-compatible
Merkle tree. **`opentimestamps-client` was REMOVED under Amendment A5** — the OTS/Bitcoin 4th tier is
gone; the chain is 3 tiers (audit `prev_hash` → Merkle root → manifest signature).

Host pip tooling (`requirements.txt`, host-mode only): `volatility3==2.27.0`, `matplotlib`
(report figures).

---

## 5. Node dependencies

| Package | Pin | Workspace |
|---|---|---|
| `next` | `15.1.0` | `apps/web` dashboard |
| `react` / `react-dom` | `19.0.0` | `apps/web` |
| `nes.css` | `2.3.0` | dashboard UI |
| `tailwindcss` | `4.0.0` | dashboard styling |
| `chokidar` | `4.0.0` | audit-JSONL file tail |
| `typescript` / `eslint` / `vitest` | `5.7.0` / `9.7.0` / `2.1.0` | dashboard toolchain |
| `remotion` (+ `@remotion/cli`/`google-fonts`/`transitions`) | `4.0.237` | demo video (`scripts/make-demo-video/`) |

Operator-runtime MCP servers (`n8n-mcp`, `@playwright/mcp`, `@modelcontextprotocol/server-puppeteer`)
are pulled on demand via `npx -y` — not workspace deps.

---

## 6. Verify

```bash
bash scripts/doctor.sh           # human summary: READY / NOT READY + remedies
bash scripts/doctor.sh --json    # machine-readable; diff against this file
bash scripts/install-dfir-tools.sh   # install the 8 external tools into ~/.local/bin
```
