# Codex Compatibility

Status: ACTIVE

This document explains how to use Codex as a developer/operator interface for Find Evil without changing the product architecture. The official general SANS judge/demo path remains the default deterministic `scripts/verdict <evidence>` launcher or an interactive Claude Code session (`claude` / `scripts/find-evil`) for manual exploration. Strict Phase 4 offline acceptance uses the allowed beta-native `scripts/verdict --agent <single.evtx>` loop; Codex compatibility is not that runtime and does not gate Phase 4.

Codex compatibility means: Codex can read the same repo instructions and, if its MCP client supports stdio servers, launch the same two narrow product MCP servers. It does not mean adding broad external MCPs.

The beta-native loop does not reverse Amendment A2: it is limited to
`services/agent/findevil_agent/agentloop/`, and the removed pre-A2 modules, LangGraph, and FastAPI
remain forbidden. Native mode currently accepts one EVTX file; every non-EVTX type and directory
fails closed before preflight or MCP startup and must use default deterministic analysis. A
local/DGX provider changes inference location, not detection-quality claims.

## Canonical MCP Servers

`.mcp.json` registers six servers total. The two audit-chained product servers are:

| Server | Purpose | Expected tools |
|---|---|---:|
| `findevil-mcp` | Rust DFIR tool surface over evidence and forensic artifacts | 32 |
| `findevil-agent-mcp` | Python audit, manifest, verifier, ACH, memory, ACP, and expert-feedback support tools | 13 |

Expected total: 45 product tools. The other four registered servers are non-product operator conveniences.

These are the only product-default MCP servers — the only two in the audit chain. `.mcp.json` *also* registers four **non-product** servers (`n8n-mcp`, `playwright`, `puppeteer`, and `qmd` dev-memory recall) for post-verdict automation, browser tasks, and memory; they touch no evidence and emit no Findings, so seeing six entries in `.mcp.json` is expected, not a misconfiguration (full inventory: [`reference/mcp-and-tools.md`](reference/mcp-and-tools.md)). Do not add generic filesystem, Docker, Kubernetes, GitHub, fetch, or shell MCPs as defaults.

The Protocol SIFT gateway (`teamdfir/protocol-sift`) is a welcome common base that installs independently via `protocol-sift install` on the same SIFT VM. It is **not** a product-default MCP for Find Evil!: its broad shell-backed surface (200+ tools, `execute_shell`) is architecturally distinct from our 45-typed-tool product surface. If Protocol SIFT is installed, both gateways coexist under separate MCP server names; neither requires nor conflicts with the other. See [`docs/architecture.md#relationship-to-protocol-sift`](architecture.md#relationship-to-protocol-sift).

## Local Codex MCP Config

If your Codex build supports a user-level `config.toml` with `mcp_servers` entries, add equivalent stdio servers outside this repo. Do not commit user-level config or secrets.

Run Codex from the repo root so `cwd = "."` and relative paths resolve correctly.

```toml
[mcp_servers.findevil-mcp]
command = "cargo"
args = ["run", "--release", "-p", "findevil-mcp", "--quiet"]
cwd = "."

[mcp_servers.findevil-agent-mcp]
command = "uv"
args = [
  "run",
  "--directory",
  "services/agent_mcp",
  "python",
  "-m",
  "findevil_agent_mcp.server",
]
cwd = "."
```

This mirrors the product-server subset of `.mcp.json` and does not require tokens.

For non-interactive `codex exec` on Windows, prefer launching the compiled Rust binary after it exists. This avoids `cargo run --release` trying to build or touch `target/` inside Codex's sandbox.

```toml
[mcp_servers.findevil-mcp]
command = "target/release/findevil-mcp.exe"
cwd = "."
required = true
enabled_tools = ["case_open", "evtx_query"]
startup_timeout_sec = 30
tool_timeout_sec = 120
```

Build it first with the normal repo validation path, for example:

```bash
cargo build --release -p findevil-mcp --locked
```

## SIFT VM Mode

SIFT mode is encoded in `.mcp.json.sift`. It uses SSH stdio to start both MCP servers inside the SIFT VM, where Volatility, Hayabusa, Velociraptor, and YARA dependencies are available.

Use the canonical launcher when possible:

```bash
scripts/verdict <path-to-evidence> --sift
```

For Codex, treat `.mcp.json.sift` as the source of truth for the SSH command shape. `scripts/find-evil-sift` is helper plumbing for SIFT transport, not a separate product workflow. Do not automatically copy `.mcp.json.sift` over `.mcp.json` or edit user-level Codex config unless the operator explicitly asks.

Operator-owned values in `.mcp.json.sift` include:

- SSH key path
- SIFT VM username and host/IP
- repo path inside the VM
- binary paths for `vol`, `hayabusa`, and `velociraptor`

Do not commit private keys, tokens, local evidence paths, or per-user secrets.

## Agent Instructions

Codex-compatible agents should read `AGENTS.md` at the repo root. That file defers to `CLAUDE.md`, which remains authoritative for:

- document hierarchy
- non-negotiable DFIR invariants
- tool count and A5 divergence notes
- commands
- evidence handling
- commit safety

When investigating evidence, read the runtime identity files in the order listed in `CLAUDE.md` and `AGENTS.md`:

1. `agent-config/SOUL.md`
2. `agent-config/AGENTS.md`
3. `agent-config/PLAYBOOK.md`
4. `agent-config/TOOLS.md`
5. `agent-config/MEMORY.md`
6. `agent-config/HEARTBEAT.md`
7. `agent-config/JUDGING.md`

## What Not To Add

Do not add these as product-default MCPs:

- `filesystem`
- `git`
- `fetch`
- browser automation MCPs
- Docker MCPs
- Kubernetes MCPs
- GitHub org/admin MCPs
- any MCP that exposes raw shell execution

Those tools may be useful in other repos, but Find Evil's security story depends on a narrow, typed, auditable surface. Native coding-agent tools and existing repo scripts should handle normal code search, edits, GitHub operations, tests, and packaging.

## Forbidden Tool Drift

Fail review if any configured or documented product MCP surface includes:

```text
execute_shell
ots_stamp
ots_verify
```

`execute_shell` breaks the typed-surface trust boundary. `ots_stamp` and `ots_verify` were removed under Amendment A5 when the chain collapsed to three tiers: audit `prev_hash` links, Merkle root, and a manifest signature tier: Ed25519 by default, Sigstore/Rekor when configured.

## Validation

Run the smallest relevant checks first.

```bash
python scripts/verdict-policy-smoke.py
ruff check .
ruff format --check .
uv run --directory services/agent_mcp python -m pytest -q
cargo test --workspace --locked
```

MCP-focused smoke tests:

```bash
python scripts/rust-mcp-smoke.py --real-evidence
uv run --directory services/agent_mcp python ../../scripts/agent-mcp-smoke.py
```

If real evidence is unavailable, run component-level tests and state the limitation. Do not fabricate evidence or findings.

## Tested Codex Commands

These commands were exercised with `@openai/codex` `0.128.0` on Windows.

List the two Find Evil servers without writing user-level config:

```powershell
npx -y @openai/codex mcp `
  -c "mcp_servers.findevil-mcp.command='target/release/findevil-mcp.exe'" `
  -c "mcp_servers.findevil-mcp.cwd='.'" `
  -c "mcp_servers.findevil-agent-mcp.command='uv'" `
  -c "mcp_servers.findevil-agent-mcp.args=['run','--directory','services/agent_mcp','python','-m','findevil_agent_mcp.server']" `
  -c "mcp_servers.findevil-agent-mcp.cwd='.'" `
  list
```

Run a constrained non-interactive EVTX MCP test:

```powershell
npx -y @openai/codex exec `
  --ignore-user-config `
  --ephemeral `
  --dangerously-bypass-approvals-and-sandbox `
  --disable shell_tool `
  -C "." `
  -c "mcp_servers.findevil-mcp.command='target/release/findevil-mcp.exe'" `
  -c "mcp_servers.findevil-mcp.cwd='.'" `
  -c "mcp_servers.findevil-mcp.required=true" `
  -c "mcp_servers.findevil-mcp.enabled_tools=['case_open','evtx_query']" `
  -c "mcp_servers.findevil-mcp.startup_timeout_sec=30" `
  -c "mcp_servers.findevil-mcp.tool_timeout_sec=120" `
  "Use the configured Find Evil MCP tools, not shell commands. Investigate fixtures/single-evtx/Security.evtx narrowly: call case_open on that EVTX file, then call evtx_query with limit 25. Return the tool names, case_id, image_hash prefix, row_count, records_seen, parse_errors, whether any finding-worthy event was observed, and a provisional verdict. Do not edit files. Do not describe limited coverage as clean, cleared, disproven, or absence of evil."
```

The bypass flag is only for non-interactive MCP smoke testing. Keep the command constrained with all of these safeguards:

- `--ignore-user-config`
- `--ephemeral`
- `--disable shell_tool`
- `enabled_tools = ["case_open", "evtx_query"]`
- a prompt that forbids edits and shell commands

For normal interactive Codex use, prefer the TUI and approve MCP calls manually instead of using the bypass flag.

## Web Cockpit

The Next.js dashboard includes a Codex operator page at `/codex`.

```bash
pnpm --filter @findevil/web dev
```

Open:

```text
http://localhost:3000/codex
```

Codex skill shortcut:

```text
dashboard
```

Codex's built-in slash commands are fixed, so use the manual dashboard launcher when you want the local cockpit:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/codex-dashboard.ps1
```

The page provides:

- suggested Find Evil investigation prompts
- evidence/run path input
- a generated guarded Codex prompt for the TUI/dashboard
- a `codex://new` deeplink for the Codex desktop app
- an optional local one-shot `codex exec` chat runner

The browser page cannot send messages into an already-running Codex CLI TUI. For the CLI TUI, copy the generated prompt and paste it into the terminal. For the Codex desktop app, use the `codex://new` deeplink button. For browser-contained output, use the separate one-shot runner.

The runner is disabled by default. To enable it for local testing:

```bash
FINDEVIL_CODEX_UI_ENABLE=1 pnpm --filter @findevil/web dev
```

The server route remains constrained:

- it uses `--ignore-user-config`
- it uses `--ephemeral`
- it disables Codex's shell tool
- it allowlists MCP tools per investigation mode
- it accepts paths only under documented evidence/output roots unless `FINDEVIL_CODEX_EXTRA_ROOTS` is set

Use the Codex TUI's built-in dashboard for normal interactive operation. The web cockpit is a prompt and one-shot investigation wrapper, not a replacement for either the product's general Claude Code/default judge-demo paths or the beta-native Phase 4 acceptance runtime.

## Investigation Prompt

Once Codex has the two product MCP servers available, use the same operator prompt as Claude Code:

```text
investigate <case path>
```

The resulting Findings must still cite `tool_call_id`, execution claims still require two artifact classes, and the final manifest must verify offline.

Do not call limited output clean, cleared, disproven, or proof of absence. Say `NO_EVIL` only when the verdict policy supports it, and describe the exact evidence scope reviewed.

## Compatibility Boundary

Codex support is best-effort until exercised end-to-end in the target Codex runtime. Treat Claude Code as the reference interactive interface and default `scripts/verdict` as the general one-shot judge/demo path. Codex is not a substitute for strict Phase 4 acceptance through the beta-native `--agent` loop.
