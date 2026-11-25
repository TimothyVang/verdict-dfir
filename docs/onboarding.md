# Onboarding — first contact with VERDICT

Referenced by `scripts/setup` (the shell hands gated, browser-only assets to the
Claude Code path). Read this when a session opens in this repo and the user's first
message is `setup`, `i'm new`, `help`, `hello`, or "what can you do / how do I use
this", **or** a preflight check fails. It documents the behavioral/UX flow only — the
mechanics live in `README.md`, `INSTALL.md`, `QUICKSTART.md`, and
`docs/using/running-verdict.md`; do not duplicate those here.

---

## Greeting (first-contact triggers only)

When the first message is `help` / `hello` / `hi` / "what can you do" / "what is
this", greet briefly:

> **VERDICT — a DFIR agent that runs inside Claude Code.** Point it at evidence and it
> opens a Case, drives typed read-only forensic tools, verifies every Finding, and
> writes a signed Verdict + report. Two ways to run:
> 1. **Hands-free:** `scripts/verdict <path-to-evidence>` (or `scripts/verdict --watch`, then drop a file into the evidence drop-zone).
> 2. **Interactive:** type `investigate <path-to-evidence>` or `/verdict <path>`.
>
> Type `help` for the command list, or `investigate <path>` to start.

Show this only on the triggers above — not on every session start.

## Preflight (run once per session, before the first tool call)

Verify the runtime surface; print a one-line summary and offer to fix failures. The
canonical check is `bash scripts/doctor.sh` (`--json` for machine-readable):

| Item | Check | Fix |
|---|---|---|
| Claude credential | `CLAUDE_CODE_OAUTH_TOKEN` / logged-in `claude` / `ANTHROPIC_API_KEY` | `claude setup-token` or `claude auth login` |
| Rust/Cargo | `cargo --version` (pinned by `rust-toolchain.toml`) | rustup |
| Python + uv | `uv --version`, Python 3.11–3.12 | `pip install uv` |
| MCP server binary | `target/release/findevil-mcp` present | `bash scripts/setup` (builds it) |
| `git`, `unzip` | present | system package manager |
| Node 20 + pnpm | only for the live dashboard | `npm install -g pnpm` |

Block only on a missing Claude credential plus at least one of Rust/Python; note
optional gaps (Node/pnpm only matter for the dashboard) and continue.

## Fresh clone / first-run setup

- **Fresh clone** (`target/release/findevil-mcp` absent): run `bash scripts/setup`. It
  installs/checks prerequisites, builds the Rust MCP server, syncs the Python MCP env,
  installs supported helper tooling, and runs the preflight doctor. On failure, report
  the exact error and stop — never work around a broken environment silently.
- **`setup` / `i'm new`:** run `bash scripts/setup`, then complete any browser-only
  gated step the shell could not. The only gated asset is the **SANS SIFT OVA**, and it
  is needed **only** for `--sift`/disk-image parity; local mode is the default and needs
  no gated asset. Do not auto-fetch it unless the user wants SIFT mode. When fetching is
  needed, drive the registered browser MCP (Playwright/Puppeteer) — never invent or store
  SANS credentials.

## Opening links

A browser MCP is registered. Offer to open relevant URLs rather than only printing them:
the live dashboard, a generated `REPORT.html`, or a docs/GitHub page. Auto-open the
dashboard once its dev server is listening.

## Quick reference (print on `help`)

```
VERDICT — Quick Reference
─────────────────────────────────────────────────────
scripts/verdict <path>            Run a full DFIR investigation against evidence
scripts/verdict --sift <path>     Run the DFIR tools inside the SANS SIFT VM
scripts/verdict --watch           Drop a file into the evidence dir and auto-run
scripts/verdict <case-root> --fleet   Whole multi-host case (hosts/ and/or disks/)
investigate <path>  /  /verdict <path>   Interactive entry points
bash scripts/setup                Install/check prerequisites, build, preflight
bash scripts/doctor.sh [--json]   Preflight only

Credential modes (priority order):
  1. CLAUDE_CODE_OAUTH_TOKEN   (claude setup-token)
  2. logged-in `claude`        (claude auth login)
  3. ANTHROPIC_API_KEY

Verdict words (full semantics: docs/verdict-semantics.md):
  SUSPICIOUS      reportable evidence found
  INDETERMINATE   leads / limited coverage — not a scoped clearance
  NO_EVIL         no reportable Finding in what was actually examined (never whole-environment clean)

Docs: README.md · INSTALL.md · QUICKSTART.md · docs/using/running-verdict.md
      docs/verdict-semantics.md · docs/false-positives.md · docs/architecture.md
─────────────────────────────────────────────────────
```

A run is complete only when the pipeline reaches `case_open`, every Finding cites a
`tool_call_id`, `report_qa` is audited, and `manifest_verify.json` reports `overall: true`.
If that file is missing or `overall` is not `true`, report `RUN INCOMPLETE / CUSTODY
INVALID` — do not call the output signed or customer-ready.
