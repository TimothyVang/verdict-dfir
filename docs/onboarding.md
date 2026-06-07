# Session-Start Onboarding (VERDICT)

This doc holds the verbatim onboarding behavior referenced by `CLAUDE.md` §0. Read it when
a session triggers onboarding: the user's first message is `help`, `hello`, `hi`, or they
ask "what can you do" / "how do I use this" / "what is this", **or** a preflight check fails.

---

## Greeting (show on first-contact triggers only)

When a user opens Claude Code in this repo for the first time and their first message is one
of the triggers above, greet them with:

> **Welcome to VERDICT — DFIR at machine speed.**
>
> You can do two things here:
>
> 1. **Investigate evidence** — paste a path to your evidence file and say `investigate <path>`. Example: `investigate /cases/nist-hacking-case.E01`
>    VERDICT will open the case, fork two analysis pools, run DFIR tools, and produce a sigstore-signed report. Or run it hands-free: `scripts/verdict <path>` (or `scripts/verdict --watch` and drop a file into `evidence/`).
>
> 2. **Develop the tool** — ask me to read/write code, fix bugs, or run a live test (the demo video has its own pipeline).
>
> Type `help` at any time for a list of commands, or `investigate <path>` to start an investigation.

Do not show this greeting on every session start — only on the triggers above.

---

## Pre-flight checklist (run ONCE per session, silently, before the first tool call)

Check each item. For any failure, print a clear one-line message and offer to fix it
automatically or provide the exact install command.

```
ITEM                    CHECK                                    AUTO-FIX OFFER
────────────────────────────────────────────────────────────────────────────────
claude CLI              which claude                             "Run: claude auth login"
Rust toolchain          cargo --version                          "Run: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
uv (Python env)         uv --version                             "Run: pip install uv"
Node 20+                node --version (must be ≥20)             "Run: nvm install 20 && nvm use 20" or offer to open nodejs.org
pnpm                    pnpm --version                           "Run: npm install -g pnpm"
MCP server binary       ls target/release/          "Run: cargo build --workspace --release --locked"
Python agent-mcp env    uv sync --directory services/agent_mcp   (run it automatically with permission)
edge-tts (optional)     python3 -c "import edge_tts"             "Run: pip install edge-tts  (only needed for demo video)"
```

After checks, print a one-line summary:
- All green: `[preflight] All dependencies present. Ready.`
- Any red: list what is missing and offer to install/fix before proceeding.

**Do not block the user.** If a check fails for a non-critical dep (edge-tts), note it and
continue. Only block on `claude CLI` and at least one of Rust OR Python being missing.

---

## Chrome DevTools — open links for the user

A Chrome DevTools MCP server is registered globally. You CAN open URLs in the user's browser
on their behalf. **Always offer to open relevant links instead of just printing them.**

Rules:
- When you reference a local server (`http://localhost:3000`, `http://localhost:3000/debug`), offer: "Want me to open that in Chrome for you?"
- When you reference a GitHub URL, docs page, or external resource the user needs to read, offer: "Want me to open that link for you?"
- When the dashboard dev server starts (`pnpm --filter @findevil/web dev`), automatically navigate to `http://localhost:3000` once it is listening, then tell the user it's open.
- When a Remotion preview renders to `/tmp/find-evil-preview.mp4`, offer to open it.
- When an investigation completes and `REPORT.html` is generated, offer to open it in the browser.

To open a URL, use the `mcp__cloakbrowser__navigate` tool. If the browser is not connected,
tell the user: "Chrome DevTools is not connected. Start Chrome with remote debugging:
`google-chrome --remote-debugging-port=9222` then retry."

---

## First-run install helper

If `target/release/findevil-mcp` does NOT exist (i.e., fresh clone), run the install script
automatically:

```bash
bash scripts/install.sh
```

`scripts/install.sh` handles credential detection (OAuth token → interactive Claude session
→ API key), builds the Rust MCP server, syncs Python envs, and prints a checklist. If
`install.sh` fails, report the exact error line and stop — do not try to work around a broken
environment silently.

---

## First-run setup ("setup" / "i'm new")

When the user's first message is `setup`, `i'm new`, `im new`, or `new`, run the full first-run
setup, then finish any browser-only steps the shell could not.

Steps:

1. Run the orchestrator and stream its output (do not silence it):

   ```bash
   bash scripts/setup
   ```

   `scripts/setup` runs `scripts/install.sh` (toolchain + `findevil-mcp` build + agent-mcp venv
   + host DFIR tools), re-checks what is still missing, and writes a handoff at
   `tmp/setup-state.json`.

2. Read `tmp/setup-state.json`. Report the one-line status from `ready`. If `missing_required`
   is non-empty, surface each `{label, remedy}` and stop — the environment is not yet usable.
   If `missing_curl` is non-empty, offer to re-run `bash scripts/install-dfir-tools.sh`
   (non-blocking).

3. If `gated` contains an entry with `present:false`, run the browser fallback. Look it up in
   `scripts/gated-tools.json`, then:
   - Drive the Puppeteer MCP (`mcp__puppeteer__puppeteer_*`) to navigate `landing_url`. These
     tools are not pre-approved, so the user will be prompted to allow them on first use; that
     is expected. If `login_required`, use the `credentials_env` vars when present; otherwise
     pause and let the user log in in the visible browser, then continue. Never invent or store
     credentials; never log them.
   - The seeded `browser.steps` are marked NEEDS-LIVE-CONFIRMATION. On a first run, do a
     human-supervised recon pass (navigate + screenshot) to capture the real form fields, EULA
     control, and resolved `.ova` href before trusting any automated steps.
   - Complete the form/EULA, then `puppeteer_evaluate` to resolve the download URL.
   - Fetch with `curl -fL -C -` to the destination (resumable). If the URL needs the session,
     export cookies from the browser and pass via `curl --cookie`.
   - Verify (`verify.min_bytes`, reject HTML error pages, record sha256), then place as
     `sift-<version>.ova` at the repo root (or set `OVA_PATH`).
   - Re-run `bash scripts/setup` to confirm the asset is now detected.
   - On ANY failure (site changed, login wall, blocked, no file, checksum/HTML mismatch,
     offline): delete any partial file, report the exact failing step with a screenshot, and
     fall back to the registry `manual_fallback` (open the page, user downloads manually). A
     "could not fetch" must never block the rest of setup — local-host mode works without the OVA.

4. When setup is green, offer the next action: `scripts/verdict <path>` (hands-free) or
   `investigate <path>` (interactive). Offer to open the dashboard at `http://localhost:3000`
   once `pnpm --filter @findevil/web dev` is listening (see the Chrome DevTools section above).

Do not auto-fetch the SANS SIFT OVA unless the user wants SIFT/disk mode — local-host mode is
the default and needs no gated asset. A user who wants prompt-free browser runs can add the
`mcp__puppeteer__puppeteer_*` tools to `.claude/settings.local.json` themselves; note
`puppeteer_evaluate` executes arbitrary JS, so that is their explicit choice to make.

---

## Quick reference (print on `help`)

When the user types `help` (and only then), print this:

```
VERDICT — Quick Reference
─────────────────────────────────────────────────────
investigate <path>          Run a full DFIR investigation against evidence
scripts/verdict <path>           Live-test the app end-to-end on your evidence (the real check)
scripts/verdict --watch          Drop a file into evidence/ and auto-run when the copy finishes
bash scripts/run-all-smokes.sh   (optional) Local CI predictor — what L1 runs; NOT a live test
bash scripts/find-evil-auto <evidence>   Headless end-to-end run
bash scripts/make-demo-video.sh  Generate the demo video (needs edge-tts + pnpm)
pnpm --filter @findevil/web dev  Start the live audit dashboard at localhost:3000

Credential modes (in priority order):
  1. CLAUDE_CODE_OAUTH_TOKEN env var   (claude setup-token)
  2. Interactive session               (claude auth login)
  3. ANTHROPIC_API_KEY env var

Docs:
  QUICKSTART.md            — 3-step quick start
  docs/verdict-semantics.md — what SUSPICIOUS / INDETERMINATE / NO_EVIL mean
  SUBMISSION_COMPLIANCE.md — judge compliance checklist
  docs/false-positives.md  — analyst checklists
─────────────────────────────────────────────────────
```
