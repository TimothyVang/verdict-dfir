# `@findevil/web` — Find Evil! NES.css live dashboard

**Status:** Active local dashboard. `/` renders the SSE audit-tail role-state grid, `/debug` shows raw audit events, and `/codex` provides the Codex operator cockpit plus an opt-in local one-shot runner. Remaining A3 polish is the pixel-art sprite swap and the AuditBeadString + HashChainBadge + FindingChip chrome.

The dashboard is an operator aid only. It tails local case output and never creates Findings or evidence.

## Run locally

```bash
pnpm install --frozen-lockfile
pnpm --filter @findevil/web dev
# open http://localhost:3000
```

The Codex operator wrapper lives at:

```text
http://localhost:3000/codex
```

The page is useful in two modes:

- Prompt cockpit: always available. Pick a suggested investigation, copy the guarded prompt, and paste it into the Codex TUI/dashboard.
- Local one-shot runner: disabled by default. Set `FINDEVIL_CODEX_UI_ENABLE=1` before starting the dashboard to let `/api/codex` launch constrained `codex exec` runs.

The browser dashboard cannot send text into an already-running Codex CLI TUI session; Codex does not expose a live TUI input API. Use **Copy TUI prompt** for the terminal, **Open Codex app** for a `codex://new` deeplink, or **Run in chat** for a separate one-shot `codex exec` run.

Example local runner startup:

```bash
FINDEVIL_CODEX_UI_ENABLE=1 pnpm --filter @findevil/web dev
```

On Windows PowerShell:

```powershell
$env:FINDEVIL_CODEX_UI_ENABLE = "1"
pnpm --filter @findevil/web dev
```

Codex users can also invoke the repo skill named `dashboard` from the Codex TUI. It starts the local dev server, so it does not require a prior Next.js production build. It uses:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/codex-dashboard.ps1
```

The runner is intentionally narrow: it uses `--ignore-user-config`, `--ephemeral`, disables Codex's shell tool, and passes per-mode MCP `enabled_tools` allow-lists. It still uses Codex's non-interactive bypass flag because current `codex exec` auto-cancels MCP calls otherwise; keep this route local and disabled unless you are actively testing it.

The build:

```bash
pnpm --filter @findevil/web build
```

## Stack

| Layer | Pick | Why |
|---|---|---|
| Framework | Next.js 15 (App Router) | Spec #2 §6 + Amendment A3 |
| UI library | React 19 | Next 15's default |
| CSS | Tailwind v4 (CSS-first config via `@import "tailwindcss"` + `@theme`) | Cleaner than v3's config.js for this scope |
| Component library | nes.css ~2.3 (8-bit / NES-style) | Amendment A3 §1.2 aesthetic |
| TypeScript | 5.7+ strict | Project default |

## Why no `tailwind.config.ts`

Tailwind v4 moves config from JS to CSS — the `@theme` block in `app/globals.css` (added in Phase 5/6) is the equivalent. A `tailwind.config.ts` shim is only needed if you wire in JS plugins or do programmatic theme generation, neither of which we do.

## Path allow-list for `/api/audit`

The SSE tail at `GET /api/audit?case=<dir>` (`app/api/audit/route.ts`) validates `<dir>` against an allow-list in `lib/audit-tail.ts` (`isAllowedCasePath`) before opening any file handle. A path outside the allow-list returns `400` with a JSON body `{ error: "case path not in allow-list", reason: "..." }` and is never read.

Default allow-listed roots (resolved against `process.cwd()`, which for the dashboard is the repo root):

- `goldens/` — committed L3 test fixtures
- `tmp/auto-runs/` — `scripts/verdict` / internal automation-engine run output
- `tmp/smoke/` — synthetic smoke output
- `test-forensics/` — operator's local DFIR corpus (gitignored)

To add roots without code changes, set the `FINDEVIL_DASHBOARD_EXTRA_ROOTS` env var. It uses the platform path delimiter (`:` on POSIX, `;` on Windows — i.e. `path.delimiter`):

```bash
# POSIX
FINDEVIL_DASHBOARD_EXTRA_ROOTS="/srv/evidence:/mnt/dfir-share" pnpm --filter @findevil/web dev

# Windows
set FINDEVIL_DASHBOARD_EXTRA_ROOTS=D:\evidence;E:\dfir-share
pnpm --filter @findevil/web dev
```

The allow-list closes the path-traversal hole flagged in PR #7's `route.ts` comment — a malicious browser tab pointed at the dashboard URL can no longer trick the route into reading arbitrary filesystem paths.

## Path allow-list for `/api/codex`

The Codex wrapper accepts evidence or run paths only under these repo-relative roots:

- `fixtures/`
- `goldens/`
- `tmp/auto-runs/`
- `tmp/smoke/`
- `test-forensics/`

To add local roots without code changes, set `FINDEVIL_CODEX_EXTRA_ROOTS` using the platform path delimiter. The route passes paths to Codex as prompt text only; the actual evidence read still happens through the typed Find Evil MCP tools.
