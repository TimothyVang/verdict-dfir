# Agent Containment

How Claude Code (and Codex) are confined to this project folder: they may read
and write **inside** the repo, but are blocked from writing outside it, reading
your secrets, or reaching the network with built-in tools. This ships with the
repo, so anyone who installs it gets the same rules.

## What is enforced

| Rule | Mechanism | Where |
|------|-----------|-------|
| `Write`/`Edit` cannot target a path outside the project | `scripts/hooks/guard-outside-project.py` (PreToolUse hook; resolves symlinks) | shared |
| New stray files cannot land at the repo root | `scripts/hooks/guard-root-writes.py` (PreToolUse hook) | shared |
| `Read` cannot open secrets (`~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.config/gh`, `~/.netrc`, `~/.claude/.credentials.json`) | `guard-outside-project.py` hook | shared |

**No tools are blocked.** Every tool is enabled — `WebFetch`, `WebSearch`,
`curl`/`wget`, and all the rest — so research and normal work are unimpeded.
Containment is done by **scoping where files land**, not by disabling tools.

The shared rules live in **`.claude/settings.json`** (committed). Machine-specific
settings — absolute-path env, personal allow-list, MCP enablement — live in
**`.claude/settings.local.json`** (gitignored, never shipped).

## What is deliberately NOT enforced

Be clear-eyed about the boundary:

- **Reads outside the repo are allowed** (except the secret paths above). This is
  intentional: the forensic and toolchain binaries the agent runs — `uv`, `vol`,
  `hayabusa`, `node`, `log2timeline.py` — live under `~` and `/usr`. Blocking
  those reads would break the product.
- **Bash is NOT confined to the folder.** No tools are denied and no OS sandbox is
  enabled (both by choice — tool denials and the `bubblewrap` sandbox were judged
  too disruptive for DFIR work). So a `Bash` command can still write or send data
  outside the project. The folder boundary is enforced for Claude's **built-in
  file tools only** (`Write`/`Edit` via `guard-outside-project.py`); it does **not**
  cover arbitrary shell commands. If you later want Bash itself sealed to the
  folder, the only reliable way is Claude Code's `bubblewrap` sandbox
  (`sandbox.enabled` + `socat`) — that was explicitly deferred.

So, precisely: **`Write`/`Edit` cannot escape the project; `Read` cannot touch
secrets; everything else (Bash, network, reads of system/toolchain paths) is
allowed and not folder-confined.**

## Portability — run it anywhere, contained to this folder

Everything that confines the project derives the project root from its own file
location at runtime, so it works from any CWD and after the folder is moved:
`scripts/lib/project-env.sh`, the `scripts/run-mcp-*.sh` launchers, `scripts/verdict`,
and the `scripts/hooks/*.py` guards (which Claude Code invokes via
`$CLAUDE_PROJECT_DIR`). You can invoke any of them by absolute path from anywhere —
they target this folder and save into it.

The one piece that cannot self-derive is Claude Code's `env` block in
`.claude/settings.local.json`: Claude Code does **not** expand variables there, so the
values must be absolute. To keep that portable, `scripts/setup-containment.sh`
regenerates the block from `project-env.sh` for wherever the folder currently lives:

```bash
bash scripts/setup-containment.sh   # after a clone or a move
```

It is path-agnostic, clears any inherited env first (so it always re-roots to its own
location), and writes only inside the project. `scripts/setup` runs it automatically,
so a fresh clone is configured on first setup. Restart Claude Code afterward to load
the regenerated env.

## Precedence and override

Claude Code merges settings in order (later = higher priority): user
(`~/.claude/settings.json`) < project shared (`.claude/settings.json`) < project
local (`.claude/settings.local.json`) < managed (`/etc/claude-code/managed-settings.json`).
A `deny` at any level blocks outright. Because the shared rules are operator-local
overridable, they are a guardrail, not a lockdown. For rules that cannot be turned
off, move the `permissions.deny` block into a managed-settings file (needs root).

## Notes

- The PreToolUse hooks auto-run `scripts/hooks/*.py` for everyone who opens this
  repo in Claude Code. They are in-repo, reviewable, and only guard paths.
- Changes to `.claude/settings.json` take effect on the next Claude Code restart
  (settings load at session start).
- Related: `docs/repo-layout.md` (where files live + the `.project-local/`
  runtime containment).
