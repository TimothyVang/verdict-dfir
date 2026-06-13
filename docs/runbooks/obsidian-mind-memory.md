# obsidian-mind — the VERDICT memory layer

> **Status: ACTIVE.** How the `obsidian-mind/` vault works as VERDICT's dev/operator memory,
> how it's wired in, and the hard boundary it must keep. Optional, like
> [n8n](n8n-automation-integration.md) — never part
> of the DFIR product or the audit chain.

## What it is

`obsidian-mind/` (MIT, separate git repo, gitignored from this tree) is an Obsidian-vault memory
system for coding agents: markdown notes with YAML frontmatter and `[[wikilinks]]`, semantic
search via **QMD**, lifecycle hooks, ~18 `/om-*` curation commands, and 9 subagents. We use it as
the **primary project/operator memory** — DFIR tradecraft, architecture decisions, gotchas — that
accumulates across sessions. It is the better successor to the flat `~/.claude/.../memory/` index
(semantic recall, a knowledge graph, git durability, low token cost), but it does **not** replace
`CLAUDE.md` (the instruction core) or the in-flow Hermes memory.

The VERDICT-specific content lives in `obsidian-mind/brain/` (`North Star`, `Key Decisions`,
`Gotchas`, `Patterns`, `Skills`, `Memories`) and `obsidian-mind/reference/`.

## The hard boundary (non-negotiable)

The vault is **never evidence, never in a case `audit.jsonl`/`run.manifest.json`, never
Merkle-hashed, and never emits a Finding.** It never produces a `tool_call_id` and never changes a
Finding's Confidence or the Verdict. This is the same boundary the n8n grounding
sidecars keep. The only **in-flow** memory is the audit-chained Hermes FTS5 pair
(`memory_remember`/`memory_recall`) — a different system; see
[`../reference/mcp-and-tools.md`](../reference/mcp-and-tools.md).

## The two memory systems, side by side

| System | Where | Scope | In audit chain? |
|---|---|---|---|
| **obsidian-mind** (this) | `obsidian-mind/` vault, QMD store in `~/.cache/qmd/verdict-memory.sqlite` | dev/operator project knowledge | **No** |
| **Hermes FTS5** | `memory_remember`/`memory_recall` tools, `~/.local/state/findevil/…` | in-flow cross-case investigation memory | **Yes** |

## Install (one-time)

The memory layer needs **Node 22+** (the hook scripts use `--experimental-strip-types`) and
**QMD** (~1.6 GB embedding/rerank models). The product/dashboard stay on Node 20 — install Node 22
side-by-side via nvm.

```bash
# 1. Node 22 (side-by-side; repo default stays Node 20)
source ~/.nvm/nvm.sh && nvm install 22

# 2. QMD (global, under Node 22)
nvm use 22 && npm install -g @tobilu/qmd

# 3. Build the semantic index over the vault (downloads models on first run)
cd obsidian-mind && node --experimental-strip-types scripts/qmd-bootstrap.ts
#    -> QMD index 'verdict-memory' ready  (store: ~/.cache/qmd/verdict-memory.sqlite)
```

**Fallback (no Node 22 / no models):** the vault still works as a plain git-tracked markdown
memory — recall via `grep`/Obsidian-CLI instead of QMD, and skip the MCP/hook steps below. You
lose semantic search but keep durability, structure, and human-readability.

## QMD recall — shipped in `.mcp.json` (works from a fresh clone)

`qmd` is the **6th MCP server** in the committed `.mcp.json`, launched by the machine-independent
`scripts/run-mcp-qmd.sh` (it resolves Node 22 via nvm and runs the vault's `qmd-mcp.mjs` scoped to
the `verdict-memory` index). So once a clone has run the install steps above, the next `claude`
session exposes `mcp__qmd__query` / `get` / `multi_get` / `status` — no per-machine
`claude mcp add` needed. Verify: `claude mcp get qmd` → `Project config (shared via .mcp.json)` +
`✓ Connected`.

The launcher is **inert without Node 22 + QMD** (it exits cleanly so the server just doesn't
start), so a judge / a fresh clone without the toolchain is unaffected — `qmd` is dev/operator
memory, never in the audit chain. (Implementation note: `@tobilu/qmd`'s `exports` field only
exposes `.`, so the wrapper falls back to the `qmd` shim, which is why the launcher puts the
Node-22 bin on `PATH`.)

## Recall + curation flow — wired into the repo (no folder switching)

The memory layer is integrated into the **main repo** `.claude/`, so a single `claude` in the repo
root gives you the whole loop:

- **Recall (automatic).** `mcp__qmd__query` (index `verdict-memory`) is available, and CLAUDE.md
  `CLAUDE.md` "Non-Negotiable Guardrails" keeps memory outside evidence and the audit chain. Fallback:
  `qmd --index verdict-memory query "<topic>"` from `obsidian-mind/`.
- **Context injection (automatic, dev sessions only).** The repo SessionStart hook runs
  `scripts/obsidian-mind-hook.sh session-start`, injecting the North Star + brain-topic index. It
  is **gated OFF during `scripts/verdict` investigations** (`FIND_EVIL_LOCAL`) and inert without
  Node 22 — so a judge's run is never polluted.
- **Curate from the repo root.** `/om-standup`, `/om-dump`, `/om-wrap-up`, `/om-weekly` are repo
  slash commands (`.claude/commands/`) that operate on `obsidian-mind/…` paths. `/om-dump <fact>`
  captures into the right `brain/`/`work/` note.
- **Auto-reindex (automatic, vault-scoped).** The repo PostToolUse hook reindexes QMD when a file
  **under `obsidian-mind/`** is written, and no-ops on normal Rust/Python/docs edits.
- **Deeper curation** (the full vault hook set + the 4 subagents) still lives in the vault's own
  `.claude/` for `cd obsidian-mind && claude` sessions; the repo wiring covers the daily loop.

The hooks **inject context and reindex only — they never write to a case audit chain or touch
evidence**, so the M2 "no second unverified trail" stance holds, and the SessionStart investigation
gate keeps dev memory out of `scripts/verdict` runs.

### Enabling / disabling

The hooks live in `.claude/settings.json` (committed). The guard `scripts/obsidian-mind-hook.sh` is
the safety rail — **inert without Node 22 + QMD** (so a fresh clone / a judge is unaffected),
**vault-scoped** for writes, **investigation-gated** for SessionStart, and it never blocks a tool
call. To force the memory layer off for a session, set `FINDEVIL_NO_MEMORY_HOOK=1`.

## Verify

```bash
claude mcp get qmd                                   # ✓ Connected
cd obsidian-mind && qmd --index verdict-memory query "dashboard port 3100"   # returns the Gotchas note
# guard is vault-scoped + inert:
printf '%s' '{"tool_input":{"file_path":"'"$PWD"'/docs/README.md"}}' | bash scripts/obsidian-mind-hook.sh validate-write.ts; echo "repo edit exit=$? (no-op)"
```

No obsidian-mind write should ever appear in any case `audit.jsonl`. If it does, the boundary is
broken — stop and fix.
