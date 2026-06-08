# obsidian-mind — the VERDICT memory layer

> **Status: ACTIVE.** How the `obsidian-mind/` vault works as VERDICT's dev/operator memory,
> how it's wired in, and the hard boundary it must keep. Optional, like
> [Engram](engram-memory-integration.md) and [n8n](n8n-automation-integration.md) — never part
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
Finding's Confidence or the Verdict. This is the same boundary Engram and the n8n grounding
sidecars keep. The only **in-flow** memory is the audit-chained Hermes FTS5 pair
(`memory_remember`/`memory_recall`) — a different system; see
[`../reference/mcp-and-tools.md`](../reference/mcp-and-tools.md).

## The three memory systems, side by side

| System | Where | Scope | In audit chain? |
|---|---|---|---|
| **obsidian-mind** (this) | `obsidian-mind/` vault, QMD store in `~/.cache/qmd/verdict-memory.sqlite` | dev/operator project knowledge | **No** |
| **Hermes FTS5** | `memory_remember`/`memory_recall` tools, `~/.local/state/findevil/…` | in-flow cross-case investigation memory | **Yes** |
| **Engram** (optional) | `engram-vang/`, `~/.engram/` | operator knowledge base | No |

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

## Wire QMD recall into the main repo session

Registered at **local scope** so the committed `.mcp.json` stays at its clean five product/operator
servers (the QMD server is machine-specific and dev-only):

```bash
NODE22="$(nvm which 22)"; GLOBNM="$(dirname "$NODE22")/../lib/node_modules"
claude mcp add -s local qmd \
  -e NODE_PATH="$GLOBNM" \
  -e PATH="$(dirname "$NODE22"):/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
  -- "$NODE22" "$PWD/obsidian-mind/.claude/scripts/qmd-mcp.mjs"
claude mcp get qmd      # expect: ✓ Connected
```

The `PATH` entry matters: `@tobilu/qmd`'s `exports` field only exposes `.`, so the wrapper's
subpath resolve fails and it falls back to the `qmd` shim — which must be on PATH (the Node-22
bin dir). After this, a new session exposes `mcp__qmd__query` / `mcp__qmd__get` /
`mcp__qmd__multi_get` / `mcp__qmd__status`, scoped to the `verdict-memory` index.

## Recall + curation flow

- **Recall (any repo session):** call `mcp__qmd__query` before answering a question that touches a
  brain topic (Gotchas, Patterns, Key Decisions, Skills). Fall back to
  `qmd --index verdict-memory query "<topic>"` or `grep` if the MCP isn't loaded.
- **Curate (vault session):** `cd obsidian-mind && claude`, then `/om-standup` (load context),
  `/om-dump` (capture + auto-route), `/om-wrap-up` (review + reindex). The vault's **own**
  `.claude/settings.json` runs the full 5-hook lifecycle set (SessionStart / UserPromptSubmit /
  PostToolUse / PreCompact / Stop) plus the 9 subagents — these run **here**, not in the main repo
  session, deliberately (see below). After curating, the QMD index updates automatically.
- **Write a memory:** add it to the right `brain/` note with a `[[wikilink]]` to context, then
  update `brain/Memories.md` if a new topic was created. Never run repo investigation tools "to
  remember" — memory and evidence are separate.

## Why the lifecycle hooks run in vault sessions, not the repo session

Two deliberate reasons the full obsidian-mind hook set is scoped to vault-native sessions and
**not** added to the repo's startup config:

1. **No dev memory in a judge's investigation.** The SessionStart context-injection hook would
   push vault notes into every `claude`/`scripts/verdict` session — including a judge's. The repo
   SessionStart stays focused on the evidence-suggestion block (`scripts/session-suggest.sh`).
2. **No second audit trail.** The repo's `.claude/settings.json` deliberately avoids Stop hooks
   so nothing writes a parallel, unverified trail beside the M2 hash-chained `audit.jsonl`. The
   vault's Stop hook only nudges a checklist (writes nothing to the audit chain), but keeping it
   vault-scoped preserves that stance cleanly.

### Optional: vault-scoped reindex in the main session

If you want vault notes you edit *from the main repo session* to reindex automatically, add this
to `.claude/settings.local.json` yourself (Claude Code's auto-mode classifier blocks the agent
from editing its own hook config — this is an intentional self-modification guardrail, so it is a
manual step):

```json
"hooks": {
  "PostToolUse": [
    { "matcher": "Write|Edit", "hooks": [
      { "type": "command", "command": "bash scripts/obsidian-mind-hook.sh validate-write.ts", "timeout": 20 },
      { "type": "command", "command": "bash scripts/obsidian-mind-hook.sh qmd-refresh.ts", "timeout": 20 }
    ]}
  ]
}
```

`scripts/obsidian-mind-hook.sh` is the safety rail: it is **inert** without the Node-22 memory
layer (exits 0) and **vault-scoped** — it runs the vault hook ONLY when the edited file is under
`obsidian-mind/`, so it never validates or blocks normal Rust/Python/docs edits in the repo.

## Verify

```bash
claude mcp get qmd                                   # ✓ Connected
cd obsidian-mind && qmd --index verdict-memory query "dashboard port 3100"   # returns the Gotchas note
# guard is vault-scoped + inert:
printf '%s' '{"tool_input":{"file_path":"'"$PWD"'/docs/README.md"}}' | bash scripts/obsidian-mind-hook.sh validate-write.ts; echo "repo edit exit=$? (no-op)"
```

No obsidian-mind write should ever appear in any case `audit.jsonl`. If it does, the boundary is
broken — stop and fix.
