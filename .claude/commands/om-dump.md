---
description: "Capture a durable fact into the obsidian-mind memory vault from the repo root. Routes to the right brain/ or work/ note with frontmatter + wikilinks, then reindexes QMD."
---

Capture the following into the VERDICT memory vault at `obsidian-mind/` — the dev/operator memory
layer (never evidence, never in a case audit chain, never a Finding). For each distinct piece:

1. **Classify**: gotcha, pattern, architecture/amendment decision, project update, or general work note.
2. **Search first**: call `mcp__qmd__query` (or `qmd --index verdict-memory search "..."` run from
   `obsidian-mind/`) to find an existing note; prefer appending over creating a new one.
3. **Write** to the right note under the vault (kept structure only — there is no perf/org/1-1):
   - Environment/dashboard/engine/SIFT/n8n traps + Tier-1 DFIR caveats → `obsidian-mind/brain/Gotchas.md`
   - Recurring investigation/build tradecraft → `obsidian-mind/brain/Patterns.md`
   - Architecture / amendment / invariant decisions → `obsidian-mind/brain/Key Decisions.md`
   - In-flight project work → `obsidian-mind/work/active/<title>.md`
   - Codebase/architecture reference → `obsidian-mind/reference/<title>.md`
   Use YAML frontmatter (`date`, `description` ~150 chars, `tags`) and at least one `[[wikilink]]`.
4. **Index**: update `obsidian-mind/brain/Memories.md` if a new topic note was created.
5. **Reindex** (skip if the PostToolUse hook is enabled — it auto-reindexes):
   `cd obsidian-mind && node --experimental-strip-types scripts/qmd-bootstrap.ts` (Node 22).

Report what was captured and where. Boundary: never run repo investigation tools "to remember" —
memory and evidence stay separate.

Content to capture:
$ARGUMENTS
