---
description: "Weekly synthesis over the obsidian-mind memory vault — cross-session patterns, North Star alignment, knowledge that should be promoted into brain/."
---

Synthesize the week against the obsidian-mind memory vault at `obsidian-mind/`:

1. Review recent repo activity: `git log --oneline --since="7 days ago" --no-merges`.
2. Scan `obsidian-mind/brain/Memories.md` Recent context + recent `work/active/` notes; query
   `mcp__qmd__query` for recurring themes.
3. Identify:
   - Recurring gotchas/patterns that should be promoted into `obsidian-mind/brain/Gotchas.md` / `Patterns.md`.
   - Decisions worth recording in `obsidian-mind/brain/Key Decisions.md`.
   - Drift from `obsidian-mind/brain/North Star.md` (suggest an update if goals shifted).
4. Promote the durable findings into the right `brain/` notes (frontmatter + `[[wikilinks]]`),
   update `Memories.md`, and reindex (`cd obsidian-mind && node --experimental-strip-types scripts/qmd-bootstrap.ts`).

Report the synthesis + what was promoted. Memory only — never touches evidence or a case audit chain.
