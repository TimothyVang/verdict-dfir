---
description: "End-of-session review from the repo root — capture durable learnings into the obsidian-mind vault, verify notes/links, reindex. Auto-invoke when the user says 'wrap up'."
---

Full session review before ending. Invoke automatically when the user says "wrap up", "let's wrap",
or similar. This is a READ + CAPTURE pass over the obsidian-mind memory vault at `obsidian-mind/`.

1. **Review** the session for durable knowledge worth remembering: new gotchas, patterns,
   decisions, or project progress.
2. **Capture** each into the right vault note (kept structure only):
   - `obsidian-mind/brain/Gotchas.md` · `Patterns.md` · `Key Decisions.md`
   - `obsidian-mind/work/active/<title>.md` for in-flight work; `obsidian-mind/reference/` for codebase knowledge
   Full frontmatter (`date`, `description`, `tags`) + at least one `[[wikilink]]`. Prefer appending
   to existing notes (search via `mcp__qmd__query` first).
3. **Update indexes**: `obsidian-mind/brain/Memories.md` (Recent context) and
   `obsidian-mind/work/Index.md` if new notes were created.
4. **Verify**: every new note has frontmatter + at least one link; no orphans.
5. **Reindex** (skip if the PostToolUse hook is enabled):
   `cd obsidian-mind && node --experimental-strip-types scripts/qmd-bootstrap.ts`.

Report: **Done** (captured), **Fixed** (small issues), **Flagged** (needs your input). Boundary:
memory only — never write evidence or a case audit chain; never run investigation tools "to remember".
