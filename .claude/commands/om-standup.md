---
description: "Morning kickoff from the repo root — load VERDICT memory context (North Star, brain topics, active work, recent git), surface priorities."
---

Run the standup against the obsidian-mind memory vault at `obsidian-mind/`:

1. Read `obsidian-mind/brain/North Star.md` — current goals + the memory boundary.
2. Scan `obsidian-mind/brain/Memories.md` — the topic index; query `mcp__qmd__query` (or
   `qmd --index verdict-memory search "..."` from `obsidian-mind/`) for anything relevant to today.
3. Check `obsidian-mind/work/Index.md` and `obsidian-mind/work/active/` for in-flight work.
4. Recent repo activity: `git log --oneline --since="24 hours ago" --no-merges`.

Present a concise standup:
- **Yesterday** — what got done (git log + any work/active notes)
- **Active work** — current `work/active/` items
- **North Star alignment** — how active work maps to the goals
- **Top gotchas/decisions on deck** — pulled from `brain/` via QMD
- **Suggested focus** — what to prioritize today

Keep it concise — a quick orientation, not a deep dive. This reads memory only; it never touches
evidence or a case audit chain.
