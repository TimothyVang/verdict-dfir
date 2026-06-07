# Runbook: Engram Memory Integration (Optional)

**Status: ACTIVE**
**Scope: optional operator tooling — not part of the Find Evil! submission surface.**

[Engram](../../engram-vang/README.md) is a standalone knowledge/memory platform that exposes
its capabilities to an LLM agent over MCP (event log → Obsidian vault → hybrid RAG). This
runbook covers wiring it in as a **third, optional MCP server** alongside Find Evil!'s two
product servers. It does **not** change the investigation flow, the typed evidence-tool
surface, or the audit/crypto chain.

---

## Integration decisions (what this runbook assumes)

| Decision | Choice | Implication |
|---|---|---|
| Role | **Standalone MCP server** | Available to the agent; **not** wired into Pool A/Pool B. The built-in A3 cross-case memory (`memory_remember` / `memory_recall`) is left untouched. |
| Submission posture | **Optional, not bundled** | Treated like the SIFT DFIR binaries (Hayabusa/Volatility): the operator wires it in; it is `.gitignore`'d and never enters the Devpost zip. |
| Where it runs | **Local host only** | `engram-mcp` and its daemons run on the host. SIFT-VM mode still reaches the DFIR tools over SSH; Engram stays local. |
| License | **Apache-2.0** (relicensed from AGPL-3.0 on 2026-06-06) | No copyleft/permissive conflict with the Apache-2.0 submission. Still kept optional/standalone per the posture above. |

---

## License & submission compliance

Engram was relicensed from **AGPL-3.0-or-later to Apache-2.0** on 2026-06-06 by its author
(`engram-vang/LICENSE`, `engram-vang/pyproject.toml`, `engram-vang/README.md`). That removes
the contamination risk the AGPL would otherwise pose to the Apache-2.0 submission
(CLAUDE.md §3: AGPL/GPL tools must be subprocess-only, never linked).

Even though the license now permits it, this integration deliberately keeps Engram **separate**:

- **Separate process, MCP stdio only.** `engram-mcp` runs as its own process; nothing in
  `services/` imports `engram`. This matches the architectural pattern for every external
  tool (DFIR binaries are subprocess-only too).
- **Not bundled.** `engram-vang/` and `Rocba-Memory.zip` are `.gitignore`'d. The Devpost zip
  (`scripts/package-devpost.sh`) does not include them. Engram has its own git repo and
  release lifecycle.
- **Not in the judge-facing required docs.** `docs/architecture.md` (Devpost Required
  Component #3) intentionally does **not** mention Engram — the submission surface is the
  31-tool typed product, and adding optional operator tooling there would muddy the
  "narrow surface" story. This runbook is the canonical home for Engram integration.

---

## Boundaries (DFIR integrity — do not cross)

These keep Engram from polluting the investigation's evidentiary guarantees:

1. **Engram output is never evidence.** Do not cite an Engram `rag.query` / `kb.get` result
   as a `tool_call_id` in a Finding. Engram retrieval is operator/analyst knowledge, the
   same status as prior-case memory: **context and prioritization only, never current-case
   evidence**, and it never counts toward the SOUL.md ≥2 artifact-class rule.
2. **Engram is not in the audit/crypto chain.** Its reads/writes do not append to
   `audit.jsonl`, are not Merkle-hashed, and are not covered by `manifest_verify`. The
   chain-of-custody story is unchanged.
3. **It does not replace the A3 memory tools.** `memory_remember` / `memory_recall` remain
   the in-flow cross-case memory the pools call. Engram is a richer personal knowledge base
   for the operator, used outside the scored investigation path.

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Python 3.11+ | Engram pins `requires-python = ">=3.11"` |
| `uv` (or `pip`) | `pip install uv` |
| `claude` CLI on PATH | For `claude mcp add` |
| Obsidian (optional) | Only needed for the human vault surface |
| SQLite ≥ 3.41 | Required by the `sqlite-vec` extension |

---

## Install

```bash
cd engram-vang
uv pip install -e .        # or: pip install -e .
./bin/eos-init             # creates ~/.engram/{config.yml,.env,vault,db.sqlite}
```

`eos-init` scaffolds `~/.engram/`. Edit two files before first use:

- `~/.engram/config.yml` — paths, embedding model, retrieval/confidence weights
  (template: `engram-vang/config.example.yml`).
- `~/.engram/.env` — secrets (`ENGRAM_TAVILY_API_KEY`, `ENGRAM_ANTHROPIC_API_KEY`,
  `ENGRAM_FIRECRAWL_API_KEY`); leave blank to disable the corresponding research adapter.
  Never commit this file.

---

## Wire it as a local MCP server

### Recommended: user-scope registration (survives SIFT-mode config swaps)

```bash
claude mcp add -s user engram ~/.engram/.venv/bin/engram-mcp
claude mcp list   # expect: engram  ...  ✓ Connected
```

**Why user scope, not the repo `.mcp.json`:** `scripts/find-evil-sift` swaps the repo-level
`.mcp.json` for `.mcp.json.sift` (SSH transport) on entry and restores it on exit. A
user-scope server lives in `~/.claude.json`, so it is **unaffected by the swap** — Engram
stays available locally in both local mode and SIFT-VM mode without any extra wiring. User
scope also keeps Engram out of the committed repo, which matches the "not bundled" posture.

### Alternative: per-project (do not commit)

If you prefer a per-project registration, add the block below to a **local, uncommitted**
`.mcp.json`. Because `.mcp.json` is committed in this repo, do **not** add Engram to the
tracked file — copy it to `.mcp.json.local` and merge manually, or just use user scope above.

```json
{
  "mcpServers": {
    "engram": {
      "type": "stdio",
      "command": "/home/<you>/.engram/.venv/bin/engram-mcp"
    }
  }
}
```

Restart Claude Code. Verify the namespaces appear with `/mcp`:
`kb.*`, `rag.*`, `research.*`, `playbook.*`, `goals.*`, `sources.*`
(full reference: `engram-vang/docs/mcp-tool-reference.md`).

---

## Run the daemons (local)

Engram needs four background daemons plus an optional digest timer. They run on the **host**,
independent of the SIFT VM.

### systemd user units (recommended)

```bash
cp engram-vang/systemd/engram-*.service ~/.config/systemd/user/
cp engram-vang/systemd/engram-daily-digest.timer ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now \
  engram-projector engram-watcher engram-reactor engram-poller engram-daily-digest.timer
```

### Or four shells (quick start)

```bash
engram-projector   # log → vault markdown
engram-watcher     # vault edits → log
engram-reactor     # embed-on-ingest, staleness, near-dup post-check
engram-poller      # poll registered sources on schedule
```

---

## Verify

```bash
./bin/eos-status          # event/content counts + daemon cursors
claude mcp list           # engram → ✓ Connected
```

In a Claude Code session, confirm the tools are reachable with `/mcp`, then exercise a
round trip: ask the agent to `kb.write` a note, then `rag.query` it back.

---

## How an operator uses it during an investigation

Engram is for the **operator's** working knowledge, kept distinct from the scored
investigation:

- Stash reusable DFIR tradecraft, environment baselines, or prior-incident notes via
  `kb.write`, and recall them with `rag.query` while triaging.
- Register `sources.*` feeds (vendor advisories, MITRE pages) so the knowledge base stays
  current without manual fetching.
- Keep findings discipline intact: anything Engram surfaces that you want to act on must be
  re-derived from the typed DFIR tools and cited with a real `tool_call_id` before it
  becomes a Finding. Engram informs where to look; the product proves what happened.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `engram-mcp` not found | Re-run `uv pip install -e .` in `engram-vang/`; confirm `~/.engram/.venv/bin/engram-mcp` exists |
| `sqlite-vec` extension load failure | `python -c "import sqlite3; print(sqlite3.sqlite_version)"` must be ≥ 3.41 |
| First run is slow | Initial run downloads `all-MiniLM-L6-v2` (~80 MB) to `~/.cache/huggingface/` |
| Vault not updating | Check `~/.engram/db.sqlite` exists and the projector daemon's stderr |
| `engram` shows disconnected in `claude mcp list` | Confirm the absolute path in the registration; user-scope path must be absolute |

---

## What this runbook does NOT do

- It does not modify the committed `.mcp.json` / `.mcp.json.sift` (Engram is optional).
- It does not add Engram to the investigation flow, the audit chain, or the 31-tool count.
- It does not bundle Engram or `Rocba-Memory.zip` into the submission (both are `.gitignore`'d).
