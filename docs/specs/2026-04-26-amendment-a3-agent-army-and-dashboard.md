# Amendment A3 — Agent-Army Bridge + Cross-Case Memory + NES.css Dashboard

> **Status: SHIPPED (Phases 1-4 + role-state dashboard) / PARKED (pixel-art/chrome polish).** The three Python MCP tools (`memory_remember`, `memory_recall`, `pool_handoff`), the FTS5 memory store at `services/agent/findevil_agent/memory/store.py`, and the `apps/web/` SSE-audit-tail dashboard with role-state sprite containers all shipped. The pixel-art sprite swap and AuditBeadString/HashChainBadge/FindingChip chrome are gated on a Claude Design prototyping pass.

**Date:** 2026-04-26
**Status:** Active — supersedes Amendment A2 §2.1 (the `apps/web/` deferral) and extends `services/agent_mcp/` with three new tools.
**Scope:** Python MCP server (new tools, no rewrite), `apps/web/` resurrection, `.gitignore` correctness, agent-config (no edits — roles unchanged).
**Rationale:** Three things we know now that A2 didn't:
1. **OpenClaw, Hermes Agent, Pixel Agents, and Claude Design** are real, MIT-licensed, and locally cloned under `git-hub-references/` (see `git-hub-references/CLAUDE.md`). They give us pattern references for hallucination containment, cross-case memory, sprite-style dashboards, and Anthropic-blessed visual prototyping — none of which existed in usable form when A2 was written on 2026-04-25.
2. **IBM Agent Communication Protocol (ACP)** under the Linux Foundation gives us a public standard for agent-to-agent handoff (Pool A → Pool B → judge), distinct from the MCP-for-tools layer we already use. Citation: <https://agentcommunicationprotocol.dev/>. The Zed editor's identically-named "Agent Client Protocol" (<https://zed.dev/acp>) is a different protocol; OpenClaw already implements it (`git-hub-references/openclaw/docs.acp.md`) — useful precedent that protocol bridges are tractable.
3. **Cross-case memory was the original Hermes-as-MCP-sidecar story** in `BUILD_PLAN_v2.md` §3 layer L3. A2 dropped Hermes; A3 reinstates the *capability* without the *runtime dep* by porting the FTS5 + skill-auto-creation pattern into `services/agent_mcp/` directly.

Originating document: the repo-root `braindump` file (research-enriched 2026-04-26).

> **Interpretation note (read first).** The originating braindump asks for a "greenfield plan." That word is ambiguous and load-bearing. A3 reads it as **design-fresh, engineer-additively**: the *orchestration shape* (how agents talk, what gets remembered across cases, how the dashboard renders) is designed clean-slate from the new prior art; the *engineering* keeps everything A2 ships (12 Rust DFIR tools, 10 Python crypto/ACH tools, `agent-config/` roles, Claude Code as supervisor). If you wanted A3 to literally replace `services/agent_mcp/` with a new bus, push back on §1 below — the spec is structured to be reverted to a stricter interpretation in one editing pass.

---

## 1. Decision

A3 adds three capabilities on top of the A2 stack:

1. **Three new Python MCP tools inside `services/agent_mcp/`** (no new server, no new `.mcp.json` entry):
   - **`memory_remember`** — append a (case_id, kind, key, value, sha256, ts) row to a project-local SQLite FTS5 index for future cross-case recall. Hermes-pattern; replaces the deferred L3 sidecar.
   - **`memory_recall`** — query the FTS5 index by IOC / hash / TTP / hostname; returns prior-case hits with case_ids and confidence-decayed scores.
   - **`pool_handoff`** — IBM-ACP-shaped agent-to-agent message (role, payload, correlation_id) recorded into the audit JSONL as `kind="acp_handoff"`. Used by Pool A to hand structured findings to Pool B (and either to the judge) without going through Claude Code's natural-language channel.

2. **`apps/web/` resurrected as a NES.css live dashboard** — overrides A2 §2.1's deferral. The shipped app reads the existing `audit.jsonl` hash chain over SSE at `/api/audit`, derives one role-state card each for Pool A, Pool B, Verifier, Judge, and Correlator, and preserves `/debug` as a raw stream viewer. Pixel-art sprite art and the AuditBeadString chrome remain gated on an Anthropic Claude Design prototyping pass (<https://www.anthropic.com/news/claude-design-anthropic-labs>, launched 2026-04-17); no audit schema changes are required.

3. **`.gitignore` correction.** Add `/git-hub-references/` so the seven cloned external repos under that path (openclaw, hermes-agent, hermes-agent-self-evolution, pixel-agents, claude-agent-sdk-python, claude-agent-sdk-typescript, awesome-openclaw-skills, plus DFIR awesome-lists) cannot leak into a `v-submit` packaging run. The current root-anchored `/openclaw/` pattern doesn't catch the relocated copy; this is documented in `git-hub-references/CLAUDE.md` §"Important: .gitignore gap" and is a hard prerequisite for any `scripts/package-devpost.sh` invocation.

Claude Code remains the supervisor (Amendment A2 §1 unchanged). The army is the same five agent-config roles as A2; A3 just dresses them as sprites and gives them a memory layer + a structured handoff channel.

---

## 2. Deltas

### 2.1 Override of A2 §2.1 (`apps/web/` deferral)

A2 §2.1 deferred `apps/web/` and `apps/mcp-widgets/` to a week-7 polish bonus. A3 promotes `apps/web/` back onto the critical path. `apps/mcp-widgets/` (M3 MCP App widgets) **stays deferred** — A3 does not need them; the dashboard reads the audit JSONL directly.

The Devpost README "Try it" block (A2 §2.4) gains one optional line:

```bash
# (Optional, after the investigate step) — open the dashboard in another tab:
open http://localhost:3000        # or pnpm --filter @findevil/web dev
```

### 2.2 Added by the pivot

**`services/agent_mcp/findevil_agent_mcp/tools/` gains three modules:**

| File | Tool name | Wraps |
|---|---|---|
| `memory_remember.py` | `memory_remember` | New `findevil_agent.memory.MemoryStore.remember(case_id, kind, key, value, sha256)` |
| `memory_recall.py` | `memory_recall` | New `findevil_agent.memory.MemoryStore.recall(query, kind?, limit=10)` |
| `pool_handoff.py` | `pool_handoff` | New `findevil_agent.acp.handoff(from_role, to_role, payload, correlation_id)` (records audit-log line; returns echo) |

The underlying logic lives in `services/agent/findevil_agent/`:

- `findevil_agent/memory/store.py` — SQLite FTS5 wrapper, schema (single `memories` virtual table + `meta` table for case_id index), `remember()` / `recall()`.
- `findevil_agent/acp/handoff.py` — IBM-ACP-shaped Pydantic message + `handoff()` that writes a `kind="acp_handoff"` line into the same hash-chained `audit.jsonl` the rest of the agent uses.

**SQLite memory store location:**
- Per-machine: `${XDG_STATE_HOME:-~/.local/state}/findevil/memory.sqlite` (Linux/macOS).
- Windows dev: `%LOCALAPPDATA%\findevil\memory.sqlite`.
- The file is `.gitignore`'d (`*.sqlite` rule already exists at `.gitignore:73`).
- Survives across cases. Per-case isolation is per-row via `case_id`.

**`apps/web/` (Next.js 15 + Tailwind v4 + NES.css):**

```
apps/web/
├── package.json                    # Next.js 15, react 19, tailwindcss v4, nes.css
├── tsconfig.json
├── next.config.ts
├── app/
│   ├── layout.tsx                  # NES.css base styles import
│   ├── page.tsx                    # Dashboard: 5 sprites + audit chain bead string
│   └── api/audit/route.ts          # WebSocket upgrade → tails audit.jsonl
├── components/
│   ├── sprites/
│   │   ├── PoolASprite.tsx         # persistence-pool pixel-art character
│   │   ├── PoolBSprite.tsx         # exfil-pool pixel-art character
│   │   ├── VerifierSprite.tsx
│   │   ├── JudgeSprite.tsx
│   │   └── CorrelatorSprite.tsx
│   ├── AuditBeadString.tsx         # one bead per audit_append, color by kind
│   ├── FindingChip.tsx             # [CONFIRMED · tool · sha256] in NES.css frame
│   └── HashChainBadge.tsx          # green = chain valid, red = mismatch
├── lib/
│   ├── audit-tail.ts               # server-side: chokidar on audit.jsonl, push to WS
│   └── audit-types.ts              # generated from findevil_agent/events via pydantic-to-typescript
└── public/sprites/                 # PNG sprite sheets, 32x32 per frame
```

The dashboard reads `audit.jsonl` from the case directory specified by `?case=<path>` query string. Default development case: `goldens/synthetic-benign/`.

**Sprite mapping** (one per `agent-config/AGENTS.md` role):

```
       [Supervisor] (Claude Code, off-screen — no sprite)
            │
     ┌──────┼──────────────────┐
   [PoolA]  [PoolB]      [Verifier]
   persist  exfil         re-runs cited tool_call_ids
     └────┬─┘                 │
          ▼                   │
       [Judge]  ◄─────────────┘
          ▼
     [Correlator] → [Manifest icon]
     ≥2 artifacts
```

Each sprite has 4 animation frames: idle, working (tool call active), waiting (blocked on supervisor decision), verdict (just emitted a Finding). State is derived from the audit JSONL stream — no new event types added.

**`.mcp.json` is unchanged.** The three new tools register inside the existing `findevil-agent-mcp` server.

### 2.3 IBM-ACP bridge — minimal shape

`pool_handoff` records to `audit.jsonl` rather than opening a network port. This is intentional — IBM-ACP is HTTP-based in its full form, but for a single-machine investigation we don't need the network surface, and the audit JSONL is already the durable agent-to-agent channel. Future expansion to networked ACP (multi-host, fleet mode) is straightforward: the `handoff()` function gains an optional HTTP transport that POSTs to a sibling Python MCP server's `/acp/v1/handoff` endpoint. Out of scope for A3.

The IBM-ACP message envelope we adopt verbatim:
```json
{
  "acp_version": "1.0",
  "from_role": "pool_a",
  "to_role": "pool_b",
  "correlation_id": "uuid-v7",
  "payload": { "...role-specific..." },
  "ts": "2026-04-26T14:23:00Z"
}
```

### 2.4 Memory store — schema

Single SQLite database, single FTS5 virtual table:

```sql
CREATE VIRTUAL TABLE memories USING fts5(
    case_id UNINDEXED,
    kind,            -- 'ioc' | 'hash' | 'ttp' | 'hostname' | 'finding_summary'
    key,             -- searchable text
    value,           -- searchable text
    sha256 UNINDEXED,
    ts UNINDEXED,
    tokenize='porter unicode61'
);

CREATE TABLE meta (
    case_id TEXT PRIMARY KEY,
    case_path TEXT,
    first_seen_ts TEXT,
    last_updated_ts TEXT
);
```

`recall()` returns rows ordered by descending **combined confidence**, where `confidence = relevance × decay`:

- `relevance = 1.0 / (1.0 + abs(bm25_score))` — SQLite's `bm25()` returns negative scores (more negative = better match), so we take the absolute value and remap into `[0, 1]`; better matches get higher relevance.
- `decay = exp(-days_since_last_seen / 90)` — 90-day half-life, tunable via the `_HALF_LIFE_DAYS` module constant.
- Sorting is done in Python after computing `confidence`, since SQLite's `ORDER BY bm25(...)` returns insertion order on ties — and decay must be allowed to break those ties.
- FTS5 query strings containing `.`, `@`, `-`, etc. are phrase-quoted before being passed to `MATCH` (e.g. `"evil.com"` rather than `evil.com`). This avoids `fts5: syntax error near "."` while still matching the canonical IOC / hash / TTP shapes the store is designed for. Multi-word queries become phrase searches — conservative but appropriate for the lookup-shaped workload; revisit if multi-token recall becomes a real use case.

---

## 3. No changes to

- `services/mcp/` (Rust MCP server) — same 12 tools, no edits.
- `agent-config/` — Pool A / Pool B / verifier / judge / correlator role definitions unchanged. The dashboard renders these roles; the spec doesn't redefine them.
- `services/agent/findevil_agent/` existing modules (M2 crypto, M4 ACH, verifier, judge, correlator) — A3 *adds* `memory/` and `acp/` subpackages but touches no existing files.
- `services/swarm/` — unchanged.
- `scripts/find-evil`, `scripts/find-evil-auto`, `scripts/autonomous-loop.py` — unchanged.
- `apps/mcp-widgets/` — stays deferred per A2 §2.1 (only `apps/web/` gets resurrected).
- Sandbox layers (L0-L3), CI workflows — unchanged.
- Audit JSONL schema — `pool_handoff` adds a new `kind="acp_handoff"` value but reuses the existing `prev_hash` chain mechanism. No schema break.

---

## 4. Acceptance criteria

- [ ] **Memory store**: `uv run --directory services/agent pytest tests/test_memory_store.py -v` green for round-trip remember → recall; FTS5 query returns expected ranked rows.
- [ ] **MCP tool surface**: `uv run --directory services/agent_mcp pytest tests/test_server.py -v` green; `findevil_agent_mcp` server now advertises **13 tools** (10 existing + 3 new). Tool count assertion in the test verifies the surface.
- [ ] **ACP handoff**: `pool_handoff` writes a valid JSONL line that passes `audit_verify`; the line's `kind` is `"acp_handoff"` and the payload round-trips through the IBM-ACP envelope shape.
- [ ] **Dashboard scaffold**: `pnpm --filter @findevil/web dev` boots on `localhost:3000`; navigating to `/?case=goldens/synthetic-benign` renders all 5 sprites and at least one bead in the AuditBeadString.
- [ ] **Live tail**: with `apps/web/` running, executing one `audit_append` MCP tool call against the demo case triggers a WebSocket push that adds one bead to the dashboard within 500ms.
- [ ] **Hash-chain badge**: `<HashChainBadge />` renders green when audit JSONL verifies, red when a synthetic tampered line is injected.
- [ ] **`.gitignore` fix verified**: `git check-ignore git-hub-references/openclaw/README.md` returns `git-hub-references/` (not empty).
- [ ] **No regression**: existing 40 tests in `services/agent_mcp/tests/` still green.
- [ ] **No new runtime deps from openclaw / hermes-agent / pixel-agents.** A `git grep -E '(openclaw|hermes_agent|pixel_agents)'` inside `services/`, `apps/web/`, and `agent-config/` returns zero matches (CI gate).

---

## 5. Rollback path

A3 is structured so each of the three additions can be reverted independently:

1. **Memory tools rollback**: delete `services/agent/findevil_agent/memory/`, `services/agent_mcp/findevil_agent_mcp/tools/memory_*.py`, drop the `memory_*` registrations from `services/agent_mcp/findevil_agent_mcp/server.py`. ~30 minutes. `*.sqlite` already gitignored so no orphan files in the index.
2. **ACP handoff rollback**: delete `services/agent/findevil_agent/acp/`, `services/agent_mcp/findevil_agent_mcp/tools/pool_handoff.py`, drop the registration. ~15 minutes. The `kind="acp_handoff"` audit lines remain valid JSONL — they just stop being produced.
3. **Dashboard rollback (back to A2 §2.1)**: delete `apps/web/`. ~5 minutes. No consumers in the rest of the tree.

Full A3 rollback (all three): ~1 hour. The `.gitignore` fix should stay regardless — it's a correctness fix, not an A3-specific change.

---

## 6. Decision log

**2026-04-26, user directive (braindump in repo root, then enriched + AskUserQuestion):**

- **Greenfield scope**: user picked "Greenfield-from-scratch" but separately picked "Existing roles as sprites" + "Inside services/agent_mcp/", which contradict literal greenfield. A3 interprets the combined intent as **design-fresh, engineer-additively**: clean-slate orchestration *shape* on top of the A2 *engineering*. If the user reads §1 and disagrees, A3 is structured to be re-edited toward stricter greenfield in one pass.
- **Agent-army specificity**: user picked "Existing roles as sprites" — A3 commits to 5 sprites (Pool A, Pool B, Verifier, Judge, Correlator) mapping 1:1 to `agent-config/AGENTS.md`. No new role definitions.
- **ACP bridge ownership**: user picked "Inside `services/agent_mcp/`" — A3 commits to three new tools in the existing Python MCP server, no third process.
- **OpenClaw / Hermes runtime status**: user picked "Borrow patterns, don't ship" in the prior round (braindump §6.2). A3 honors this — no new runtime deps from `git-hub-references/` clones, just pattern transfer.

A1 + A2 remain authoritative for everything A3 doesn't override. A3's only direct supersession is A2 §2.1 (the `apps/web/` deferral).
