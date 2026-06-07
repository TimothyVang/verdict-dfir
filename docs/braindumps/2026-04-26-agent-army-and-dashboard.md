# Braindump — agent-army DFIR workflow (research-enriched)

> **Status: RESEARCH (origin doc, superseded by Amendment A3).** This braindump produced Amendment A3 (`docs/specs/2026-04-26-amendment-a3-agent-army-and-dashboard.md`), which is the canonical record of what was actually decided + shipped. Kept here for the original brainstorming context.

> Status (original): enriched from the original 20-line vision with verified citations + a survey of
> what's already cloned locally. Originals preserved in spirit; everything else has a URL or
> a local file path behind it.

## Workflow vision (one-liners — preserved from original)

- Visual dashboard for the agents — pixel / sprite vibe, riff on **Claude Design**.
- "Agent army" does the DFIR analysis and the report writing.
- Use **OpenClaw + Hermes Agent** for self-learning to cut hallucinations + false positives.
- Connect them via **Agent Communication Protocol (ACP)**.
- **Claude Code is the interface** — no custom shell.
- **No `/loop`** — a real Claude Code agent harness.
- **Greenfield plan** — design the workflow fresh, don't just bolt onto existing scripts.

> "Greenfield" interpretation in this doc: the *orchestration shape* (who talks to whom,
> via what protocol, in what order, with what memory) is up for fresh design. The existing
> primitives — `findevil-mcp` (Rust, 13 DFIR tools), `findevil-agent-mcp` (Python, 11
> crypto/ACH tools), the audit JSONL hash chain, `agent-config/` role definitions — are
> the **foundation**, not the shackle. Flagged as a decision in §6 below.

## 1. The local research library (start here, not GitHub)

You already cloned everything we need into `git-hub-references/` — the index is at
`git-hub-references/CLAUDE.md`. The directory contains:

| Local path | Upstream | Why it matters here |
|---|---|---|
| `git-hub-references/openclaw/` | <https://github.com/openclaw/openclaw> | TS, MIT. Has its own ACP bridge — see `openclaw/docs.acp.md` |
| `git-hub-references/hermes-agent/` | <https://github.com/openclaw/hermes-agent> | **Empty — only `.git/`**, working tree never checked out |
| `git-hub-references/hermes-agent-self-evolution/` | <https://github.com/NousResearch/hermes-agent-self-evolution> | Python, MIT. **Full PLAN.md present**, DSPy + GEPA |
| `git-hub-references/awesome-openclaw-skills/` | <https://github.com/VoltAgent/awesome-openclaw-skills> | Catalog: `awesome-openclaw-skills/categories/` |
| `git-hub-references/awesome-openclaw-usecases/` | (community) | Use-case patterns |
| `git-hub-references/pixel-agents/` | <https://github.com/pablodelucca/pixel-agents> | TS, MIT. VS Code ext, full source: `src/`, `server/`, `shared/`, `e2e/` |
| `git-hub-references/claude-agent-sdk-python/` | <https://github.com/anthropics/claude-agent-sdk-python> | Has its own `CLAUDE.md` — pytest/ruff target *that* repo, not ours |
| `git-hub-references/claude-agent-sdk-typescript/` | <https://github.com/anthropics/claude-agent-sdk-typescript> | TS counterpart |
| `git-hub-references/awesome-forensics/` | (community awesome-list) | DFIR tool catalog |
| `git-hub-references/awesome-incident-response/` | (community awesome-list) | IR playbook references |
| `git-hub-references/DFIRMindMaps/` | (community) | Visual DFIR reference maps |
| `git-hub-references/h4cker/` | (community — security/DFIR tutorials) | Reference reading |
| `git-hub-references/LOLBAS/` | <https://lolbas-project.github.io/> | Living-Off-The-Land binaries — Pool A persistence detection corpus |
| `git-hub-references/ThreatHunter-Playbook/` | (community) | Hunt patterns Pool B can mine for exfil signatures |
| `git-hub-references/BMAD-METHOD/` | (community methodology) | Agent collaboration methodology reference |

> ⚠️ **`.gitignore` gap** documented in `git-hub-references/CLAUDE.md` §"Important": parent
> `.gitignore` patterns are root-anchored (`/openclaw/`), so `git-hub-references/openclaw/`
> is **not** ignored. Fix before any `v-submit` packaging — add `/git-hub-references/` to
> the parent `.gitignore`. Don't accidentally ship the upstream MIT trees in our submission.

## 2. ACP — which one, and why it actually fits

The acronym collides — there are **two unrelated protocols** named ACP:

- **Agent Communication Protocol (ACP)** — IBM / BeeAI, under Linux Foundation. Agent-to-agent.
  HTTP-based, framework-agnostic (BeeAI, LangChain, CrewAI, custom).
  Spec: <https://agentcommunicationprotocol.dev/introduction/welcome> ·
  Repo: <https://github.com/i-am-bee/acp> · Overview: <https://www.ibm.com/think/topics/agent-communication-protocol>.
  **This is the one you mean.** "ACP connects agents to agents; MCP connects agents to tools and
  knowledge" — <https://research.ibm.com/blog/agent-communication-protocol-ai>.
- **Agent Client Protocol (ACP)** — Zed Editor + JetBrains, JSON-RPC over stdio. Editor-to-agent.
  Spec: <https://zed.dev/acp> · Repo: <https://github.com/agentclientprotocol/agent-client-protocol>.
  Useful trivia: **OpenClaw already implements this one** — see `git-hub-references/openclaw/docs.acp.md`
  ("OpenClaw ACP Bridge — exposes an ACP agent over stdio and forwards prompts to a running
  OpenClaw Gateway over WebSocket").

Bridging openclaw ↔ hermes for our use case wants the **IBM ACP** (agent-to-agent). The Zed ACP
in OpenClaw's source is a useful precedent — proves the team knows protocol bridges — but it's
the editor-side protocol, not the agent-mesh protocol.

**Concrete bridge sketch** (greenfield, not yet built):
```
        ┌───────────────────┐  IBM ACP   ┌─────────────────────┐
        │ Pool A / Pool B   │◄──────────►│ Hermes-style memory │
        │ (Claude Code      │  HTTP/JSON │ (FTS5 cross-case    │
        │  forked subagents)│            │  recall + skill     │
        └────────┬──────────┘            │  auto-creation)     │
                 │                       └─────────────────────┘
                 │ MCP (existing)
                 ▼
        ┌───────────────────┐
        │ findevil-mcp +    │
        │ findevil-agent-mcp│
        └───────────────────┘
```

## 3. What we already have (read before proposing new work)

The "agent army" largely exists — it just isn't dressed in sprites yet:

- **`agent-config/AGENTS.md`** — Pool A (persistence) + Pool B (exfil) + verifier + judge +
  correlator. **That is the army.**
- **`scripts/find-evil`** — interactive `claude` session (the canonical entry point).
- **`scripts/find-evil-auto`** + **`scripts/find_evil_auto.py`** — the headless SIFT-VM
  orchestrator engine (the wrapper `scripts/verdict` calls). Already a harness, not a `/loop`.
- **`scripts/autonomous-loop.py`** — queue-driven `claude -p` spawner. Lightweight non-`/loop`
  runner already settled (memory: `feedback_use_harness_not_loop.md`).
- **`findevil-mcp`** (Rust, 13 typed DFIR tools) + **`findevil-agent-mcp`** (Python, 11
  crypto/ACH tools). Auto-spawned via `.mcp.json`.
- **`docs/false-positives.md`** — three FP-prevention layers + four operational habits, already
  documented (CONFIRMED > INFERRED > HYPOTHESIS hierarchy, ACH pool-vs-pool, ≥2 artifact rule).
- **`apps/web/`** + **`apps/mcp-widgets/`** — **deferred** per Amendment A2 §2.1. **The door
  this braindump proposes to re-open.**

## 4. Building blocks — researched

### 4.1 OpenClaw — borrow patterns, don't ship

- Local: `git-hub-references/openclaw/` · Upstream: <https://github.com/openclaw/openclaw>
- Skill catalog (5198 community skills): `git-hub-references/awesome-openclaw-skills/categories/`
- Pattern catalog (162 production agent templates): <https://github.com/mergisi/awesome-openclaw-agents>
- Reference SKILL.md format: `git-hub-references/openclaw/AGENTS.md` ("Telegraph style. Root rules
  only. Read scoped `AGENTS.md` before subtree work.")
- **Why we won't ship it**: parent `CLAUDE.md` "External reference clones" rule + license-tree
  hygiene. The MCP-server architecture replaces what OpenClaw provides as runtime.
- **What to borrow**: (a) the AGENTS.md skill-vs-index split as a hallucination-containment
  pattern; (b) the `openclaw acp` bridge architecture as a precedent for our IBM-ACP bridge
  (different protocol, same shape: stdio ↔ network); (c) skill patterns from
  `awesome-openclaw-skills/categories/` we can transcribe (never copy-paste — license boundary).

### 4.2 Hermes Agent + Self-Evolution — the self-learning story

- Base agent (upstream only — local clone is empty): <https://github.com/nousresearch/hermes-agent>
- Docs: <https://hermes-agent.nousresearch.com/docs/>
- **Self-evolution (locally cloned, full source)**: `git-hub-references/hermes-agent-self-evolution/`
  · Upstream: <https://github.com/NousResearch/hermes-agent-self-evolution>
- The Self-Evolution `PLAN.md` defines four optimization tiers — **Tier 1 (Skill Files)** is
  the lowest-risk highest-value lever: wrap a SKILL.md as a DSPy module, evaluate against a
  test corpus, evolve with GEPA. This is exactly what we'd want for our Pool A / Pool B
  prompts. Quote: *"Skills are pure text, easily mutated, and directly measurable (did the
  agent complete the task correctly when following this skill?)"*
- Key Hermes mechanism: **FTS5 cross-session memory** + autonomous skill creation after
  N tool calls + LLM-summarized recall.
- **What to borrow**: (a) an FTS5-backed cross-case memory layer inside `services/agent_mcp/`
  (replaces the "L3 cross-case memory" the empty `hermes-agent/` clone was meant to host);
  (b) Tier 1 GEPA-style skill evolution against `goldens/nist-hacking-case/` — measurable
  Pool A prompt improvement. **No GPU training, just API calls** (PLAN.md is explicit on this).

### 4.3 Claude Code agent harness — the non-`/loop` path

- Official subagents docs: <https://code.claude.com/docs/en/sub-agents>
  (canonical URL after the `docs.claude.com` → `code.claude.com` redirect).
- Fork mode: `CLAUDE_CODE_FORK_SUBAGENT=1` lets a subagent inherit the parent's prompt cache
  (referenced in our `agent-config/AGENTS.md`).
- Anthropic's official Agent Skills repo: <https://github.com/anthropics/skills>
  (Apache 2.0, `~`124k stars, canonical skill-format reference). Local SDK clones for
  comparison: `git-hub-references/claude-agent-sdk-python/` and
  `git-hub-references/claude-agent-sdk-typescript/`.
- **Existing user decision**: `feedback_use_harness_not_loop.md` + `feedback_loop_cadence.md`
  in user memory — don't re-litigate.

### 4.4 Pixel Agents — visual reference for the dashboard

- Local: `git-hub-references/pixel-agents/` · Upstream: <https://github.com/pablodelucca/pixel-agents>
- TS, MIT, VS Code extension. Full source available locally: `src/`, `server/`, `shared/`, `e2e/`.
- Reads JSONL transcripts, animates Claude Code subagents as pixel-art office characters
  (typing / reading / waiting states).
- **Not adopted as runtime.** Reference for the aesthetic + a useful local-dev companion.
  We build our own web dashboard (next).

### 4.5 NES.css web dashboard (re-opens A2 §2.1 — flagged)

- NES.css: <https://github.com/nostalgic-css/NES.css> (MIT, "NES-style 8bit-like CSS framework").
- Sibling alt: 98.css <https://github.com/jdan/98.css> if retro-Windows beats retro-NES.
- **Plan**: resurrect `apps/web/` as a Next.js + NES.css live dashboard tailing the existing
  audit JSONL hash chain over WebSocket. Pool A and Pool B render as pixel-art sprites;
  verdicts float as `[CONFIRMED · tool · sha256]` chips; the audit chain renders as a
  bead-string (one bead per `audit_append`).
- Anthropic-blessed prototyping path: **Claude Design** (Anthropic Labs, Opus 4.7-backed,
  launched 2026-04-17). Use it to mock the layout before hand-coding.
  Announcement: <https://www.anthropic.com/news/claude-design-anthropic-labs> ·
  Get-started: <https://support.claude.com/en/articles/14604416-get-started-with-claude-design>.
- **Architectural cost**: this overrides Amendment A2 §2.1, which deferred `apps/web/` to a
  week-7 bonus. We need an **Amendment A3** in `docs/specs/` to make that
  override official. Out of scope for this braindump pass — but flagged so we don't do it
  silently.

### 4.6 DFIR research libraries already on disk (Pool A/B fuel)

These aren't agents — they're pattern corpora the agent army can grep / RAG against. All
already cloned under `git-hub-references/`:

- `LOLBAS/` — Living-Off-The-Land binaries catalog. Pool A (persistence) reads this when
  ranking suspicion of a benign-looking signed binary.
- `ThreatHunter-Playbook/` — community hunt patterns. Pool B (exfil) reads this when
  hypothesizing about staging / data-collection chains.
- `awesome-incident-response/` — IR playbook references for the report-writer agent.
- `awesome-forensics/` — DFIR tool catalog (cross-check tool selection in `findevil-mcp`).
- `DFIRMindMaps/` — visual DFIR reference maps. Asset for the dashboard.
- `h4cker/` — broad DFIR/security tutorials, useful as RAG corpus.
- `BMAD-METHOD/` — agent-collaboration methodology reference.

## 5. DFIR-specific FP / hallucination prior art (Devpost-narrative citations)

- **SANS ACH (Analysis of Competing Hypotheses) template**: <https://www.sans.org/tools/ach-template>.
  Our Pool A vs Pool B + judge structure **is** ACH — gives us a SANS-issued reference to
  cite verbatim in the Devpost narrative.
- The verifier-pair-with-deterministic-check pattern is exactly what `verify_finding` does
  (re-runs cited `tool_call_id`, hash-matches output). Citation-grounded, not invented.

## 6. Tensions to resolve (decisions for you, not for me)

1. **"Greenfield" scope**. Two readings:
   (a) the **orchestration shape** is fresh — new bridge layer, new dashboard, but the
       MCP servers + audit JSONL + agent-config stay (low-throwaway);
   (b) **start over** — replace `services/` with an OpenClaw-Gateway-and-Hermes-bus stack
       (high-throwaway, may not fit the 2026-06-15 deadline).
   Recommendation: (a). Confirm or override.

2. **OpenClaw / Hermes runtime status**. *Resolved last pass*: borrow patterns, don't ship.
   No `.gitignore` change, no new runtime deps. Hermes-style FTS5 memory becomes a new tool
   inside `services/agent_mcp/` modeled on Hermes' approach but written for our codebase.
   Greenfield reading (a) is consistent with this; reading (b) would re-open it.

3. **`apps/web/` deferral (A2 §2.1)**. *You opted to re-open.* Action item, not done here:
   write **Amendment A3** in `docs/specs/` before touching `apps/web/` so the
   override is documented, not silent.

4. **"Agent army" specificity**. Two readings:
   (a) the existing Pool A / Pool B / judge / verifier / correlator dressed as sprites;
   (b) more specialized DFIR subagents (memory-forensics specialist, timeline specialist,
       malware-triage specialist, persistence specialist) layered on top.
   Decision impacts the dashboard layout, A3 spec scope, and whether we extend AGENTS.md.

5. **ACP bridge ownership**. Where does the IBM-ACP bridge live? Three options:
   (a) new third MCP server `services/agent_acp_bridge/` (cleanest separation);
   (b) inside `services/agent_mcp/` as additional tools;
   (c) external sidecar process — closer to what OpenClaw does with `openclaw acp`.

## 7. Suggested next steps (no code — decision-driving only)

- Read this end-to-end. Push back on anything that misreads the vision.
- Pick (a) or (b) for the **greenfield scope** question (§6.1).
- Pick (a) or (b) for the **agent army specificity** question (§6.4).
- Pick where the **ACP bridge** lives (§6.5).
- If dashboard stays in: open Claude Design, mock the NES.css layout against the audit JSONL
  schema, then I'll draft **Amendment A3** to formally re-open `apps/web/`.
- If memory layer is in: scope the FTS5 cross-case memory tool inside `services/agent_mcp/`
  (Hermes-pattern, our codebase). Probably 1–2 new MCP tools: `memory_recall` + `memory_remember`.
- Before any `v-submit` packaging: **fix the `git-hub-references/` `.gitignore` gap**
  (see `git-hub-references/CLAUDE.md`).
- Optional: pull the **awesome-openclaw-agents** index online and grep it for SKILL.md
  shapes worth porting into `agent-config/`.
