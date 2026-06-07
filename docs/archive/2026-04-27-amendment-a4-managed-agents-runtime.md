# Amendment A4 — Managed Agents production runtime

> **Status: RESEARCH (deferred, archived).** Implementation deferred until post-submission adoption. PURELY ADDITIVE — A1/A2/A3 are unchanged. The SANS submission ships against the local Claude Code path (A2). A future contributor wanting hosted durability for an organization implements `services/mcp_http/` + `services/managed_agent/` + `scripts/find-evil-managed` per §4.5.
>
> **Archive note (non-authoritative).** Two design-era references below are stale relative to shipped code: (1) the live one-command entry point is now `scripts/verdict <evidence>` (the headless `scripts/find-evil-auto` engine is internal); (2) `judge_selfscore` is no longer pipeline-emitted — the SANS-rubric self-assessment is a standalone pre-submission grader, `scripts/self-score.py`, that does not touch the sealed audit chain. The Pool A/B `judge_findings` MERGE agent is unrelated. CLAUDE.md and the executable registries are authoritative.

**Status:** spec, future deployment work (not blocking the SANS submission). Origin: user redirect 2026-04-27 — *"Managed Agents is a fit for the SANS Find Evil! agent itself running in production. … that's a real future use case for the product."*

**Composes with, does NOT replace:** Amendment A1 (subscription credential mode) and Amendment A2 (Claude Code as the primary interface). A4 introduces a **third deployment mode** alongside the existing two; the hackathon submission still ships against A1 + A2 + A3, and a SANS judge cloning the repo runs the existing `scripts/find-evil` / `scripts/find-evil-auto` paths unchanged.

**Reference:** Anthropic Managed Agents engineering post (2026-04) + the `claude-api` skill's `shared/managed-agents-*.md` files. The architectural shapes used here are taken from those — `client.beta.agents.create`, `client.beta.environments.create`, `client.beta.sessions.create` + `events.send`/`events.stream`, `mcp_servers` declarations on the agent, vault-attached MCP credentials on the session, `agent.custom_tool_use` ↔ `user.custom_tool_result` round-trip.

---

## 0. Why this exists (and why it's an amendment, not a replacement)

A1 + A2 are the right shape for the hackathon: a judge clones the repo, opens Claude Code, runs an investigation against evidence on their own machine. Subscription auth means $0 incremental cost; local execution means no network dependency on Anthropic's hosting; the audit chain lands on the judge's disk under `tmp/auto-runs/`.

A4 is the right shape for **production deployment as a service** — an organization (SANS, an MSSP, an enterprise IR team) running Find Evil! as a long-lived agent platform across many investigations:

- Investigations are long-horizon (hours of forensic work on a 50 GB memory image is realistic). Managed Agents provides durable session state across hours; a Claude Code session can crash and lose work.
- The ACH dual-pool architecture spawns subagents that themselves run for tens of minutes. Managed Agents handles per-session container provisioning + crash-recovery natively; the local mode relies on the user keeping their machine open.
- Multi-tenant deployment (different analysts running different cases simultaneously) is straightforward with Managed Agents (one agent config, N concurrent sessions); under A2 each analyst needs their own Claude Code session on their own machine.
- The cryptographic chain-of-custody attestation is unchanged — audit.jsonl + Merkle root + sigstore + OTS still produce the FRE 902(14) self-authenticating receipt; it just lands in the managed container's `/mnt/session/outputs/` instead of the user's local disk.

A4 is **not** part of the hackathon submission timeline. It's a deployment-mode design that becomes useful post-submission, when the project is being adopted by organizations that need the durability + multi-tenancy properties.

## 1. The three deployment modes (post-A4)

| Mode | Origin | Where the agent loop runs | Where DFIR tools run | Auth | Use case |
|---|---|---|---|---|---|
| **Local Claude Code** | A1 + A2 (status quo) | User's Claude Code session | User's machine (or local Docker) | Claude Code subscription | Hackathon judges, individual analysts, dev. **The submission ships against this.** |
| **SIFT-VM bridge** | A2 (status quo) | User's Claude Code session | SSH'd into a SIFT VM | Subscription + SSH key | Analysts who want SANS-blessed tool versions without local install |
| **Managed Agents (A4)** | this amendment | Anthropic orchestration layer | Managed Agents container | API key (organization) | Production deployment, multi-tenant SaaS, MSSP fleet investigations |

A4 deliberately does NOT replace the first two. A future contributor changing one of the existing entry points is making a mistake.

## 2. Architecture

```
                        ┌─────────────────────────────────────┐
                        │  Anthropic orchestration layer      │
   Agent (config) ─────▶│  (Find Evil! agent loop:            │
   1× per deploy        │   Claude + agent-config/* prompts)  │
                        └──────────────┬──────────────────────┘
                                       │ tool calls
                                       ▼
   Environment (template) ──▶ Managed Agents container
                                       │
                            Session ───┤
                            1× per     ├── findevil-mcp (HTTP shim of the Rust DFIR tool surface)
                            investigation├── findevil-agent-mcp (HTTP shim of the Python crypto/ACH/memory/ACP surface)
                                       ├── DFIR tools pre-baked: Hayabusa, Volatility, YARA, Velociraptor
                                       ├── Resources: evidence file mounts, optional GitHub repo
                                       └── Custom tools (host-orchestrator round-trip)
```

The agent loop runs on Anthropic's orchestration layer (Anthropic's compute, not ours). The container is the **tool execution sandbox** — when the agent decides to call `vol_pslist`, the container runs the subprocess.

## 3. What stays the same

These are project invariants that A4 deliberately does not touch:

- **`agent-config/*.md` files** — SOUL, AGENTS, PLAYBOOK, TOOLS, MEMORY, HEARTBEAT, JUDGING. Same agent identity. The agent's `system` prompt is the concatenation of these (or a subset; see §6 open questions).
- **The 25 typed MCP tools** — 12 Rust DFIR + 13 Python crypto/ACH/memory/ACP. Same tool *surface*, exposed differently (HTTP shim for A4 vs the existing stdio for A1/A2).
- **audit.jsonl hash chain + Merkle root + sigstore + OTS** — the cryptographic chain-of-custody attestation runs unchanged. The audit chain lands in the managed container's `/mnt/session/outputs/audit.jsonl`; the manifest gets sigstore-signed and OTS-stamped from there.
- **ACH dual-pool topology + verifier + judge + correlator** — same role decomposition, same orchestration shape (supervisor → fork into Pool A / Pool B → re-merge through verifier + judge + correlator).
- **`judge_selfscore` + `manifest_finalize` + `ots_stamp`** — same sequencing, same audit-chain semantics.

## 4. What changes (the new pieces A4 adds)

### 4.1 MCP transport: stdio → HTTP

**Today:** both MCP servers are stdio JSON-RPC 2.0:
- `services/mcp/` — Rust `findevil-mcp` (12 DFIR tools)
- `services/agent_mcp/` — Python `findevil-agent-mcp` (13 crypto/ACH/memory/ACP tools)

**Under A4:** Managed Agents requires `mcp_servers: [{type: "url", url: "..."}]` (HTTP transport, see `shared/managed-agents-tools.md`). Two new HTTP shim services:

- `services/mcp_http/findevil-mcp/` — thin HTTP/SSE wrapper around the Rust binary. Same JSON-RPC 2.0 dispatch, just over HTTP. Probably `axum` + the existing `findevil-mcp` core compiled as a library instead of a binary.
- `services/mcp_http/findevil-agent-mcp/` — thin HTTP/SSE wrapper around the Python server. Probably FastAPI + the existing `findevil_agent_mcp.server` dispatch.

The stdio servers stay shipped under `services/mcp/` and `services/agent_mcp/` for A1/A2 compatibility. A4 is **additive** — no existing service is rewritten or removed.

### 4.2 Tool installation in the container

**Today:** DFIR tools (Hayabusa, Volatility 3, YARA, Velociraptor) live on the user's machine or in the SIFT VM. The Rust MCP server invokes them via subprocess.

**Under A4:** the Managed Agents container needs the same tools available. Three options, in preference order:

1. **Custom Anthropic-supplied container image** with DFIR tools pre-baked. This requires Anthropic-side support for "bring your own container image" — confirm availability before designing around it. (`shared/managed-agents-environments.md` mentions only `config.type: "cloud"` as supported; custom images are a noted gap.)
2. **Install at session start via the `bash` tool** in the agent toolset. Slow (3-5 minutes per session) but works on day-1. Not great for cost or analyst experience.
3. **Subprocess-out via custom tools.** Agent emits `agent.custom_tool_use` for `vol_pslist`; host orchestrator runs Volatility on its own infrastructure; result returns via `user.custom_tool_result`. Most flexible (host can be a SIFT VM) but moves the security boundary back to the host, partially defeating the Managed-Agents-isolation pitch.

The right answer probably depends on what Anthropic ships first. **Open question for the design pass.**

### 4.3 Evidence file handling

**Today:** evidence is on the user's local disk; the agent reads it directly.

**Under A4:** evidence has to enter the container somehow. Three sub-cases:

- **Small evidence (≤500 MB):** Files API upload + session resource mount. Direct.
- **Large evidence (1-50 GB):** Files API caps at 500 MB. Two paths:
  1. Chunk-and-upload (multiple Files API entries, custom tool reassembles in container)
  2. **Custom tool for chunked read** — agent emits `agent.custom_tool_use` for `read_evidence(offset, length)`; host orchestrator (which holds the actual evidence) returns the bytes. Container never holds the full image; agent reads it as a tape.
- **Multi-host fleet investigations:** GitHub repository as a resource, with the fleet manifest (host names + evidence paths). Agent reads the manifest, then per-host calls a custom tool to receive evidence chunks.

Path 2 is the most operationally clean for production: the host orchestrator manages evidence storage (with whatever encryption + chain-of-custody it already has), and the agent only sees what it asks for. This also means evidence never enters Anthropic's infrastructure in bulk — only the byte ranges the agent actively uses for its analysis.

### 4.4 Custom-tool round-trip for host-side operations

Beyond evidence reads, several Find Evil! operations should stay host-side under A4 — they need credentials or local access the container shouldn't have:

| Operation | Why host-side | Custom tool name |
|---|---|---|
| Read evidence bytes (chunked) | Evidence shouldn't enter Anthropic infra in bulk | `read_evidence_range` |
| Look up fleet host metadata | Fleet manifest may have org-internal IPs/secrets | `lookup_fleet_host` |
| Push final report to org-internal portal | Org credentials | `submit_report` |
| Cross-case memory recall against on-prem store | If the org runs an on-prem Hermes/FTS5 instead of a Managed Agents memory store | `cross_case_memory_recall` |

The agent declares these as `custom` tools in `agents.create()`; the host orchestrator (which already holds the API key driving the session) handles the round-trip.

### 4.5 New paths under `services/`

```
services/
├── mcp/                       # existing — Rust stdio MCP server (A1/A2)
├── agent_mcp/                 # existing — Python stdio MCP server (A1/A2)
├── agent/                     # existing — Python crypto/ACH/memory/ACP library
├── swarm/                     # existing — build swarm
├── mcp_http/                  # NEW (A4)
│   ├── findevil-mcp/          # Rust HTTP shim around services/mcp/ core
│   └── findevil-agent-mcp/    # Python HTTP shim around services/agent_mcp/
├── managed_agent/             # NEW (A4) — agent + environment + session driver
│   ├── agent.yaml             # versioned agent config (per CLI YAML pattern)
│   ├── environment.yaml       # versioned environment config
│   ├── orchestrator.py        # session driver: handles SSE stream + custom-tool round-trip
│   └── tests/                 # unit tests for orchestrator + integration tests for full session flow
```

### 4.6 New script: `scripts/find-evil-managed`

Mirrors `scripts/find-evil-auto` shape but kicks off a Managed Agent session instead of a Claude Code subprocess:

```bash
bash scripts/find-evil-managed <evidence-path> [--unattended]
```

Internally:
1. Load `AGENT_ID` + `ENV_ID` from config (created once via `ant beta:agents create < services/managed_agent/agent.yaml`).
2. Upload evidence (or register chunked-read custom tool, see §4.3).
3. `client.beta.sessions.create(agent=AGENT_ID, environment_id=ENV_ID, resources=[...], vault_ids=[...])`.
4. Stream events, handle `agent.custom_tool_use` per §4.4, handle `agent.tool_use` for built-in tools (Anthropic side), persist audit.jsonl from `agent.tool_result` events.
5. On `session.status_idle` with terminal `stop_reason`, finalize manifest + sigstore + OTS, download artifacts via `files.list({scope_id: session.id})`.

## 5. Cost + identity model

A1 explicitly chose "subscription, not metered" to avoid token costs for the hackathon submission. A4 reintroduces metered API costs — this is a deliberate tradeoff:

- **A1/A2 path** (subscription via Claude Code): $0 incremental cost per investigation. Right for individual judges, dev, and the hackathon demo.
- **A4 path** (Managed Agents API key): metered. Anthropic's pricing for Managed Agents is undisclosed at the time of this amendment; revisit when published.

A4 doesn't override A1's subscription default — it introduces a third option for organizations that prefer paid cloud durability. Documentation should make the cost difference explicit so an analyst doesn't accidentally drive the metered path.

## 6. Open questions (require user / Anthropic input before implementing)

1. **Custom container images.** Does Managed Agents support bring-your-own container image yet? (Per the skill content as of 2026-04, only `config.type: "cloud"` with Anthropic-default image is documented.) If yes, §4.2 path 1 is straightforward. If no, choose between path 2 (slow install) and path 3 (host-side subprocess).

2. **Evidence size handling.** If the typical SANS use case is 5-50 GB images, the Files API 500 MB cap forces §4.3 path 2 (chunked custom tool reads). Confirm with the eventual operator (SANS / MSSP / enterprise IR) whether evidence may transit Anthropic infra at all — some compliance regimes (HIPAA, classified) explicitly forbid it. If forbidden, §4.3 path 2 is mandatory regardless of size.

3. **Cross-case memory layer.** Find Evil! ships an on-disk SQLite FTS5 store (Amendment A3 §2.4). Two options for A4:
   - Use Managed Agents' native `memory_store` resource (per `shared/managed-agents-memory.md`). Different storage, different versioning model — may diverge from the Hermes-pattern recall semantics A3 codified.
   - Keep the SQLite store on the host, expose via a custom tool. Preserves A3 semantics exactly; loses Managed Agents' built-in audit + redaction.

   Probably worth A/B-ing: A3-style for hackathon judges, native Managed Agents memory for long-running production deployments.

4. **Agent versioning + the `judge_selfscore` chain.** Managed Agents agents are versioned objects; sessions pin to a version. If we update `agent-config/AGENTS.md` mid-investigation, the session keeps the old version. Need to decide whether `judge_selfscore` records the agent's `version` ID alongside the existing rubric scores so a judge can verify which version of the agent's identity produced the audit chain.

5. **MCP server hosting.** The HTTP shims (§4.1) need to be hosted somewhere reachable by Managed Agents:
   - Anthropic-hosted? (Doesn't seem possible under the current Managed Agents API — `mcp_servers: [{type: "url", url: "..."}]` references external URLs.)
   - Operator-hosted? (Each org running A4 hosts their own copies.)
   - Public hosted (e.g. by the Find Evil! project)? (Single point of failure; complicates cost model.)

   Operator-hosted is probably right for production, but it raises the bar for the "first run" — an org adopting Find Evil! has to spin up two HTTP services. Document this in the eventual A4 operator runbook.

## 7. Acceptance criteria (when this lands as code, not now)

- [ ] `services/mcp_http/findevil-mcp/` HTTP shim passes the same smoke harness as `services/mcp/` (rust-mcp-smoke equivalent, but over HTTP). Same 12 tool dispatch, same SHA-256 outputs.
- [ ] `services/mcp_http/findevil-agent-mcp/` ditto for the 13 Python tools.
- [ ] `services/managed_agent/orchestrator.py` can run a synthetic case (the `goldens/judge-case/` curated bundle) end-to-end against a managed session, producing the same audit chain shape A2 produces locally.
- [ ] `services/managed_agent/agent.yaml` + `environment.yaml` apply via `ant beta:agents create` / `ant beta:environments create` cleanly.
- [ ] Stop-condition gate (per `shared/managed-agents-client-patterns.md` Pattern 5) — the orchestrator does NOT break on bare `session.status_idle`; it checks `stop_reason.type !== 'requires_action'` first.
- [ ] All existing A1/A2 smoke harnesses still pass — no regression in the local Claude Code path.
- [ ] `docs/runbooks/managed-agents-operator.md` documents the operator setup (host MCP shims, create vaults, create agent, run sessions).
- [ ] Cost-disclosure note in `README.md` and `docs/cryptographic-attestation.md` — A4 mode is metered; A1/A2 modes remain subscription / $0.

## 8. Rollback path

A4 is **purely additive**. Removing it is straightforward:

1. Delete `services/mcp_http/`, `services/managed_agent/`, `scripts/find-evil-managed`.
2. Delete `docs/runbooks/managed-agents-operator.md`.
3. Revert `README.md` cost-disclosure section.

A1/A2/A3 are unaffected. No invariants change. ~1 hour of mechanical deletion.

## 9. What this amendment does NOT do

- Does not deprecate A1's subscription mode, A2's Claude-Code-as-orchestrator stance, or A3's dashboard work.
- Does not change the hackathon submission deadline path. The 2026-06-15 submission ships against A1+A2+A3; A4 is for whoever picks up the project after.
- Does not commit to building all of §4 in any particular order. The HTTP shims (§4.1) are a prerequisite for everything else; the custom-tool round-trip (§4.4) and chunked evidence reads (§4.3) are independent.
- Does not specify a timeline. A4 is a design artifact; implementation cadence depends on whoever adopts the project for production deployment.

## 10. Decision log

**2026-04-27, user redirect during the autonomous-iteration loop:** *"Managed Agents is a fit for the SANS Find Evil! agent itself running in production (long-horizon investigation runs, durable session state across hours of forensic work, multiple sandboxed tool calls) — that's a real future use case for the product. … do this."*

The user explicitly framed A4 as **future work**, distinct from the dashboard implementation work that was paused (Plan C). This amendment captures the design while it's fresh; concrete implementation defers until the hackathon submission ships and someone wants to run Find Evil! at production scale.

A1's subscription decision is preserved: the hackathon path is $0, A4 is a parallel deployment for organizations that want hosted durability.

Authoritative reference for the Managed Agents API surface: the `claude-api` skill's `shared/managed-agents-*.md` files (loaded 2026-04-27). If those contradict this amendment in a future session, the skill is the source of truth — update this amendment to match.
