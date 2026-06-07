# Runbook: n8n Finding-to-Action Automation (Optional)

**Status: ACTIVE**
**Scope: optional operator tooling — not part of the Find Evil! submission surface.**

[n8n](https://github.com/n8n-io/n8n) is a workflow-automation engine. This runbook wires it in
as an **operator-local orchestration harness *around* the product**: it automates repeatable
investigation runs and the **post-verdict finding-to-action fan-out** (notify / ticket /
IOC-enrich / fleet-sweep). It runs **downstream of the scored investigation** — it does **not**
become the investigation orchestrator, touch the typed evidence-tool surface, or enter the
audit/crypto chain. Claude Code remains the product orchestrator (Amendment A2).

This is the n8n sibling of [`engram-memory-integration.md`](engram-memory-integration.md); the
two compose — Engram grounds DFIR claims while triaging, n8n automates what happens after the
verdict.

---

## Integration decisions (what this runbook assumes)

| Decision | Choice | Implication |
|---|---|---|
| Role | **Operator harness around the product** | n8n orchestrates repeatable runs + finding-to-action; it is **not** wired into Pool A/Pool B and is **not** the A2 orchestrator. Claude Code still starts everything. |
| Where it sits in the flow | **Downstream of `verdict.json`** | n8n consumes the *output* of a finished, audited investigation (`manifest_finalize` → `verdict.json`). It never feeds the scored path. |
| Integration surface | **`n8n-mcp` (MIT), user-scope MCP server** | Claude Code uses `n8n-mcp` to build/validate/deploy n8n workflows and trigger runs. The 31-tool product surface is untouched. |
| Submission posture | **Optional, not bundled** | Treated like the SIFT DFIR binaries and Engram: operator wires it in; `n8n-references/` is `.gitignore`'d and never enters the Devpost zip. |
| Where it runs | **Local host only** | The operator's own n8n instance + `n8n-mcp` run on the host. SIFT-VM mode still reaches DFIR tools over SSH; n8n stays local. |
| License | **n8n core = fair-code (Sustainable Use), `n8n-mcp`/`n8n-skills` = MIT** | n8n core is **not** OSI MIT/Apache, so it must **never** be bundled or linked into the Apache-2.0 submission. Keeping it optional/operator-run/standalone is what makes this compliant. |

---

## License & submission compliance

The submission must ship as MIT/Apache-2.0 (CLAUDE.md §3). n8n core ships under the **fair-code
Sustainable Use License** (`n8n-references/n8n/LICENSE.md` + `LICENSE_EE.md`) — permissive for
self-hosted internal use, but **not** an OSI permissive license. Therefore:

- **Never bundled, never linked.** `n8n-references/` is `.gitignore`'d. `scripts/package-devpost.sh`
  does not include it. The operator runs their **own** n8n instance from upstream; nothing in
  `services/` imports or vendors n8n.
- **`n8n-mcp` and `n8n-skills` are MIT** (`n8n-references/n8n-mcp/LICENSE`,
  `n8n-references/n8n-skills/LICENSE`) — safe to reference, still kept optional/standalone.
- **Not in the judge-facing required docs.** `docs/architecture.md` (Devpost Required Component
  #3) intentionally does **not** mention n8n — the submission surface is the 31-tool typed
  product. This runbook is the canonical home for n8n integration, the same way the Engram
  runbook is for Engram.
- **Honors the anti-overbuild line.** The project's anti-overbuild guidance is "do not add
  n8n … runtime work" — i.e. do not build n8n into the *product runtime*. This runbook keeps n8n
  strictly **outside** the product as optional operator automation, so the product runtime is
  unchanged.

---

## Boundaries (DFIR integrity — do not cross)

These keep n8n from polluting the investigation's evidentiary guarantees:

1. **n8n output is never evidence.** A workflow result, enrichment, or notification is never
   cited as a `tool_call_id` in a Finding and never counts toward the SOUL.md ≥2 artifact-class
   rule. n8n acts on findings the product already proved; it does not produce findings.
2. **n8n is not in the audit/crypto chain.** Its runs do not append to `audit.jsonl`, are not
   Merkle-hashed, and are not covered by `manifest_verify`. The chain-of-custody story is
   unchanged. The signed `run.manifest.json` is the boundary: n8n reads it, never extends it.
3. **It runs after the verdict, not during.** n8n triggers on a *finished* investigation
   (`verdict.json` present, manifest verified). It is not part of Pool A/Pool B, the heartbeat
   loop, or `judge_findings`/`correlate_findings`.
4. **Evidence stays read-only.** finding-to-action workflows act on *derived outputs* (verdict,
   IOCs, host list) — never on the original `.e01`/`.mem`. No n8n node touches the evidence vault.

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Node 20 + `npx` | Runs both `n8n` and `n8n-mcp` without a global install |
| `claude` CLI on PATH | For `claude mcp add` |
| Docker (optional) | Cleanest way to run a persistent local n8n instance |
| A finished case | `verdict.json` + verified `run.manifest.json` under `tmp/auto-runs/<case-id>/` |

---

## Install

### 0. One-shot: `scripts/setup-n8n.py` (automated, idempotent)

`scripts/install.sh` runs this automatically (best-effort, non-fatal); you can also run it directly:

```bash
N8N_AUTO_DOCKER=1 python3 scripts/setup-n8n.py   # starts n8n if none is up, then provisions it
```

It ensures an owner account exists (creating one on a fresh instance, else logging in), ensures a
REST API key exists, and deploys + activates the `findevil-finding-to-action` workflow. Credentials
and the key are written to gitignored `tmp/n8n-credentials.txt` / `tmp/n8n-apikey.txt` (the paths
`scripts/n8n_post.py` and the dashboard already read). Env: `N8N_BASE`, `N8N_OWNER_EMAIL`,
`N8N_OWNER_PASSWORD`, `SLACK_WEBHOOK_URL`, `N8N_AUTO_DOCKER=1`. Skip from install with
`FINDEVIL_SKIP_N8N=1`. The manual steps below are the fallback when you'd rather set it up by hand.

### 1. Run a local n8n instance (operator-owned)

```bash
# Docker (recommended for a persistent instance):
docker run -it --rm --name n8n -p 5678:5678 -v n8n_data:/home/node/.n8n docker.n8n.io/n8nio/n8n
# or ephemeral:  npx n8n
```

Open `http://localhost:5678`, create the owner account, then **Settings → n8n API → Create API
key**. Keep the key out of the repo (operator secret, like any other credential).

### 2. Point `n8n-mcp` at it

`n8n-mcp` has two modes. **Docs-only** (no API config) gives Claude node/template knowledge.
**Management mode** adds the 13 `n8n_*` tools (create/validate/deploy/trigger) and needs your
instance's URL + key:

```bash
export N8N_API_URL=http://localhost:5678
export N8N_API_KEY=<the key you created>
```

---

## Wire `n8n-mcp` as a local MCP server

### Recommended: user-scope registration (survives SIFT-mode config swaps)

```bash
claude mcp add -s user n8n-mcp \
  -e N8N_API_URL=http://localhost:5678 \
  -e N8N_API_KEY=<your-key> \
  -- npx -y n8n-mcp
claude mcp list   # expect: n8n-mcp  ...  ✓ Connected
```

**Why user scope, not the repo `.mcp.json`:** `scripts/find-evil-sift` swaps the repo `.mcp.json`
for `.mcp.json.sift` on entry and restores it on exit. A user-scope server lives in
`~/.claude.json`, so it is **unaffected by the swap** and stays available in both local and
SIFT-VM mode. User scope also keeps n8n out of the committed repo, matching the "not bundled"
posture. **Do not** add n8n-mcp to the tracked `.mcp.json` / `.mcp.json.sift` — that would put a
fair-code-adjacent server in the submission's committed config.

### Optional: the n8n-skills authoring aid

`n8n-references/n8n-skills/` (MIT) is a set of Claude Code skills for composing flawless n8n
workflows via `n8n-mcp`. Install per its README only if you want guided workflow authoring; it is
purely an operator convenience and ships nothing.

---

## The finding-to-action seam

This is the only place n8n connects to the product, and it is one-directional (product → n8n):

```
  manifest_finalize ──► verdict.json (+ signed run.manifest.json)   [SCORED, AUDITED — frozen here]
                              │
                              ▼  operator triggers (via Claude Code + n8n-mcp)
                       n8n workflow reads verdict.json
                              │
        ┌─────────────┬───────┴────────┬─────────────────┐
        ▼             ▼                ▼                 ▼
     notify       open ticket     IOC enrich        fleet sweep
   (Slack/email) (Jira/TheHive)  (VT/MISP/OTX)   (Velociraptor hunt)
```

Map actions to MITRE technique using [`../finding-to-action.md`](../finding-to-action.md) — it
already lists the per-technique IR steps (e.g. T1014 DKOM → hash-sweep `.sys` across the fleet;
T1055 injection → sandbox the region, correlate 4688). An n8n workflow is just the automation of
those steps; the *decision* of what is actionable was made by the audited product, not by n8n.

**Discipline:** if a finding-to-action step surfaces something new (e.g. an enrichment flags a
second host), that is a **new lead**, not a Finding. Re-run the typed DFIR tools against it and
cite a real `tool_call_id` before it becomes evidence. n8n informs where to look next; the
product proves what happened.

---

## Verify

```bash
claude mcp list                      # n8n-mcp → ✓ Connected
curl -s http://localhost:5678/healthz   # n8n instance up
```

In a Claude Code session, confirm the tools are reachable with `/mcp`, then exercise a round
trip: ask the agent to build a trivial "read verdict.json → print summary" workflow with
`n8n-mcp`, deploy it, and trigger it against a finished `tmp/auto-runs/<case-id>/verdict.json`.

---

## How an operator uses it

- **Repeatable runs.** Wrap `scripts/find-evil-auto <evidence>` in an n8n workflow so a dropped
  image kicks off the headless single-shot run, then routes the resulting `verdict.json` to the
  fan-out above — all started from Claude Code.
- **Finding-to-action fan-out.** On `SUSPICIOUS` verdicts, auto-notify, open the ticket, and
  enrich IOCs; on `INDETERMINATE`, route to an analyst queue; on `NO_EVIL`, file the scope note.
- **Pair with Engram.** Engram grounds your tradecraft against `docs/references/` while you triage
  (see the Engram runbook's "Grounding against `docs/references/`" section); n8n executes the
  downstream actions once the verdict is signed.

---

## What this runbook does NOT do

- It does not modify the committed `.mcp.json` / `.mcp.json.sift` (n8n is optional, user-scope).
- It does not add n8n to the investigation flow, the audit chain, the 31-tool count, or
  `docs/architecture.md`.
- It does not make n8n the orchestrator — Claude Code remains the A2 orchestrator; n8n is the
  downstream automation envelope.
- It does not bundle n8n, `n8n-mcp`, or any `n8n-references/` clone into the submission (all
  `.gitignore`'d).
