# Runbook: n8n Finding-to-Action Automation (Optional)

**Status: ACTIVE**
**Scope: optional operator tooling — not part of the Find Evil! submission surface.**

[n8n](https://github.com/n8n-io/n8n) is a workflow-automation engine. This runbook wires it in
as an **operator-local orchestration harness *around* the product**: it automates repeatable
investigation runs and the **post-verdict finding-to-action fan-out** (notify / ticket /
IOC-enrich / fleet-sweep). It runs **downstream of the scored investigation** — it does **not**
become the investigation orchestrator, touch the typed evidence-tool surface, or enter the
audit/crypto chain. Claude Code remains the product orchestrator (Amendment A2).

This runbook is the canonical home for the optional post-verdict automation: n8n automates what
happens after the verdict is signed.

---

## Integration decisions (what this runbook assumes)

| Decision | Choice | Implication |
|---|---|---|
| Role | **Operator harness around the product** | n8n orchestrates repeatable runs + finding-to-action; it is **not** wired into Pool A/Pool B and is **not** the A2 orchestrator. Claude Code still starts everything. |
| Where it sits in the flow | **Downstream of `verdict.json`** | n8n consumes the *output* of a finished, audited investigation (`manifest_finalize` → `verdict.json`). It never feeds the scored path. |
| Integration surface | **`n8n-mcp` (MIT), user-scope MCP server** | Claude Code uses `n8n-mcp` to build/validate/deploy n8n workflows and trigger runs. The 45-tool product surface is untouched. |
| Submission posture | **Optional, not bundled** | Treated like the SIFT DFIR binaries: operator wires it in; `n8n-references/` is `.gitignore`'d and never enters the Devpost zip. |
| Where it runs | **Local host only** | The operator's own n8n instance + `n8n-mcp` run on the host. SIFT-VM mode still reaches DFIR tools over SSH; n8n stays local. |
| License | **n8n core = fair-code (Sustainable Use), `n8n-mcp`/`n8n-skills` = MIT** | n8n core is **not** OSI MIT/Apache, so it must **never** be bundled or linked into the Apache-2.0 submission. Keeping it optional/operator-run/standalone is what makes this compliant. |

---

## License & submission compliance

The submission must ship under the repo license boundary (`LICENSE`). n8n core ships under the **fair-code
Sustainable Use License** (`n8n-references/n8n/LICENSE.md` + `LICENSE_EE.md`) — permissive for
self-hosted internal use, but **not** an OSI permissive license. Therefore:

- **Never bundled, never linked.** `n8n-references/` is `.gitignore`'d. `scripts/package-devpost.sh`
  does not include it. The operator runs their **own** n8n instance from upstream; nothing in
  `services/` imports or vendors n8n.
- **`n8n-mcp` and `n8n-skills` are MIT** (`n8n-references/n8n-mcp/LICENSE`,
  `n8n-references/n8n-skills/LICENSE`) — safe to reference, still kept optional/standalone.
- **Not in the judge-facing required docs.** `docs/architecture.md` (Devpost Required Component
  #3) intentionally does **not** mention n8n — the submission surface is the 45-tool typed
  product. This runbook is the canonical home for n8n integration.
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
`N8N_OWNER_PASSWORD`, `N8N_AUTO_DOCKER=1`. Skip from install with
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

**Why user scope, not the repo `.mcp.json`:** SIFT mode uses `.mcp.json.sift` for the two
product servers' SSH transport. A user-scope server lives in
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

## The grounding workflow (anti-hallucination) — `findevil-grounding`

The second, higher-value seam. Where finding-to-action *acts* on a verdict, grounding *checks*
one: it researches the verdict's MITRE-technique claims against authoritative sources and flags
the ones the sources do not support — the likely-hallucination surface. Same one-directional,
post-verdict, never-evidence posture as above.

```
verdict.json ──► scripts/ground_verdict.py (host) ──► POST findevil-grounding (n8n)
                        │                                    │
                        │                       browserless renders attack.mitre.org
                        │                       (structured extract: name + excerpt + provenance)
                        ▼                                    │
        grounding_research.json  ◄───── research_bundle (no LLM in n8n) ──┘
                        │
                        ▼  Claude Code judges in-session (agent-config/GROUNDING.md)
                  grounding.json   { per-claim: supported | contradicted | unsupported | unknown,
                                     quoted source excerpts, possible_hallucination flag }
```

**Why n8n carries no LLM.** The workflow only fetches and *structures* public sources. Claude
Code is the brain: it reads the bundle and renders the per-claim verdict itself (no Anthropic key,
no `claude -p`). This keeps the judgment in the audited agent, not in an opaque automation step.

**Run it (Phase 1, keyless):**

```bash
python3 scripts/setup-grounding-workflow.py          # self-bootstraps: findevil-net + browserless + deploy
python3 scripts/ground_verdict.py <case-dir|case-id> # writes <case>/grounding_research.json
# then, in a Claude Code session: judge the bundle per agent-config/GROUNDING.md -> <case>/grounding.json
```

**Networking.** browserless is host-bound at `127.0.0.1:3000`; n8n reaches it container-to-container
as `http://browserless:3000` over the shared `findevil-net` network. `setup-grounding-workflow.py`
creates the network, starts browserless on it, and attaches a running n8n container — idempotently.

**Anti-hallucination contract (locked by `scripts/grounding-smoke.py`):**
- a real technique grounds (`found: true`, name + quoted MITRE excerpt);
- a bogus id is rejected (`found: false`) — MITRE's 404 page does not name it;
- a renumbered id is surfaced (`id_match: false`, `mitre_id` = the id MITRE now serves) rather
  than silently passed or dropped;
- fetched web text is **untrusted DATA** — n8n returns structured-extract only (tags stripped,
  excerpt length-capped), and the judge treats any embedded instructions as inert (GROUNDING.md);
- **quote-or-`unknown`:** no claim is `supported` without a verbatim excerpt from an allowlisted
  authoritative source.

**Boundary (same as the whole runbook).** `grounding_research.json` and `grounding.json` are
post-verdict sidecars — never a `tool_call_id`, never appended to `audit.jsonl`, never in
`run.manifest.json`, and they never change a finding's Confidence or the Verdict (frozen at
`manifest_finalize`). The grounding smoke asserts the chain is byte-unchanged after a run.

## IOC reputation enrichment (host-side, multi-source)

Alongside technique grounding, `ground_verdict.py` enriches the verdict's typed IOCs
(`malware_triage.aggregate_iocs` — hashes/domains/ips/urls, never a blind regex) against
**multiple sources — VirusTotal v3 and abuse.ch (ThreatFox / MalwareBazaar / URLhaus)** — and
writes an `ioc_enrichment` block (per-IOC `sources[]`, one record per provider) into
`grounding_research.json`. The judge then records per-IOC `malicious | clean | unknown` in
`grounding.json` (`ioc_grounding[]`), surfaced in the dashboard GroundingPanel.

**Multi-source corroboration + conflict resolution.** Agreeing sources strengthen `malicious`;
when sources conflict (e.g. VirusTotal 0/91 clean on a major domain vs a single ThreatFox
botnet_cc hit on google.com), the judge resolves by **breadth of consensus** — the domain is
benign infrastructure abused by malware, judged `clean` with the conflict noted, both sources
quoted (`agent-config/GROUNDING.md`).

**Enrichment runs HOST-SIDE, not in n8n.** n8n persists execution inputs in its database, so
routing an API key through the webhook would leak the secret into n8n's execution store.
VirusTotal/abuse.ch are plain JSON APIs (no browser needed), so the host calls them directly and
keys never leave the gitignored files. n8n stays the **browser-rendered-research** engine (MITRE
now, open-web search later) where the value is rendering untrusted HTML and no secret is involved.

**Keys (browser login):** `scripts/get-api-key.cjs <provider>` opens **real Google Chrome** with
the automation fingerprints stripped (so Google SSO is not blocked), waits for the operator to
sign in, then reads the API key off the account page → gitignored `tmp/api-keys/<provider>.txt`
(or set `VT_API_KEY` / `ABUSECH_API_KEY`). VirusTotal: key shown directly. abuse.ch: requires a
completed profile (unique username + display name → Create Profile) before **Generate Key** issues
an Auth-Key — shown **once** ("not viewable again"), so capture/copy it then. Same boundary:
enrichment results are an operator aid, never evidence.

## Open-web research (self-hosted SearXNG, keyless)

For corroboration beyond the authoritative APIs, the workflow does keyless open-web research.
Public SERPs block headless browsers (DuckDuckGo returns an anomaly challenge, Bing serves
unreliable redirect-wrapped results), so we run **our own search engine**: a self-hosted
**SearXNG** container on `findevil-net` (JSON output, no upstream blocking for low-volume
grounding; `setup-grounding-workflow.py` bootstraps it idempotently). The research node queries
SearXNG → takes the top result URLs → renders the top hits via browserless → structured-extracts
`{title, snippet, excerpt, url}` (scripts/styles stripped, length-capped). `ground_verdict.py`
seeds queries from malware families surfaced by IOC enrichment, then asserted-technique claims.

Open web is the **lowest-trust** tier: inert DATA, never authoritative, never makes a claim
`supported` on its own — it adds context the analyst can follow (e.g. a Recorded Future write-up
of the malware family). Same boundary: operator aid, never evidence.

## Grounding-aware action routing (supersedes finding-to-action)

`scripts/ground_actions.py` reads the judged `grounding.json` and derives **recommended** next
actions keyed off the grounding statuses + the verdict word: a `supported` technique on a
`SUSPICIOUS` verdict or a `malicious` IOC routes to **act** (the per-technique IR step from
`docs/finding-to-action.md`, a fleet hunt for the IOC); a `possible_hallucination`,
`contradicted`, or `possible_overclaim` routes to **review** (re-examine — never auto-act). Every
action is `auto: false` (human-in-the-loop) and written into the `grounding.json` sidecar; the
dashboard shows a "Recommended actions" section. This **replaces** the old
`findevil-finding-to-action` n8n workflow (whose in-node `fs.writeFileSync` is disallowed on
n8n 2.x); `setup-n8n.py` no longer deploys it, but still provisions the n8n owner + API key the
grounding workflow needs.

## CVE/NVD grounding (engine tag + NVD validation)

The verdict engine (`find_evil_auto.py`) tags findings with CVE ids that **literally appear** in
their text (`finding.cves[]` — purely additive, no inference, no verdict impact; locked by
`verdict-policy-smoke`). Post-verdict, `ground_verdict.py` validates each id against the keyless
**NVD** JSON API → `cve_research` ({description, CVSS, severity}); the judge records
`cve_grounding[]` (supported / unsupported / unknown). A finding citing a CVE id NVD does not
recognize is flagged `possible_hallucination`. CVSS is severity **context, not proof** the CVE was
exploited on this host. The dashboard shows a "CVE grounding" section.

## Auto-run + headless judging

`scripts/verdict` runs grounding automatically after the verdict (right after the `n8n_post.py`
hook): when n8n is reachable it calls `ground_verdict.py` then `ground_actions.py` — **non-fatal**,
gated on a `/healthz` check, and skippable with `FINDEVIL_SKIP_GROUNDING=1`. Because an unattended
run has no agent in the loop, `ground_verdict.py` writes a **deterministic first-pass**
`grounding.json` (technique on MITRE → supported / not on MITRE → contradicted+flag; provider-
flagged IOC → malicious; CVE on NVD → supported; `judged_by` says "deterministic first-pass") so
the dashboard populates headless. It is **non-clobbering** — an existing agent-judged
`grounding.json` is never overwritten; a Claude Code session refines the first-pass per
`agent-config/GROUNDING.md`. `scripts/doctor.sh` reports grounding-infra readiness (n8n +
browserless + searxng).

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

- **Repeatable runs.** Wrap
  `scripts/verdict <evidence> --no-dashboard --unattended --run-summary tmp/run-summary.json`
  in an n8n workflow so a dropped image kicks off the non-interactive single-shot run, then routes
  the resulting `verdict.json` to the fan-out above — all started from Claude Code.
- **Finding-to-action fan-out.** On `SUSPICIOUS` verdicts, auto-notify, open the ticket, and
  enrich IOCs; on `INDETERMINATE`, route to an analyst queue; on `NO_EVIL`, file the scope note.

---

## What this runbook does NOT do

- It does not modify the committed `.mcp.json` / `.mcp.json.sift` (n8n is optional, user-scope).
- It does not add n8n to the investigation flow, the audit chain, the 45-tool count, or
  `docs/architecture.md`.
- It does not make n8n the orchestrator — Claude Code remains the A2 orchestrator; n8n is the
  downstream automation envelope.
- It does not bundle n8n, `n8n-mcp`, or any `n8n-references/` clone into the submission (all
  `.gitignore`'d).
