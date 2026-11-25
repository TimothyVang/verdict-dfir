# AGENTS.md — Roles and Routing

Under Amendment A2 the agent runtime is Claude Code itself; the
roles below are spawned as subagents via Claude Code's native Task
mechanism from a single supervisor session. (`CLAUDE_CODE_FORK_SUBAGENT=1`
is a build-time internal and is not used in this product.) They are conceptual roles, not
separate processes — each one runs the same Claude with a
narrowly-scoped system prompt.

## supervisor
Owns the investigation plan. Reads `agent-config/PLAYBOOK.md` to pick
the per-evidence-type tool sequence, decomposes goals into sub-tasks
across Pool A and Pool B, dispatches the pools in parallel, then
calls verifier → judge → correlator → manifest_finalize (terminal
step under Amendment A5). Never touches evidence directly; only
dispatches and merges.

**Evidence location.** Live-run evidence is the gitignored `evidence/`
directory at the repo root (override with `$FINDEVIL_EVIDENCE_ROOT`; see
`evidence/README.md`). A fresh git worktree's `evidence/` is empty — pass an
explicit path or set `$FINDEVIL_EVIDENCE_ROOT`. Never fabricate, stub, or mock
evidence for a run; if `evidence/` is empty, say so and ask for a path rather
than substituting.

**Memory-store path resolution (do this once at session start, before
forking subagents):** the cross-case memory SQLite file lives at
`$FINDEVIL_MEMORY_STORE` if set, else `$XDG_STATE_HOME/findevil/memory.sqlite`,
else `$HOME/.local/state/findevil/memory.sqlite` on POSIX or
`%LOCALAPPDATA%\findevil\memory.sqlite` on Windows. Resolve the
absolute path once via the `Bash` tool, remember it as the session
constant `MEMORY_STORE_PATH`, and pass it as `store_path=` to every
`memory_remember` / `memory_recall` call (Pool A, Pool B, and any
forked subagent that needs to consult prior cases). The file is
created on first write.

## Pool A — persistence-biased
Investigates the evidence assuming the attacker is *staying*. Uses
the typed MCP surface to look at:
- Run keys, RunOnce, Services (`registry_query`)
- Scheduled tasks (`evtx_query` event ID 4698, `registry_query`)
- WMI subscriptions, IFEO debugger hijacks (`registry_query`)
- LSASS-resident modules, driver tampering (`vol_pslist` +
  `vol_psscan` + `vol_psxview` + `vol_malfind`)
- Prefetch + Amcache for execution provenance (`prefetch_parse`)

Pool A's bias means it weights persistence-shaped evidence higher
in confidence. Run the tools; emit Findings with `pool_origin=A`.

**Cross-case memory (per-Finding):**
- *Before* drafting a Finding, call `memory_recall(store_path=MEMORY_STORE_PATH,
  query=<the IOC, hash, TTP code, or hostname you'd cite>)`. Non-empty
  hits become a `prior_observations: [{case_id, ts, confidence}, …]`
  field on the Finding. Empty hits are also informative — note "no
  prior observations" in the Finding's reasoning so the analyst can
  see the recall happened.
- *After* the judge marks a Finding `CONFIRMED`, call
  `memory_remember(store_path=MEMORY_STORE_PATH, case_id=<this case>,
  kind=<ttp|hostname|finding_summary>, key=<short id>, value=<full text>,
  sha256=<sha256:...>)` so future Pool A invocations on different cases
  can recall it. Pool A's typical kinds: `ttp` (e.g. `T1547.001`),
  `hostname` (the persisted box), `finding_summary` (one-line of the
  persistence mechanism). Skip for HYPOTHESIS-tier — the chain only
  remembers things we'd stand behind.

## Pool B — exfiltration-biased
Investigates assuming the attacker is *taking something*. Looks at:
- Staging directories, archive creation patterns (`mft_timeline`,
  `usnjrnl_query`)
- `certutil` / `bitsadmin` / `Invoke-WebRequest` execution
  (`evtx_query` 4688, `prefetch_parse`)
- Large-file rename-then-delete patterns (`usnjrnl_query`)
- USB writes, removable-media events (`evtx_query`)
- Suspicious outbound endpoints in EVTX or memory
  (`vol_pslist` cmdlines, `evtx_query` 5156)

Same MCP surface, different reasoning prior. Emit Findings with
`pool_origin=B`. The two pools run in parallel and may cite the
same `tool_call_id` with different confidence labels — that's a
contradiction, surfaced before the judge.

**Cross-case memory (same recall-before / remember-after policy as
Pool A):** Pool B's typical `memory_remember` kinds skew toward `ioc`
(C2 domains, IPs, URLs), `hash` (staged binary hashes, archive
hashes), and `finding_summary` (one-line of the exfil mechanism).
Use `memory_recall` whenever you're about to cite an IOC / hash /
TTP. A prior-case hit adds prioritization and context, but it is not
current-case evidence and must not upgrade a HYPOTHESIS into an
INFERRED Finding by itself.

## verifier
Re-runs every Finding's cited `tool_call_id` via the
`verify_finding` MCP tool. The verifier spawns its own short-lived
findevil-mcp child process; output's SHA-256 must match the
original audit-log entry byte-for-byte. **Veto power:** any
Finding without a `tool_call_id` is rejected outright.
Disagreement on hash means the cited tool was re-run with the
same args and produced a different output — the verifier
downgrades or rejects depending on severity.

**Structured handoff to the judge:** after each verifier verdict
(approved / downgraded / rejected), call `pool_handoff(audit_path=
<case audit.jsonl>, from_role="verifier", to_role="judge",
payload={finding_id, action, replay_record_sha256})`. This records
a `kind="acp_handoff"` line in the audit chain so the judge
receives structured verifier output instead of a natural-language
message — the IBM-ACP envelope's `correlation_id` lets the judge
group all verifier decisions for one finding when the verifier
re-runs after a downgrade.

## judge
Calls `judge_findings` MCP tool. Credibility-weighted merge: each
pool's score = `base_confidence × pool_credibility`. Pools that
produced corroborating CONFIRMED findings build credibility;
pools that produced HYPOTHESIS-only get downweighted. Output is a
merged list with reconciled confidence labels and a per-Finding
explanation of which pool contributed what.

## correlator
Calls `correlate_findings` MCP tool. Enforces the SOUL.md ≥2
artifact-class rule: any "X executed" Finding must cite ≥2 distinct
artifact classes (Prefetch + Amcache+ShimCache, or EDR + memory).
Single-source claims auto-downgrade. Outcome is `kept` or
`downgraded` per Finding with a reason.

When the judge or correlator organically flips a Finding's confidence
tier (for example, a CONFIRMED claim downgraded to HYPOTHESIS on the
≥2 artifact-class rule, or a tier raised on corroboration), commit that
flip as a `verdict_revision` record carrying its own reason. These are
rare by design — a safety net, not a routine step — and are written to
the prev_hash-linked audit chain so the conclusion-change is offline-
verifiable via `manifest_verify` and rendered as the report's
Self-Correction section. Never synthesize a flip to manufacture one.

## Routing rules

- **Persistence questions** → Pool A is the lead, Pool B may
  contradict if it sees evidence the persistence is staging for
  exfil. Resolve via judge.
- **Exfiltration questions** → Pool B is the lead, Pool A may
  contradict if it sees evidence the staging is actually long-term
  storage (no outbound).
- **Both: identity/account questions** → both pools `evtx_query`
  the Security log; Pool A reads it as authentication-persistence
  (account creation, lateral movement to a new host as part of
  staying), Pool B reads it as exfil-precursor (RDP from a host
  that just downloaded a tool).
- **Live-process questions** → both pools run `vol_pslist` +
  `vol_psscan` + `vol_psxview` + `vol_malfind`. Pool A flags processes by
  persistence path (run from `Temp`, lives in `services.exe`
  child tree); Pool B flags them by network behavior (cmdline
  contains internet IPs, has open sockets).
- **Report assembly** → supervisor, gated by verifier. Verifier
  rejects → supervisor re-dispatches (one retry, then escalates
  the Finding to HYPOTHESIS).

## Cross-case memory + structured handoff (A3 §2.2 / §2.3)

Three MCP tools added in Amendment A3 give the army (a) prior-case
recall and (b) a structured agent-to-agent channel distinct from
Claude Code's natural-language messaging:

| Tool | Caller | Purpose |
|---|---|---|
| `memory_recall` | Pool A, Pool B (and judge, if cross-checking) | "Have we seen this IOC / hash / TTP before?" Returns prior-case hits ranked by BM25 × 90-day decay. Phrase-match semantics — pass single tokens or exact phrases. |
| `memory_remember` | Pool A, Pool B (post-CONFIRMED) | Seeds the cross-case index for future investigations. CONFIRMED-tier only; HYPOTHESIS doesn't get remembered. |
| `pool_handoff` | verifier → judge (always); Pool A → Pool B (when handing exfil-staging context); supervisor → any role (when assigning a structured task) | IBM-ACP envelope written to the audit chain as `kind="acp_handoff"`. Use the `correlation_id` to thread replies across multiple handoffs about one finding. |

The store path is the `MEMORY_STORE_PATH` constant the supervisor
resolves once at session start (see the supervisor section).
Forked subagents inherit the path via the prompt the supervisor
passes when forking.

## Why this structure (Heuer's ACH applied as agent topology)

A consensus-seeking single-agent architecture would resolve
contradictions internally — invisible to the analyst. Find Evil's
Pool A + Pool B + judge surfaces the disagreement as a
first-class output (`kind=contradiction` audit record) BEFORE
reconciliation. The analyst sees both arguments and the
reconciliation; they can override the judge if they think Pool A
or B was right.

This is not a multi-LLM voting trick. It's Heuer's 1999 *Psychology
of Intelligence Analysis* operationalized: structure the reasoning
to disprove hypotheses, not to confirm them.
