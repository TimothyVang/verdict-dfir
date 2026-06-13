# CLAUDE.md

This file guides Claude Code (claude.ai/code) when working in this repository. Under
**Amendment A2** (active) Claude Code IS the Product's primary interface — when a SANS judge
runs `scripts/find-evil` or `claude` from this repo, the session you are reading is what
executes the investigation. CLI binary is `claude`.

> This file is the load-bearing core. Bulky reference material lives in linked docs:
> onboarding behavior → `docs/onboarding.md`; commands & the live-test gate →
> `docs/live-test-matrix.md`; repo layout, subsystems, amendment history →
> `docs/repo-guide.md`; judge-facing trust boundaries → `docs/architecture.md`;
> the full MCP/tool/dependency/env inventory → `docs/reference/`; how to run the product →
> `docs/using/`; the dev/operator memory layer → `docs/runbooks/obsidian-mind-memory.md`.

---

## 0. What VERDICT is

VERDICT is a DFIR agent. Point it at digital evidence and it produces a signed **Verdict** —
*is there evil here?* — plus a report. There is no separate app server: **Claude Code IS the
engine.** When you run `claude` in this repo and investigate evidence, *this session* is the
forensic analyst.

**Workflow, one line:** drop evidence into `evidence/` → run `scripts/verdict` → watch the
live dashboard at `http://localhost:3000` → read the Verdict in
`tmp/auto-runs/<case-id>/verdict.json` and `REPORT.pdf`.

**Two ways to run it:**
- **Hands-free:** `scripts/verdict <evidence>` (or `scripts/verdict --watch`, then drop a file into `evidence/`).
- **Interactive:** `claude` (or `scripts/find-evil`), then prompt `investigate <path>`.

**Three Verdicts** (full semantics in `docs/verdict-semantics.md`):
- `SUSPICIOUS` — found something; triage now.
- `INDETERMINATE` — saw leads, couldn't corroborate them; review when convenient.
- `NO_EVIL` — scoped-clean *within what was actually examined*; never "definitely safe."

**Under the hood.** `case_open` SHA-256s the evidence and opens a **Case**; it forks **Pool A**
(persistence) and **Pool B** (exfil), which drive the typed, read-only MCP tools (31 Rust +
12 Python). Every **Finding** must cite a `tool_call_id`. The whole run is sealed into a
hash-chained, signed manifest you can verify offline.

To confirm the tool works on your evidence, run a **live test** (`docs/live-test-matrix.md`) —
a real investigation against real evidence is the verification standard, not a smoke run.

### Session-start onboarding (behavioral)

Run these silently, once per session, before the first tool call. Full text in
**`docs/onboarding.md`** — read it when any of these fire:

- **Preflight check** — verify `claude` CLI, Rust/uv/Node/pnpm, the MCP server binary, and
  the agent-mcp env. Print a one-line summary; offer to fix failures. Block only on `claude`
  CLI plus at least one of Rust OR Python missing; don't block on optional deps. (Checklist
  table in `docs/onboarding.md`.)
- **Fresh clone** — if `target/release/findevil-mcp` does NOT exist, run `bash scripts/install.sh` automatically; on failure report the exact error line and stop.
- **Greeting / `help`** — show the welcome block ONLY when the user's first message is `help`, `hello`, `hi`, or "what can you do" / "how do I use this" / "what is this". Print the quick-reference block only on `help`. Both blocks live in `docs/onboarding.md`.
- **First-run setup** — if the user's first message is `setup`, `i'm new`, `im new`, or `new`, run `bash scripts/setup`, read `tmp/setup-state.json`, and complete any browser-only gated downloads (the SANS SIFT OVA) via the Puppeteer MCP. Full steps in `docs/onboarding.md`.
- **Browser links** — a browser MCP server (Playwright/Puppeteer) is registered. Always *offer* to open relevant URLs (localhost dashboard, GitHub, generated `REPORT.html`, Remotion preview) via `mcp__playwright__browser_navigate` instead of just printing them. Auto-open `http://localhost:3000` once the dashboard dev server is listening.

---

## 1. Mission

This is the SANS **Find Evil!** hackathon submission (deadline **2026-06-15 11:45 PM EDT** = 22:45 CDT).

> **Canonical public repo:** [`github.com/TimothyVang/verdict-dfir`](https://github.com/TimothyVang/verdict-dfir) — public, Apache-2.0, single `master` branch, email-clean history. The `v-submit` release hosts the demo video + submission zip + report. (The local working directory is still named `sans-hackathon`; the earlier `TimothyVang/sans-hackathon` repo is the original and is superseded by this one for submission.)

Two modes:

- **Agent mode** — a user opens `scripts/find-evil` / `claude` and asks `investigate <case path>`. You are the SANS Find Evil! DFIR agent: supervisor over Pool A (persistence) + Pool B (exfil) subagents, driving the typed MCP tool surface, emitting Findings that cite a `tool_call_id`, producing a hash-chained audit log.
- **Dev mode** — a developer asks you to read/write code. Follow the four coding principles (§6) and conventions (§7). The dev "done" gate is a passing **live test**, not a smoke run.

If a prompt fits *either* mode, finish reading this file before acting.

---

## 2. Agent investigation prompt (read these files in order)

When the user asks you to **investigate `<case path>`**, read these in order — they encode
mission, identity, and hard rules you MUST NOT violate:

1. **`agent-config/SOUL.md`** — purpose; epistemic hierarchy (CONFIRMED > INFERRED > HYPOTHESIS); FRE 902(14) self-authenticating-evidence stance; strict cross-artifact rule for execution claims; no-attribution rule.
2. **`agent-config/AGENTS.md`** — supervisor / Pool A / Pool B / judge / verifier / correlator roles. You are the supervisor; the two pools are forked as subagents via Claude Code's native Task mechanism (not `CLAUDE_CODE_FORK_SUBAGENT=1`, a build-time internal not used in this product).
3. **`agent-config/PLAYBOOK.md`** — investigation tool sequences per evidence type. Defaults, not laws — deviate when the case shape diverges and log the deviation.
4. **`agent-config/TOOLS.md`** — the typed tool surface (Rust `findevil-mcp` + Python `findevil-agent-mcp`).
5. **`agent-config/MEMORY.md`** — Tier-1 DFIR caveats (Amcache LastModified ≠ execution, ShimCache order changed at Win8.1, EVTX Logon Type 3 vs 10, etc.).
6. **`agent-config/EXPERT.md`** — 99% automation / 1% expert-signoff doctrine; report QA rules turn expert edits into playbooks, connectors, or gates.
7. **`agent-config/HEARTBEAT.md`** — the per-iteration self-check loop.

> `agent-config/JUDGING.md` is **not** part of this read-order. It is the pre-submission
> self-assessment rubric, graded after a run by `scripts/self-score.py` — a separate manual
> step, never part of the product flow, dashboard, or demo.

**Investigation flow:** `case_open` → split into Pool A + Pool B subagents → each pool runs
DFIR tools and emits Findings (each citing a `tool_call_id`) → `detect_contradictions` →
analyst resolves → `verify_finding` re-runs each cited tool → `judge_findings`
(credibility-weighted merge) → `correlate_findings` → `manifest_finalize` (signs the run).

---

## 3. Non-negotiable invariants

Violating any of these breaks the judging story or an integration contract.

- **No `execute_shell` MCP tool, ever.** The Rust surface is deliberately narrow (31 typed tools — the long-tail verbs `vol_run`/`ez_parse`/`plaso_parse`/`mac_triage` are allow-listed parameterized verbs, not shells: an off-list plugin/tool/module/parser name is rejected before argv; the single-purpose subprocess wraps `journalctl_query`/`login_accounting`/`ausearch`/`nfdump_query`/`suricata_eve`/`indx_parse` take a typed path + fixed argv, never a shell). Adding shell pass-through undoes the "reduces the attack surface" pitch. The 31 Rust + 12 Python product tools are the only verbs in the audit chain; the non-product servers `.mcp.json` also registers (`n8n-mcp`/`playwright`/`puppeteer`/`qmd`) never touch evidence and never emit Findings.
- **Every Finding cites a `tool_call_id`.** The verifier vetos any Finding without one. UI chips render `[confirmed · tool · sha256]` per finding.
- **Epistemic hierarchy is strict.** `CONFIRMED` (backed by tool output) > `INFERRED` (≥2 confirmed facts, labeled) > `HYPOTHESIS` (prefixed "hypothesis:"). Nothing else is legal.
- **Execution claims need ≥2 artifact classes** (Prefetch + Amcache+ShimCache, or EDR telemetry). Amcache alone is insufficient — it's catalog-registration time, not execution.
- **Evidence is read-only.** Original `.e01` opened via libewf; write-only working dir elsewhere. No tool mutates evidence. SHA-256 verified at `case_open`.
- **Hash-chained audit JSONL is append-only.** Each line has `prev_hash`. Chain is **3 tiers** post-A5 (audit prev_hash → rs_merkle → manifest signature: Ed25519 default, Sigstore identity tier when configured); the 4th OpenTimestamps/Bitcoin tier was removed. See `docs/cryptographic-attestation.md`.
- **AGPL/GPL tools (Hayabusa, Chainsaw, Volatility3, Velociraptor, YARA) are subprocess-only — never linked.** Linking contaminates the submission license (must be MIT or Apache-2.0).
- **All timestamps UTC, ISO-8601, trailing `Z`.** SHA-256 preferred over MD5. Never assert attribution.
- **Judge narrative:** "orchestrator that reduces friction," never "autonomous responder" (Rob Lee's explicit preference).
- **Replay evidence is a customer-PDF blocker.** `verify_finding_replay_embedded` is a blocker in `agent-config/expert-rules.json` and `scripts/find_evil_auto.py`. Do not downgrade without an explicit policy change.

---

## 4. Tool surface

Two MCP servers registered in `.mcp.json`, auto-spawned on session start. Full per-tool list
in `agent-config/TOOLS.md`.

| Server | Lang | Count | Scope |
|---|---|---|---|
| `findevil-mcp` | Rust (`services/mcp/`) | 31 | DFIR primitives: `case_open`, disk mount/extract/unmount, evtx/mft/usnjrnl/registry/prefetch, hayabusa, vol_pslist/psscan/psxview/malfind, yara, vel_collect, browser_history, sysmon/zeek/pcap, **+ 5 allow-listed generic verbs: `vol_run` (Vol3 plugin), `ez_parse` (Eric Zimmerman), `plaso_parse` (log2timeline), `mac_triage` (mac_apt), `cloud_audit` (CloudTrail/Entra/M365/GCP/k8s/VPC)**, **+ 6 single-purpose subprocess wraps: `journalctl_query`, `login_accounting`, `ausearch` (Linux host), `nfdump_query`, `suricata_eve` (network), `indx_parse` ($I30/INDX)**. Read-only on evidence; SHA-256 every output. |
| `findevil-agent-mcp` | Python (`services/agent_mcp/`) | 12 | Crypto/ACH: audit_append/verify, manifest_finalize/verify, verify_finding, detect_contradictions, judge_findings, correlate_findings. Memory: memory_remember/recall. ACP: pool_handoff. Expert: expert_miss_capture. |

`.mcp.json` registers **4 additional non-product servers** — `n8n-mcp` (post-verdict automation),
`playwright`, `puppeteer` (browser tasks), and `qmd` (obsidian-mind dev-memory recall) — that are
**not in the audit chain and emit no Findings**. So `.mcp.json` has 6 servers total while the
product surface is 43 tools; neither number contradicts the other. Full server + dependency
inventory: `docs/reference/mcp-and-tools.md` and `docs/reference/dependencies.md`.

**DKOM redundancy is intentional.** `vol_pslist` walks the active list; `vol_psscan`
signature-scans EPROCESS pool memory; `vol_psxview` cross-references process views.
Divergence is the classic DKOM / T1014 signal — but disambiguate from an acquisition smear /
kernel-global read failure (psscan-only OS singletons, duplicate `System` EPROCESS,
`KeNumberProcessors`=0) before asserting T1014. Don't fold them.

**Entry points.** `scripts/verdict <evidence>` is THE entry point (preflight → investigate →
dashboard → signed verdict + report; `--sift` runs DFIR tools in the SIFT VM, `--fleet` runs a
whole multi-host case folder end to end — auto-detected on a `hosts/`/`disks/` layout —
`--no-dashboard` skips the browser; output in `tmp/auto-runs/<case-id>/`). Interactive: `claude` /
`scripts/find-evil` then `investigate <path>`. Headless engine: `scripts/find_evil_auto.py`.
Offline manifest verification: the `manifest_verify` MCP tool. SIFT setup and the full
command catalog are in `docs/live-test-matrix.md` and `docs/repo-guide.md`; operator usage
(every flag, watch mode, the fleet pipeline, output layout) is in `docs/using/running-verdict.md`
and `docs/using/fleet-analysis.md`.

---

## 5. Commands

The canonical command catalog (live-test gate, smoke runners, Rust/Python/Next.js, readiness
gates, sandbox layers, CI) lives in **`docs/live-test-matrix.md`**. `QUICKSTART.md` is the
3-step quick start. Don't hard-code smoke counts — the runners print the current tally.

**The dev "done" gate** is a passing live test, summarized: `scripts/verdict <path>` must run
past `case_open`, every Finding must cite a `tool_call_id`, `manifest_verify.json.overall`
must be `true`, and the Verdict word must be honest about coverage (an `INDETERMINATE` on a
custody-only disk is a PASS). Full PASS criteria and the per-evidence-type matrix:
`docs/live-test-matrix.md`.

**Test evidence vs. scored benchmarks (don't conflate the two).** `evidence/` is the ad-hoc
live-run drop zone — pass an explicit path per case (`scripts/verdict evidence/<file>`); never
run with no path when it holds multiple unrelated cases. `fixtures/<case>/` is the *scored*
benchmark corpus, paired 1:1 with `goldens/<case>/expected-findings.json` and graded by
`scripts/score-recall.py`. The split is **enforced**: `scripts/fetch-fixtures.sh` aborts if
`FIXTURES` resolves under `evidence/`. A **golden is an answer key** — only author one when a
real published ground truth exists (NIST key, scenario solution); competition cases whose briefs
are mere *background* (ROCBA, base-dc, SANS starter) are **live-run-only, not scoreable**. Never
fabricate a golden. Full corpus inventory, the SANS Egnyte download mechanism, and per-dataset
recall results: `docs/DATASET.md`.

---

## 6. How to code in this repo (four principles)

Adapted from Karpathy's observations on LLM coding pitfalls. Bias toward caution over speed;
for trivial tasks use judgment.

**1. Think before coding.** State assumptions explicitly. If multiple interpretations exist, present them — don't pick silently. If something is unclear, stop, name it, ask. Under A2, *every* tool call is on someone's evidence — uncertainty must surface.

**2. Simplicity first.** Minimum code that solves the problem. No features beyond what was asked, no speculative abstractions, no error handling for impossible scenarios. If 200 lines could be 50, rewrite. Would a senior DFIR engineer say this is overcomplicated?

**3. Surgical changes.** Touch only what you must. Don't "improve" adjacent code or refactor what isn't broken. Match existing style. Note unrelated dead code; don't delete it. Remove only imports/variables *your* changes made unused. Every changed line traces to the request.

**4. Goal-driven execution.** Turn tasks into verifiable goals ("add a tool" → typed I/O + failing integration test + boundary error tests, then make them green). State a brief plan for multi-step work and verify each step.

Working when: diffs are small and focused, fewer rewrites, clarifying questions come *before*
implementation rather than after mistakes.

---

## 7. Conventions

- **TDD loop is mandatory for every plan task.** Failing test → RED → implement → GREEN → commit with the exact message the plan specifies. One commit per plan task; never batch.
- **Conventional Commits:** `feat(scope):`, `test(scope):`, `chore(scope):`, `fix(scope):`, `docs(scope):`. Existing scopes: `mcp`, `sandbox`, `ci`, `plan`, `amendment A1`.
- **Never use `--no-verify`, `--no-gpg-sign`, or `git commit --amend`** in plan execution. Hook failure → fix root cause → new commit.
- **Pinned dependency versions.** Specs pin exact versions (e.g. `rmcp = "=0.16.0"`, `evtx = "=0.11.2"`). When code already ships a different pin, the shipped pin wins and the spec is the thing to update (see §8).
- **DFIR vocabulary, not software vocabulary.** Use **Case** (not session/run/job), **Observable** (not file/path/blob), **Task** (not step/action), **Finding** (not result), **Verdict** (not conclusion), **Confidence** (not score). Carve-outs: (1) "artifact" is correct DFIR-canonical — "artifact class" (Prefetch/MFT/EVTX/Amcache) is the SOUL.md ≥2-corroboration vocabulary and must NOT become "Observable class"; (2) "hit" is correct for rule-engine matches (YARA hit, Sigma hit); (3) "investigation" is correct as the activity-noun. Unit of work is **Case** (`case_id`); say "the case directory," not "the investigation directory."
- **Python tooling:** `uv` for envs/lockfile; `pytest`; `ruff`. Python 3.11.
- **Rust tooling:** `cargo test --workspace --locked`, `cargo clippy --deny warnings`. Rust 1.88 (rust-toolchain.toml authoritative).
- **Node tooling:** `pnpm --frozen-lockfile`; `tsc --noEmit` in L0; `pnpm test` in L1. Node 20.

---

## 8. Credential modes & spec/code divergences

**Credential modes** (Amendment A1) — `scripts/install.sh` detects three in priority order:
1. `CLAUDE_CODE_OAUTH_TOKEN` env var (from `claude setup-token`) — non-interactive, preferred for judges with a subscription.
2. Interactive Claude Code session (`~/.claude/` via `claude auth login`) — dev default.
3. `ANTHROPIC_API_KEY` env var — direct metered API.

**Spec/code divergences — code wins.** Specs were written 2026-04-23; code has shipped since
2026-04-24. Where they disagree, shipped code + its pin files are authoritative. Eight settled
divergences live in `docs/divergences-resolved.md`; the two still-moving items (A5 OTS removal
references in legacy specs; replay-evidence-as-blocker) are in `docs/repo-guide.md`.

---

## 8.5 Memory (dev/operator knowledge layer)

VERDICT has **two memory systems**; keep them straight, and keep the dev/operator one out of
the audit chain.

1. **obsidian-mind vault** (`obsidian-mind/`) — the **primary project/operator memory**: DFIR
   tradecraft, the Tier-1 artifact caveats, architecture decisions, gotchas. Git-tracked markdown
   (`brain/`) with semantic recall via QMD (`mcp__qmd__query`, registered at local scope), curated
   with `/om-*` commands. It is the better successor to the flat `~/.claude/.../memory/` index, but
   it is **never evidence, never in a case `audit.jsonl`, never Merkle-hashed, never a Finding** —
   the same boundary the n8n grounding feature keeps. How-to + the hard boundary:
   `docs/runbooks/obsidian-mind-memory.md`.
2. **Hermes FTS5** — the in-flow **investigation** memory: `memory_remember`/`memory_recall`,
   audit-chained **as process provenance** (when given an `audit_log_path` they record *that*
   recall/remember happened, but the records are never a Merkle evidence leaf and never a
   Finding's `tool_call_id`), part of the product (§4). This is the *only* memory inside the
   investigation; recall hits ride on a Finding as a non-evidentiary `prior_observations` field.

`CLAUDE.md` stays the instruction core; the vault is where evolving knowledge lives.

**Default behavior — use the memory, don't just have it (wired into the repo, no folder switch):**
- **Recall first.** Before answering a question about how this repo works, a past decision, a known
  gotcha, or "how do we usually…", call `mcp__qmd__query` (index `verdict-memory`) and ground the
  answer in what comes back. The SessionStart hook also injects the North Star + brain-topic index
  at the start of interactive sessions (it is gated OFF during `scripts/verdict` investigations).
- **Check the brain notes before debugging.** Hard-won traps live in `obsidian-mind/brain/Gotchas.md`
  (build/CI/crypto pins — yara-x/mft toolchain pins, RFC-8785 canonical JSON, the 3.10-engine
  `execution_claim` mirror, the L3 OVA-name drift, the `tool_call_id`-only enforcement gap, the
  SIFT-fleet-on-Linux fixes — `find-evil-auto` python3, `fleet_correlate.py` snake_case psscan
  fields, the writable VM `vol` symbol cache, HGFS evidence staging); recurring
  engine/MCP mechanics in `Patterns.md`, the architecture "why" in `Key Decisions.md`, and runnable
  scripts/components in `Skills.md`. Consult them before re-debugging a known build/CI/crypto issue.
- **Capture durable facts.** When you learn something that will matter next session (a fix, a
  gotcha, a decision), write it to the right `obsidian-mind/brain/…` note — or run `/om-dump <fact>`
  — not into this file. The PostToolUse hook reindexes vault writes automatically.
- **Never cross the boundary.** Memory is never evidence, never in a case `audit.jsonl`, never a
  Finding. Don't run investigation tools "to remember." See `docs/runbooks/obsidian-mind-memory.md`.

---

## 9. Navigation index

| For… | Read |
|---|---|
| Session-start onboarding behavior (greeting, preflight, browser, install) | `docs/onboarding.md` |
| Commands, live-test gate, per-evidence-type matrix | `docs/live-test-matrix.md` |
| Repo layout, 3 subsystems, sandbox layers, A1–A6 amendment history, project state | `docs/repo-guide.md` |
| Judge-facing trust boundaries & architecture diagram | `docs/architecture.md` |
| Full MCP-server + tool inventory (6 servers / 43 product tools) | `docs/reference/mcp-and-tools.md` |
| Dependency + external-DFIR-tool + version matrix | `docs/reference/dependencies.md` |
| Env-var reference (~35 vars) | `docs/reference/environment-variables.md` |
| How to run the product (flags, modes, output layout) | `docs/using/running-verdict.md` |
| Fleet analysis (3-stage pipeline) | `docs/using/fleet-analysis.md` |
| Whole-case local run (stage a corpus, run every host, no SIFT VM) | `docs/using/whole-case-local-run.md` |
| Evidence staging / report customization | `docs/using/evidence-intake.md`, `docs/using/reports.md` |
| Public test-dataset corpus, goldens, recall scoring | `docs/DATASET.md` |
| Per-tool analyst playbooks + expected-failure table | `docs/analyst/tool-playbooks.md` |
| How to add a new typed MCP tool (extension seam) | `docs/extending-the-tool-surface.md` |
| Dev/operator memory layer (obsidian-mind + boundary) | `docs/runbooks/obsidian-mind-memory.md` |
| Failure modes → code-enforced detectors → fixes | `docs/troubleshooting.md` |
| 3-step quick start | `QUICKSTART.md` |
| Verdict word semantics | `docs/verdict-semantics.md` |
| False-positive prevention & analyst checklists | `docs/false-positives.md` |
| Crypto chain-of-custody (post-A5 3-tier) | `docs/cryptographic-attestation.md` |
| Judge compliance checklist | `SUBMISSION_COMPLIANCE.md` |
| Runtime agent identity & hard rules | `agent-config/SOUL.md`, `AGENTS.md`, `TOOLS.md`, `MEMORY.md`, `HEARTBEAT.md`, `EXPERT.md` |
| Per-feature change history | `CHANGELOG.md`; `git log --oneline -20` |

Before writing code, read the relevant spec (`docs/specs/`) and plan (`docs/plans/`) for the
subsystem you're touching. When spec and code disagree, **code + committed pin files win.**
