# Amendment A1 — Option B: Claude Code Subscription Mode

> **Status: SHIPPED, swarm specifics superseded by A6.** The Product accepts three credential modes (`CLAUDE_CODE_OAUTH_TOKEN`, interactive `~/.claude/`, `ANTHROPIC_API_KEY`) — that part is live in `scripts/install.sh`. This amendment's primary subject, the **build swarm**, was removed entirely under **Amendment A6 (2026-06-07)**: `services/swarm/` and all swarm wiring no longer exist. Treat the swarm-specific content below (worker credentials, `session_guard.py`, LiteLLM removal) as historical. LiteLLM proxy + `services/swarm/budget.py` were never built (per A1).

**Date:** 2026-04-23
**Status:** Active — supersedes affected sections of Spec #1 and Spec #2
**Scope:** Swarm invocation + Product runtime credentials
**Rationale:** Cost control via existing Claude Code subscription; API key becomes optional for judges only.

---

## 1. Decision

**For the build swarm (Spec #1):** run in **Claude Code Subscription mode**. Workers invoke the local `claude` CLI (leveraging the user's existing Claude Code subscription) instead of routing through LiteLLM proxy to a metered Anthropic API key.

**For the Product (Spec #2):** at runtime on SIFT, the Product accepts **three** credential modes in priority order:
1. **Claude Code OAuth token** (env var `CLAUDE_CODE_OAUTH_TOKEN`): the long-lived non-interactive token produced by `claude setup-token`. Inference-only scope; ideal for judges who already have a Claude Code subscription and want a script-friendly credential with no interactive OAuth flow.
2. **Claude Code session** (`~/.claude/` from `claude auth login`): interactive-login credentials. Used in dev.
3. **Anthropic API key** (env var `ANTHROPIC_API_KEY`): direct metered API access. Used when no Claude Code is available.

`scripts/install.sh` detects in this order and errors clearly if none are present. All three paths are judge-valid — the user does NOT need an API key to build. Judges choose whichever they already have.

---

## 2. Deltas from Spec #1 (Build Swarm)

### 2.1 Removed

- LiteLLM proxy as primary budget enforcement mechanism.
- `services/swarm/config/litellm_config.yaml`.
- `services/swarm/budget.py` USD-based `BudgetExhaustedError`.
- Per-PR virtual LiteLLM keys.
- Global `max_budget: 50.0` / `budget_duration: 1d` hard cap.
- `ANTHROPIC_API_KEY` requirement for swarm operation.

### 2.2 Replaced with

**Worker invocation** — `services/swarm/workers/base_worker.py`:
- Workers spawn `claude` CLI subprocess directly (no LiteLLM proxy in the path).
- Worker inherits the user's logged-in Claude Code session (`~/.claude/` credentials on laptop).
- `CLAUDE_CODE_FORK_SUBAGENT=1` still set — prompt cache savings remain.
- Model selection via `claude --model claude-opus-4-7` / `claude-sonnet-4-6` flags unchanged.

**Budget enforcement** — replaces `services/swarm/budget.py`:
- New module: `services/swarm/session_guard.py`.
- Detects Claude Code rate-limit signals (HTTP 429, "usage limit reached" stderr, session expiry).
- On rate-limit: kill current worker, log `SessionLimitError`, pause supervisor. Does NOT retry — the next night's run picks up where it left off via Postgres checkpoint.
- Soft advisory counter: tracks messages dispatched per 5-hour rolling window; warns in `night_report.jsonl` at >80% of typical subscription ceiling.

**Failure modes, ranked:**
1. Subscription limit hit mid-PR → worker's worktree left dirty, branch not pushed. Pre-flight in `swarm-start.sh` cleans leaked worktrees next run (already spec'd in §9.2 of Spec #1).
2. Subscription limit hit between PRs → supervisor detects on next dispatch attempt, emits `night_report.jsonl` with "halt: session_exhausted", exits cleanly. Resume tomorrow.
3. Session credentials expire → same as #2; user re-runs `claude auth login` in the morning.

**What stays the same from Spec #1:**
- LangGraph supervisor + PostgresSaver for DAG durability.
- `git worktree` per PR — non-negotiable.
- Critic subagent gating every PR (also via `claude` CLI now).
- No-progress detector (3 zero-diff tool calls → kill).
- `--max-turns 40` per subagent.
- 8-hour wall-clock watchdog.
- Dry-run gate (first PR must pass CI before releasing the rest).
- Draft-only PRs; human merges; never auto-merge.
- `jshchnz/claude-code-scheduler` for nightly kickoff.

### 2.3 Budget line — revised

| Line | Old (Spec #1) | New (Option B) |
|---|---|---|
| Claude API spend | $2,650 worst case / ~$795 expected | **$0** (subscription already paid for) |
| LiteLLM Postgres | $0 | N/A (removed) |
| Postgres for swarm DAG | $0 (unchanged) | $0 (unchanged) |
| **Swarm-only ceiling** | **$2,650** | **$0** |

Net savings: $2,650 worst case, ~$795 expected. Total project ceiling drops from ~$3,500-4,000 to **~$1,000-1,500** (GHA CI + optional Product self-testing).

### 2.4 Risk — revised

| # | Risk | Mitigation (Option B) |
|---|---|---|
| W1 (new framing) | Subscription exhaustion mid-night | Swarm halts cleanly on 429; resume next night via Postgres checkpoint. No lost work. No financial damage. |
| W1a | Subscription limits force fewer PRs/night than API-key mode | Accept reduced throughput. Week schedule may slip by 1-2 days; dog-leg cuts already defined in master design §7. |
| W1b | Subscription rate limits are opaque (not published) | Session guard tracks empirical burn rate; advises in `night_report.jsonl`. User observes and adjusts cadence. |

W1 in the original Spec #1 (the $47k LangChain ping-pong incident) is **no longer applicable** — subscription mode cannot trigger runaway USD spend. The failure mode shifts from "catastrophic billing" to "throttled throughput," which is a strictly better risk profile for a time-boxed hackathon.

---

## 3. Deltas from Spec #2 (The Product)

### 3.1 New: Credential Mode Detection at Startup

Add to `services/agent/config.py`:

```python
# services/agent/config.py — addition sketch

def resolve_credentials() -> Literal["oauth_token", "claude_code_session", "api_key"]:
    """
    Detect which Claude credential path to use.
    Order of precedence:
      1. CLAUDE_CODE_OAUTH_TOKEN env var set (from `claude setup-token`)
         → use `claude` CLI with token injected via env
      2. ~/.claude/ directory exists with a valid interactive session
         (from `claude auth login`) → use `claude` CLI directly
      3. ANTHROPIC_API_KEY env var set → use direct Anthropic API
      4. Otherwise → fail fast with a message documenting all three options
    """
    ...
```

`services/agent/graph.py` routes to the appropriate Claude invocation based on the result. Modes 1 and 2 both invoke the local `claude` CLI subprocess; mode 1 passes the token via env, mode 2 relies on on-disk session state. Mode 3 uses the `anthropic` SDK directly (metered).

### 3.2 New Install-Time Check: `scripts/install.sh`

Add a pre-flight credential check (checks all three modes in priority order):

```bash
# scripts/install.sh — addition

if [ -n "$CLAUDE_CODE_OAUTH_TOKEN" ] && command -v claude &> /dev/null; then
    echo "[find-evil] Detected CLAUDE_CODE_OAUTH_TOKEN — will use long-lived Claude Code token."
elif command -v claude &> /dev/null && [ -d ~/.claude ]; then
    echo "[find-evil] Detected Claude Code interactive session — will use subscription auth."
elif [ -n "$ANTHROPIC_API_KEY" ]; then
    echo "[find-evil] Will use ANTHROPIC_API_KEY for direct Anthropic API calls."
else
    echo "ERROR: find-evil requires one of (any works — pick whichever you have):"
    echo ""
    echo "  (1) CLAUDE_CODE_OAUTH_TOKEN env var — non-interactive, script-friendly."
    echo "      Generate with: claude setup-token"
    echo "      Requires a Claude Code subscription; token is inference-only."
    echo ""
    echo "  (2) Claude Code interactive session — for dev/demo use."
    echo "      Install: https://code.claude.com"
    echo "      Then run: claude auth login"
    echo ""
    echo "  (3) ANTHROPIC_API_KEY env var — direct Anthropic API, metered."
    echo "      Get a key at: https://console.anthropic.com"
    echo "      Expected cost: <\$1 per standard SIFT evidence run."
    echo ""
    exit 1
fi
```

### 3.3 Judge-Facing README (Additions to `README-submission.md` template)

Add section "Credentials Required":

> **find-evil** requires access to Claude Opus or Sonnet to run the analysis agents. Pick whichever credential you already have — all three are supported and equally valid:
>
> 1. **Claude Code long-lived token** (recommended for judges with a Claude Code subscription). Run `claude setup-token` once on the judging machine and export `CLAUDE_CODE_OAUTH_TOKEN=<token>`. Non-interactive — works in batch/CI without any OAuth flow. Token is inference-only (safe to keep in env).
>
> 2. **Claude Code interactive session** (recommended for live development). Install from https://code.claude.com and run `claude auth login`. The tool detects your session automatically from `~/.claude/`.
>
> 3. **Anthropic API key** (recommended for judges with no Claude Code). Set `ANTHROPIC_API_KEY=sk-ant-...` in your environment. Get a key at https://console.anthropic.com/. Expected per-case cost: <$1 for a standard SIFT evidence run.
>
> The tool fails fast at startup with a clear error listing all three options if none are present. No other credentials are required.

### 3.4 AC-10 Updated (runtime entry points)

Original AC-10 in Spec #2: "`openclaw run --case nist-hacking.E01` produces the same `RunVerdict` as `find-evil run --case nist-hacking.E01`."

**Added AC-10a:** the same run produces identical `RunVerdict` under both credential modes (Claude Code harness + API key) on the NIST Hacking Case fixture. L3 golden-run exercises both paths in separate jobs.

---

## 4. No changes to Spec #3 (Sandbox)

The sandbox layers are credential-agnostic. L3's `scripts/l3-run-goldens.sh` uses whichever credential mode is configured in the runner's environment; for GHA runners this is the `ANTHROPIC_API_KEY` secret (judge-parity mode), so L3 tests the judge's exact code path by default.

---

## 5. No changes to Spec #4 (Orchestration Glue) except

`budget-guard.yml` in Spec #4 §3 queries LiteLLM `/spend` — that endpoint no longer exists in Option B. Replacement:

**Revised `budget-guard.yml`:**
- If `ANTHROPIC_API_KEY` secret is set in the repo (implying user has added one for L3 runs): query Anthropic's usage API daily; alert if >$40/day or >$50/day.
- If not set (swarm-only subscription mode): the budget-guard workflow is a no-op (exits 0 with message "Option B mode — no metered API in use").

---

## 6. Rollback path

If Option B proves unworkable (subscription throttling blocks more than 2 consecutive nights of swarm progress), revert to Spec #1 Option A:

1. Create an Anthropic API key at `console.anthropic.com`.
2. Set `ANTHROPIC_API_KEY` in laptop env.
3. Re-enable `services/swarm/config/litellm_config.yaml` (kept in git history — can be restored via `git show <commit>:services/swarm/config/litellm_config.yaml`).
4. `services/swarm/budget.py` restored from history.
5. `services/swarm/session_guard.py` becomes a dead code path (gated by env flag `CLAUDE_CODE_SUBSCRIPTION_MODE`).

Rollback takes ~30 minutes. The Spec #1 USD-budget architecture remains documented and implementable.

---

## 7. Decision log entry

**2026-04-23, user directive:** test swarm in subscription mode (Option B) first; keep API-key path available for judges at submission. Amendment A1 captures the deltas; Specs #1, #2, #3, #4 remain reference documents — authoritative for everything Amendment A1 does not explicitly override.
