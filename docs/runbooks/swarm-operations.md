# Runbook: Swarm Operations

**Status: ACTIVE**
**Scripts:** `scripts/swarm-start.sh`, `scripts/swarm-status.sh`
**Spec reference:** `docs/specs/2026-04-24-autonomous-build-swarm-design.md` (Spec #1, interpret through A1)

The build swarm runs overnight, picks tasks from a Postgres-checkpointed DAG, opens draft
PRs via `gh`, and waits for human triage each morning. It does not run during the day; it
does not auto-merge.

---

## Prerequisites

| Requirement | Check |
|---|---|
| Docker Desktop running | `docker compose -f docker/swarm-postgres.yml ps` |
| `gh` CLI authenticated | `gh auth status` |
| `claude` CLI on PATH | `command -v claude` |
| Claude Code credentials | Either `~/.claude/` (after `claude auth login`) or `CLAUDE_CODE_OAUTH_TOKEN` env var |
| Clean `main`/`master` | `git status --porcelain` (should be empty) |

No `ANTHROPIC_API_KEY` is required. The swarm uses the user's Claude Code subscription
(Option B per Amendment A1).

---

## Start a nightly run

```bash
bash scripts/swarm-start.sh
```

The script runs five pre-flight checks (Postgres, `gh` auth, `claude` CLI, git clean, no
orphan worktrees), then launches the supervisor:

```bash
cd services/swarm && uv run python -m findevil_swarm.main run "$@"
```

**Note on package name:** the module is `findevil_swarm` (not `services.swarm.*` as written
in some older plan documents). The script at `scripts/swarm-start.sh:105` is authoritative.

### Dry-run gate (weekly planning)

```bash
cd services/swarm && uv run python -m findevil_swarm.main run --week 4 --dry-run-gate
```

Prints the week's planned tasks without opening PRs or touching worktrees.

---

## Morning triage

```bash
bash scripts/swarm-status.sh
```

Prints:

1. Open `swarm-generated` PRs (draft, last night's output)
2. Latest summary JSON from logs/swarm/
3. Tail of the latest event log
4. Postgres DAG state (row counts by thread_id)

Review each draft PR, merge or close, then start a new night's run.

---

## Resume after an interrupted run

The Postgres DAG is the checkpoint. If the swarm died mid-run (rate limit, crash,
manual kill), resume from where it stopped:

```bash
cd services/swarm && uv run python -m findevil_swarm.main run --resume
```

The supervisor reads the last stable checkpoint from Postgres and continues. Orphan
`wt-*` worktrees from a crashed run are cleaned up during the next `swarm-start.sh`
pre-flight check.

---

## Postgres DAG state

Start the Postgres container standalone (if not already running):

```bash
docker compose -f docker/swarm-postgres.yml up -d
```

Query DAG state manually:

```bash
docker compose -f docker/swarm-postgres.yml exec postgres \
    psql -U swarm -c "SELECT thread_id, state, count(*) FROM tasks GROUP BY thread_id, state ORDER BY thread_id;"
```

---

## Rate-limit / usage-limit handling

When the Claude CLI returns a 429 or `usage limit reached` / `reached your usage limit`
message, `session_guard.py` catches it and halts the supervisor cleanly. The Postgres
checkpoint is written before halting. Resume the next night with `--resume`. No in-flight
retry; no automatic backoff loop.

---

## Orphan worktree cleanup

Each swarm PR runs in its own git worktree (`wt-<task-id>/`). Crashed runs leave orphan
worktrees under `.wt/`. The `swarm-start.sh` pre-flight check detects and reports them.
Remove them manually:

```bash
git worktree list  # identify wt-* entries
git worktree remove --force wt-<task-id>
```

Then re-run `swarm-start.sh`.

---

## Mock workers (testing without Claude credits)

```bash
bash scripts/swarm-start.sh --mock-workers
```

Workers return stub responses. Useful for verifying Postgres checkpointing and PR-opening
logic without consuming Claude Code usage.

---

## Lightweight alternative: autonomous-loop.py

For simple sequential queue-based runs without the full swarm infrastructure:

```bash
python scripts/autonomous-loop.py [--max-hours N] [--min-hours N] [--dry-run]
```

Reads `memory/project_autonomous_queue.md`, picks the highest-priority unblocked item,
spawns `claude -p --permission-mode acceptEdits` per item, commits on the current branch.
No Postgres, no per-PR worktrees, no `gh` PR creation. See CLAUDE.md §5 for full options.
