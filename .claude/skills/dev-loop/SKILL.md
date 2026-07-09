---
name: dev-loop
description: Drive a coding task to a verified, 5-star finish with a bounded agentic OODA loop (observe, orient, plan, act) gated by TDD, an explicit Definition of Done, and a code-quality bar, then commit and open a PR to the dev remote. Runs in an isolated git worktree and keeps a durable plan/checklist on disk so an interrupted run can resume. Use this whenever the user wants something built, fixed, or refactored "until it's done", "until tests pass", or "until it meets the definition of done", asks to iterate/loop on an implementation, wants 5-star repo/code quality, or says run dev-loop / agentic loop / OODA loop / TDD loop. Prefer this over a one-shot edit whenever the first attempt is unlikely to be the final answer (bugfixes, flaky tests, coverage gaps, multi-step features) and the work should end in a real green build and a PR, not a claim.
---

# Dev Loop

Take one coding task from "asked" to "verifiably done, clean, committed, and proposed as a
PR" through a short feedback loop you can defend. The point is not autonomy — it is a loop
with a real acceptance gate, a quality bar, and named stopping conditions, so the work ends
in a green build or an honest "blocked", never in a confident claim that isn't true.

Treat this like the project's own evidence ethic: **no claim of done without a receipt you
can re-run.** A passing test you executed is a receipt. "It should pass" is not.

## The contract (read once, then hold it the whole loop)

- **Isolate the work** in a git worktree so the main checkout is never disturbed and the diff
  stays clean (next section).
- **Keep a resumable plan** on disk and check it off as you go, so an interrupted run picks up
  where it left off instead of starting over.
- **Define done before you act.** Write the Definition of Done as an observable, reproducible
  checklist first. If you cannot state the command whose exit code decides "done", you are
  not ready to act — go back and make the goal checkable.
- **Clear the quality bar, not just the test.** Done means clean code and sound logic too —
  see `references/quality-bar.md`. A green test over sloppy code is not done.
- **One bounded change per cycle.** Smallest reversible step toward the DoD, then verify.
- **Re-read fresh state before consequential actions.** Don't ship against stale code.
- **Preserve unrelated work.** Keep the diff surgical. Never "clean up" code the task didn't
  ask about.
- **Never report an error, a skipped step, or an exhausted budget as success.** A red test is
  red. Say so, with the output.
- **Stop on a named terminal state, not on vibes** (see Terminal states).

## Work in an isolated worktree

Run the whole loop in a dedicated git worktree, not the main checkout. This keeps unrelated
uncommitted work safe, keeps your diff clean, and lets a run be abandoned without leaving a
mess. Create it from the branch you'll ship:

```bash
git worktree add -b <type>/<short-topic> ../wt-<short-topic>   # e.g. ../wt-lnk-reroute
cd ../wt-<short-topic>
```

(If a worktree helper or skill is available, use it; otherwise the commands above.) Do all
Observe/Act/Verify cycles here. After the PR is open you may remove it:
`git worktree remove ../wt-<short-topic>`. If the task is tiny and the working tree is already
clean, a plain branch in place is acceptable — but isolation is the default.

## Keep a resumable plan + task list

Write the plan to a durable checklist file so progress survives an interrupted session. A
checkbox is a claim, so on resume you **re-run** a checked item's check before trusting it —
the file records intent and receipts, it does not replace verification.

- **Location:** `.dev-loop/plan.md` (inside the worktree). Keep it out of version control — add
  `.dev-loop/` to `.gitignore` or `.git/info/exclude`. It is a working journal, not a
  deliverable, and must never land in the PR diff.
- **On start, resume first.** If `.dev-loop/plan.md` exists for this task, read it, re-verify
  each `- [x]` item by re-running its check, then continue from the first `- [ ]`. Only create a
  fresh plan if none exists.
- **Format:**

```markdown
# dev-loop plan — <one-line task>
branch: <branch>   worktree: <path>   updated: <UTC ISO-8601 Z>

## Definition of Done
- [ ] acceptance: <command whose exit code decides done>
- [ ] tdd: <test> goes red→green
- [ ] suite: <relevant suite> green
- [ ] static: <fmt/lint/typecheck> clean
- [ ] quality: clears references/quality-bar.md
- [ ] diff is surgical
- [ ] conventional commit written

## Tasks
- [x] <done step> — receipt: <command + result you saw>
- [ ] <next bounded step>

## State
<where we are, last check output, any terminal state reached>
```

- **Update it every Record step:** check off finished items, add tasks you discovered, refresh
  `updated:` and `## State`. The plan is the single source of truth for "what's left."

## Set the Definition of Done (orient before you act)

Pin down "done" as a checklist of things you can *run*. A good DoD for this repo:

1. **Acceptance:** the behavior asked for is demonstrated by a named test/command (e.g.
   `pytest …::test_x` passes, or `scripts/verdict <evidence>` reaches `manifest_verify
   overall=true`).
2. **TDD:** new behavior is covered by a test that **failed before and passes after** (red →
   green). A bugfix's regression test reproduces the bug first.
3. **Suite:** the relevant existing suite still passes (no regressions).
4. **Static checks:** format / lint / typecheck pass for the languages touched.
5. **Quality:** the change clears `references/quality-bar.md` (clean code, sound logic, and the
   repo's 5-star judging criteria).
6. **Surgical:** `git diff` contains only what the task needs.
7. **Conventional commit:** describable in one `type(scope): summary` line.

If the user gave their own DoD, use it verbatim and don't invent extra gates. If an unknown
detail changes what "done" means, ask one short question rather than guessing.

This repo's verification menu (pick the subset the change touches — see `CLAUDE.md`):

```bash
cargo test --workspace --locked          # Rust MCP tools
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo fmt --all --check
uv run --directory services/agent pytest        # Python domain logic
uv run --directory services/agent_mcp pytest    # Python MCP shims
ruff check . && ruff format --check .
pnpm --filter @findevil/web lint && pnpm --filter @findevil/web typecheck && pnpm --filter @findevil/web test
bash scripts/run-all-smokes.sh           # policy / path-existence smokes
```

Passing smokes predict CI; they do not prove a real run. If the task touches investigation
behavior, the honest done-gate is a live `scripts/verdict <supported-evidence-path>`.

## Quality bar (aim for 5 stars)

"Works" is the floor. The bar is a 5-star repo and 5-star code. Hold every change against
`references/quality-bar.md` before Ship — it distills clean-code rules, logic-correctness
rules, and the six judging criteria from `agent-config/JUDGING.md`. The load-bearing few:

- **Receipts over claims.** Every claim in the code, commit, PR, or docs traces to something a
  reviewer can re-run. A documented limitation counts *for* you; a confident wrong claim gets
  zero credit. Lead with the caveat, not the win.
- **Architectural over prompt.** Enforce a guarantee in a type/check/interface, not a comment
  that says "please don't" — and test that the bypass fails.
- **Clean code, sound logic.** Small focused files/functions, immutability, no magic values,
  early returns, no silent failures, edge cases covered, validation at every boundary.
- **Laziest that works (ponytail).** The best code is the one never written: climb the ladder —
  does it need to exist (YAGNI) → stdlib → native feature → installed dep → one line → minimum
  code — and stop at the first rung that holds. Deletion over addition; shortest working diff
  wins; no speculative abstractions. Run **`/ponytail-review`** on the diff during Verify. (Never
  simplify away validation, error handling, security, or audit-chain determinism — see
  `references/quality-bar.md`.)
- **Traceable + reproducible.** A reviewer can take any three claims from the PR and locate the
  code/test behind each; the change reconstructs from the commit + its receipts alone.
- **Depth over breadth, and docs travel with behavior.** One deeply-verified change beats a wide
  shallow one; if setup/behavior/extension changed, update the doc in the same change.

## The loop

Run these in order each cycle. Observe → Orient → Plan → Act is your OODA front half; Verify is
the TDD/DoD/quality gate; Record and the stop check keep it bounded and honest.

1. **Observe.** On first entry, resume the plan file (above). Then read the state that matters:
   the failing test or current behavior, the code on the path, the last cycle's result, any
   in-scope feedback (an issue, a review). Re-read, don't remember.
2. **Orient.** Form one concrete hypothesis about the smallest thing that moves toward the DoD.
   On cycle one, write the failing test (TDD red) if it doesn't exist, and write/refresh the
   plan file.
3. **Plan.** Pick the single highest-value in-scope action that tests the hypothesis, and name
   the check you'll run to know if it worked.
4. **Act.** Make that one bounded, reversible change.
5. **Verify (the gate).** Run the acceptance check and the relevant suite/static checks under
   recorded conditions, and hold the change against the quality bar. Capture the actual output —
   exit code, failing assertion, count. This is the receipt.
6. **Record.** Update `.dev-loop/plan.md`: check off finished DoD/task items with their receipts,
   add newly discovered tasks, refresh State. Keep it real; this is what lets a fresh session
   reconstruct the run.
7. **Repeat or stop.** If every DoD item is green → **Ship**. If progress was measurable and no
   user limit is hit → loop to Observe with the next item. Otherwise → the matching terminal
   state.

Re-derive the failing signal each cycle; don't trust a green from three edits ago. When you fix
a flaky or environment-shaped failure, separate the working signal from the acceptance gate so
you don't overfit to a lucky run — re-run it.

## Terminal states (pick one; never blur them)

- **done** — every DoD item verified green this cycle. Proceed to Ship.
- **blocked** — an action the loop must not take on its own is required: a destructive or
  irreversible step, a production/external/credentialed action, a real ambiguity only the user
  can resolve, or a dependency you cannot install safely. Stop and surface exactly what you need.
- **exhausted** — a user-set limit (iterations, time, scope) is reached without done. Report
  progress and the remaining red items; do not relabel as done.
- **stagnated** — two consecutive cycles produce no measurable progress toward any DoD item
  (same failure, no new information). Stop, summarize what you tried and the current failing
  output, and ask for direction. A loop that isn't learning is just thrashing — end it.

If no user limit was given, use the **stagnated** no-progress stop rather than inventing a cap.
Record the terminal state in the plan file so a resume knows it stopped on purpose.

## Ship (only from terminal state: done)

Reaching Ship means the DoD was verified **this cycle**, not earlier. Re-run the full DoD once
more if any edit happened since the last green.

This repo's remotes (verify with `git remote -v`): `origin` = `TimothyVang/dev-verdict-github` is
**dev**; `release` = `TimothyVang/verdict-dfir` and `beta` = `verdict-dfir-beta` are
public/protected. The loop ships to **dev only**.

1. **Confirm the branch** — you're on the worktree's `<type>/<short-topic>` branch, never the
   default branch. Never commit to `master`/`main`.
2. **Stage only the task's changes.** Review `git status`/`git diff`; never `git add -A` blindly.
   Confirm `.dev-loop/` is excluded — the plan journal must not enter the commit.
3. **Commit with a Conventional Commit** (`feat:`, `fix:`, `refactor:`, `docs:`, `test:`,
   `chore:`, `perf:`, `ci:`). One-line summary, body only if it earns it. **Never** `--no-verify`,
   never `--amend` someone else's commit, never skip signing — let the repo's hooks run; if a
   hook fails, that's a red DoD item, go back to the loop.
4. **Push to `origin`** (dev) with **`git ship`** — the repo's free, platform-agnostic push
   helper (`git-ship`, on PATH; runs as `git ship`). Plain `git ship` defaults to pushing the
   current branch to `origin` with no force-push and hooks intact, which is exactly the dev
   push. Use it bare: **never** `--tag` and **never** `--remote release`/`beta` — cutting a
   release or pushing a protected remote is the separate human-approved promotion step
   (`CLAUDE.md`). Preview with `git ship --dry-run` first if unsure. Fallback if `git ship` is
   unavailable: `git push -u origin <branch>`. Never force-push either way.
5. **Open a PR against the dev base** with `gh pr create --repo TimothyVang/dev-verdict-github`.
   Title = the conventional-commit summary. Body = what changed, why, and the **test plan**: the
   exact DoD commands you ran and their results (paste the receipts). State residual/follow-up
   honestly.
6. **Report the PR URL** and stop. You may now `git worktree remove` the worktree. Promotion to
   `release` is a separate, human-approved step (`CLAUDE.md`) — this loop never does it.

Shipping is the loop's defined, user-authorized terminal action for **done**. Any step outside
it — promoting to release, deleting work, force-pushing, touching production — is **blocked**,
not done: surface it and wait.

## Honesty (the whole reason this loop exists)

Lead with the caveat, not the win. If the suite is red, the feature is half-built, or you
skipped a check, say that first and name the artifact (which test, which command, which exit
code). A PR that says "tests pass" must be backed by output you actually saw. The receipts — the
failing-then-passing test, the green suite, the smoke result, the quality-bar pass — are what
make "done" defensible to the next person who reads the diff. Without them you don't have done,
you have a hope, and this loop exists precisely so you never ship a hope as a fact.
