# Quality bar — aim for a 5-star repo and 5-star code

The Definition of Done is not "it works." It is "it works, the code is clean, the logic is
sound, and every claim traces to a receipt." This file is the checklist the loop's **Verify**
step holds the change against before it can reach **Ship**. Treat each section as a gate: a red
item is a red DoD item — go back into the loop, don't ship around it.

Source of the judging rules: `agent-config/JUDGING.md` (the repo's six-criterion rubric and the
official June-2026 Judge Pack). The point of stars is calibration: 3 = competent and
unremarkable, 5 = best-in-class and would hold up under an adversary. Don't default to the
middle — earn the top.

## Contents
- Part A — Code quality (clean code)
- Part B — Logic correctness
- Part C — 5-star repo (judging criteria, distilled)
- Part D — This repo's hard rules

---

## Part A — Code quality (clean code)

Aim for code the next person reads without friction and changes without fear.

- **Small, focused files.** 200–400 lines is the norm, 800 is the hard ceiling. A file doing
  three jobs is three files. Organize by feature/domain, not by type.
- **Small functions.** Under ~50 lines, one responsibility. If you need a comment to explain a
  block, that block usually wants to be a named function.
- **Shallow nesting.** More than ~4 levels is a smell; prefer early returns / guard clauses over
  stacked conditionals.
- **Immutability by default.** Return new values; don't mutate inputs, shared objects, or arrays
  in place. Hidden in-place mutation is the source of the bugs nobody can reproduce.
- **KISS / DRY / YAGNI.** Simplest thing that actually works. Extract real repetition (not
  speculative). Don't build for a future that isn't here; don't add a flag nobody asked for.
- **No magic values.** Name the threshold, the limit, the delay. `MAX_RETRIES = 3`, not `3`.
- **Naming carries intent.** `camelCase`/`snake_case` for values, `PascalCase` for types,
  `UPPER_SNAKE_CASE` for constants, `is/has/should/can` for booleans. A good name removes a
  comment.
- **No debug residue in committed code.** No stray `print`/`console.log`, commented-out blocks,
  or `TODO: remove`. (A deliberate, marked shortcut is fine — flag it, don't smuggle it.)
- **Comments earn their place.** Explain *why*, not *what* the code already says. Keep them true;
  a stale comment is worse than none. Match the file's existing comment density and idiom.
- **Surgical diff.** The change touches only what the task needs. Don't drive-by-reformat or
  "improve" unrelated code in the same change.

### Laziness — the ponytail ladder (least code that works)

The best code is the one never written. Before writing anything, climb the ladder and **stop at the
first rung that holds** — it's a reflex, not a research project:

1. **Does this need to exist at all?** Speculative need → skip it, say so in one line. (YAGNI)
2. **Stdlib does it?** Use it.
3. **Native platform feature covers it?** A DB constraint over app code, CSS over JS, a built-in over a lib.
4. **An already-installed dependency solves it?** Use it — never add a new dep for what a few lines do.
5. **One line?** One line.
6. **Only then:** the minimum code that works.

Deletion over addition; boring over clever (clever is what someone decodes at 3am); fewest files;
shortest working diff wins. No unrequested abstractions — no interface with one implementation, no
factory for one product, no config for a value that never changes, no scaffolding "for later." Mark a
deliberate shortcut with a `ponytail:` comment that names the ceiling and the upgrade path
(`# ponytail: global lock, per-account if throughput matters`) so simple reads as intent, not ignorance.

**Never simplify away** (these override the ladder — same force as Part B): input validation at trust
boundaries, error handling that prevents data loss, security, accessibility, the determinism the audit
chain depends on, or anything explicitly requested. Lazy means writing *less code*, not picking the
flimsier algorithm or dropping a guard. A lazy change still leaves its one runnable check (the TDD test).

This repo has the **ponytail** skills wired in: run **`/ponytail-review`** on your diff during Verify to
catch reinvented stdlib, speculative abstractions, and dead flexibility before Ship — or **`/ponytail`**
while writing for the laziest-that-works default.

## Part B — Logic correctness

Working on the happy path is the floor, not the bar.

- **Handle the edges, not just the center.** Empty, null/None, zero, one, many, max, negative,
  duplicate, out-of-order, and the boundary value. The off-by-one lives here.
- **No silent failures.** Never swallow an error or return a misleading fallback that hides it.
  Handle it explicitly, or let it propagate with context. A bare `except: pass` / empty `catch`
  is a defect.
- **Validate at every boundary.** Treat all external/untrusted input (user, network, file,
  another service, attacker-controlled evidence text) as hostile until validated. Fail fast with
  a clear message.
- **Tests cover the failure path.** A test that only proves the happy path is half a test. Add
  the case that would have caught the bug — and, for a bugfix, write it first so you watch it go
  red, then green.
- **Determinism where it's load-bearing.** If output feeds a hash, a replay, or an audit, it must
  be reproducible: stable ordering, canonical serialization, no wall-clock/random in the path
  that must replay byte-for-byte.
- **Concurrency safety.** No shared-mutable races; prefer immutable messages and clear ownership.
- **State the invariant.** Know the one thing that must always be true (e.g. "every Finding cites
  a tool_call_id") and make the code enforce it, not just hope for it.

## Part C — 5-star repo (judging criteria, distilled from `agent-config/JUDGING.md`)

These are the repo-quality rules behind the six judged criteria. Make the change move the repo
*toward* 5 stars, never away.

1. **Autonomous execution — organic, never staged.** Self-correction must be real and visible
   (a genuine failure → named course-correction), not a contrived error with a suspiciously clean
   fix. The loop's named terminal states (done/blocked/exhausted/stagnated) are how you keep this
   honest. No silent retries.
2. **Accuracy & honesty — the asymmetry pays for specifics.** Every claim (in code comments, the
   commit, the PR, the docs) traces to a re-runnable receipt: a test, a command, a tool output.
   A documented limitation counts *for* you; a confident wrong claim a reviewer catches gets zero
   credit. Distinguish what's proven from what's inferred from what's hypothesis — don't blur
   them. Lead with the caveat, not the win.
3. **Breadth and depth — depth wins.** One correct, deeply-corroborated change beats a wide,
   shallow sweep. Where a claim can be cross-checked from a second source, do it.
4. **Constraint implementation — architectural over prompt.** Enforce guarantees in the type
   system / a check / a fixed interface, not in a comment that says "please don't." Prefer a guard
   that *can't* be bypassed, and add the test that proves the bypass fails.
5. **Audit trail — traceable and reproducible.** Any reviewer can pick a claim and reach the exact
   producing step. The change is reconstructable from the commit + its receipts alone, with no
   external state. (The **three-claim trace**: a reviewer should be able to take any three claims
   from the PR and locate the code/test that backs each.)
6. **Usability and docs — another practitioner can build on it.** If behavior, setup, or the
   extension pattern changed, update the doc in the same change. The bar: a stranger clones and
   runs it from the README without asking you.

## Part D — This repo's hard rules (from `CLAUDE.md`)

Non-negotiable for VERDICT changes — a change that violates one is not done:

- **Evidence is read-only.** No code path mutates source/mounted evidence or case files.
- **Evidence-agnostic.** All code (tools, MCP, parsers, `.py`, Rust) must work for ANY evidence name
  and type in `/evidence` — never hard-code image-specific values (usernames/hosts like `Mr. Evil`,
  image names like `SCHARDT`, per-image misspellings, specific URLs/paths/serials, or `nhc-XXX` golden
  IDs in production code/docstrings/finding descriptions). Key on general DFIR signatures; describe what
  was actually parsed. Enforced by `scripts/evidence-agnostic-smoke.py`.
- **Rust MCP tools** require typed schemas, unknown-field denial where applicable, safe errors,
  server registration, and tests. No `execute_shell`; long-tail execution stays behind
  allow-listed typed wrappers.
- **Python MCP tools are thin protocol shims** under `services/agent_mcp/`; domain logic belongs
  in `services/agent/`.
- **Sanitizer mirrors stay in sync and deterministic** (`sanitize.rs` ↔ `sanitize.py`); a
  `verify_finding` replay must reproduce the same `output_sha256`.
- **Don't restore removed orchestrator surfaces** (old graph/API/CLI/supervisor/FastAPI/LangGraph
  under `services/agent/`).
- **Custody/honesty wording:** never call limited coverage clean/cleared/no-evil; use UTC ISO-8601
  `Z` timestamps and SHA-256.
- **Optional automation, dashboards, browser tools, and memory sidecars are never evidence and
  never create Findings** — keep them out of the Finding path.
