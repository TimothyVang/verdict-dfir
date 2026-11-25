# VERDICT — Help Wanted

VERDICT shipped at a SANS AI hackathon. It works, the core idea holds up, and I think it's
genuinely useful — but it can be a lot better, and I'd rather build it in the open with people who
know DFIR and AI than grind it solo. If that's you: welcome, and thank you.

> **Heads-up on where to contribute.** [Open issues here](https://github.com/TimothyVang/verdict-dfir-beta/issues),
> and send code as a pull request against the **`develop`** branch of this repo. The gates are local
> (`bash scripts/run-all-smokes.sh` plus the per-language suites) — no GitHub Actions runners
> required; a maintainer runs them on your branch and reviews, and two approvals merge it. The
> build/test/submit mechanics live in [`CONTRIBUTING.md`](../CONTRIBUTING.md) — this page is the
> "what is this and where do I help" map.

---

## What VERDICT is (the 90-second version)

VERDICT is a **digital-forensics & incident-response (DFIR) agent with three runtime paths**: the
default deterministic `scripts/verdict` quality floor, an allowed beta-native `--agent` loop for
strict single-EVTX Phase 4 offline acceptance, and
[Claude Code](https://claude.com/claude-code) as the canonical interactive/cloud runtime. There is
no separate app server. You point it at supported evidence and it:

1. opens a read-only **Case** and SHA-256s the evidence,
2. drives a **narrow, typed, read-only** tool surface (45 product tools — 32 Rust DFIR tools + 13
   Python crypto/memory tools; **no `execute_shell`, ever**),
3. **verifies every Finding** (re-runs the cited tool and compares output hashes),
4. and writes a **scoped verdict** — `SUSPICIOUS` / `INDETERMINATE` / `NO_EVIL` — plus an analyst
   report, sealed into a **hash-chained, signed manifest you can verify offline**.

What it is **not**: an autonomous responder (the analyst approves the plan and the verifier re-runs
every cited tool before any Finding reaches the report), and `NO_EVIL` is never a whole-environment
clean bill of health — only "no reportable Finding in the artifacts actually examined." That scoping
discipline is the whole point. See [`docs/verdict-semantics.md`](verdict-semantics.md).

---

## See it in action

Narrated demos (AI voiceover) of real runs:

- ▶ **[Full walkthrough (4:35)](https://youtu.be/4RQnVden6L8)** — one command to a signed
  `SUSPICIOUS` verdict, verifiable offline.

<!--
  GitHub will NOT inline-play a committed .mp4 — to get a play-in-place player, drag the file into a
  GitHub Issue/release in the browser, copy the https://github.com/user-attachments/assets/<id> URL
  it returns, and paste it into a <video src="..."> here. (Label a Remotion render a "demo
  walkthrough", not a "real run", if it isn't a screen capture.)
-->

> **Maintainer TODO — drop the rest of the demo links here.** You mentioned "a bunch of cool
> videos"; paste the URLs/files and I'll lay them out (per-feature: dashboard live tail, manifest
> tamper-detection, fleet rollup, contradiction surfacing, etc.).

---

## The hard problem: keeping the AI honest

The thing I have **not** fully solved is the one everybody worries about with an LLM doing forensics:
**hallucination.** A language model will, given the chance, confidently assert that a binary ran or
data was exfiltrated when the evidence doesn't actually support it.

VERDICT's bet is that you don't fix this with a better prompt — you fix it **architecturally**, so a
hallucination *can't survive into the verdict* unless it passes through gates that re-check it
against re-runnable tool output and corroborating artifacts. Today those gates are:

- **Citation or it didn't happen.** Every Finding must cite a `tool_call_id`. Uncited claims are
  vetoed outright.
- **Verifier replay.** The verifier re-runs each cited tool call and compares output hashes; a
  Finding whose output drifted gets downgraded a tier or rejected. Replay is deterministic, so the
  audit chain attests exactly what the model saw.
- **Two biased pools + contradiction surfacing.** A persistence-biased pool and an exfil-biased pool
  work the same evidence; `detect_contradictions` flags disagreements *before* the judge merges.
- **The ≥2-artifact-class rule.** Any "this ran" / "this was exfiltrated" claim needs corroboration
  from two distinct evidence classes (Prefetch + Amcache, EVTX 4688 + MFT, …) or it's auto-downgraded
  to `HYPOTHESIS`. Hayabusa/Sigma/YARA/malfind output are **leads, not facts**.
- **A confidence taxonomy + coverage manifest** that make the limits explicit instead of papering
  over them, and a **signed manifest** anyone can verify offline.

The full picture: [`docs/false-positives.md`](false-positives.md),
[`docs/architecture.md`](architecture.md), and the runtime rules in
[`agent-config/`](../agent-config/) (`SOUL.md`, `PLAYBOOK.md`, `MEMORY.md`).

**It works — but it doesn't drive the false-positive rate to zero, and the gates have gaps.** That's
where you come in.

---

## Where you can help (open problems)

> **Maintainer TODO — paste your real "stuff I haven't cracked yet" list here.** The items below are
> starters I pulled from the codebase so the page isn't empty; replace/extend with your actual
> priorities and I'll re-rank them.

| Area | What's open | Skills | Difficulty |
|---|---|---|---|
| **FP floor / calibration** | The agent isn't zero-FP against the clean `goldens/synthetic-benign/` baseline. Want: auto-detect which rule fired, propose a tune-out, track the FP floor over time. | DFIR, Sigma/YARA tuning, Python | medium |
| **DKOM vs. acquisition smear** | `vol_pslist`/`vol_psscan` divergence looks like a rootkit but is often a corrupt/smeared capture. Disambiguating it reliably is hard (we got burned once — see false-positives.md). | memory forensics, Volatility 3 | hard |
| **Prompt-injection at the evidence boundary** | Attacker-controlled evidence text is neutralized in `services/mcp/src/sanitize.rs` + the Python mirror. New evasion classes / a fuzz corpus would harden it. | security, Rust/Python | medium |
| **Coverage breadth** | More evidence types and parsers (macOS/Linux artifacts, more cloud audit sources) behind the typed tool surface — never `execute_shell`. | DFIR tooling, Rust MCP tools | medium |
| **Evaluation corpus** | A bigger, public set of golden cases (benign + known-bad) and a metric for "did the agent over-claim?" so improvements are measurable, not vibes. | DFIR, eval/benchmarking | research |
| **Cross-host FP filters** | `scripts/fleet_correlate.py` filters known EDR/agent stacks so they don't read as lateral movement; it needs coverage for more enterprise stacks. | IR at scale, Python | good-first |
| **Docs & onboarding** | Make a first run frictionless for someone who's never touched the project. | technical writing | good-first |

Tag difficulty honestly when you file — a `good-first` mislabeled as `hard` scares people off, and
vice versa.

---

## How to actually contribute

1. **Read [`CONTRIBUTING.md`](../CONTRIBUTING.md)** — build/test commands, the CI tiers, the
   conventional-commit + DFIR-vocabulary rules. Everything there mirrors what CI runs.
2. **Open an issue first** for anything non-trivial (templates live in
   [`.github/ISSUE_TEMPLATE/`](../.github/ISSUE_TEMPLATE/)) so we can agree on the approach before
   you spend a weekend on it.
3. **The "done" gate is a live run**, not a green smoke: `scripts/verdict evidence/<file>` produces a
   real verdict with `manifest_verify.json` → `overall: true`. An honest `INDETERMINATE` on thin
   evidence is a pass.

### Invariants a PR must not break (so your work isn't wasted)

These are load-bearing for the security story — a PR that violates one gets blocked, no matter how
good it is. Full list in [`CONTRIBUTING.md`](../CONTRIBUTING.md) / `CLAUDE.md`:

- **No `execute_shell` MCP tool.** The narrow typed surface *is* the product.
- **Every Finding cites a `tool_call_id`;** evidence is read-only; the audit log is append-only and
  hash-chained.
- **Keep the Amendment A2 boundary.** Claude Code remains canonical for interactive/cloud use. The
  only allowed beta-native orchestrator is the thin `services/agent/findevil_agent/agentloop/` path
  reached by `scripts/verdict --agent`; do not restore `graph.py`, `api.py`, `cli.py`,
  `supervisor.py`, `specialists/`, LangGraph, or FastAPI.
- **AGPL/GPL DFIR tools stay subprocess-only, never linked** (keeps the tree Apache-2.0).

The current official general judge/demo paths remain default `scripts/verdict <evidence>` and an
interactive Claude Code session. Strict Phase 4 offline acceptance separately uses `--agent` on one
EVTX file. Every non-EVTX type and directory fails closed in native mode and uses the deterministic
path; none of these runtime distinctions claim improved local-model detection.

---

Tapped out, shipping anyway, and glad you're here. Open an issue, say hi, pick a row from the table.
