# JUDGING.md — Pre-submission self-assessment rubric

The six quality criteria used by `scripts/self-score.py`, the
maintainer's pre-submission grading tool. This rubric is **not** part
of the investigation pipeline: the live agent/supervisor does not emit
self-score records mid-investigation, and the product, dashboard, and
demo video never reference it. Grading is a separate, after-the-fact
step a maintainer runs by hand against a completed case directory
before submission.

`scripts/self-score.py` reads a finished case's `audit.jsonl` (and
`verdict.json` if present), reconstructs the signals each criterion
asks about, and writes `<case>/self-score.json`. It does **not** append
to the audit chain — that chain is sealed at `manifest_finalize`.

Each criterion below names *which artifact in the completed audit trail*
the grader points at to answer it.

## 1. Autonomous Execution Quality (tiebreaker)
> Does the agent reason about next steps, handle failures, and
> self-correct in real time?

**Demonstrate via:** the audit JSONL itself. Every iteration writes a
plan-step → tool-call → observation → next-plan-step record. Tool
failures appear as `tool_call.error` entries followed by a planner
record adjusting course (e.g. fallback tool, narrower scope, or
explicit "deferring" with reason). HEARTBEAT.md self-tests count too.
**Anti-pattern:** silent retry. Failures must be logged and named.

## 2. IR Accuracy
> Are findings correct? Hallucinations caught and flagged? Confirmed
> findings distinguished from inferences?

**Demonstrate via:** SOUL.md epistemic hierarchy. Every Finding carries
`level ∈ {CONFIRMED, INFERRED, HYPOTHESIS}`. CONFIRMED ↔ tool_call_id
+ raw excerpt. INFERRED ↔ ≥2 confirmed facts + `derived_from` cite.
HYPOTHESIS ↔ `"hypothesis:"` prefix. The verifier role re-runs every
cited tool_call before report write-out. The `detect_contradictions`
MCP tool flags within-run hallucinations; the judge merges
credibility-weighted across Pool A/B.

## 3. Breadth and Depth of Analysis
> How much case data can the agent handle? Depth on fewer types beats
> shallow coverage of many.

**Demonstrate via:** the case manifest's `evidence_inventory[]` lists
every artifact class touched (Prefetch, MFT, EVTX, Amcache, ShimCache,
USN, Registry, Memory, YARA hits, …) with bytes-scanned and rows-
returned per class. Depth is shown by the cross-artifact corroboration
chain — execution claims **must** cite ≥2 artifact classes (CLAUDE.md
non-negotiable + SOUL.md hard rule). One deep persistence chain across
4 artifact classes scores higher than 12 shallow EVTX queries.

## 4. Constraint Implementation
> Are guardrails architectural or prompt-based? Judges evaluate where
> security boundaries are enforced and whether they were tested for
> bypass.

**Demonstrate via:** the typed Rust MCP tool surface (13 shipped
tools, including `vol_psscan` and `vol_psxview` for DKOM cross-validation). No `execute_shell`, no path traversal, every tool serializes
typed Input/Output. Architectural enforcement points:
- Read-only evidence opener (libewf in `case_open`, no mutation path).
- SHA-256 verification of image at open and at every tool re-execution.
- Hash-chained append-only audit JSONL (each line cites `prev_hash`).
- Tool-level `readOnlyHint`/`destructiveHint` annotations (commit
  `151510a`).
- L0 CI invariants guard for Amendment A2 (commit `ad4a36e`).
- Bypass tests live in `services/mcp/tests/` — UTF-8 truncation panic
  fix (`405117a`) is one example of a tested bypass attempt.
**Anti-pattern:** "the prompt says don't do X." Prompt-only guardrails
score lower than typed-surface enforcement.

## 5. Audit Trail Quality
> Can judges trace any finding back to the specific tool execution
> that produced it?

**Demonstrate via:** Finding → `tool_call_id` → JSONL audit record →
SHA-256 of the tool's stdout → `manifest_finalize` Merkle root →
sigstore signature with Rekor transparency-log inclusion proof.
The chain is verifiable offline by the `manifest_verify` MCP tool —
judges run it against the submitted run manifest and reach the
underlying tool execution with one path. M2 crypto stack is the
load-bearing answer; FRE 902(14) self-authenticating is the framing.
(The OpenTimestamps + Bitcoin anchor that previously closed this
chain was removed under Amendment A5; see
`docs/cryptographic-attestation.md` for the trade-off on prong (b).)

## 6. Usability and Documentation
> Can another practitioner deploy and build on this?

**Demonstrate via:** `scripts/find-evil` (local-mode launcher),
`scripts/find-evil-sift` (SIFT-VM SSH-bridge mode), `scripts/install.sh`
(three credential paths per Amendment A1), the Apache-2.0 license,
the published accuracy-benchmark repo (BUILD_PLAN_v2 §differentiator
10), and the four spec/plan documents (`docs/`). A judge
who clones the repo and runs `scripts/find-evil` should reach a
working investigation in <5 minutes; a developer should be able to
add a new MCP tool by following the pattern in `services/mcp/src/
tools/prefetch_parse.rs` (reference implementation) without reading
external docs.

## Pre-submission self-check

After a case completes, `scripts/self-score.py` reconstructs the run
from the sealed `audit.jsonl` and answers one row per criterion:

| # | Question | Answer style |
|---|----------|--------------|
| 1 | Did any tool call fail this run? If yes, did the audit log show explicit course-correction? | `failures=N corrections=N` |
| 2 | What % of Findings are CONFIRMED vs INFERRED vs HYPOTHESIS? | `C=X% I=Y% H=Z%` |
| 3 | How many artifact classes did this case touch? Which Findings cross ≥2? | `classes=[…] crossed=[…]` |
| 4 | Were any tool calls rejected by typed-surface validation this run? | `rejected=N reasons=[…]` |
| 5 | Does every Finding cite a tool_call_id? (must be 100%; verifier vetoes otherwise) | `cited=N/N` |
| 6 | Is the run reproducible from the manifest alone (no external state)? | `reproducible=yes/no` |

The grader prints these rows and writes them to `<case>/self-score.json`.
This output lives **outside** the sealed audit chain — it is an
after-the-fact maintainer assessment, not something the investigation
agent emits or signs.
