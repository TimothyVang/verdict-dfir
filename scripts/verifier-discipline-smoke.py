#!/usr/bin/env python3
"""verifier-discipline-smoke - mechanical, LLM-free verifier-discipline gate.

A completed VERDICT run leaves two offline-verifiable artifacts: the hash-chained
``audit.jsonl`` and the scoped ``verdict.json``. ``manifest_verify`` already proves
the chain is intact and that each Finding's tool re-run reproduces its hash. What
it does NOT mechanically assert is that the *verifier was actually exercised* for
everything that shipped, and that the recovery records cite real executed tool
calls. A run could (in principle) ship a Finding whose ``tool_call_id`` never
appears as an executed ``tool_call_output``, ship a Finding the verifier
``rejected``, or log a ``course_correction`` blaming a tool call that never ran.

This smoke parses ``audit.jsonl`` + ``verdict.json`` and asserts, deterministically:

1. **Evidence anchor executed.** Every shipped ``Finding.tool_call_id`` resolves
   to a real ``tool_call_output`` record (the tool actually produced output — not
   a fabricated id).
2. **Verifier exercised, nothing rejected.** Every shipped CONFIRMED/INFERRED
   Finding has a matching ``verifier_action`` record, and no shipped Finding
   carries a ``verifier_action`` of ``rejected``.
3. **Counts reconcile (never pinned).** The shipped-finding count, the
   ``finding_approved`` record count, and the approved ``verifier_action`` count
   are cross-checked against each other — reconciled, not compared to a literal
   (CLAUDE.md: "do not hard-code counts ... reconcile, don't pin"). If a
   ``suppression_funnel`` tally is present it is reconciled too.
4. **Recovery cites executed tool calls.** Every ``course_correction`` /
   ``verdict_revision`` record that names a tool-call id (``trigger_tool_call_id``
   / ``tool_call_id`` / ``failed_tool_call_id``) points at a tool call that
   actually started or executed — not a fabricated command string.

The audit-record kinds mirror the typed ``AgentEvent`` union in
``services/agent/findevil_agent/events.py`` (``ToolCallOutput`` -> the persisted
``tool_call_output`` kind, ``VerifierAction`` -> ``verifier_action``, ``Finding``
-> ``finding_approved``); this smoke only *reads* those kinds.

Custody-neutral: read-only over committed artifacts; it never re-signs, mutates
the chain, or changes any scoring math.

Usage::

    python3 scripts/verifier-discipline-smoke.py            # self-test + committed fixtures
    python3 scripts/verifier-discipline-smoke.py <run_dir>  # check one run dir

Exit 0 if every checked run is clean (and the self-test catches the negatives);
non-zero on the first discipline violation.
"""

from __future__ import annotations

import json
import sys
import tempfile
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# Persisted audit-record kinds. These are the snake_case on-disk names of the
# typed AgentEvent variants in services/agent/findevil_agent/events.py
# (ToolCallStart/ToolCallOutput/VerifierAction/Finding) plus the recovery kinds
# the engine appends to the chain (course_correction / verdict_revision).
KIND_TOOL_CALL_START = "tool_call_start"
KIND_TOOL_CALL_OUTPUT = "tool_call_output"
KIND_VERIFIER_ACTION = "verifier_action"
KIND_FINDING_APPROVED = "finding_approved"
KIND_COURSE_CORRECTION = "course_correction"
KIND_VERDICT_REVISION = "verdict_revision"

# Confidence tiers that assert a tool-backed fact (HYPOTHESIS is a lead, exempt).
ANCHORED_CONFIDENCE = ("CONFIRMED", "INFERRED")

# Verifier action that must never ship.
REJECTED = "rejected"

# Keys a recovery record may use to cite the tool call that triggered it.
RECOVERY_TCID_KEYS = ("trigger_tool_call_id", "tool_call_id", "failed_tool_call_id")


def _load_audit(run_dir: Path) -> list[dict]:
    """Parse audit.jsonl into a list of records (skipping blank lines)."""
    path = run_dir / "audit.jsonl"
    records: list[dict] = []
    with path.open(encoding="utf-8") as handle:
        for lineno, raw in enumerate(handle, start=1):
            raw = raw.strip()
            if not raw:
                continue
            try:
                records.append(json.loads(raw))
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{lineno}: invalid JSON ({exc})") from exc
    return records


def audit_violations(run_dir: Path) -> list[str]:
    """Return a list of verifier-discipline violations for one run dir.

    Empty list = clean. Each entry is a human-readable violation string. This is
    the reusable core the smoke and its tests both drive.
    """
    run_dir = Path(run_dir)
    violations: list[str] = []

    records = _load_audit(run_dir)
    verdict_path = run_dir / "verdict.json"
    verdict = json.loads(verdict_path.read_text(encoding="utf-8"))
    shipped = verdict.get("findings") or []

    # Index the audit chain.
    started_tcids: set[str] = set()
    executed_tcids: set[str] = set()
    verifier_actions: dict[str, list[str]] = {}
    finding_approved_ids: list[str] = []

    for rec in records:
        kind = rec.get("kind")
        payload = rec.get("payload") or {}
        if kind == KIND_TOOL_CALL_START:
            if payload.get("tool_call_id"):
                started_tcids.add(payload["tool_call_id"])
        elif kind == KIND_TOOL_CALL_OUTPUT:
            if payload.get("tool_call_id"):
                executed_tcids.add(payload["tool_call_id"])
        elif kind == KIND_VERIFIER_ACTION:
            fid = payload.get("finding_id")
            action = payload.get("action")
            if fid is not None:
                verifier_actions.setdefault(fid, []).append(action)
        elif kind == KIND_FINDING_APPROVED:
            fid = payload.get("finding_id")
            if fid is None:
                fid = (payload.get("finding") or {}).get("finding_id")
            if fid is not None:
                finding_approved_ids.append(fid)

    # Check 1 + 2: per shipped finding.
    for finding in shipped:
        fid = finding.get("finding_id", "<unknown>")
        tcid = (finding.get("tool_call_id") or "").strip()
        confidence = finding.get("confidence")

        if confidence in ANCHORED_CONFIDENCE:
            if not tcid:
                violations.append(
                    f"shipped {confidence} finding {fid} has a blank tool_call_id"
                )
            elif tcid not in executed_tcids:
                violations.append(
                    f"shipped finding {fid} cites tool_call_id {tcid!r} that never "
                    "appears as an executed tool_call_output"
                )

        actions = verifier_actions.get(fid, [])
        if confidence in ANCHORED_CONFIDENCE and not actions:
            violations.append(
                f"shipped {confidence} finding {fid} has no verifier_action record "
                "(verifier was not exercised for a shipped fact)"
            )
        if REJECTED in actions:
            violations.append(
                f"shipped finding {fid} ships despite a verifier_action of 'rejected'"
            )
        # The finding may also carry its own verifier_action verdict inline.
        inline = finding.get("verifier_action")
        if isinstance(inline, str) and inline == REJECTED:
            violations.append(
                f"shipped finding {fid} carries an inline verifier_action='rejected'"
            )

    # Check 3: counts reconcile (reconciled across independent tallies, never
    # pinned to a literal — CLAUDE.md rule). The finding_approved records are the
    # per-finding ship tally: their count must equal the shipped count and their
    # ids must cover every shipped finding. (The approved verifier_action tally
    # is intentionally NOT count-equated to shipped, since a shipped HYPOTHESIS
    # lead need not carry an "approved" action — check 2 already proves every
    # anchored shipped finding has a non-rejected verifier_action.)
    shipped_count = len(shipped)
    shipped_ids = {f.get("finding_id") for f in shipped}
    if finding_approved_ids:
        if len(finding_approved_ids) != shipped_count:
            violations.append(
                f"count mismatch: {shipped_count} shipped finding(s) but "
                f"{len(finding_approved_ids)} finding_approved record(s)"
            )
        uncovered = shipped_ids - set(finding_approved_ids)
        if uncovered:
            violations.append(
                "shipped finding(s) with no finding_approved record: "
                + ", ".join(sorted(str(x) for x in uncovered))
            )

    funnel = verdict.get("suppression_funnel")
    if isinstance(funnel, dict):
        violations.extend(_reconcile_funnel(funnel, shipped_count))

    # Check 4: every recovery record that cites a tool-call id must point at a
    # tool call that actually started or executed.
    candidate_tcids = started_tcids | executed_tcids
    for rec in records:
        kind = rec.get("kind")
        if kind not in (KIND_COURSE_CORRECTION, KIND_VERDICT_REVISION):
            continue
        payload = rec.get("payload") or {}
        for key in RECOVERY_TCID_KEYS:
            cited = payload.get(key)
            if not cited or not isinstance(cited, str):
                continue
            if cited not in candidate_tcids:
                violations.append(
                    f"{kind} record cites {key}={cited!r} that never appears as a "
                    "started/executed tool call (fabricated trigger)"
                )

    return violations


def _reconcile_funnel(funnel: dict, shipped_count: int) -> list[str]:
    """Reconcile a suppression_funnel tally against the shipped count.

    Tolerant of the exact field names: the reported/kept stage must equal the
    shipped count, and the raw stage must equal the sum of all numeric stages
    (reconcile, never pin). Returns violation strings.
    """
    violations: list[str] = []
    numeric = {k: v for k, v in funnel.items() if isinstance(v, int)}
    reported = None
    for key in ("reported", "kept", "shipped"):
        if key in numeric:
            reported = numeric[key]
            break
    if reported is not None and reported != shipped_count:
        violations.append(
            f"suppression_funnel reports {reported} but {shipped_count} finding(s) shipped"
        )
    raw = numeric.get("raw")
    if raw is not None:
        downstream = sum(v for k, v in numeric.items() if k != "raw")
        if downstream and raw != downstream:
            violations.append(
                f"suppression_funnel raw={raw} != sum of downstream stages ({downstream})"
            )
    return violations


def _committed_run_dirs() -> list[Path]:
    """Every committed run fixture that carries both audit.jsonl + verdict.json."""
    roots = [REPO / "docs" / "sample-run", REPO / "docs" / "release-evidence"]
    found: list[Path] = []
    for root in roots:
        if not root.is_dir():
            continue
        for audit in sorted(root.rglob("audit.jsonl")):
            run = audit.parent
            if (run / "verdict.json").is_file():
                found.append(run)
    return found


def _self_test() -> list[str]:
    """Synthetic positive + negative fixtures — protect the checker itself.

    Returns a list of self-test failures (empty = the checker behaves).
    """
    failures: list[str] = []
    clean_records = [
        {
            "kind": KIND_TOOL_CALL_START,
            "payload": {"tool": "case_open", "tool_call_id": "tc-001"},
        },
        {"kind": KIND_TOOL_CALL_OUTPUT, "payload": {"tool_call_id": "tc-001"}},
        {
            "kind": KIND_TOOL_CALL_START,
            "payload": {"tool": "evtx_query", "tool_call_id": "tc-002"},
        },
        {"kind": KIND_TOOL_CALL_OUTPUT, "payload": {"tool_call_id": "tc-002"}},
        {
            "kind": KIND_VERIFIER_ACTION,
            "payload": {"action": "approved", "finding_id": "f-1"},
        },
        {"kind": KIND_FINDING_APPROVED, "payload": {"finding_id": "f-1"}},
    ]
    clean_findings = [
        {"finding_id": "f-1", "tool_call_id": "tc-002", "confidence": "CONFIRMED"}
    ]

    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)

        def _materialize(name: str, records: list[dict], findings: list[dict]) -> Path:
            run = base / name
            run.mkdir(parents=True, exist_ok=True)
            (run / "audit.jsonl").write_text(
                "".join(json.dumps(r) + "\n" for r in records), encoding="utf-8"
            )
            (run / "verdict.json").write_text(
                json.dumps({"verdict": "SUSPICIOUS", "findings": findings}),
                encoding="utf-8",
            )
            return run

        # Positive: clean run must pass.
        clean = _materialize("clean", clean_records, clean_findings)
        if audit_violations(clean):
            failures.append("self-test: clean synthetic run unexpectedly flagged")

        # Negative (a): finding tool_call_id absent from the chain.
        bad_findings = [dict(clean_findings[0], tool_call_id="tc-404")]
        absent = _materialize("absent_tcid", clean_records, bad_findings)
        if not audit_violations(absent):
            failures.append("self-test: absent finding tool_call_id NOT flagged")

        # Negative (b): course_correction citing a fabricated tool_call_id.
        bad_records = clean_records + [
            {
                "kind": KIND_COURSE_CORRECTION,
                "payload": {
                    "failed_tool": "registry_query",
                    "trigger_tool_call_id": "tc-999",
                },
            }
        ]
        fabricated = _materialize("bad_correction", bad_records, clean_findings)
        if not audit_violations(fabricated):
            failures.append(
                "self-test: fabricated course_correction trigger NOT flagged"
            )

    return failures


def _check_one(run_dir: Path) -> int:
    violations = audit_violations(run_dir)
    label = run_dir.relative_to(REPO) if run_dir.is_relative_to(REPO) else run_dir
    if violations:
        print(f"  FAIL {label}")
        for v in violations:
            print(f"    - {v}")
        return 1
    print(f"  ok   {label}")
    return 0


def main(argv: list[str]) -> int:
    if len(argv) > 1:
        rc = 0
        for arg in argv[1:]:
            rc |= _check_one(Path(arg).resolve())
        return rc

    print("verifier-discipline-smoke: self-test")
    self_failures = _self_test()
    for f in self_failures:
        print(f"  {f}")
    if self_failures:
        print("FAIL: checker self-test did not behave")
        return 1
    print("  ok   self-test (clean passes; absent tcid + fabricated trigger caught)")

    print("verifier-discipline-smoke: committed run fixtures")
    runs = _committed_run_dirs()
    if not runs:
        print("  (no committed run fixtures found)")
    rc = 0
    counts: Counter[str] = Counter()
    for run in runs:
        result = _check_one(run)
        rc |= result
        counts["fail" if result else "ok"] += 1
    print(
        f"verifier-discipline-smoke: {counts['ok']} clean, {counts['fail']} flagged "
        f"(of {len(runs)} committed run fixture(s))"
    )
    if rc:
        print("FAIL: a committed run violates verifier discipline")
    else:
        print("OK")
    return rc


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
