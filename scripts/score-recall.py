#!/usr/bin/env python3
"""VERDICT ground-truth recall scorer — a maintainer grading tool, NOT the product.

Companion to ``scripts/self-score.py``. Where self-score answers the six JUDGING
quality criteria, this answers a different question: **of the findings a correct
run should surface for this case, how many did the run actually find?** It is an
offline, after-the-fact assessment — it does not touch the sealed audit chain and
is never part of the investigation pipeline.

It reads a finished case directory's ``verdict.json`` and the matching
``goldens/<case-id>/expected-findings.json`` (the ground-truth answer key), matches
each expected finding against the run's findings, and computes recall. It replaces
the brittle exact ``diff`` that ``scripts/l3-run-goldens.sh`` used to do — real run
findings never byte-match a hand-authored golden, so we match on MITRE technique or
description/hint token overlap instead.

Matching: an expected finding is RECALLED when some run finding either
  - shares its ``mitre_technique`` (exact, non-null), or
  - overlaps its ``description`` + ``artifact_hint`` tokens above ``MATCH_THRESHOLD``
    (Jaccard over lowercased alphanumeric tokens, stopwords removed).

Precision side (over-claiming): a run finding matched to no expected claim is
``extra``. On an ``exhaustive`` (closed-world) golden every extra is a false
positive; on an open-world golden an extra is only a *provable* false positive
when it matches a planted ``anti_fact`` (a claim that is false for the case) or a
``known_negative`` (a benign IOC-lookalike a correct run must not assert). The
scorer reports ``precision_percent`` / ``f1`` / ``hallucination_rate`` and a
``precision_scored`` flag so open-world numbers are not mistaken for authoritative.

PASS rule (exit 0) requires ALL of:
  - ``recall_percent >= min_recall_percent`` from the golden,
  - ``verdict_match`` — the run's verdict word is consistent with the golden's.
    Consistency is honest, not literal: a NEUTRAL run (``INDETERMINATE``/``UNKNOWN``)
    matches only a NEUTRAL golden — it is also what a tool failure emits, so it
    cannot stand in for a definite answer — and the evil/no-evil polarity must
    agree otherwise, and
  - no ``anti_fact`` / ``known_negative`` violation — asserting a known-wrong claim
    fails the run even on an open-world key. Generic extra findings are reported
    but do not fail, so surfacing a real claim the key omitted is not punished.

Exit codes (a harness must be able to tell these four apart):
  0  PASS      — scored, and the run cleared the key.
  1  FAIL      — scored, and the run did not. ``<case>/recall-score.json`` holds
                 the metrics behind the verdict.
  2  ERROR     — could not score: no case dir / no verdict.json / no golden
                 resolved, or the key is broken (unsupported ``scoring_status``,
                 ``min_recall_percent: null`` stub). A maintainer has to fix
                 something.
  3  EXCLUDED  — the KEY declares itself unscoreable (``scoring_status:
                 not_ready``). Nothing was measured and nothing failed; the
                 golden asked not to be scored, and its ``not_ready_reason`` is
                 printed and written to ``<case>/recall-excluded.json``. A caller
                 that folds this into 1 or 2 is reporting a dataset decision as an
                 engine result — the dishonest direction, because it presents a
                 failure with no metrics behind it.

Usage:
    python scripts/score-recall.py <case-dir> [--golden goldens/<id>] [--quiet]
    python scripts/score-recall.py                 # newest dir under tmp/auto-runs/
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

# Single source of truth for the scoring core. The pure recall / precision /
# verdict-consistency / negative-coverage logic lives in the product package
# (services/agent/findevil_agent/accuracy.py) so the `accuracy_compare` MCP shim
# and this maintainer CLI share one implementation (no logic fork). This script
# keeps only the CLI + printing layer below.
#
# accuracy.py is stdlib-only, so we load it directly by file path rather than via
# ``import findevil_agent.accuracy`` — that package's __init__ pulls in the agent
# runtime (StrEnum etc., Python 3.11+), which this hyphenated maintainer script
# (often run with a bare ``python3``) should not require.
_REPO_ROOT = Path(__file__).resolve().parent.parent
_ACC_PATH = _REPO_ROOT / "services" / "agent" / "findevil_agent" / "accuracy.py"
_acc_spec = importlib.util.spec_from_file_location("findevil_accuracy_core", _ACC_PATH)
assert _acc_spec and _acc_spec.loader, f"cannot load accuracy core at {_ACC_PATH}"
_accuracy = importlib.util.module_from_spec(_acc_spec)
_acc_spec.loader.exec_module(_accuracy)

newest_case_dir = _accuracy.newest_case_dir
resolve_golden = _accuracy.resolve_golden
score = _accuracy.score
GoldenNotScoreable = _accuracy.GoldenNotScoreable

# Named so callers (scripts/l3-run-goldens.sh, any board) stop hard-coding ints.
# 3 mirrors scripts/fixture-readiness.py, which already returns 3 for NOT_READY
# and 2 for a checker error — same distinction, same numbers.
EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_ERROR = 2
EXIT_NOT_SCOREABLE = 3


def _print_report(result: dict[str, Any]) -> None:
    print(f"=== VERDICT recall score — {result['case_id']} ===")
    print(f"  case_dir : {result['case_dir']}")
    print(f"  golden   : {result['golden']}")
    print(
        f"  recall   : {result['recalled_n']}/{result['expected_n']} "
        f"= {result['recall_percent']}%  (min {result['min_recall_percent']}%)"
    )
    scored = "scored" if result["precision_scored"] else "open-world (not scored)"
    # precision/F1 are None when nothing was scoreable (nothing matched, nothing
    # provably wrong). Print that as n/a — a zero-denominator run is unmeasured,
    # not perfect.
    prec = result["precision_percent"]
    prec_txt = "n/a (nothing scored)" if prec is None else f"{prec}%"
    f1_txt = "n/a" if result["f1"] is None else result["f1"]
    print(
        f"  precision: {prec_txt}  "
        f"(F1 {f1_txt}; {result['false_positives_n']} FP / "
        f"{result['extra_n']} extra of {result['run_finding_n']} findings; {scored})"
    )
    halluc = result["hallucination_rate"]
    print(f"  halluc.  : {'n/a (no findings)' if halluc is None else halluc}")
    print(
        f"  fp_planted: {result['fp_planted']} (planted bait the run must not assert)"
    )
    print(
        f"  verdict  : run={result['run_verdict']} golden={result['golden_verdict']} "
        f"match={'yes' if result['verdict_match'] else 'NO'}"
    )
    if not result["run_completed"]:
        print(
            "  run      : INCOMPLETE — " + "; ".join(result["run_incomplete_reasons"])
        )
    if result["planted_bait"]:
        print("  PLANTED BAIT ASSERTED (fails the run):")
        for b in result["planted_bait"]:
            terms = f" {b['terms']}" if b.get("terms") else ""
            print(
                f"    - {b['finding_id']} [{b['violation']}]{terms}: {b['description']}"
            )
    if result["false_positives"]:
        print("  false positives:")
        for fp in result["false_positives"]:
            tag = f" [{fp['violation']}]" if fp.get("violation") else ""
            print(f"    - {fp['finding_id']}{tag}: {fp['description']}")
    if result["unmatched"]:
        print("  missed:")
        for m in result["unmatched"]:
            tech = f" [{m['mitre_technique']}]" if m.get("mitre_technique") else ""
            print(f"    - {m['finding_id']}{tech}: {m['description']}")
    print(f"  RESULT   : {'PASS' if result['pass'] else 'FAIL'}")


def _print_exclusion(exc: GoldenNotScoreable, *, quiet: bool) -> None:
    """Say EXCLUDED, name the key, and quote the key's own reason.

    Deliberately never prints "FAIL" or a metric: there is nothing measured here.
    Goes to stderr alongside the other non-result messages so a harness capturing
    stdout for a report does not pick this up as one.
    """
    print(f"=== EXCLUDED (not scoreable) — {exc.case_id} ===", file=sys.stderr)
    print(f"  golden   : {exc.golden_path}", file=sys.stderr)
    print(f"  declared : scoring_status={exc.scoring_status}", file=sys.stderr)
    print(
        f"  reason   : {exc.reason or '(the key gives no not_ready_reason)'}",
        file=sys.stderr,
    )
    if not quiet:
        print(
            "  This golden asked not to be scored. No accuracy claim — for or "
            "against the engine — can be made from it.",
            file=sys.stderr,
        )


def _write_exclusion_marker(
    case_dir: Path, golden_path: Path, exc: GoldenNotScoreable
) -> Path:
    """Record the exclusion machine-readably, in a file that is NOT a score.

    A board reading ``recall-score.json`` must not find a document it can mistake
    for metrics, so this is a separate filename carrying no ``pass`` / ``recall_*``
    keys at all — only the key's declaration.
    """
    marker = case_dir / "recall-excluded.json"
    marker.write_text(
        json.dumps(
            {
                "excluded": True,
                "case_id": exc.case_id,
                "case_dir": str(case_dir),
                "golden": str(golden_path),
                "scoring_status": exc.scoring_status,
                "reason": exc.reason,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return marker


def main(argv: list[str]) -> int:
    args = [a for a in argv[1:] if a not in ("--quiet",)]
    quiet = "--quiet" in argv
    golden_override: str | None = None
    if "--golden" in args:
        gi = args.index("--golden")
        golden_override = args[gi + 1] if gi + 1 < len(args) else None
        args = args[:gi] + args[gi + 2 :]

    case_dir = Path(args[0]) if args else newest_case_dir()
    if case_dir is None:
        print(
            "usage: python scripts/score-recall.py <case-dir> [--golden <dir>]",
            file=sys.stderr,
        )
        print(
            "  (no case dir given and none found under tmp/auto-runs/)", file=sys.stderr
        )
        return EXIT_ERROR
    if not (case_dir / "verdict.json").is_file():
        print(f"error: {case_dir}/verdict.json not found", file=sys.stderr)
        return EXIT_ERROR

    golden_path = resolve_golden(case_dir, golden_override)
    if golden_path is None:
        print(
            f"error: no expected-findings.json golden found for {case_dir}",
            file=sys.stderr,
        )
        print("  pass one explicitly with --golden goldens/<case-id>", file=sys.stderr)
        return EXIT_ERROR

    try:
        result = score(case_dir, golden_path)
    except GoldenNotScoreable as exc:
        # The KEY said "do not score me". That is a dataset decision, not an
        # accuracy failure and not a maintainer bug, so it gets its own exit code
        # and its own marker file — never a recall-score.json, because there is no
        # score to put in one.
        _print_exclusion(exc, quiet=quiet)
        _write_exclusion_marker(case_dir, golden_path, exc)
        return EXIT_NOT_SCOREABLE
    except ValueError as exc:
        # e.g. an unpopulated stub golden (min_recall_percent: null). Report the
        # golden by name rather than dying in a traceback.
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    if not quiet:
        _print_report(result)
    out = case_dir / "recall-score.json"
    out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    if not quiet:
        print(f"\nwrote {out}")
    return EXIT_PASS if result["pass"] else EXIT_FAIL


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
