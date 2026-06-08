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

PASS rule (exit 0) requires BOTH:
  - ``recall_percent >= min_recall_percent`` from the golden, and
  - ``verdict_match`` — the run's verdict word is consistent with the golden's.
    Consistency is honest, not literal: ``INDETERMINATE`` is always accepted (a
    scoped-partial run is never a recall failure, per the live-test gate), and the
    evil/no-evil polarity must agree otherwise.

Usage:
    python scripts/score-recall.py <case-dir> [--golden goldens/<id>] [--quiet]
    python scripts/score-recall.py                 # newest dir under tmp/auto-runs/
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

# A run finding matches an expected one when it COVERS this fraction of the
# expected finding's distinctive tokens. Recall asks "did the run surface this
# ground-truth claim?" — so we normalize the overlap by the expected token set,
# not by the union (symmetric Jaccard unfairly penalizes verbose run findings
# that fully state the claim and then add caveats). Set at 0.5 so a match needs the
# *distinctive* tokens of the claim, not just shared generic DFIR vocabulary
# (email/host/http) that a semantically-unrelated finding can accumulate to ~0.4.
MATCH_COVERAGE = 0.5
# Floor on absolute shared tokens so a tiny expected set can't match on one or
# two generic words that survived stopword removal.
MATCH_MIN_SHARED = 3

# Tokens with no discriminating power for DFIR finding descriptions.
_STOPWORDS = frozenset(
    """a an and are as at be by for from has have in into is it its of on or that
    the to via with within shows show indicates indicating evidence artifact
    artifacts file files entry entries consistent suspicious recent recently""".split()
)

# Verdict words the product emits, grouped by polarity. INDETERMINATE is handled
# separately (always accepted). Goldens use the same vocabulary as verdict.json.
_EVIL_WORDS = frozenset({"CONFIRMED_EVIL", "SUSPICIOUS", "SUSPICION", "EVIL"})
_BENIGN_WORDS = frozenset({"NO_EVIL", "BENIGN"})
_NEUTRAL_WORDS = frozenset({"UNKNOWN", "INDETERMINATE"})


def _tokens(*parts: str | None) -> set[str]:
    text = " ".join(p for p in parts if p).lower()
    return {t for t in re.findall(r"[a-z0-9]+", text) if t not in _STOPWORDS and len(t) > 2}


def _coverage(expected: set[str], candidate: set[str]) -> tuple[float, int]:
    """How much of the expected token set the candidate covers.

    Returns (coverage_fraction, shared_count). Normalizing by the expected set
    (not the union) makes a verbose-but-correct run finding match a concise
    ground-truth claim.
    """
    if not expected or not candidate:
        return 0.0, 0
    shared = len(expected & candidate)
    return shared / len(expected), shared


def _newest_case_dir() -> Path | None:
    root = Path("tmp/auto-runs")
    if not root.is_dir():
        return None
    cases = [d for d in root.iterdir() if d.is_dir() and (d / "verdict.json").is_file()]
    return max(cases, key=lambda d: d.stat().st_mtime) if cases else None


def _resolve_golden(case_dir: Path, override: str | None) -> Path | None:
    """Find the expected-findings.json for this case.

    Order: explicit --golden, then goldens/<verdict.case_id>, then a goldens dir
    whose name is a substring of the case dir name (handles auto-<uuid> dirs that
    record their logical case_id inside verdict.json).
    """
    if override:
        p = Path(override)
        cand = p if p.is_file() else p / "expected-findings.json"
        return cand if cand.is_file() else None

    goldens = Path("goldens")
    verdict = case_dir / "verdict.json"
    if verdict.is_file():
        try:
            cid = json.loads(verdict.read_text(encoding="utf-8")).get("case_id")
        except json.JSONDecodeError:
            cid = None
        if cid:
            cand = goldens / str(cid) / "expected-findings.json"
            if cand.is_file():
                return cand
    if goldens.is_dir():
        name = case_dir.name
        for sub in sorted(goldens.iterdir()):
            cand = sub / "expected-findings.json"
            if cand.is_file() and (sub.name in name or name in sub.name):
                return cand
    return None


def _verdict_consistent(run_verdict: str | None, golden_verdict: str | None) -> bool:
    """Honest verdict consistency — deliberately ASYMMETRIC.

    The product's three verdict words carry an epistemic polarity: EVIL
    (CONFIRMED_EVIL/SUSPICIOUS), BENIGN (NO_EVIL), NEUTRAL (INDETERMINATE/UNKNOWN).

    Rules, in order:
      1. A NEUTRAL *run* verdict is always accepted. We never punish honest
         uncertainty — a scoped-partial or "saw leads, couldn't corroborate" run
         is the correct posture, not a failure (matches the live-test gate).
      2. Once the run makes a *definite* call (EVIL or BENIGN), a NEUTRAL *golden*
         means the case was authored to expect uncertainty — so the definite call
         is over/under-confident and FAILS. This is what makes a false-positive
         control (e.g. alihadi-09 "Encrypt Them All", golden INDETERMINATE) bite:
         a run that escalates to CONFIRMED_EVIL/SUSPICIOUS is wrong.
      3. Otherwise the polarity must agree.
    """
    rv = (run_verdict or "").upper()
    gv = (golden_verdict or "").upper()
    if rv in _NEUTRAL_WORDS:
        return True
    if gv in _NEUTRAL_WORDS:
        return False
    if rv in _EVIL_WORDS and gv in _EVIL_WORDS:
        return True
    if rv in _BENIGN_WORDS and gv in _BENIGN_WORDS:
        return True
    return rv == gv


def _is_eligible(expected: dict[str, Any], rf: dict[str, Any]) -> bool:
    """Can this run finding satisfy this expected finding?

    Eligibility is purely description-content overlap: the run finding must cover
    enough of the expected finding's distinctive tokens. MITRE technique is
    deliberately NOT a shortcut here — in cases where every finding shares one
    technique (e.g. all T1071.001), a MITRE match would make any finding eligible
    for any claim and inflate recall. Content overlap is the honest signal.
    """
    exp_tokens = _tokens(expected.get("description"), expected.get("artifact_hint"))
    cov, shared = _coverage(exp_tokens, _tokens(rf.get("description"), rf.get("artifact_path")))
    return shared >= MATCH_MIN_SHARED and cov >= MATCH_COVERAGE


def _max_matching(
    expected: list[dict[str, Any]], run_findings: list[dict[str, Any]]
) -> dict[int, int]:
    """Maximum bipartite matching (Kuhn's algorithm): expected_idx -> run_idx.

    A run finding may back at most one expected claim (no double-counting), and we
    find the assignment that covers the *most* expected claims — so neither greedy
    order nor a shared MITRE technique can under- or over-count recall.
    """
    adj: list[list[int]] = [
        [j for j, rf in enumerate(run_findings) if _is_eligible(exp, rf)] for exp in expected
    ]
    run_to_exp: dict[int, int] = {}

    def _augment(i: int, seen: set[int]) -> bool:
        for j in adj[i]:
            if j in seen:
                continue
            seen.add(j)
            if j not in run_to_exp or _augment(run_to_exp[j], seen):
                run_to_exp[j] = i
                return True
        return False

    for i in range(len(expected)):
        _augment(i, set())
    return {i: j for j, i in run_to_exp.items()}


def score(case_dir: Path, golden_path: Path) -> dict[str, Any]:
    verdict_doc = json.loads((case_dir / "verdict.json").read_text(encoding="utf-8"))
    golden = json.loads(golden_path.read_text(encoding="utf-8"))

    run_findings: list[dict[str, Any]] = verdict_doc.get("findings") or []
    expected: list[dict[str, Any]] = golden.get("findings") or []

    assignment = _max_matching(expected, run_findings)  # expected_idx -> run_idx (1:1)
    matched: list[dict[str, Any]] = []
    unmatched: list[dict[str, Any]] = []
    for i, exp in enumerate(expected):
        record = {
            "finding_id": exp.get("finding_id"),
            "description": exp.get("description"),
            "mitre_technique": exp.get("mitre_technique"),
        }
        if i in assignment:
            record["matched_run_finding_id"] = run_findings[assignment[i]].get("finding_id")
            matched.append(record)
        else:
            unmatched.append(record)

    expected_n = len(expected)
    recalled_n = len(matched)
    # An empty golden (e.g. synthetic-benign) is 100% recalled by definition: a
    # clean case has nothing to find, so a run with no findings is a perfect score.
    recall_percent = 100 if expected_n == 0 else round(recalled_n * 100 / expected_n)
    min_recall = int(golden.get("min_recall_percent", 0))

    run_verdict = verdict_doc.get("verdict")
    golden_verdict = golden.get("verdict")
    verdict_match = _verdict_consistent(run_verdict, golden_verdict)
    passed = recall_percent >= min_recall and verdict_match

    return {
        "case_id": golden.get("case_id") or verdict_doc.get("case_id"),
        "case_dir": str(case_dir),
        "golden": str(golden_path),
        "expected_n": expected_n,
        "recalled_n": recalled_n,
        "recall_percent": recall_percent,
        "min_recall_percent": min_recall,
        "run_verdict": run_verdict,
        "golden_verdict": golden_verdict,
        "verdict_match": verdict_match,
        "pass": passed,
        "matched": matched,
        "unmatched": unmatched,
    }


def _print_report(result: dict[str, Any]) -> None:
    print(f"=== VERDICT recall score — {result['case_id']} ===")
    print(f"  case_dir : {result['case_dir']}")
    print(f"  golden   : {result['golden']}")
    print(
        f"  recall   : {result['recalled_n']}/{result['expected_n']} "
        f"= {result['recall_percent']}%  (min {result['min_recall_percent']}%)"
    )
    print(
        f"  verdict  : run={result['run_verdict']} golden={result['golden_verdict']} "
        f"match={'yes' if result['verdict_match'] else 'NO'}"
    )
    if result["unmatched"]:
        print("  missed:")
        for m in result["unmatched"]:
            tech = f" [{m['mitre_technique']}]" if m.get("mitre_technique") else ""
            print(f"    - {m['finding_id']}{tech}: {m['description']}")
    print(f"  RESULT   : {'PASS' if result['pass'] else 'FAIL'}")


def main(argv: list[str]) -> int:
    args = [a for a in argv[1:] if a not in ("--quiet",)]
    quiet = "--quiet" in argv
    golden_override: str | None = None
    if "--golden" in args:
        gi = args.index("--golden")
        golden_override = args[gi + 1] if gi + 1 < len(args) else None
        args = args[:gi] + args[gi + 2 :]

    case_dir = Path(args[0]) if args else _newest_case_dir()
    if case_dir is None:
        print("usage: python scripts/score-recall.py <case-dir> [--golden <dir>]", file=sys.stderr)
        print("  (no case dir given and none found under tmp/auto-runs/)", file=sys.stderr)
        return 2
    if not (case_dir / "verdict.json").is_file():
        print(f"error: {case_dir}/verdict.json not found", file=sys.stderr)
        return 2

    golden_path = _resolve_golden(case_dir, golden_override)
    if golden_path is None:
        print(f"error: no expected-findings.json golden found for {case_dir}", file=sys.stderr)
        print("  pass one explicitly with --golden goldens/<case-id>", file=sys.stderr)
        return 2

    result = score(case_dir, golden_path)
    if not quiet:
        _print_report(result)
    out = case_dir / "recall-score.json"
    out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    if not quiet:
        print(f"\nwrote {out}")
    return 0 if result["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
