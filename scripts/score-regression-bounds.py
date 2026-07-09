#!/usr/bin/env python3
"""Accuracy regression-bounds guard — fail if a scored run drops below a committed floor.

Companion to ``score-recall.py``. After that scorer writes ``<case>/recall-score.json``,
this asserts the run has not regressed below the floor committed in
``goldens/<case>/regression-bounds.json`` so a prompt/tool edit that silently lowers
recall, raises the hallucination rate, or lets a planted bait through is caught.

The floor is the *reproducible* number, not the aspirational golden bar. NIST recall, for
example, is run-dependent (5/14 = 36% on leaner runs, 7/14 = 50% on the richer ones), so
its floor is 36 — well under the 71% golden target — and the guard fires only on a genuine
regression below what the system currently ships. No number is invented: a floor is only
committed once a real run has reproduced it.

This is a post-run / L3 guard, not an L1 smoke: case run directories are gitignored, so a
fresh clone has nothing to score. Run it after ``score-recall.py`` (or point it at a staged
run). It exits 0 if every present bound holds, 1 on any regression, 2 on a missing input.

Usage:
    python3 scripts/score-regression-bounds.py <case-dir> [--bounds <bounds.json>]
    # default bounds: goldens/<case-basename>/regression-bounds.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

# Every bound key, mapped to how it is checked against a recall-score.json metric.
# A bounds file with any other key is a typo and must fail loudly, not silently pass.
_FLOOR_KEYS = {
    "min_recall_percent": "recall_percent",
    "min_precision_percent": "precision_percent",
}
_CEIL_KEYS = {
    "max_hallucination_rate": "hallucination_rate",
    "max_fp_planted": "fp_planted",
}
_FLAG_KEYS = {"require_verdict_match": "verdict_match"}
_ALL_BOUND_KEYS = set(_FLOOR_KEYS) | set(_CEIL_KEYS) | set(_FLAG_KEYS)


def check_bounds(metrics: dict[str, Any], bounds: dict[str, Any]) -> list[str]:
    """Return a list of human-readable bound violations ([] means the run passed).

    Pure: takes the parsed ``recall-score.json`` metrics and a bounds dict. Only the
    bound keys present are checked, so a partial bounds file is valid. An unknown bound
    key raises ValueError (a typo must fail, not silently no-op).
    """
    # Underscore-prefixed keys (e.g. "_comment") are doc-only and ignored; any other
    # unrecognized key is a typo and must fail loudly rather than silently no-op.
    unknown = {k for k in bounds if not k.startswith("_")} - _ALL_BOUND_KEYS
    if unknown:
        raise ValueError(
            f"unknown regression-bound key(s): {sorted(unknown)} "
            f"(allowed: {sorted(_ALL_BOUND_KEYS)})"
        )
    violations: list[str] = []
    for key, metric in _FLOOR_KEYS.items():
        if key in bounds:
            got = metrics.get(metric, 0)
            if got < bounds[key]:
                violations.append(f"{metric} {got} < floor {bounds[key]} ({key})")
    for key, metric in _CEIL_KEYS.items():
        if key in bounds:
            got = metrics.get(metric, 0)
            if got > bounds[key]:
                violations.append(f"{metric} {got} > ceiling {bounds[key]} ({key})")
    for key, metric in _FLAG_KEYS.items():
        if bounds.get(key) and not metrics.get(metric):
            violations.append(f"{metric} is not satisfied (required by {key})")
    return violations


def main(argv: list[str]) -> int:
    args = [a for a in argv[1:] if not a.startswith("--")]
    if not args:
        print(
            "usage: python3 scripts/score-regression-bounds.py <case-dir> [--bounds <f>]",
            file=sys.stderr,
        )
        return 2
    case_dir = Path(args[0])
    score_path = case_dir / "recall-score.json"
    if not score_path.is_file():
        print(
            f"error: {score_path} not found — run scripts/score-recall.py first",
            file=sys.stderr,
        )
        return 2

    bounds_path: Path | None = None
    if "--bounds" in argv:
        bounds_path = Path(argv[argv.index("--bounds") + 1])
    else:
        bounds_path = Path("goldens") / case_dir.name / "regression-bounds.json"
    if not bounds_path.is_file():
        print(f"error: bounds file {bounds_path} not found", file=sys.stderr)
        return 2

    metrics = json.loads(score_path.read_text(encoding="utf-8"))
    bounds = json.loads(bounds_path.read_text(encoding="utf-8"))
    violations = check_bounds(metrics, bounds)

    print(f"=== regression-bounds — {case_dir} (bounds: {bounds_path}) ===")
    if not violations:
        print("  OK — all committed floors hold.")
        return 0
    for v in violations:
        print(f"  [REGRESSION] {v}")
    print(f"FAIL — {len(violations)} regression(s) below the committed floor.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
