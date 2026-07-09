#!/usr/bin/env python3
"""Generate the committed, independently-recomputable accuracy report (P0-1/P0-2).

Walks committed scored-run case directories (default: ``docs/sample-run/*`` that
contain a ``verdict.json``), and for each one recomputes BOTH axes — never blended:

  * investigative_recall   — ``findevil_agent.accuracy.score`` vs the resolved
    golden (recall / precision / F1 / planted bait, each caught FP carrying a
    ``catch_reason``);
  * deterministic_grounding — the goldens-FREE discipline view from
    ``scripts/score-overclaim.py`` (citation / replay / custody). When a case has
    no ``manifest_verify.json`` the custody view is marked unavailable, never shown
    as a verified default.

Writes ``docs/release-evidence/accuracy-report.json``. Re-running on the same
commit + same case artifacts is reproducible, so a reviewer can regenerate and
diff. Both scorer modules are stdlib-only and loaded by file path, so this runs
under plain ``python3`` (no findevil_agent install needed).

Usage:
    python scripts/generate-accuracy-report.py [case_dir ...]
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent
GOLDENS = REPO / "goldens"
DEFAULT_RUNS = REPO / "docs" / "sample-run"
OUT = REPO / "docs" / "release-evidence" / "accuracy-report.json"


def _load(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if not spec or not spec.loader:
        raise RuntimeError(f"cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


accuracy = _load(
    REPO / "services" / "agent" / "findevil_agent" / "accuracy.py", "accuracy"
)
overclaim = _load(REPO / "scripts" / "score-overclaim.py", "score_overclaim")


def _git_commit() -> str:
    try:
        return subprocess.run(
            ["git", "-C", str(REPO), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
    except (subprocess.CalledProcessError, OSError):
        return "unknown"


def _resolve_golden(case_dir: Path) -> Path | None:
    """REPO-rooted golden resolution (CWD-independent mirror of accuracy.resolve_golden)."""
    verdict = case_dir / "verdict.json"
    if verdict.is_file():
        try:
            cid = json.loads(verdict.read_text(encoding="utf-8")).get("case_id")
        except json.JSONDecodeError:
            cid = None
        if cid:
            cand = GOLDENS / str(cid) / "expected-findings.json"
            if cand.is_file():
                return cand
    if GOLDENS.is_dir():
        for sub in sorted(GOLDENS.iterdir()):
            if sub.is_dir() and sub.name in case_dir.name:
                cand = sub / "expected-findings.json"
                if cand.is_file():
                    return cand
    return None


def _grounding(case_dir: Path) -> dict[str, Any] | None:
    """The goldens-free discipline view; custody marked unavailable without a manifest.

    Returns ``None`` when the case lacks the audit artifacts the discipline view
    needs (e.g. no ``audit.jsonl``), so the caller records grounding as
    ``{"available": False}`` rather than crashing — a missing artifact must never
    read as a verified default.
    """
    if not (case_dir / "audit.jsonl").is_file():
        return None
    try:
        g = overclaim.score(case_dir)
    except Exception:
        return None
    custody_available = (case_dir / "manifest_verify.json").is_file()
    return {
        "available": True,
        "citation_coverage": g.get("citation_coverage"),
        "replay_pass_rate": g.get("replay_pass_rate"),
        "replay_attempted_n": g.get("replay_attempted_n"),
        "custody_available": custody_available,
        "custody_ok": g.get("custody_ok") if custody_available else None,
        "overclaim_snuck_through_n": g.get("overclaim_snuck_through_n"),
        # Tier A disclosure: raw->reported suppression funnel + allowed-but-not-run
        # tool table (goldens-free, read-only) from score-overclaim.
        "suppression_funnel": g.get("suppression_funnel"),
        "untested_surface": g.get("untested_surface"),
    }


def main(argv: list[str]) -> int:
    case_dirs = (
        [Path(a).resolve() for a in argv]
        if argv
        else sorted(p.parent for p in DEFAULT_RUNS.glob("*/verdict.json"))
    )
    cases: list[dict[str, Any]] = []
    disclosed: list[dict[str, Any]] = []
    for case_dir in case_dirs:
        golden = _resolve_golden(case_dir)
        report = accuracy.score_report(case_dir, golden, grounding=_grounding(case_dir))
        report["case_dir"] = str(case_dir.relative_to(REPO))
        if golden is None:
            # No external answer key: DISCLOSE the case (Tier A grounding + Tier B
            # null-with-reason) rather than silently dropping it.
            disclosed.append(report)
        else:
            report["golden"] = str(golden.relative_to(REPO))
            cases.append(report)

    # Fail closed: a Tier B recall/precision number must NEVER appear without a
    # resolved external answer key. score_report enforces this at the source; this
    # gate is the belt-and-suspenders check that the committed artifact obeys it.
    violations: list[str] = []
    for c in cases:
        ir = c["investigative_recall"]
        if not ir.get("scored") or not isinstance(ir.get("recall_percent"), int):
            violations.append(
                f"{c['case_dir']}: scored case missing a numeric Tier B recall"
            )
    for d in disclosed:
        ir = d["investigative_recall"]
        if ir.get("scored") or isinstance(ir.get("recall_percent"), int):
            violations.append(
                f"{d['case_dir']}: Tier B recall asserted without an external answer key"
            )
    if violations:
        print("FAIL (fail-closed accuracy gate):", file=sys.stderr)
        for v in violations:
            print(f"  - {v}", file=sys.stderr)
        return 1

    total_fp_planted = sum(c["investigative_recall"]["fp_planted"] for c in cases)
    total_fp_caught = sum(
        len(c["investigative_recall"]["planted_bait_caught"]) for c in cases
    )
    doc = {
        "schema_version": 1,
        "product_commit": _git_commit(),
        "note": (
            "Two-axis, tier-labelled accuracy: Tier A = deterministic_grounding "
            "(goldens-free: citation / replay / custody, computable now) and Tier B = "
            "investigative_recall (recall / precision / F1, valid ONLY against an external "
            "answer key). Never blended. A case with no resolved key is DISCLOSED under "
            "disclosed_no_external_key with Tier B null-with-reason, never given a fabricated "
            "number. Recompute with scripts/generate-accuracy-report.py."
        ),
        "source_cases": [c["case_dir"] for c in cases],
        "disclosed_no_external_key": [d["case_dir"] for d in disclosed],
        "summary": {
            "cases_scored": len(cases),
            "cases_passing": sum(1 for c in cases if c["pass"]),
            "cases_disclosed_no_key": len(disclosed),
            "total_fp_planted": total_fp_planted,
            "total_fp_caught_and_reasoned_away": total_fp_caught,
        },
        "cases": cases,
        "disclosed_no_external_key_cases": disclosed,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        f"wrote {OUT.relative_to(REPO)} "
        f"({len(cases)} Tier-B-scored cases, {len(disclosed)} disclosed no-key)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
