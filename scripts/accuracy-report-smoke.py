#!/usr/bin/env python3
"""Offline schema gate for the committed accuracy report (P0-1/P0-2).

Validates ``docs/release-evidence/accuracy-report.json`` without needing any live
run artifacts: the two axes must be present and labeled per case, every
caught false-positive must carry a ``catch_reason``, and there must be NO single
blended accuracy number (the whole point of P0-2 is that recall and grounding are
reported separately). Regenerate the report with
``scripts/generate-accuracy-report.py``.

Run: ``python scripts/accuracy-report-smoke.py`` (exit 1 on any violation).
Part of ``scripts/run-all-smokes.sh``.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
REPORT = REPO / "docs" / "release-evidence" / "accuracy-report.json"

# A single blended accuracy scalar at case top level would defeat the two-axis
# split — these keys must NOT appear there.
BLENDED_KEYS = {"accuracy", "blended", "overall_accuracy", "score"}


def main() -> int:
    failures: list[str] = []

    if not REPORT.is_file():
        print(
            f"FAIL: {REPORT.relative_to(REPO)} is missing (run generate-accuracy-report.py)"
        )
        return 1
    try:
        doc = json.loads(REPORT.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"FAIL: {REPORT.relative_to(REPO)} is not valid JSON: {exc}")
        return 1

    for key in ("schema_version", "summary", "cases", "product_commit"):
        if key not in doc:
            failures.append(f"top-level key missing: {key}")

    for sk in (
        "cases_scored",
        "cases_disclosed_no_key",
        "total_fp_planted",
        "total_fp_caught_and_reasoned_away",
    ):
        if sk not in doc.get("summary", {}):
            failures.append(f"summary key missing: {sk}")

    cases = doc.get("cases", [])
    if not isinstance(cases, list) or not cases:
        failures.append("cases must be a non-empty list")

    def _is_numeric(v: object) -> bool:
        return isinstance(v, (int, float)) and not isinstance(v, bool)

    for i, case in enumerate(cases if isinstance(cases, list) else []):
        where = case.get("case_id", f"#{i}")
        ir = case.get("investigative_recall")
        dg = case.get("deterministic_grounding")
        if not isinstance(ir, dict):
            failures.append(f"{where}: missing investigative_recall section")
            ir = {}
        if not isinstance(dg, dict):
            failures.append(f"{where}: missing deterministic_grounding section")
            dg = {}
        elif "available" not in dg:
            failures.append(
                f"{where}: deterministic_grounding lacks an 'available' flag"
            )
        # Tier labels: A = grounding (key-free), B = recall (key-required).
        if ir.get("tier") != "B":
            failures.append(f"{where}: investigative_recall must be tier 'B'")
        if dg.get("tier") != "A":
            failures.append(f"{where}: deterministic_grounding must be tier 'A'")
        # Scored Tier B cases must carry a numeric recall AND a resolved key.
        if not ir.get("scored"):
            failures.append(f"{where}: a case in 'cases' must be Tier-B scored")
        if not _is_numeric(ir.get("recall_percent")):
            failures.append(
                f"{where}: scored case lacks a numeric Tier B recall_percent"
            )
        if not str(case.get("golden") or "").strip():
            failures.append(f"{where}: Tier B recall present without a resolved golden")
        blended = BLENDED_KEYS & set(case)
        if blended:
            failures.append(
                f"{where}: blended accuracy key(s) present: {sorted(blended)}"
            )
        for fp in (ir or {}).get("planted_bait_caught", []):
            if not str(fp.get("catch_reason") or "").strip():
                failures.append(
                    f"{where}: a caught FP has no catch_reason ({fp.get('finding_id')})"
                )

    # Fail-closed contract: a disclosed no-key case must NEVER carry a fabricated
    # Tier B number — recall/precision/F1 are null-with-reason and there is no golden.
    NO_KEY = {"value": None, "reason": "no_external_answer_key"}
    for i, case in enumerate(doc.get("disclosed_no_external_key_cases", [])):
        where = case.get("case_id") or case.get("case_dir") or f"disclosed#{i}"
        ir = case.get("investigative_recall") or {}
        if ir.get("scored"):
            failures.append(f"{where}: disclosed no-key case marked scored")
        if case.get("golden") not in (None, ""):
            failures.append(
                f"{where}: disclosed no-key case has a golden (should be none)"
            )
        for k in ("recall_percent", "precision_percent", "f1"):
            if ir.get(k) != NO_KEY:
                failures.append(
                    f"{where}: Tier B {k} must be null-with-reason without a key, got {ir.get(k)!r}"
                )
        if (case.get("deterministic_grounding") or {}).get("tier") != "A":
            failures.append(f"{where}: disclosed case grounding must be tier 'A'")

    print("=== accuracy-report smoke ===")
    print(f"  validated {REPORT.relative_to(REPO)} ({len(cases)} case(s))")
    if failures:
        print(f"  FAIL: {len(failures)} schema issue(s):")
        for f in failures:
            print(f"    - {f}")
        return 1
    print(
        "  PASS: two-axis report well-formed; every caught FP has a catch_reason; no blended number."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
