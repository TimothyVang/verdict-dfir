#!/usr/bin/env python3
"""Validate committed VERDICT golden answer-key files.

This is a schema and hygiene smoke for ``goldens/*/expected-findings.json``.
It deliberately does not require raw evidence fixtures to be present: evidence
is gitignored and staged separately, while answer keys are small enough to keep
under source control.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent
GOLDENS = REPO / "goldens"

VALID_VERDICTS = {
    "CONFIRMED_EVIL",
    "SUSPICIOUS",
    "SUSPICION",
    "EVIL",
    "NO_EVIL",
    "BENIGN",
    "UNKNOWN",
    "INDETERMINATE",
}
VALID_CONFIDENCE = {"CONFIRMED", "INFERRED", "HYPOTHESIS"}

REQUIRED_TOP_LEVEL = {"case_id", "source_url", "license", "verdict", "findings"}
REQUIRED_FINDING = {
    "finding_id",
    "description",
    "confidence",
    "artifact_class",
    "artifact_hint",
}


def _nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _validate(path: Path) -> list[str]:
    errors: list[str] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return [f"invalid JSON: {exc}"]

    missing = sorted(REQUIRED_TOP_LEVEL - data.keys())
    if missing:
        errors.append(f"missing top-level key(s): {', '.join(missing)}")

    case_id = data.get("case_id")
    if not _nonempty_string(case_id):
        errors.append("case_id must be a non-empty string")
    elif case_id != path.parent.name:
        errors.append(f"case_id {case_id!r} must match directory {path.parent.name!r}")

    verdict = data.get("verdict")
    if verdict not in VALID_VERDICTS:
        errors.append(f"verdict {verdict!r} is not a recognized scorer verdict")

    pending = data.get("status") == "pending_manual_walkthrough"
    min_recall = data.get("min_recall_percent")
    if pending:
        if min_recall is not None:
            errors.append(
                "pending_manual_walkthrough stubs must omit min_recall_percent"
            )
    elif not isinstance(min_recall, int) or not 0 <= min_recall <= 100:
        errors.append("min_recall_percent must be an integer from 0 to 100")

    for key in ("source_url", "license"):
        if not _nonempty_string(data.get(key)):
            errors.append(f"{key} must be a non-empty string")

    findings = data.get("findings")
    if not isinstance(findings, list):
        errors.append("findings must be a list")
        return errors

    seen_ids: set[str] = set()
    for idx, finding in enumerate(findings):
        label = f"findings[{idx}]"
        if not isinstance(finding, dict):
            errors.append(f"{label} must be an object")
            continue
        missing_finding = sorted(REQUIRED_FINDING - finding.keys())
        if missing_finding:
            errors.append(f"{label} missing key(s): {', '.join(missing_finding)}")
        finding_id = finding.get("finding_id")
        if not _nonempty_string(finding_id):
            errors.append(f"{label}.finding_id must be a non-empty string")
        elif finding_id in seen_ids:
            errors.append(f"duplicate finding_id {finding_id!r}")
        else:
            seen_ids.add(finding_id)
        for key in ("description", "artifact_class", "artifact_hint"):
            if not _nonempty_string(finding.get(key)):
                errors.append(f"{label}.{key} must be a non-empty string")
        confidence = finding.get("confidence")
        if confidence not in VALID_CONFIDENCE:
            errors.append(f"{label}.confidence {confidence!r} is not valid")

    return errors


def main() -> int:
    paths = sorted(GOLDENS.glob("*/expected-findings.json"))
    print("=" * 60)
    print("Find Evil! - golden-answer-key-smoke")
    print("=" * 60)
    if not paths:
        print("[FAIL] no goldens/*/expected-findings.json files found")
        return 1

    failed = 0
    for path in paths:
        rel = path.relative_to(REPO).as_posix()
        errors = _validate(path)
        if errors:
            failed += 1
            print(f"[FAIL] {rel}")
            for error in errors:
                print(f"       - {error}")
        else:
            print(f"[OK  ] {rel}")

    print()
    if failed:
        print(f"FAIL - {failed} invalid answer-key file(s)")
        return 1
    print(f"OK - {len(paths)} answer-key file(s) valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
