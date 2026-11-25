#!/usr/bin/env python3
"""Validate committed VERDICT golden answer-key files.

This is a schema and hygiene smoke for ``goldens/*/expected-findings.json``.
It deliberately does not require raw evidence fixtures to be present: evidence
is gitignored and staged separately, while answer keys are small enough to keep
under source control.
"""

from __future__ import annotations

import json
from pathlib import Path, PurePosixPath
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
VALID_SCORING_STATUSES = {"ready", "not_ready"}

REQUIRED_TOP_LEVEL = {"case_id", "source_url", "license", "verdict", "findings"}
REQUIRED_FINDING = {
    "finding_id",
    "description",
    "confidence",
    "artifact_class",
    "artifact_hint",
}
HASH_LENGTHS = {"md5": 32, "sha1": 40, "sha256": 64}


def _nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _safe_relative_path(value: Any) -> bool:
    if not _nonempty_string(value) or "\\" in value:
        return False
    path = PurePosixPath(value)
    return not path.is_absolute() and ".." not in path.parts


def _valid_digests(spec: dict, label: str, errors: list[str]) -> int:
    found = 0
    for algorithm, length in HASH_LENGTHS.items():
        value = spec.get(algorithm)
        if value is None:
            continue
        found += 1
        if (
            not isinstance(value, str)
            or len(value) != length
            or any(character not in "0123456789abcdefABCDEF" for character in value)
        ):
            errors.append(f"{label}.{algorithm} must be {length} hexadecimal characters")
    return found


def _validate_fixture_contract(data: dict) -> list[str]:
    contract = data.get("fixture_contract")
    if contract is None:
        return []
    if not isinstance(contract, dict):
        return ["fixture_contract must be an object"]

    errors: list[str] = []
    for key in ("staging_root", "analysis_entrypoint"):
        if not _safe_relative_path(contract.get(key)):
            errors.append(f"fixture_contract.{key} must be a safe relative POSIX path")

    source = contract.get("source_artifact")
    source_verified = source is not None
    if source is not None:
        label = "fixture_contract.source_artifact"
        if not isinstance(source, dict):
            errors.append(f"{label} must be an object")
        else:
            if not _safe_relative_path(source.get("path")):
                errors.append(f"{label}.path must be a safe relative POSIX path")
            if not isinstance(source.get("size_bytes"), int) or source["size_bytes"] <= 0:
                errors.append(f"{label}.size_bytes must be a positive integer")
            if _valid_digests(source, label, errors) == 0:
                errors.append(f"{label} requires md5, sha1, or sha256")
            archive_type = source.get("archive_type")
            if archive_type is not None:
                if archive_type != "zip":
                    errors.append(f"{label}.archive_type must be 'zip'")
                if not _safe_relative_path(source.get("member_root")):
                    errors.append(f"{label}.member_root must be a safe relative POSIX path")
                if not isinstance(source.get("strict_members"), bool):
                    errors.append(f"{label}.strict_members must be boolean")

    required = contract.get("required_artifacts")
    if not isinstance(required, list) or not required:
        errors.append("fixture_contract.required_artifacts must be a non-empty list")
        return errors
    for index, artifact in enumerate(required):
        label = f"fixture_contract.required_artifacts[{index}]"
        if not isinstance(artifact, dict):
            errors.append(f"{label} must be an object")
            continue
        if not _safe_relative_path(artifact.get("path")):
            errors.append(f"{label}.path must be a safe relative POSIX path")
        artifact_type = artifact.get("type", "file")
        if artifact_type == "directory":
            if not isinstance(artifact.get("min_files"), int) or artifact["min_files"] <= 0:
                errors.append(f"{label}.min_files must be a positive integer")
            continue
        if artifact_type != "file":
            errors.append(f"{label}.type must be 'file' or 'directory'")
            continue
        if not isinstance(artifact.get("size_bytes"), int) or artifact["size_bytes"] <= 0:
            errors.append(f"{label}.size_bytes must be a positive integer")
        if _valid_digests(artifact, label, errors) == 0 and not source_verified:
            errors.append(f"{label} requires a digest when no source_artifact is verified")
    return errors


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

    scoring_status = data.get("scoring_status", "ready")
    if scoring_status not in VALID_SCORING_STATUSES:
        errors.append(
            f"scoring_status {scoring_status!r} must be one of {sorted(VALID_SCORING_STATUSES)}"
        )
    if scoring_status == "not_ready" and not _nonempty_string(data.get("not_ready_reason")):
        errors.append("scoring_status=not_ready requires not_ready_reason")
    errors.extend(_validate_fixture_contract(data))

    pending = data.get("status") == "pending_manual_walkthrough"
    min_recall = data.get("min_recall_percent")
    if pending:
        if min_recall is not None:
            errors.append("pending_manual_walkthrough stubs must omit min_recall_percent")
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
