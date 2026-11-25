#!/usr/bin/env python3
"""Fail-closed readiness check for staged L3 golden fixtures.

An answer key plus a directory is not an accuracy benchmark.  The answer key
must permit scoring and the directory must contain at least one non-empty
artifact routed by the Product's canonical artifact classifier.  Generic
archives are excluded: they can contain source code, documentation, or an
unsupported telemetry format, and must be extracted before accuracy scoring.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
import zipfile
import zlib
from pathlib import Path, PurePosixPath
from typing import NamedTuple

REPO_ROOT = Path(__file__).resolve().parent.parent
PLAYBOOK_PATH = REPO_ROOT / "services" / "agent" / "findevil_agent" / "playbook.py"
VALID_SCORING_STATUSES = {"ready", "not_ready"}


def _load_artifact_classifier():
    module_name = "_fixture_readiness_playbook"
    spec = importlib.util.spec_from_file_location(module_name, PLAYBOOK_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load canonical artifact classifier: {PLAYBOOK_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module.classify_artifact_path


class Readiness(NamedTuple):
    ready: bool
    reason: str
    artifacts: tuple[str, ...] = ()
    staging_root: Path | None = None
    analysis_entrypoint: Path | None = None


def _load_golden(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ValueError(f"missing answer key: {path}") from None
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid answer key JSON {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"answer key must be a JSON object: {path}")
    return data


def _supported_artifacts(fixture_dir: Path) -> tuple[str, ...]:
    classify_artifact_path = _load_artifact_classifier()
    artifacts: list[str] = []
    for path in fixture_dir.rglob("*"):
        relative = path.relative_to(fixture_dir)
        if ".git" in relative.parts or path.is_symlink() or not path.is_file():
            continue
        if path.stat().st_size <= 0:
            continue
        classification = classify_artifact_path(relative.as_posix())
        artifact_class = classification.get("artifact_class")
        # A generic zip is routed as a Velociraptor collection before its
        # contents are validated.  That is not enough to prove an arbitrary
        # benchmark archive contains analyzable evidence.
        if artifact_class not in {"unknown", "velociraptor"}:
            artifacts.append(relative.as_posix())
    return tuple(sorted(artifacts))


def _safe_contract_path(root: Path, value: object, label: str) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty relative POSIX path")
    if "\\" in value:
        raise ValueError(f"{label} must use POSIX separators")
    relative = PurePosixPath(value)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"{label} must stay within the fixture")
    root_resolved = root.resolve()
    candidate = root_resolved.joinpath(*relative.parts)
    if not candidate.resolve(strict=False).is_relative_to(root_resolved):
        raise ValueError(f"{label} escapes the fixture")
    return candidate


def _validated_spec(spec: object, label: str) -> dict:
    if not isinstance(spec, dict):
        raise ValueError(f"{label} must be an object")
    if not isinstance(spec.get("path"), str):
        raise ValueError(f"{label}.path must be a string")
    return spec


def _preflight_artifact(root: Path, spec: dict, label: str) -> tuple[Path, str | None]:
    path = _safe_contract_path(root, spec["path"], f"{label}.path")
    artifact_type = spec.get("type", "file")
    if artifact_type not in {"file", "directory"}:
        raise ValueError(f"{label}.type must be 'file' or 'directory'")
    if path.is_symlink():
        return path, f"required artifact is a symlink: {spec['path']}"
    if artifact_type == "directory":
        if not path.is_dir():
            return path, f"missing required directory: {spec['path']}"
        min_files = spec.get("min_files", 1)
        if not isinstance(min_files, int) or min_files < 1:
            raise ValueError(f"{label}.min_files must be a positive integer")
        file_count = sum(
            1 for candidate in path.rglob("*") if candidate.is_file() and not candidate.is_symlink()
        )
        if file_count < min_files:
            return (
                path,
                f"required directory {spec['path']} has {file_count} files; "
                f"expected at least {min_files}",
            )
        return path, None

    if not path.is_file():
        return path, f"missing required artifact: {spec['path']}"
    size_bytes = spec.get("size_bytes")
    if not isinstance(size_bytes, int) or size_bytes <= 0:
        raise ValueError(f"{label}.size_bytes must be a positive integer")
    actual_size = path.stat().st_size
    if actual_size != size_bytes:
        return (
            path,
            f"size mismatch for {spec['path']}: expected={size_bytes} actual={actual_size}",
        )
    return path, None


def _expected_digests(spec: dict, label: str) -> tuple[tuple[str, str], ...]:
    digests: list[tuple[str, str]] = []
    lengths = {"md5": 32, "sha1": 40, "sha256": 64}
    for algorithm, length in lengths.items():
        expected = spec.get(algorithm)
        if expected is None:
            continue
        if (
            not isinstance(expected, str)
            or len(expected) != length
            or any(character not in "0123456789abcdefABCDEF" for character in expected)
        ):
            raise ValueError(f"{label}.{algorithm} must be {length} hexadecimal characters")
        digests.append((algorithm, expected.lower()))
    return tuple(digests)


def _verify_digests(path: Path, spec: dict, label: str) -> str | None:
    for algorithm, expected in _expected_digests(spec, label):
        digest = hashlib.new(algorithm)
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        actual = digest.hexdigest()
        if actual != expected:
            return f"{algorithm} mismatch for {spec['path']}: expected={expected} actual={actual}"
    return None


def _verify_zip_extraction(source_path: Path, source_spec: dict, staging_root: Path) -> str | None:
    archive_type = source_spec.get("archive_type")
    if archive_type is None:
        return None
    if archive_type != "zip":
        raise ValueError("fixture_contract.source_artifact.archive_type must be 'zip'")
    member_root_value = source_spec.get("member_root")
    if not isinstance(member_root_value, str):
        raise ValueError("fixture_contract.source_artifact.member_root must be a string")
    member_root = PurePosixPath(member_root_value)
    if member_root.is_absolute() or ".." in member_root.parts:
        raise ValueError(
            "fixture_contract.source_artifact.member_root must be a safe relative path"
        )
    strict_members = source_spec.get("strict_members", False)
    if not isinstance(strict_members, bool):
        raise ValueError("fixture_contract.source_artifact.strict_members must be boolean")

    expected_files: set[str] = set()
    with zipfile.ZipFile(source_path) as archive:
        for info in archive.infolist():
            normalized = info.filename.replace("\\", "/")
            member = PurePosixPath(normalized)
            if member.is_absolute() or ".." in member.parts:
                return f"unsafe archive member path: {info.filename}"
            if info.is_dir():
                continue
            try:
                relative = member.relative_to(member_root)
            except ValueError:
                continue
            if not relative.parts:
                continue
            relative_name = relative.as_posix()
            expected_files.add(relative_name)
            extracted = _safe_contract_path(
                staging_root,
                relative_name,
                "fixture_contract.source_artifact archive member",
            )
            if extracted.is_symlink() or not extracted.is_file():
                return f"missing extracted archive member: {relative_name}"
            if extracted.stat().st_size != info.file_size:
                return (
                    f"archive member size mismatch for {relative_name}: "
                    f"expected={info.file_size} actual={extracted.stat().st_size}"
                )
            crc = 0
            with extracted.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    crc = zlib.crc32(chunk, crc)
            if crc & 0xFFFFFFFF != info.CRC:
                return f"archive member content mismatch: {relative_name}"

    if not expected_files:
        return f"source archive has no files under member_root={member_root_value}"
    if strict_members:
        actual_files = {
            path.relative_to(staging_root).as_posix()
            for path in staging_root.rglob("*")
            if path.is_file() and not path.is_symlink()
        }
        extra_files = sorted(actual_files - expected_files)
        if extra_files:
            return f"staging root contains files absent from source archive: {extra_files[0]}"
    return None


def _fixture_contract(golden: dict) -> dict | None:
    contract = golden.get("fixture_contract")
    if contract is None:
        return None
    if not isinstance(contract, dict):
        raise ValueError("fixture_contract must be an object")
    return contract


def evaluate_fixture(golden_path: Path, fixture_dir: Path) -> Readiness:
    """Return whether ``fixture_dir`` may be scored against ``golden_path``."""

    golden = _load_golden(golden_path)
    scoring_status = golden.get("scoring_status", "ready")
    if scoring_status not in VALID_SCORING_STATUSES:
        raise ValueError(
            f"unsupported scoring_status {scoring_status!r}; "
            f"expected one of {sorted(VALID_SCORING_STATUSES)}"
        )
    if scoring_status == "not_ready":
        reason = golden.get("not_ready_reason")
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("scoring_status=not_ready requires not_ready_reason")
        return Readiness(False, reason.strip())
    if not fixture_dir.is_dir():
        return Readiness(False, f"missing fixture directory: {fixture_dir}")

    contract = _fixture_contract(golden)
    staging_root = fixture_dir.resolve()
    analysis_entrypoint = staging_root
    if contract is not None:
        staging_root = _safe_contract_path(
            fixture_dir, contract.get("staging_root"), "fixture_contract.staging_root"
        )
        if not staging_root.is_dir() or staging_root.is_symlink():
            return Readiness(False, f"missing staging root: {contract.get('staging_root')}")
        analysis_entrypoint = _safe_contract_path(
            staging_root,
            contract.get("analysis_entrypoint"),
            "fixture_contract.analysis_entrypoint",
        )
        if not analysis_entrypoint.exists() or analysis_entrypoint.is_symlink():
            return Readiness(
                False,
                f"missing analysis entrypoint: {contract.get('analysis_entrypoint')}",
            )

        source_artifact = contract.get("source_artifact")
        source_verified = False
        if source_artifact is not None:
            source_spec = _validated_spec(source_artifact, "fixture_contract.source_artifact")
            source_path, failure = _preflight_artifact(
                fixture_dir,
                source_spec,
                "fixture_contract.source_artifact",
            )
            if failure:
                return Readiness(False, failure)
            if not _expected_digests(source_spec, "fixture_contract.source_artifact"):
                raise ValueError("fixture_contract.source_artifact requires a digest")
            failure = _verify_digests(
                source_path,
                source_spec,
                "fixture_contract.source_artifact",
            )
            if failure:
                return Readiness(False, failure)
            failure = _verify_zip_extraction(source_path, source_spec, staging_root)
            if failure:
                return Readiness(False, failure)
            source_verified = True

        required = contract.get("required_artifacts")
        if not isinstance(required, list) or not required:
            raise ValueError("fixture_contract.required_artifacts must be a non-empty list")
        required_specs = tuple(
            _validated_spec(spec, f"fixture_contract.required_artifacts[{index}]")
            for index, spec in enumerate(required)
        )
        preflight = tuple(
            (
                spec,
                *_preflight_artifact(
                    staging_root,
                    spec,
                    f"fixture_contract.required_artifacts[{index}]",
                ),
            )
            for index, spec in enumerate(required_specs)
        )
        for _spec, _path, failure in preflight:
            if failure:
                return Readiness(False, failure)
        for index, (spec, path, _failure) in enumerate(preflight):
            label = f"fixture_contract.required_artifacts[{index}]"
            if spec.get("type", "file") == "file":
                digests = _expected_digests(spec, label)
                if not digests and not source_verified:
                    raise ValueError(
                        f"{label} requires a digest when no verified source_artifact exists"
                    )
                failure = _verify_digests(path, spec, label)
                if failure:
                    return Readiness(False, failure)

    artifacts = _supported_artifacts(staging_root)
    if not artifacts:
        return Readiness(
            False,
            "no supported evidence artifacts; documentation, source trees, "
            "and unvalidated archives are not scorable evidence",
        )
    return Readiness(
        True,
        f"{len(artifacts)} supported artifact(s)",
        artifacts,
        staging_root,
        analysis_entrypoint,
    )


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("golden", type=Path, help="expected-findings.json path")
    parser.add_argument("fixture", type=Path, help="staged fixture directory")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    return parser.parse_args()


def _print_result(result: Readiness, case_id: str, as_json: bool) -> None:
    status = "READY" if result.ready else "NOT_READY"
    if not as_json:
        print(f"{status} {case_id}: {result.reason}")
        return
    payload: dict[str, object] = {
        "status": status,
        "case_id": case_id,
        "reason": result.reason,
        "artifacts": result.artifacts,
    }
    if result.staging_root is not None and result.analysis_entrypoint is not None:
        payload = {
            **payload,
            "staging_root": str(result.staging_root),
            "analysis_entrypoint": str(result.analysis_entrypoint),
            "analysis_entrypoint_relative": result.analysis_entrypoint.relative_to(
                result.staging_root
            ).as_posix(),
        }
    print(json.dumps(payload, sort_keys=True))


def main() -> int:
    args = _parse_args()
    case_id = args.golden.parent.name
    try:
        result = evaluate_fixture(args.golden, args.fixture)
    except (OSError, RuntimeError, ValueError) as exc:
        if args.json:
            print(
                json.dumps(
                    {"status": "ERROR", "case_id": case_id, "reason": str(exc)},
                    sort_keys=True,
                )
            )
        else:
            print(f"ERROR: {exc}")
        return 2

    _print_result(result, case_id, args.json)
    if not result.ready:
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
