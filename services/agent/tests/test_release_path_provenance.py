"""Tests for /home-free provenance paths in the signed audit chain.

The signed audit chain, ``verdict.json``, and ``run.manifest.json`` historically
baked absolute ``/home/...`` output/ledger paths into attestation metadata
(``referenced_paths``, ``cryptographic_attestation.manifest_path``,
``packet_attestation.verdict_artifact_path``, the ``verdict_artifact`` record
``path``, and the expert-miss ``ledger_path``). Those fields are hashed into the
chain but never re-opened by trace-finding / ``manifest_verify`` (resolution is by
SHA + ``prev_hash``, not by opening the path), so relativizing the recorded STRING
value keeps custody valid while removing the local-path leak from public fixtures.

``_release_path`` is the single helper that performs that relativization. It lives
inline in ``scripts/find_evil_auto.py`` (which runs under bare python3 and cannot
import the 3.11 ``findevil_agent`` package), mirroring the import pattern of
test_verdict_revision.py, and is exercised here under the 3.11 agent venv.
"""

from __future__ import annotations

import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402


def test_release_path_relativizes_case_dir_path_to_basename() -> None:
    # Arrange: an absolute /home output path as the engine would hold it.
    case_dir = "/home/analyst/Desktop/proj/tmp/auto-runs/case-xyz"
    verdict_path = f"{case_dir}/verdict.json"

    # Act
    released = fea._release_path(verdict_path)

    # Assert: basename form, no /home, no absolute prefix.
    assert released == "verdict.json"
    assert "/home" not in released
    assert not released.startswith("/")


def test_release_path_relativizes_under_base() -> None:
    # Arrange: a path that is genuinely under an explicit base directory.
    base = "/home/analyst/Desktop/proj/tmp/auto-runs/case-xyz"
    nested = f"{base}/extracted/disk/lnk/Recent/foo.lnk"

    # Act
    released = fea._release_path(nested, base=base)

    # Assert: relative-to-base form (POSIX-style), no /home, not absolute.
    assert released == "extracted/disk/lnk/Recent/foo.lnk"
    assert "/home" not in released
    assert not released.startswith("/")


def test_release_path_falls_back_to_basename_when_not_under_base() -> None:
    # Arrange: p is NOT under base -> must not raise, falls back to basename.
    base = "/home/analyst/Desktop/proj/tmp/auto-runs/case-xyz"
    other = "/home/analyst/elsewhere/run.manifest.json"

    # Act
    released = fea._release_path(other, base=base)

    # Assert
    assert released == "run.manifest.json"
    assert "/home" not in released


def test_release_path_basename_only_when_no_base() -> None:
    ledger = "/var/lib/state/expert_misses.jsonl"
    assert fea._release_path(ledger) == "expert_misses.jsonl"


def _contains_home_or_absolute(value: object) -> bool:
    """Recursively detect any /home or absolute-path string leak in a record."""
    if isinstance(value, str):
        return "/home" in value or value.startswith("/home")
    if isinstance(value, dict):
        return any(_contains_home_or_absolute(v) for v in value.values())
    if isinstance(value, list):
        return any(_contains_home_or_absolute(v) for v in value)
    return False


def test_referenced_paths_record_has_no_home_leak() -> None:
    # Arrange: emulate the expert-signoff referenced_paths block the engine emits.
    case_dir = "/home/analyst/Desktop/proj/tmp/auto-runs/case-xyz"
    referenced_paths = {
        "run_manifest": fea._release_path(f"{case_dir}/run.manifest.json"),
        "verdict": fea._release_path(f"{case_dir}/verdict.json"),
    }

    # Assert
    assert not _contains_home_or_absolute(referenced_paths)
    assert referenced_paths == {
        "run_manifest": "run.manifest.json",
        "verdict": "verdict.json",
    }


def test_verdict_artifact_record_has_no_home_leak() -> None:
    # Arrange: emulate the verdict_artifact audit record + packet_attestation
    # provenance fields the engine emits into the chain.
    case_dir = "/home/analyst/Desktop/proj/tmp/auto-runs/case-xyz"
    verdict_path = f"{case_dir}/verdict.json"
    manifest_path = f"{case_dir}/run.manifest.json"

    verdict_artifact_record = {
        "kind": "verdict_artifact",
        "path": fea._release_path(verdict_path),
        "sha256": "deadbeef",
        "byte_count": 123,
    }
    packet_attestation = {
        "verdict_artifact_path": fea._release_path(verdict_path),
        "verdict_artifact_sha256": "deadbeef",
    }
    cryptographic_attestation = {
        "manifest_path": fea._release_path(manifest_path),
        "packet_attestation": packet_attestation,
    }

    # Assert: none of the recorded provenance carries /home or an absolute path.
    assert not _contains_home_or_absolute(verdict_artifact_record)
    assert not _contains_home_or_absolute(cryptographic_attestation)
    assert verdict_artifact_record["path"] == "verdict.json"
    assert packet_attestation["verdict_artifact_path"] == "verdict.json"
    assert cryptographic_attestation["manifest_path"] == "run.manifest.json"
