"""Regression tests for whole-case local runner CLI behavior."""

from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]


def test_run_whole_case_local_help_prints_usage() -> None:
    result = subprocess.run(
        ["bash", str(ROOT / "scripts" / "run-whole-case-local.sh"), "--help"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "Usage:" in result.stdout
    assert "run-whole-case-local.sh <case-root> [out-dir]" in result.stdout
    assert "File name too long" not in result.stderr


def test_run_whole_case_local_missing_root_fails_cleanly(tmp_path: Path) -> None:
    missing_root = tmp_path / "missing-case"

    result = subprocess.run(
        ["bash", str(ROOT / "scripts" / "run-whole-case-local.sh"), str(missing_root)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 2
    assert f"case root does not exist: {missing_root}" in result.stderr
    assert "File name too long" not in result.stderr
