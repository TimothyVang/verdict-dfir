"""Regression tests for whole-case local runner CLI behavior."""

from __future__ import annotations

import json
import shutil
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


def test_run_whole_case_local_records_failed_target_rows(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    scripts = repo / "scripts"
    scripts.mkdir(parents=True)
    shutil.copy2(ROOT / "scripts" / "run-whole-case-local.sh", scripts)
    shutil.copy2(ROOT / "scripts" / "whole_case_targets.py", scripts)
    (scripts / "verdict").write_text("#!/usr/bin/env bash\nexit 7\n", encoding="utf-8")
    (scripts / "fleet_local.py").write_text("#!/usr/bin/env python3\n", encoding="utf-8")
    case_root = tmp_path / "case"
    out = tmp_path / "out"
    (case_root / "hosts" / "host-a").mkdir(parents=True)

    result = subprocess.run(
        ["bash", str(scripts / "run-whole-case-local.sh"), str(case_root), str(out)],
        cwd=repo,
        check=False,
        capture_output=True,
        text=True,
    )

    rows = [json.loads(line) for line in (out / "results.jsonl").read_text().splitlines()]
    assert result.returncode == 1
    assert rows == [{"host": "mem:host-a", "verdict": "ERROR", "exit_code": 7}]
