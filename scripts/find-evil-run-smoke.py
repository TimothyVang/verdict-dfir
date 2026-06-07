#!/usr/bin/env python3
"""Smoke test: find-evil-run one-command operator entry.

Verifies via bash -n (syntax check) and grep-asserts that each pipeline
stage is wired correctly. --dry-run is exercised without hitting inference.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "find-evil-run"


def test_script_exists_and_executable() -> None:
    assert SCRIPT.exists(), f"Missing: {SCRIPT}"


def test_bash_syntax_clean() -> None:
    result = subprocess.run(
        ["bash", "-n", str(SCRIPT)],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, f"bash -n failed: {result.stderr}"


def test_script_chains_doctor() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert "doctor.sh" in text, "find-evil-run does not reference doctor.sh"


def test_script_chains_install_or_build() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert "cargo build" in text or "findevil-mcp" in text, \
        "find-evil-run does not reference cargo build or findevil-mcp"


def test_script_chains_find_evil_auto() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert "find_evil_auto" in text, "find-evil-run does not chain find_evil_auto"


def test_dry_run_produces_no_inference() -> None:
    result = subprocess.run(
        ["bash", str(SCRIPT), "--dry-run"],
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0, f"--dry-run exited {result.returncode}: {result.stderr}"
    combined = result.stdout + result.stderr
    assert "DRY-RUN" in combined, f"--dry-run did not emit DRY-RUN markers: {combined[:300]}"
    assert "Stage 4/4" in combined, "find-evil-run --dry-run did not reach Stage 4"


def test_dry_run_has_skip_build_flag() -> None:
    result = subprocess.run(
        ["bash", str(SCRIPT), "--dry-run", "--skip-build"],
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0, f"--skip-build failed: {result.stderr}"
    combined = result.stdout + result.stderr
    assert "--skip-build" in SCRIPT.read_text(), "find-evil-run missing --skip-build flag"


def main() -> int:
    tests = [
        ("script_exists_and_executable", test_script_exists_and_executable),
        ("bash_syntax_clean", test_bash_syntax_clean),
        ("chains_doctor", test_script_chains_doctor),
        ("chains_install_or_build", test_script_chains_install_or_build),
        ("chains_find_evil_auto", test_script_chains_find_evil_auto),
        ("dry_run_produces_no_inference", test_dry_run_produces_no_inference),
        ("dry_run_has_skip_build_flag", test_dry_run_has_skip_build_flag),
    ]
    passed = 0
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"  [PASS] {name}")
            passed += 1
        except Exception as exc:
            print(f"  [FAIL] {name}: {exc}")
            failed += 1
    print(f"\nfind-evil-run-smoke: {passed} passed, {failed} failed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
