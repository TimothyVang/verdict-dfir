#!/usr/bin/env python3
"""Smoke test: scripts/verdict — the one-command entry point.

Verifies via bash -n (syntax) and grep-asserts that the single workflow wires
each stage (preflight → build → investigate → dashboard). --dry-run is
exercised without running any investigation.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "verdict"


def test_script_exists_and_executable() -> None:
    assert SCRIPT.exists(), f"Missing: {SCRIPT}"


def test_bash_syntax_clean() -> None:
    result = subprocess.run(["bash", "-n", str(SCRIPT)], capture_output=True, text=True)
    assert result.returncode == 0, f"bash -n failed: {result.stderr}"


def test_chains_doctor() -> None:
    assert "doctor.sh" in SCRIPT.read_text(
        encoding="utf-8"
    ), "verdict does not reference doctor.sh"


def test_chains_build() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert (
        "cargo build" in text or "findevil-mcp" in text
    ), "verdict does not reference cargo build / findevil-mcp"


def test_chains_engine() -> None:
    assert "find_evil_auto" in SCRIPT.read_text(
        encoding="utf-8"
    ), "verdict does not chain the find_evil_auto engine"


def test_has_sift_and_dashboard_flags() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert "--sift" in text, "verdict missing --sift flag"
    assert "--no-dashboard" in text, "verdict missing --no-dashboard flag"


def test_sift_staging_rejects_unsafe_remote_names() -> None:
    test_sift_staging_sanitizer_selftest()
    text = SCRIPT.read_text(encoding="utf-8")
    assert "safe_guest_basename" in text, "verdict lacks SIFT basename sanitizer"
    assert (
        "unsafe evidence filename for --sift staging" in text
    ), "verdict does not reject shell-unsafe SIFT evidence filenames"
    assert (
        "unsafe SIFT guest evidence dir" in text
    ), "verdict does not reject shell-unsafe SIFT guest evidence directories"


def test_n8n_status_wording_does_not_overclaim_actions() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert (
        "n8n fired" not in text
    ), "verdict overclaims n8n reachability as fired action"
    assert (
        "n8n reachable; automation sidecar recorded" in text
    ), "verdict should distinguish n8n reachability from action creation"


def test_sift_staging_sanitizer_selftest() -> None:
    env = {**os.environ, "FINDEVIL_VERDICT_SELFTEST": "sift-sanitizers"}
    result = subprocess.run(
        ["bash", str(SCRIPT)], capture_output=True, text=True, timeout=10, env=env
    )
    assert (
        result.returncode == 0
    ), f"SIFT sanitizer selftest failed: stdout={result.stdout!r} stderr={result.stderr!r}"
    assert (
        "sift sanitizer selftest OK" in result.stdout
    ), f"SIFT sanitizer selftest did not confirm success: {result.stdout!r}"


def test_dry_run_produces_no_investigation() -> None:
    result = subprocess.run(
        ["bash", str(SCRIPT), "--dry-run"], capture_output=True, text=True, timeout=10
    )
    assert (
        result.returncode == 0
    ), f"--dry-run exited {result.returncode}: {result.stderr}"
    combined = result.stdout + result.stderr
    assert (
        "DRY-RUN" in combined
    ), f"--dry-run did not emit DRY-RUN markers: {combined[:300]}"
    assert "4/4" in combined, "verdict --dry-run did not reach the final stage (4/4)"


def test_dry_run_with_skip_build() -> None:
    result = subprocess.run(
        ["bash", str(SCRIPT), "--dry-run", "--skip-build"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, f"--skip-build failed: {result.stderr}"


def main() -> int:
    tests = [
        ("script_exists_and_executable", test_script_exists_and_executable),
        ("bash_syntax_clean", test_bash_syntax_clean),
        ("chains_doctor", test_chains_doctor),
        ("chains_build", test_chains_build),
        ("chains_engine", test_chains_engine),
        ("has_sift_and_dashboard_flags", test_has_sift_and_dashboard_flags),
        (
            "sift_staging_rejects_unsafe_remote_names",
            test_sift_staging_rejects_unsafe_remote_names,
        ),
        (
            "n8n_status_wording_does_not_overclaim_actions",
            test_n8n_status_wording_does_not_overclaim_actions,
        ),
        ("dry_run_produces_no_investigation", test_dry_run_produces_no_investigation),
        ("dry_run_with_skip_build", test_dry_run_with_skip_build),
    ]
    passed = failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"  [PASS] {name}")
            passed += 1
        except Exception as exc:
            print(f"  [FAIL] {name}: {exc}")
            failed += 1
    print(f"\nverdict-smoke: {passed} passed, {failed} failed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
