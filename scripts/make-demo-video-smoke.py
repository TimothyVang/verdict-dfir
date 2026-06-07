#!/usr/bin/env python3
"""Smoke tests for scripts/make-demo-video.py."""
from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "make-demo-video.py"
DEMO_SCRIPT = REPO_ROOT / "docs" / "demo-script-a2.md"


def test_script_syntax() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    ast.parse(source)


def test_parse_beats_returns_nine_and_300s() -> None:
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--dry-run"],
        capture_output=True, text=True, timeout=15,
    )
    assert result.returncode == 0, f"dry-run failed:\n{result.stderr[:300]}"
    lines = [l for l in result.stdout.splitlines() if l.strip().startswith("Beat")]
    assert len(lines) == 9, f"Expected 9 beat lines, got {len(lines)}:\n{result.stdout}"
    # Total duration line: "Parsed 9 beats, total 300s"
    assert "300s" in result.stdout, f"Expected 300s total in output:\n{result.stdout}"


def test_dry_run_prints_beats_without_ffmpeg() -> None:
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--dry-run"],
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0, f"--dry-run failed:\n{result.stderr[:300]}"
    assert "Beat" in result.stdout, "Expected beat listing in --dry-run output"
    assert "ffmpeg" not in result.stdout.lower() or "stopping" in result.stdout.lower(), \
        "ffmpeg should not be invoked in --dry-run mode"


def main() -> int:
    tests = [
        ("script_syntax", test_script_syntax),
        ("parse_beats_returns_nine_and_300s", test_parse_beats_returns_nine_and_300s),
        ("dry_run_prints_beats_without_ffmpeg", test_dry_run_prints_beats_without_ffmpeg),
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
    print(f"\nmake-demo-video-smoke: {passed} passed, {failed} failed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
