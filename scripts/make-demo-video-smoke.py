#!/usr/bin/env python3
"""Smoke tests for the Remotion-based demo video builder."""
from __future__ import annotations

import ast
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PREP_SCRIPT = REPO_ROOT / "scripts" / "make-demo-video-prep.py"
REMOTION_DIR = REPO_ROOT / "scripts" / "make-demo-video"
ROOT_TSX = REMOTION_DIR / "src" / "Root.tsx"
PKG_JSON = REMOTION_DIR / "package.json"


def test_prep_script_syntax() -> None:
    source = PREP_SCRIPT.read_text(encoding="utf-8")
    ast.parse(source)


def test_remotion_package_has_remotion_dep() -> None:
    pkg = json.loads(PKG_JSON.read_text(encoding="utf-8"))
    deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
    assert "remotion" in deps, f"remotion not in deps: {list(deps.keys())}"
    assert "@remotion/cli" in deps, "@remotion/cli not in deps"


def test_root_tsx_has_register_root() -> None:
    src = ROOT_TSX.read_text(encoding="utf-8")
    assert "registerRoot" in src, "Root.tsx must call registerRoot()"


def test_dry_run_shows_nine_beats_and_300s() -> None:
    result = subprocess.run(
        [sys.executable, str(PREP_SCRIPT), "--dry-run"],
        capture_output=True, text=True, timeout=15,
    )
    assert result.returncode == 0, f"--dry-run failed:\n{result.stderr[:300]}"
    lines = [l for l in result.stdout.splitlines() if "Beat" in l and "s " in l]
    assert len(lines) == 9, f"Expected 9 beat lines, got {len(lines)}:\n{result.stdout}"
    assert "300s" in result.stdout, f"Expected 300s total:\n{result.stdout}"


def main() -> int:
    tests = [
        ("prep_script_syntax", test_prep_script_syntax),
        ("remotion_package_has_remotion_dep", test_remotion_package_has_remotion_dep),
        ("root_tsx_has_register_root", test_root_tsx_has_register_root),
        ("dry_run_shows_nine_beats_and_300s", test_dry_run_shows_nine_beats_and_300s),
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
