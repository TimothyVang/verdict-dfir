#!/usr/bin/env python3
"""Smoke test: render_report._resolve_tool and cross-platform binary resolution.

Verifies that:
- _resolve_tool honours the env-var override when the path exists
- _resolve_tool falls back to shutil.which when no override is set
- _resolve_tool returns None when neither override nor PATH entry exists
- PANDOC / CHROME module constants are resolved without raising
- render_html_pdf returns (html, None) gracefully when PANDOC is None
"""

from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import types
from pathlib import Path
from unittest.mock import MagicMock, patch

SCRIPTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPTS_DIR.parent


def load_render_report() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location(
        "render_report", SCRIPTS_DIR / "render_report.py"
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    # matplotlib imports run at module level; stub them out so CI doesn't need a display
    sys.modules.setdefault("matplotlib", MagicMock())
    sys.modules.setdefault("matplotlib.pyplot", MagicMock())
    sys.modules.setdefault("matplotlib.dates", MagicMock())
    sys.modules.setdefault("matplotlib.patches", MagicMock())
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def test_resolve_tool_env_override(mod: types.ModuleType, tmp_path: Path) -> None:
    fake_exe = tmp_path / "mypandoc"
    fake_exe.write_text("#!/bin/sh\necho pandoc", encoding="utf-8")
    fake_exe.chmod(0o755)
    result = (
        mod._resolve_tool.__wrapped__(str(fake_exe), "no-such-binary-xyz")
        if hasattr(mod._resolve_tool, "__wrapped__")
        else None
    )
    # Re-call directly with env patched
    env_backup = os.environ.pop("PANDOC_BIN", None)
    try:
        os.environ["PANDOC_BIN"] = str(fake_exe)
        result = mod._resolve_tool("PANDOC_BIN", "no-such-binary-xyz")
    finally:
        if env_backup is not None:
            os.environ["PANDOC_BIN"] = env_backup
        else:
            os.environ.pop("PANDOC_BIN", None)
    assert result == str(fake_exe), f"Expected fake_exe path, got {result!r}"


def test_resolve_tool_env_bad_path(mod: types.ModuleType) -> None:
    env_backup = os.environ.pop("PANDOC_BIN", None)
    try:
        os.environ["PANDOC_BIN"] = "/nonexistent/path/to/pandoc"
        result = mod._resolve_tool("PANDOC_BIN", "no-such-binary-xyz-abc")
    finally:
        if env_backup is not None:
            os.environ["PANDOC_BIN"] = env_backup
        else:
            os.environ.pop("PANDOC_BIN", None)
    assert (
        result is None
    ), f"Expected None for bad override + missing fallback, got {result!r}"


def test_resolve_tool_which_fallback(mod: types.ModuleType) -> None:
    import shutil

    env_backup = os.environ.pop("PANDOC_BIN", None)
    try:
        result = mod._resolve_tool("PANDOC_BIN", "python3", "python")
    finally:
        if env_backup is not None:
            os.environ["PANDOC_BIN"] = env_backup
        else:
            os.environ.pop("PANDOC_BIN", None)
    python = shutil.which("python3") or shutil.which("python")
    assert result == python, f"Expected {python!r}, got {result!r}"


def test_constants_do_not_raise(mod: types.ModuleType) -> None:
    # PANDOC and CHROME must be str | None — never raise
    assert mod.PANDOC is None or isinstance(mod.PANDOC, str)
    assert mod.CHROME is None or isinstance(mod.CHROME, str)


def test_render_html_pdf_degrades_when_pandoc_none(
    mod: types.ModuleType, tmp_path: Path
) -> None:
    tmp_path.mkdir(parents=True, exist_ok=True)
    md = tmp_path / "REPORT.md"
    md.write_text("# Test\n\nHello world.\n", encoding="utf-8")
    with patch.object(mod, "PANDOC", None):
        html, pdf = mod.render_html_pdf(md)
    assert html == tmp_path / "REPORT.html"
    assert pdf is None


def main() -> int:
    mod = load_render_report()
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        tests = [
            (
                "resolve_tool_env_override",
                lambda: test_resolve_tool_env_override(mod, tmp),
            ),
            ("resolve_tool_env_bad_path", lambda: test_resolve_tool_env_bad_path(mod)),
            (
                "resolve_tool_which_fallback",
                lambda: test_resolve_tool_which_fallback(mod),
            ),
            ("constants_do_not_raise", lambda: test_constants_do_not_raise(mod)),
            (
                "render_html_pdf_degrades_when_pandoc_none",
                lambda: test_render_html_pdf_degrades_when_pandoc_none(
                    mod, tmp / "case2"
                ),
            ),
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
    print(f"\nrender-binary-smoke: {passed} passed, {failed} failed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
