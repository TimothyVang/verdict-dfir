"""scripts/verdict --fleet: one command for a multi-host case folder.

Offline and fast: --dry-run prints the stage plan without running anything.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

_REPO = Path(__file__).resolve().parents[3]
_VERDICT = _REPO / "scripts" / "verdict"


def _run(args: list[str], cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", str(_VERDICT), *args],
        cwd=str(_REPO),
        capture_output=True,
        text=True,
        timeout=60,
    )


def _case_root(tmp_path: Path) -> Path:
    root = tmp_path / "big-case"
    (root / "hosts" / "h1").mkdir(parents=True)
    (root / "hosts" / "h1" / "h1-memory.img").write_bytes(b"\x00" * 16)
    return root


class TestFleetMode:
    def test_multi_host_folder_auto_enters_fleet_mode(self, tmp_path: Path) -> None:
        root = _case_root(tmp_path)
        proc = _run([str(root), "--dry-run", "--no-dashboard", "--skip-build"], tmp_path)
        out = proc.stdout + proc.stderr
        assert proc.returncode == 0, out
        # All three stages are named in the plan.
        assert "run-whole-case-local" in out
        assert "fleet_correlate" in out
        assert "render_fleet_report" in out

    def test_explicit_fleet_flag(self, tmp_path: Path) -> None:
        root = _case_root(tmp_path)
        proc = _run([str(root), "--fleet", "--dry-run", "--no-dashboard"], tmp_path)
        out = proc.stdout + proc.stderr
        assert proc.returncode == 0, out
        assert "run-whole-case-local" in out

    def test_single_file_evidence_does_not_enter_fleet_mode(self, tmp_path: Path) -> None:
        evidence = tmp_path / "memory.img"
        evidence.write_bytes(b"\x00" * 16)
        proc = _run([str(evidence), "--dry-run", "--no-dashboard", "--skip-build"], tmp_path)
        out = proc.stdout + proc.stderr
        assert proc.returncode == 0, out
        assert "run-whole-case-local" not in out
        assert "find_evil_auto" in out  # the normal single-case engine plan
