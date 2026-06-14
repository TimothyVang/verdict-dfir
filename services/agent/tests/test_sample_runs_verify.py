"""Guard: optional committed sample runs stay offline-verifiable.

Public release clones do not ship bulky raw run outputs, but any local or
branch-specific committed showcase run under the optional sample-run directory
must remain traceable with `scripts/trace-finding`.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[3]
_SAMPLE_RUNS_ROOT = _ROOT / "docs" / "sample-run"
_SAMPLE_RUNS = sorted(p.parent for p in _SAMPLE_RUNS_ROOT.glob("*/audit.jsonl"))


@pytest.mark.parametrize("run_dir", _SAMPLE_RUNS, ids=lambda p: p.name)
def test_sample_run_trace_finding_passes(run_dir: Path) -> None:
    if not _SAMPLE_RUNS:
        pytest.skip("optional sample-run fixtures are not present in this checkout")
    result = subprocess.run(
        [sys.executable, str(_ROOT / "scripts" / "trace-finding"), str(run_dir)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, (
        f"trace-finding failed for {run_dir.name}:\n" f"{result.stdout}\n{result.stderr}"
    )
