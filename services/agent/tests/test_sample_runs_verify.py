"""Guard: every committed sample run must stay offline-verifiable.

docs/sample-run/ promises judges byte-for-byte run output whose hash chain
verifies offline (`scripts/trace-finding` exits 0). A single accidental edit
to any committed audit.jsonl breaks that promise silently — this test makes
the break loud at test time instead of judge time.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[3]
_SAMPLE_RUNS = sorted(p.parent for p in (_ROOT / "docs" / "sample-run").glob("*/audit.jsonl"))


@pytest.mark.parametrize("run_dir", _SAMPLE_RUNS, ids=lambda p: p.name)
def test_sample_run_trace_finding_passes(run_dir: Path) -> None:
    result = subprocess.run(
        [sys.executable, str(_ROOT / "scripts" / "trace-finding"), str(run_dir)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, (
        f"trace-finding failed for {run_dir.name}:\n" f"{result.stdout}\n{result.stderr}"
    )
