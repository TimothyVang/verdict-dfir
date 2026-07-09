"""Guard: the break-then-catch demo must keep telling the truth.

``scripts/entailment-demo.py`` drives the REAL verifier — it must APPROVE the
honest finding and REJECT the injected misread (its build_steps() asserts this
internally, so a disagreement makes the process exit non-zero). If this guard
fails, the demo — and the claim the clip makes — has rotted.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

_DEMO = Path(__file__).resolve().parents[3] / "scripts" / "entailment-demo.py"


def test_demo_runs_and_shows_approve_then_reject() -> None:
    result = subprocess.run(
        [sys.executable, str(_DEMO)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "APPROVED" in result.stdout
    assert "REJECTED" in result.stdout
    # the honest takeaway line, stated at the right scope (no "hallucination solved")
    assert "cannot record a structured fact that isn't in the evidence" in result.stdout
