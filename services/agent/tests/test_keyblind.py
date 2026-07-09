"""Unit tests for scripts/goldens-keyblind-smoke.py's scanner logic.

The smoke itself is the gate (exit 0/1) wired into run-all-smokes.sh. These tests
pin the scanner's *own* correctness — its exclusion list and pattern matching — so
a future refactor can't silently turn the gate into a no-op (e.g. by dropping the
accuracy.py exclusion, which would make the gate flag the legitimate scorer, or by
weakening the patterns so a real scorer import slips through).
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

_REPO = Path(__file__).resolve().parents[3]
_SMOKE = _REPO / "scripts" / "goldens-keyblind-smoke.py"

_spec = importlib.util.spec_from_file_location("goldens_keyblind_smoke", _SMOKE)
assert _spec and _spec.loader
keyblind = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(keyblind)


class TestExclusions:
    def test_scorer_core_is_excluded(self) -> None:
        # accuracy.py legitimately reads the key — it must be excluded so the gate
        # does not flag the scorer itself.
        assert keyblind.is_excluded(_REPO / "services/agent/findevil_agent/accuracy.py")

    def test_test_dirs_excluded(self) -> None:
        assert keyblind.is_excluded(_REPO / "services/agent/findevil_agent/tests/test_x.py")
        assert keyblind.is_excluded(_REPO / "services/agent/findevil_agent/__pycache__/x.py")

    def test_engine_files_not_excluded(self) -> None:
        assert not keyblind.is_excluded(_REPO / "scripts/find_evil_auto.py")
        assert not keyblind.is_excluded(_REPO / "services/agent/findevil_agent/judge.py")


class TestScanner:
    def test_scorer_import_is_flagged(self) -> None:
        hits = keyblind.violations_in("from findevil_agent.accuracy import resolve_golden")
        assert hits, "a scorer import in the run engine must be flagged"

    def test_goldens_path_is_flagged(self) -> None:
        assert keyblind.violations_in('GOLDENS = Path("goldens") / case_id')

    def test_accuracy_score_call_is_flagged(self) -> None:
        assert keyblind.violations_in("result = accuracy.score(case_dir, golden)")

    def test_clean_engine_code_passes(self) -> None:
        clean = "def investigate(evidence):\n    return run_tools(evidence)\n"
        assert keyblind.violations_in(clean) == []

    def test_unrelated_accuracy_word_not_flagged(self) -> None:
        # "prior_accuracy" / "accuracy report" prose is not a scorer reach.
        assert keyblind.violations_in("prior_accuracy = 0.5  # bayesian prior") == []


class TestLiveEngineIsKeyBlind:
    def test_real_run_engine_has_no_violations(self) -> None:
        # The shipped run engine must actually be clean today.
        for path in keyblind.run_engine_files():
            assert (
                keyblind.violations_in(path.read_text(encoding="utf-8", errors="replace")) == []
            ), f"{path} reaches the answer key"
