"""A run that produced nothing must not score as a pass.

The 2026-07-28 golden aggregate reported 4/7 passing — but two of those four
(``synthetic-benign``, ``synthetic-decoy``) passed with ``run_finding_n == 0``,
and three of the four ended ``INDETERMINATE``. Three separate scorer behaviours
combined to hand out those free passes:

  1. an empty golden (``expected_n == 0``) scored recall 100 unconditionally, so a
     run that errored out before producing anything looked perfectly recalled;
  2. ``_verdict_consistent`` accepted ``INDETERMINATE`` against ANY golden verdict,
     and ``INDETERMINATE`` is exactly what a tool failure produces; and
  3. precision/F1/hallucination reported ``100`` / ``0.0`` off a zero denominator,
     so a run with nothing scored read as perfectly precise.

Plus a latent crash: a golden with ``min_recall_percent: null`` (``sans-starter``)
hit ``int(None)``.

These tests pin all four. They are deliberately shaped like the real failures.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from findevil_agent import accuracy

_REPO_ROOT = Path(__file__).resolve().parents[3]
_GOLDENS = _REPO_ROOT / "goldens"

_BENIGN_GOLDEN = _GOLDENS / "synthetic-benign" / "expected-findings.json"
_DECOY_GOLDEN = _GOLDENS / "synthetic-decoy" / "expected-findings.json"
_NITROBA_GOLDEN = _GOLDENS / "nitroba" / "expected-findings.json"
_ALIHADI_GOLDEN = _GOLDENS / "alihadi-09-encrypt" / "expected-findings.json"
_SANS_GOLDEN = _GOLDENS / "sans-starter" / "expected-findings.json"

# A tool call as ``find_evil_auto`` records it. Every failure site tags
# ``extra["error"]`` before ``_record_tool``, so a failed tool is an ``error`` key
# on the tool_calls entry (see scripts/find_evil_auto.py::_record_tool).
_OK_TOOL = {"tool_call_id": "tc-1", "tool": "case_open"}
_FAILED_TOOL = {
    "tool_call_id": "tc-2",
    "tool": "disk_extract_artifacts",
    "error": "subprocess failed: Cannot determine file system type",
}


def _write_case(
    case_dir: Path,
    case_id: str,
    verdict: str,
    findings: list[dict[str, Any]],
    *,
    tool_calls: list[dict[str, Any]] | None = None,
    heartbeat: dict[str, Any] | None = None,
) -> Path:
    case_dir.mkdir(parents=True, exist_ok=True)
    doc: dict[str, Any] = {
        "case_id": case_id,
        "verdict": verdict,
        "findings": findings,
        "tool_calls": [_OK_TOOL] if tool_calls is None else tool_calls,
    }
    if heartbeat is not None:
        doc["heartbeat"] = heartbeat
    (case_dir / "verdict.json").write_text(json.dumps(doc), encoding="utf-8")
    return case_dir


def _echo_golden_findings(golden_path: Path) -> list[dict[str, Any]]:
    """Run findings that restate every golden claim verbatim — full recall by construction."""
    golden = json.loads(golden_path.read_text(encoding="utf-8"))
    return [
        {
            "finding_id": f"r-{i:03d}",
            "description": exp.get("description"),
            "artifact_path": exp.get("artifact_hint"),
        }
        for i, exp in enumerate(golden.get("findings") or [], start=1)
    ]


def _score_with_ready_copy(case_dir: Path, source: Path, tmp_path: Path) -> dict[str, Any]:
    """Exercise scoring math without weakening committed fixture readiness."""

    golden = json.loads(source.read_text(encoding="utf-8"))
    golden["scoring_status"] = "ready"
    golden.pop("not_ready_reason", None)
    destination = tmp_path / f"{source.parent.name}-ready.json"
    destination.write_text(json.dumps(golden), encoding="utf-8")
    return accuracy.score(case_dir, destination)


class TestEmptyGoldenIsNotAFreePass:
    """``expected_n == 0`` means "nothing to find", not "nothing went wrong"."""

    def test_indeterminate_run_does_not_pass_the_benign_golden(self, tmp_path: Path) -> None:
        # The exact shape of the 2026-07-28 synthetic-benign "pass": zero findings,
        # verdict INDETERMINATE. The golden wants NO_EVIL.
        case = _write_case(tmp_path / "benign", "synthetic-benign", "INDETERMINATE", [])
        result = _score_with_ready_copy(case, _BENIGN_GOLDEN, tmp_path)
        assert result["run_finding_n"] == 0
        assert result["recall_percent"] != 100
        assert result["pass"] is False

    def test_errored_run_does_not_pass_the_decoy_golden(self, tmp_path: Path) -> None:
        # Right verdict word, zero findings — but a tool blew up, so the run never
        # actually established the negative.
        case = _write_case(
            tmp_path / "decoy",
            "synthetic-decoy",
            "NO_EVIL",
            [],
            tool_calls=[_OK_TOOL, _FAILED_TOOL],
        )
        result = _score_with_ready_copy(case, _DECOY_GOLDEN, tmp_path)
        assert result["run_completed"] is False
        assert result["recall_percent"] != 100
        assert result["pass"] is False

    def test_heartbeat_terminated_partial_run_does_not_pass(self, tmp_path: Path) -> None:
        case = _write_case(
            tmp_path / "benign",
            "synthetic-benign",
            "NO_EVIL",
            [],
            heartbeat={"terminated_partial": True},
        )
        result = _score_with_ready_copy(case, _BENIGN_GOLDEN, tmp_path)
        assert result["run_completed"] is False
        assert result["pass"] is False

    def test_clean_true_negative_run_still_passes(self, tmp_path: Path) -> None:
        # The whole point of a true-negative golden: a run that completed, called
        # the case NO_EVIL and correctly found nothing is a real PASS. Zero-expected
        # must not become an automatic fail.
        case = _write_case(tmp_path / "benign", "synthetic-benign", "NO_EVIL", [])
        result = _score_with_ready_copy(case, _BENIGN_GOLDEN, tmp_path)
        assert result["run_completed"] is True
        assert result["recall_percent"] == 100
        assert result["pass"] is True


class TestIndeterminateIsNotAVerdictMatch:
    """``INDETERMINATE`` is what a tool failure produces — it cannot mean "correct"."""

    def test_indeterminate_run_fails_a_confirmed_evil_golden(self, tmp_path: Path) -> None:
        # Nitroba's shape: full recall, but the run never committed to a call while
        # the key says CONFIRMED_EVIL.
        case = _write_case(
            tmp_path / "nitroba",
            "nitroba",
            "INDETERMINATE",
            _echo_golden_findings(_NITROBA_GOLDEN),
        )
        result = accuracy.score(case, _NITROBA_GOLDEN)
        assert result["recall_percent"] == 100, "fixture must isolate the verdict check"
        assert result["verdict_match"] is False
        assert result["pass"] is False

    def test_indeterminate_run_matches_an_indeterminate_golden(self, tmp_path: Path) -> None:
        # The false-positive control (alihadi-09) is authored to EXPECT uncertainty.
        # A neutral run against a neutral key is the right answer, not a free pass.
        case = _write_case(
            tmp_path / "alihadi",
            "alihadi-09-encrypt",
            "INDETERMINATE",
            _echo_golden_findings(_ALIHADI_GOLDEN),
        )
        result = accuracy.score(case, _ALIHADI_GOLDEN)
        assert result["verdict_match"] is True
        assert result["pass"] is True

    def test_definite_run_still_fails_an_indeterminate_golden(self, tmp_path: Path) -> None:
        # Unchanged behaviour, pinned so the fix does not loosen the FP control:
        # escalating to CONFIRMED_EVIL on a key authored INDETERMINATE is wrong.
        case = _write_case(
            tmp_path / "alihadi",
            "alihadi-09-encrypt",
            "CONFIRMED_EVIL",
            _echo_golden_findings(_ALIHADI_GOLDEN),
        )
        result = accuracy.score(case, _ALIHADI_GOLDEN)
        assert result["verdict_match"] is False
        assert result["pass"] is False


class TestUnscoredPrecisionIsNotReportedAsPerfect:
    """A zero-denominator metric is *not measured*, and must not print as 100%."""

    def test_zero_finding_run_reports_precision_as_not_measured(self, tmp_path: Path) -> None:
        nist = _GOLDENS / "nist-hacking-case" / "expected-findings.json"
        case = _write_case(tmp_path / "nist", "nist-hacking-case", "INDETERMINATE", [])
        result = accuracy.score(case, nist)
        assert result["run_finding_n"] == 0
        assert result["precision_percent"] is None
        assert result["hallucination_rate"] is None
        assert result["f1"] is None

    def test_scored_run_still_reports_real_numbers(self, tmp_path: Path) -> None:
        case = _write_case(
            tmp_path / "nitroba",
            "nitroba",
            "CONFIRMED_EVIL",
            _echo_golden_findings(_NITROBA_GOLDEN),
        )
        result = accuracy.score(case, _NITROBA_GOLDEN)
        assert result["precision_percent"] == 100
        assert result["hallucination_rate"] == 0.0


class TestNullMinRecallFailsLoudly:
    """A golden with ``min_recall_percent: null`` is a stub, not a threshold."""

    def test_null_min_recall_raises_an_error_naming_the_golden(self, tmp_path: Path) -> None:
        # Stub golden built here, so this pins the BRANCH independently of whichever
        # committed goldens happen to be unpopulated today.
        golden = tmp_path / "stub" / "expected-findings.json"
        golden.parent.mkdir(parents=True, exist_ok=True)
        golden.write_text(
            json.dumps(
                {
                    "case_id": "stub-pending-walkthrough",
                    "status": "pending_manual_walkthrough",
                    "verdict": "UNKNOWN",
                    "min_recall_percent": None,
                }
            ),
            encoding="utf-8",
        )
        case = _write_case(tmp_path / "stub-case", "stub-pending-walkthrough", "UNKNOWN", [])
        with pytest.raises(ValueError, match="stub-pending-walkthrough"):
            accuracy.score(case, golden)

    def test_the_live_sans_starter_golden_is_still_an_unscoreable_stub(
        self, tmp_path: Path
    ) -> None:
        # Tripwire on the real committed key, which is what made this a live failure
        # rather than an expression-level one. Populating sans-starter's
        # min_recall_percent SHOULD break this test — when it does, delete this test;
        # the branch itself stays covered by the stub case above.
        case = _write_case(tmp_path / "sans", "sans-starter", "UNKNOWN", [])
        with pytest.raises(ValueError, match="sans-starter"):
            accuracy.score(case, _SANS_GOLDEN)


class TestRunCompletionMatchesTheEnginesOwnFailureModel:
    """ "Any tool call with an error" is stricter than the engine's own definition.

    Both cases below are a CORRECT run on the true-negative control: complete, right
    verdict, correctly found nothing. Failing them makes the two goldens that exist
    to catch over-claiming unusable rather than merely wrong. Neither can produce a
    false PASS — this gate only reaches ``expected_n == 0`` goldens.
    """

    def test_guardrail_rejection_is_not_an_incomplete_run(self, tmp_path: Path) -> None:
        # find_evil_auto.py:9361 records a refused out-of-scope tool request as
        # {"error": reason, "rejected": True}. That is the guardrail WORKING.
        rejected = {
            "tool_call_id": "tc-2",
            "tool": "vol_pslist",
            "error": "tool not permitted for this evidence type",
            "rejected": True,
        }
        case = _write_case(
            tmp_path / "benign",
            "synthetic-benign",
            "NO_EVIL",
            [],
            tool_calls=[_OK_TOOL, rejected],
        )
        result = _score_with_ready_copy(case, _BENIGN_GOLDEN, tmp_path)
        assert result["run_completed"] is True
        assert result["recall_percent"] == 100
        assert result["pass"] is True

    def test_transient_failure_the_engine_recovered_from_is_not_incomplete(
        self, tmp_path: Path
    ) -> None:
        # find_evil_auto.py:9234 resets the engine's consecutive-failure streak on
        # ANY successful call — "a single transient error never trips the HEARTBEAT
        # escalation". A later success is the engine saying it recovered.
        retry = {"tool_call_id": "tc-3", "tool": "disk_extract_artifacts"}
        case = _write_case(
            tmp_path / "benign",
            "synthetic-benign",
            "NO_EVIL",
            [],
            tool_calls=[_OK_TOOL, _FAILED_TOOL, retry],
        )
        result = _score_with_ready_copy(case, _BENIGN_GOLDEN, tmp_path)
        assert result["run_completed"] is True
        assert result["pass"] is True

    def test_unrecovered_trailing_failure_is_still_incomplete(self, tmp_path: Path) -> None:
        # Nothing succeeded after the failure: the run stopped on it.
        case = _write_case(
            tmp_path / "benign",
            "synthetic-benign",
            "NO_EVIL",
            [],
            tool_calls=[_OK_TOOL, _FAILED_TOOL],
        )
        result = _score_with_ready_copy(case, _BENIGN_GOLDEN, tmp_path)
        assert result["run_completed"] is False
        assert result["pass"] is False

    def test_nameless_failed_tool_does_not_render_as_the_string_None(self, tmp_path: Path) -> None:
        case = _write_case(
            tmp_path / "benign",
            "synthetic-benign",
            "NO_EVIL",
            [],
            tool_calls=[{"tool_call_id": "tc-9", "error": "boom"}],
        )
        result = _score_with_ready_copy(case, _BENIGN_GOLDEN, tmp_path)
        assert result["run_completed"] is False
        assert "None" not in "; ".join(result["run_incomplete_reasons"])

    def test_an_unrelated_later_success_does_not_count_as_recovery(self, tmp_path: Path) -> None:
        # The engine's streak answers "should I abort this case?"; the scorer is asking
        # "did this run actually see the evidence?". A successful case_close answers the
        # first and says nothing about the second. Recovered means the tool that FAILED
        # later succeeded — a retry — not that something else succeeded afterwards.
        case = _write_case(
            tmp_path / "benign",
            "synthetic-benign",
            "NO_EVIL",
            [],
            tool_calls=[_OK_TOOL, _FAILED_TOOL, {"tool_call_id": "tc-4", "tool": "case_close"}],
        )
        result = _score_with_ready_copy(case, _BENIGN_GOLDEN, tmp_path)
        assert result["run_completed"] is False
        assert "disk_extract_artifacts" in "; ".join(result["run_incomplete_reasons"])
        assert result["pass"] is False

    def test_repeated_evidence_failures_are_not_cleared_by_one_other_success(
        self, tmp_path: Path
    ) -> None:
        # Could not read the disk three times, then made one unrelated successful call.
        # Under a trailing-streak rule this scores recall=100 PASS on a true-negative
        # key with nothing found — the exact vacuous pass this branch exists to close.
        failures = [dict(_FAILED_TOOL, tool_call_id=f"tc-{i}") for i in range(2, 5)]
        case = _write_case(
            tmp_path / "benign",
            "synthetic-benign",
            "NO_EVIL",
            [],
            tool_calls=[_OK_TOOL, *failures, {"tool_call_id": "tc-9", "tool": "case_close"}],
        )
        result = _score_with_ready_copy(case, _BENIGN_GOLDEN, tmp_path)
        assert result["run_completed"] is False
        assert result["pass"] is False

    def test_a_tool_that_succeeded_then_failed_reads_as_recovered_by_decision(
        self, tmp_path: Path
    ) -> None:
        """Order-insensitivity in ``failed - succeeded`` is a DECISION, not an oversight.

        A tool that succeeded and then failed reads as recovered, because the set
        difference does not care which came first. Foreman's call (2026-07-28), and the
        reasoning is on the record: this gate has already been wrong twice by
        over-correcting in opposite directions, and both corrections were driven by a
        REPRODUCED case. Succeeded-then-failed is reasoned, not reproduced -- tightening
        on it would risk the failure mode that costs more, a false FAIL on the two
        true-negative controls that exist to catch over-claiming.

        The property being defended is unchanged: a run that did not see the evidence
        must not pass on an empty expectation. This run did see it, at least once.

        KNOWN LIMITS, spelled out so a real case can move this. Neither is reproduced
        in the recorded data today; a reproduced run is what moves it, not another
        round of reasoning.

        1. A PARTIAL read -- the tool succeeds on the first slice of evidence and then
           fails partway through the rest -- slips through and scores as complete. The
           fix for that shape is order-aware: a failure is recovered only by a LATER
           success of the same tool.
        2. Warden's sharper case (2026-07-28): a tool that succeeds on one TARGET and
           fails on another -- ``disk_extract_artifacts`` reading partition 1 and
           failing partition 2 -- reads as complete with half the evidence unread. His
           conclusion, and it is the one to follow: the fix for that is per-TARGET, not
           per-order. Ordering would not catch it at all.

        If either shape is reproduced reaching a correct verdict with nothing found,
        tighten along the axis named for that shape and delete this test.
        """
        first_ok = {"tool_call_id": "tc-2", "tool": "disk_extract_artifacts"}
        later_failure = dict(_FAILED_TOOL, tool_call_id="tc-3")
        case = _write_case(
            tmp_path / "benign",
            "synthetic-benign",
            "NO_EVIL",
            [],
            tool_calls=[_OK_TOOL, first_ok, later_failure],
        )
        result = _score_with_ready_copy(case, _BENIGN_GOLDEN, tmp_path)
        assert result["run_completed"] is True
        assert result["run_incomplete_reasons"] == []
        assert result["pass"] is True
