"""Tests for the HEARTBEAT consecutive-failure escalation.

HEARTBEAT.md mandates: "2 consecutive failed self-tests -> session terminates
with partial report" and "log it as kind=heartbeat_failure to the audit chain."
Before this change, recovery was uniformly per-tool ``course_correction`` with
no run-level escalation, so the documented escalation contract had zero
enforcing code (judging-audit gap, Autonomous Execution).

The escalation is wired into ``_course_correct`` (every tool-failure path) and
reset by ``_record_tool`` (any successful tool call), so a single failure, or
failures interleaved with successes, never escalates — only a genuine
consecutive-failure streak does.

- H1: a single course-correction emits no heartbeat_failure.
- H2: two consecutive course-corrections emit one heartbeat_failure naming the
      streak count and an escalate/partial-report recovery action.
- H3: a successful tool call between failures resets the streak, so the next
      failure does not escalate.
"""

from __future__ import annotations

import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402


class _FakePy:
    """Records every audit_append (kind, payload) the engine emits."""

    def __init__(self) -> None:
        self.audits: list[tuple[str, dict]] = []

    def call_tool(self, name: str, args: dict, timeout: float = 600.0) -> dict:
        if name == "audit_append":
            self.audits.append((args["kind"], args["payload"]))
        return {}

    def close(self) -> None:  # pragma: no cover - parity with real client
        pass


def _kinds(py: _FakePy) -> list[str]:
    return [kind for kind, _ in py.audits]


def _inv() -> "fea.Investigation":
    return fea.Investigation("/tmp/does-not-exist-evidence", case_id="case-hb")


def test_single_failure_does_not_escalate() -> None:
    inv = _inv()
    py = _FakePy()
    inv._course_correct(py, "vol_pslist", "boom", "defer")
    assert "heartbeat_failure" not in _kinds(py)


def test_two_consecutive_failures_escalate() -> None:
    inv = _inv()
    py = _FakePy()
    inv._course_correct(py, "vol_pslist", "boom", "defer")
    inv._course_correct(py, "vol_psscan", "boom again", "defer")

    hb = [payload for kind, payload in py.audits if kind == "heartbeat_failure"]
    assert len(hb) == 1
    assert hb[0]["consecutive_failures"] == 2
    assert hb[0]["action"] == "escalate"
    assert "partial" in hb[0]["recovery"].lower()


def test_success_resets_the_streak() -> None:
    inv = _inv()
    py = _FakePy()
    inv._course_correct(py, "vol_pslist", "boom", "defer")
    # A successful tool call lands between the two failures.
    inv._record_tool(py, "evtx_query", "deadbeef")
    inv._course_correct(py, "vol_psscan", "boom again", "defer")

    assert "heartbeat_failure" not in _kinds(py)
