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


def _inv() -> fea.Investigation:
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


def test_failed_tool_record_does_not_reset_streak() -> None:
    # Real failure pattern at every tool site: _course_correct increments the
    # streak, then the failed tool's error-PLACEHOLDER output is recorded via
    # _record_tool (extra carries an "error" key). That placeholder record must
    # NOT reset the streak — otherwise two consecutive tool failures could
    # never reach the HEARTBEAT threshold (the terminator would be dead code
    # on the tool-failure path).
    inv = _inv()
    py = _FakePy()
    inv._course_correct(py, "vol_pslist", "boom", "defer")
    inv._record_tool(py, "vol_pslist", "a" * 64, {"error": "boom"})
    inv._course_correct(py, "vol_psscan", "boom again", "defer")
    inv._record_tool(py, "vol_psscan", "b" * 64, {"error": "boom again"})

    hb = [p for k, p in py.audits if k == "heartbeat_failure"]
    assert len(hb) == 1
    assert hb[0]["consecutive_failures"] == 2
    assert inv._heartbeat_escalated is True


# ---------------------------------------------------------------------------
# Terminator: the escalated flag must have consequences (it used to be set
# and never read — a heartbeat-escalated run with no findings could still
# end NO_EVIL and keep opening lanes).
#
# - T1: once escalated, investigate_inventory opens no further lanes and
#       audits exactly one heartbeat_terminated record (idempotent).
# - T2: a terminated run with no findings computes INDETERMINATE, never
#       NO_EVIL — partial coverage cannot claim scoped-clean.
# - T3: the run summary carries a HEARTBEAT blocker so readiness tooling
#       sees the partial posture.
# ---------------------------------------------------------------------------


def _evtx_inventory(n: int) -> dict:
    return {
        "entries": [
            {
                "path": f"/case/sys{i}.evtx",
                "evidence_type": "evtx",
                "artifact_class": "evtx",
                "custody_status": "custody_registered",
            }
            for i in range(n)
        ],
        "summary": {},
    }


def test_escalation_skips_remaining_inventory_lanes() -> None:
    inv = _inv()
    py = _FakePy()
    rust = _FakePy()
    inv.evidence_inventory = _evtx_inventory(2)
    lane_calls: list[tuple] = []
    inv.investigate_evtx = (  # type: ignore[method-assign]
        lambda *a, **k: lane_calls.append(a)
    )

    inv._heartbeat_escalated = True
    inv.investigate_inventory(rust, py)

    assert lane_calls == []
    terminated = [p for k, p in py.audits if k == "heartbeat_terminated"]
    assert len(terminated) == 1
    assert terminated[0]["action"] == "terminate_partial"

    # Idempotent: a second pass never double-audits the terminator.
    inv.investigate_inventory(rust, py)
    terminated = [p for k, p in py.audits if k == "heartbeat_terminated"]
    assert len(terminated) == 1


def test_terminated_empty_run_is_indeterminate_not_no_evil() -> None:
    inv = _inv()
    inv.evidence_inventory = _evtx_inventory(0)
    inv.tool_calls = [{"tool_call_id": "tc-1", "tool": "evtx_query", "output_hash": "abc"}]
    # Precondition: a clean empty run over substantive tooling is NO_EVIL.
    assert inv.compute_verdict([]) == "NO_EVIL"

    inv._heartbeat_escalated = True
    assert inv.compute_verdict([]) == "INDETERMINATE"


def test_terminated_run_summary_is_partial_with_blocker() -> None:
    inv = _inv()
    py = _FakePy()
    inv._heartbeat_escalated = True

    assert inv._heartbeat_abort(py) is True

    summary = inv.build_run_summary(readiness_state="partial")
    assert summary["readiness_state"] == "partial"
    assert any("HEARTBEAT" in blocker for blocker in summary["blockers"])
