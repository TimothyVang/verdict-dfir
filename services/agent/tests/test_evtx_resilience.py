"""A corrupt EVTX must not crash the whole run.

investigate_evtx used to ``raise RuntimeError`` on an evtx_query tool error.
In a directory run that exception propagates out of investigate_inventory and
run(), so one unreadable EVTX file crashed the investigation with NO sealed
verdict and NO manifest — the opposite of the HEARTBEAT terminator's promise
("seal an honest partial Verdict, never crash"). Every other lane
course-corrects and continues; this test pins that the EVTX lane now does too.
"""

from __future__ import annotations

import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402


class _FakePy:
    def __init__(self) -> None:
        self.audits: list[tuple[str, dict]] = []

    def call_tool(self, name: str, args: dict, timeout: float = 600.0) -> dict:
        if name == "audit_append":
            self.audits.append((args["kind"], args["payload"]))
        return {}


class _FakeRust:
    """evtx_query returns a tool error (corrupt/unreadable file)."""

    def call_tool(self, name: str, args: dict, timeout: float = 600.0) -> dict:
        if name == "evtx_query":
            return {"_error": {"message": "evtx parse failed: bad chunk magic"}}
        return {}


def _inv() -> fea.Investigation:
    inv = fea.Investigation("/tmp/does-not-exist-evidence", case_id="case-evtx")
    inv.handle = {"id": "case-test"}
    return inv


def _kinds(py: _FakePy) -> list[str]:
    return [k for k, _ in py.audits]


def test_evtx_query_error_does_not_crash_run() -> None:
    inv = _inv()
    py = _FakePy()
    rust = _FakeRust()

    # Must NOT raise.
    inv.investigate_evtx(rust, py, "/case/broken.evtx")

    # Course-corrected (visible in the chain), not crashed.
    assert "course_correction" in _kinds(py)
    correction = next(p for k, p in py.audits if k == "course_correction")
    assert correction["failed_tool"] == "evtx_query"

    # The failure is surfaced as an analysis limitation, no findings drafted.
    assert any("evtx" in lim.lower() for lim in inv.analysis_limitations)
    assert inv.findings_pool_a == []
    assert inv.findings_pool_b == []


def test_evtx_error_record_tags_error_for_heartbeat() -> None:
    # The recorded tool output must carry an "error" key so a failed EVTX lane
    # contributes to the HEARTBEAT streak (the streak only resets on a clean
    # tool record).
    inv = _inv()
    py = _FakePy()
    rust = _FakeRust()

    inv.investigate_evtx(rust, py, "/case/broken.evtx")

    outputs = [p for k, p in py.audits if k == "tool_call_output"]
    assert outputs, "expected a tool_call_output record for the failed evtx_query"
    assert outputs[-1].get("error")
