"""The transient-vs-deterministic self-correction routing contract.

VERDICT routes a failed tool call down exactly one of two recovery paths:

- TRANSIENT (flaky: timeout, dropped MCP connection, queue.Empty) -> retry once
  via ``_call_resilient`` before deferring. The flaky call may succeed on retry.
- DETERMINISTIC ABSENCE (the backing binary/subtool is not installed at all) ->
  early-stop via ``_note_tool_absent``: record it once and never re-issue the
  doomed call. Retrying it is pointless -- it fails identically every time.

``_TRANSIENT_MARKERS`` is the single explicit source of truth for what counts as
transient; ``_ABSENCE_MARKERS`` is the source of truth for a deterministic
absence. This pins the CONTRACT between the two: the two marker sets must not
overlap, and any given error message must route to AT MOST one path -- otherwise
a deterministic absence could be retried (17-failure SCHARDT regression) or a
transient flake could be early-stopped (lost coverage on a recoverable blip).

- T1: the marker substring sets are disjoint (no shared substring).
- T2: a transient message classifies transient-only; a deterministic-absence
      message classifies absence-only -- never both.
- T3: end-to-end -- a transient error RETRIES exactly once via _call_resilient,
      while a deterministic-absence error is NOT retried (early-stop).
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

    def close(self) -> None:  # pragma: no cover - parity with real client
        pass


class _FakeRust:
    def __init__(self, results: list[dict]) -> None:
        self._results = list(results)
        self.calls: list[tuple[str, dict]] = []

    def call_tool(self, name: str, args: dict, timeout: float = 600.0) -> dict:
        self.calls.append((name, args))
        return self._results.pop(0)


def _inv() -> fea.Investigation:
    return fea.Investigation("/tmp/does-not-exist-evidence", case_id="case-routing")


_TRANSIENT = {"_error": {"message": "queue.Empty: no response within 600s"}}
_ABSENCE = {"_error": {"message": "plaso_parse: log2timeline.py not found (set $PLASO_DIR)"}}
_OK = {"processes": [], "processes_seen": 0}


def test_marker_sets_are_disjoint() -> None:
    # No substring may live in both allow-lists -- the routing must be a clean
    # partition, not an overlap that lets one message take both paths.
    transient = {m.lower() for m in fea.Investigation._TRANSIENT_MARKERS}
    absence = {m.lower() for m in fea.Investigation._ABSENCE_MARKERS}
    assert transient.isdisjoint(absence)


def test_each_marker_routes_to_exactly_one_path() -> None:
    inv = _inv()
    for marker in fea.Investigation._TRANSIENT_MARKERS:
        msg = f"tool failed: {marker}"
        assert inv._is_transient_error(msg), marker
        assert not inv._is_deterministic_absence(msg), marker
    for marker in fea.Investigation._ABSENCE_MARKERS:
        msg = f"tool failed: {marker}"
        assert inv._is_deterministic_absence(msg), marker
        assert not inv._is_transient_error(msg), marker


def test_transient_retries_once_absence_early_stops() -> None:
    # TRANSIENT: one retry, and the retry can succeed.
    inv = _inv()
    py = _FakePy()
    rust = _FakeRust([_TRANSIENT, _OK])
    out = inv._call_resilient(rust, py, "vol_pslist", {"case_id": "c"})
    assert out == _OK
    assert len(rust.calls) == 2  # original + one retry
    assert len([k for k, _ in py.audits if k == "tool_retry"]) == 1

    # DETERMINISTIC ABSENCE: _call_resilient does NOT retry it (no tool_retry),
    # and the early-stop bookkeeping records the absence once instead.
    inv2 = _inv()
    py2 = _FakePy()
    rust2 = _FakeRust([_ABSENCE])
    out2 = inv2._call_resilient(rust2, py2, "plaso_parse", {"case_id": "c"})
    assert "_error" in out2  # returned unchanged -> caller defers
    assert len(rust2.calls) == 1  # NO retry on a deterministic absence
    assert "tool_retry" not in [k for k, _ in py2.audits]

    handled = inv2._note_tool_absent(
        py2, "plaso_parse", out2["_error"]["message"], fallback="ez_parse"
    )
    assert handled is None or "plaso_parse" in inv2._absent_tools
    assert "plaso_parse" in inv2._absent_tools  # later sites early-stop
