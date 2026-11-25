"""Tests for the one-retry resilient tool-call tier before defer.

The judging-audit (Autonomous Execution) flagged that every recovery action
was uniformly ``defer`` — a single transient tool error (queue.Empty, a
timeout, a dropped MCP connection) dropped the whole lane instead of being
retried. HEARTBEAT.md describes reasoning about the failure and trying again
before giving up; that tier had no enforcing code.

``_call_resilient`` adds exactly one retry on a *transient* error, emitting a
``tool_retry`` audit record so the retry is visible in the chain (not a silent
re-call). A non-transient error (bad arguments, not-found) is returned
unchanged so the caller still defers — we never mask a real failure by
hammering it.

- R1: a transient error then success -> one tool_retry record, success returned.
- R2: a non-transient error is NOT retried and is returned unchanged.
- R3: a clean first call is returned with no tool_retry record.
- R4: a transient error that persists across the retry returns the error
      (caller falls back to defer) and emits exactly one tool_retry record.
"""

from __future__ import annotations

import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402


class _FakePy:
    """Records every audit_append."""

    def __init__(self) -> None:
        self.audits: list[tuple[str, dict]] = []

    def call_tool(self, name: str, args: dict, timeout: float = 600.0) -> dict:
        if name == "audit_append":
            self.audits.append((args["kind"], args["payload"]))
        return {}

    def close(self) -> None:  # pragma: no cover - parity with real client
        pass


class _FakeRust:
    """Returns the queued results in order, recording each call."""

    def __init__(self, results: list[dict]) -> None:
        self._results = list(results)
        self.calls: list[tuple[str, dict]] = []

    def call_tool(self, name: str, args: dict, timeout: float = 600.0) -> dict:
        self.calls.append((name, args))
        return self._results.pop(0)


def _inv() -> fea.Investigation:
    return fea.Investigation("/tmp/does-not-exist-evidence", case_id="case-resilient")


_OK = {"processes": [], "processes_seen": 0}
_TRANSIENT = {"_error": {"message": "queue.Empty: no response within 600s"}}
_HARD = {"_error": {"message": "invalid arguments: unknown field 'foo'"}}


def test_transient_error_then_success_retries_once() -> None:
    inv = _inv()
    py = _FakePy()
    rust = _FakeRust([_TRANSIENT, _OK])

    out = inv._call_resilient(rust, py, "vol_pslist", {"case_id": "c"})

    assert out == _OK
    assert len(rust.calls) == 2
    retries = [p for k, p in py.audits if k == "tool_retry"]
    assert len(retries) == 1
    assert retries[0]["tool"] == "vol_pslist"
    assert retries[0]["attempt"] == 2


def test_non_transient_error_is_not_retried() -> None:
    inv = _inv()
    py = _FakePy()
    rust = _FakeRust([_HARD])

    out = inv._call_resilient(rust, py, "vol_pslist", {"case_id": "c"})

    assert out == _HARD
    assert len(rust.calls) == 1  # no retry
    assert "tool_retry" not in [k for k, _ in py.audits]


def test_clean_call_has_no_retry_record() -> None:
    inv = _inv()
    py = _FakePy()
    rust = _FakeRust([_OK])

    out = inv._call_resilient(rust, py, "vol_pslist", {"case_id": "c"})

    assert out == _OK
    assert len(rust.calls) == 1
    assert "tool_retry" not in [k for k, _ in py.audits]


def test_persistent_transient_error_returns_error_after_one_retry() -> None:
    inv = _inv()
    py = _FakePy()
    rust = _FakeRust([_TRANSIENT, _TRANSIENT])

    out = inv._call_resilient(rust, py, "vol_pslist", {"case_id": "c"})

    assert "_error" in out  # caller falls back to defer
    assert len(rust.calls) == 2  # exactly one retry, not unbounded
    assert len([k for k, _ in py.audits if k == "tool_retry"]) == 1
