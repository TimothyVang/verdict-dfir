"""A rejected/errored tool call must still be LOGGED to the audit chain.

The Rust bypass tests prove hostile inputs are rejected as typed errors, but the
lessons-learned invariant — "assert each rejected attempt is LOGGED" — belongs at
the caller layer. ``Investigation._record_tool`` is the single choke point every
tool site funnels through: on success or failure it emits a ``tool_call_start``
and a ``tool_call_output`` audit record (the failure sites tag ``extra["error"]``
with the rejection's message) and registers the call in ``self.tool_calls`` with a
``tool_call_id``. If a future refactor ever skipped the audit append on the error
path, a rejected tool call would silently vanish from the chain — the very gap
this contract forbids.

These tests pin the caller-layer "rejection is logged" contract generically (not
tied to any one lane), so it cannot silently regress:

- R1: an errored tool record still emits exactly one tool_call_output, and that
      record carries the rejection's error message under "error".
- R2: the errored record is paired with a tool_call_start sharing the same
      tool_call_id, and the call is appended to self.tool_calls.
- R3: a rejected record does NOT reset the consecutive-failure streak, while a
      clean record does — distinguishing "logged" from "treated as success".
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


def _inv() -> fea.Investigation:
    return fea.Investigation("/tmp/does-not-exist-evidence", case_id="case-reject")


def _records(py: _FakePy, kind: str) -> list[dict]:
    return [payload for k, payload in py.audits if k == kind]


def test_rejected_tool_call_emits_error_tagged_output() -> None:
    # R1: the error-placeholder record a failed tool site writes still produces a
    # tool_call_output, and that record carries the rejection message.
    inv = _inv()
    py = _FakePy()

    inv._record_tool(
        py,
        "vol_pslist",
        "a" * 64,
        {"error": "rejected: unknown field 'evil'"},
    )

    outputs = _records(py, "tool_call_output")
    assert len(outputs) == 1, "a rejected tool call must emit one tool_call_output"
    assert outputs[0]["error"] == "rejected: unknown field 'evil'"


def test_rejected_tool_call_is_chain_visible_and_registered() -> None:
    # R2: the error output is paired with a tool_call_start sharing its id, and
    # the rejected call is registered in tool_calls so the chain can trace it.
    inv = _inv()
    py = _FakePy()

    tcid = inv._record_tool(
        py,
        "yara_scan",
        "b" * 64,
        {"error": "rejected: malformed arguments"},
    )

    starts = _records(py, "tool_call_start")
    outputs = _records(py, "tool_call_output")
    assert len(starts) == 1
    assert starts[0]["tool_call_id"] == tcid
    assert outputs[0]["tool_call_id"] == tcid

    assert len(inv.tool_calls) == 1
    recorded = inv.tool_calls[0]
    assert recorded["tool_call_id"] == tcid
    assert recorded["tool"] == "yara_scan"
    assert recorded["error"] == "rejected: malformed arguments"


def test_rejected_record_does_not_count_as_success() -> None:
    # R3: logging a rejection is not the same as accepting it — an error-tagged
    # record leaves the consecutive-failure streak intact, while a clean record
    # clears it. This keeps a rejected tool from masquerading as a success.
    inv = _inv()
    py = _FakePy()

    inv._consecutive_failures = 1
    inv._record_tool(py, "vol_pslist", "a" * 64, {"error": "rejected"})
    assert inv._consecutive_failures == 1, "a rejected record must not reset the streak"

    inv._record_tool(py, "vol_psscan", "c" * 64)
    assert inv._consecutive_failures == 0, "a clean record clears the streak"
