"""Tests for deterministic tool-absence early-stop + named fallback.

The judging-audit (Autonomous Execution) and a real SCHARDT run flagged a gap:
when a typed tool is deterministically *absent* on the host (e.g. ``plaso_parse``
returns "log2timeline.py not found" because plaso is not installed), the
orchestrator re-issued the same doomed call per artifact — 17 identical failures
in one committed run — and the silent pivot to the working path was NOT recorded
as a ``course_correction``. That is the opposite of self-correction.

``_is_deterministic_absence`` classifies the error (distinct from the transient
class ``_call_resilient`` already retries). ``_note_tool_absent`` records the
absence ONCE: it adds the tool to ``self._absent_tools`` (so later sites early-stop
instead of re-calling), emits a named ``course_correction`` (``mechanism=
tool_failure_resequence``) so the recovery is in the audit chain, and — when a
clean fallback exists — does NOT count the absence toward the HEARTBEAT
consecutive-failure streak (a recovered degradation is not a liveness failure).

- A1: deterministic-absence markers classify True; transient/clean classify False.
- A2: note-absent WITH a fallback emits course_correction(action=fallback,
      mechanism=tool_failure_resequence), records the tool absent, and does NOT
      increment the consecutive-failure streak.
- A3: note-absent WITHOUT a fallback emits action=defer and DOES increment the
      streak (a real deferred failure).
- A4: note-absent is idempotent per tool — a second call emits no second record
      (the early-stop, not a re-detection).
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

    def close(self) -> None:  # pragma: no cover
        pass


def _inv() -> fea.Investigation:
    return fea.Investigation("/tmp/does-not-exist-evidence", case_id="case-absence")


def test_deterministic_absence_classification() -> None:
    inv = _inv()
    absent = [
        'plaso_parse: "log2timeline.py" not found (set $PLASO_DIR or put plaso on PATH).',
        "mcp rpc error code=-32602: unknown tool: lecmd",
        "binary not found: psort.py",
        "log2timeline is not installed",
        "command not found",
    ]
    for msg in absent:
        assert inv._is_deterministic_absence(msg), msg
    not_absent = [
        "queue.Empty: no response within 600s",  # transient
        "connection reset by peer",  # transient
        "invalid arguments: unknown field 'foo'",  # hard but not absence
        "parse error at offset 12",  # genuine parse failure, tool present
        "",
    ]
    for msg in not_absent:
        assert not inv._is_deterministic_absence(msg), msg


def test_note_absent_with_fallback_records_and_does_not_count_failure() -> None:
    inv = _inv()
    py = _FakePy()
    before = inv._consecutive_failures

    inv._note_tool_absent(py, "plaso_parse", "log2timeline.py not found", fallback="ez_parse")

    assert "plaso_parse" in inv._absent_tools
    corrections = [p for k, p in py.audits if k == "course_correction"]
    assert len(corrections) == 1
    assert corrections[0]["failed_tool"] == "plaso_parse"
    assert corrections[0]["action"] == "fallback"
    assert corrections[0]["mechanism"] == "tool_failure_resequence"
    # A recovered degradation is NOT a liveness failure: streak untouched.
    assert inv._consecutive_failures == before
    assert not inv._heartbeat_escalated


def test_note_absent_without_fallback_defers_and_counts_failure() -> None:
    inv = _inv()
    py = _FakePy()
    before = inv._consecutive_failures

    inv._note_tool_absent(py, "plaso_parse", "log2timeline.py not found", fallback=None)

    corrections = [p for k, p in py.audits if k == "course_correction"]
    assert len(corrections) == 1
    assert corrections[0]["action"] == "defer"
    # A defer with no recovery path IS a deferred failure: streak advances.
    assert inv._consecutive_failures == before + 1


def test_note_absent_is_idempotent_per_tool() -> None:
    inv = _inv()
    py = _FakePy()

    inv._note_tool_absent(py, "plaso_parse", "not found", fallback="ez_parse")
    inv._note_tool_absent(py, "plaso_parse", "not found", fallback="ez_parse")

    corrections = [p for k, p in py.audits if k == "course_correction"]
    assert len(corrections) == 1  # second call early-stops, no duplicate record


# --- LNK lecmd-absence -> named registry fallback ---------------------------
# The LNK lane parses .lnk shortcuts with ez_parse/lecmd. When lecmd is
# deterministically absent the lane used to only append a silent
# ``analysis_limitations`` string, so the degradation never reached the audit
# chain as a ``course_correction``. The removable-media FINDING is not lost --
# the independent registry USBSTOR/MountedDevices lane covers it -- so the fix
# is to record the pivot as ONE named fallback correction (not a duplicate
# finding). ``_lnk_lecmd_absent_fallback`` encodes exactly that.


def test_lnk_lecmd_absence_emits_named_registry_fallback() -> None:
    inv = _inv()
    py = _FakePy()

    handled = inv._lnk_lecmd_absent_fallback(py, "mcp rpc error code=-32602: unknown tool: lecmd")

    assert handled is True
    assert "ez_parse:lecmd" in inv._absent_tools
    corrections = [p for k, p in py.audits if k == "course_correction"]
    assert len(corrections) == 1
    c = corrections[0]
    assert c["failed_tool"] == "ez_parse:lecmd"
    assert c["action"] == "fallback"
    assert c["mechanism"] == "tool_failure_resequence"
    # The reason names the real alternative coverage (registry), so the audited
    # pivot is self-explanatory and not a duplicate of the registry finding.
    assert "registry" in c["reason"].lower()
    # A recovered degradation must not advance the HEARTBEAT streak.
    assert inv._consecutive_failures == 0


def test_lnk_lecmd_genuine_parse_error_is_not_treated_as_absence() -> None:
    inv = _inv()
    py = _FakePy()

    # lecmd present but the shortcut failed to parse -> NOT an absence, so no
    # fallback correction (the lane keeps its existing limitation handling).
    handled = inv._lnk_lecmd_absent_fallback(py, "parse error at offset 12")

    assert handled is False
    assert "ez_parse:lecmd" not in inv._absent_tools
    assert not [p for k, p in py.audits if k == "course_correction"]


def test_lnk_lecmd_absence_fallback_is_idempotent() -> None:
    inv = _inv()
    py = _FakePy()

    inv._lnk_lecmd_absent_fallback(py, "code=-32602 unknown tool: lecmd")
    inv._lnk_lecmd_absent_fallback(py, "code=-32602 unknown tool: lecmd")

    corrections = [p for k, p in py.audits if k == "course_correction"]
    assert len(corrections) == 1  # one record across many failing .lnk entries
