"""A missing OPTIONAL external binary must not poison the whole case (REG-1).

Wave 2 added the PST mail lane. ``readpst`` / ``pffexport`` are not installed on
the GN7000 runner, so ``pst_parse`` returns its typed ``BinaryNotFound``. The
engine recorded that as a plain ``{"error": ...}`` tool_call, and
``accuracy._run_completed`` counts a tool that errored and never succeeded as an
unrecovered failure -- so the entire case scored NOT_READY. Measured on the
2026-08-07 goldens-local sweep (/srv/verdict-lab/logs/goldens-local/summary.json)::

    ['m57-jean', 'NOT_READY', 'tool call(s) failed and never succeeded: pst_parse', ...]
    ['nist-data-leakage', 'NOT_READY', 'tool call(s) failed and never succeeded: pst_parse', ...]

Both were honest ``FAIL recall=0`` before the lane existed. Adding a lane made
them UNSCOREABLE, which is strictly worse than scoring badly.

An unmet external-binary prerequisite is a coverage gap for ONE lane, not a
failure of the case. So it must be a GRACEFUL, RECORDED skip: the tool_call is
marked skipped (so it is not an unrecovered failure) and an
``analysis_limitations`` entry names the missing binary (so the gap is visible
rather than silent) -- the same treatment the engine already gives an unset
``$FIND_EVIL_DISK_YARA_RULES``.

The BOUNDARY is the whole point and is pinned here: a PST that EXISTS and fails
to parse (``SubprocessFailed``) is a real failure and must still surface. The two
are told apart on the server's TYPED error class, carried over the wire as the
JSON-RPC ``error.data.kind`` -- never by matching words in the message, which is
why the existing ``_ABSENCE_MARKERS`` string list does not (and must not) decide
this: none of its markers appear in "no PST reader found: install libpst ...".

- W1: the client surfaces the server's typed ``error.data.kind``; a plain error
      carries none.
- W2: ``missing_prerequisite`` classifies on that typed kind only -- a
      SubprocessFailed message that NAMES readpst is not a prerequisite gap.
- E1: the mail lane records the skip markers + a limitation naming the binary.
- E2: a real PST parse failure records NO skip marker (boundary).
- E3: the skip is per-call, so one store skipped + one store parsed still leaves
      the successful call unmarked.
- A1: ``_run_completed`` treats a recorded skip as complete.
- A2: ``_run_completed`` still fails on an unmarked pst_parse error (boundary).
- S1: the end-to-end shape of the two regressed goldens scores again.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from queue import Queue
from typing import Any

import pytest

from findevil_agent import accuracy

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402

_REPO_ROOT = Path(__file__).resolve().parents[3]
_GOLDENS = _REPO_ROOT / "goldens"

# The literal message the Rust tool emits when neither libpst nor libpff is on
# the host (services/mcp/src/tools/pst_parse.rs::PstParseError::BinaryNotFound).
_BINARY_NOT_FOUND = (
    "rust-mcp tools/call: pst_parse: no PST reader found: install libpst (readpst) "
    "or libpff (pffexport), or set $PST_READER_BIN to one of them"
)
# A PST that EXISTS and the reader choked on. Deliberately NAMES readpst so a
# string-matching classifier would misfile it as an absence.
_SUBPROCESS_FAILED = (
    "rust-mcp tools/call: pst_parse: PST reader readpst failed (exit status: 2): "
    "Error: unable to read the PST header block"
)

_STORE = "/case/extracted/disk/mail_store/Users/jean/Outlook/outlook.pst"


def _prereq_error(message: str = _BINARY_NOT_FOUND) -> dict[str, Any]:
    """A tool result as the client returns it for a TYPED prerequisite gap."""
    return {"_error": {"message": message, "kind": fea.MISSING_PREREQUISITE}}


def _plain_error(message: str = _SUBPROCESS_FAILED) -> dict[str, Any]:
    """A tool result for a real failure: same -32603, no typed kind."""
    return {"_error": {"message": message}}


# ---------------------------------------------------------------------------
# W -- the typed kind survives the wire.
# ---------------------------------------------------------------------------


class _FakeStdout:
    """Blocking line source: the client's reader thread must not see EOF early."""

    def __init__(self) -> None:
        self._q: Queue[str] = Queue()

    def feed(self, line: str) -> None:
        self._q.put(line)

    def readline(self) -> str:
        return self._q.get()


class _FakeStdin:
    def __init__(self, on_write) -> None:
        self._on_write = on_write

    def write(self, data: str) -> int:
        self._on_write(data)
        return len(data)

    def flush(self) -> None:
        pass

    def close(self) -> None:
        pass


class _ErrorServer:
    """A stdio MCP server that answers every tools/call with one JSON-RPC error."""

    def __init__(self, error: dict[str, Any]) -> None:
        self._error = error
        self.stdout = _FakeStdout()
        self.stdin = _FakeStdin(self._respond)
        self.stderr = _FakeStdout()

    def _respond(self, data: str) -> None:
        for line in data.splitlines():
            if not line.strip():
                continue
            msg = json.loads(line)
            self.stdout.feed(
                json.dumps({"jsonrpc": "2.0", "id": msg["id"], "error": self._error}) + "\n"
            )

    # subprocess.Popen surface the client touches
    def wait(self, timeout: float | None = None) -> int:
        return 0

    def kill(self) -> None:
        pass

    def poll(self) -> int | None:
        return None


def _client_for(monkeypatch: pytest.MonkeyPatch, error: dict[str, Any]) -> Any:
    server = _ErrorServer(error)
    monkeypatch.setattr(fea.subprocess, "Popen", lambda *a, **k: server)
    return fea.StdioMcpClient("ignored", "rust-mcp")


def test_client_surfaces_the_servers_typed_error_kind(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client_for(
        monkeypatch,
        {
            "code": -32603,
            "message": "pst_parse: no PST reader found: install libpst (readpst)",
            "data": {"kind": "missing_prerequisite"},
        },
    )
    out = client.call_tool("pst_parse", {"case_id": "c", "artifact_path": _STORE}, timeout=5.0)

    assert "_error" in out
    assert out["_error"]["kind"] == fea.MISSING_PREREQUISITE
    assert out["_error"]["code"] == -32603


def test_client_leaves_an_untyped_error_untyped(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client_for(
        monkeypatch,
        {"code": -32603, "message": "pst_parse: PST reader readpst failed (exit status: 2)"},
    )
    out = client.call_tool("pst_parse", {"case_id": "c", "artifact_path": _STORE}, timeout=5.0)

    assert "_error" in out
    assert out["_error"].get("kind") is None


# ---------------------------------------------------------------------------
# W2 -- the classifier reads the type, not the words.
# ---------------------------------------------------------------------------


def test_missing_prerequisite_reads_the_typed_kind() -> None:
    assert fea.missing_prerequisite(_prereq_error()) == _BINARY_NOT_FOUND


def test_a_real_parse_failure_that_names_the_binary_is_not_a_prerequisite_gap() -> None:
    # The message says "readpst" -- a substring classifier would call this an
    # absence. It is a PST that exists and failed to parse: a REAL failure.
    assert fea.missing_prerequisite(_plain_error()) is None


def test_a_successful_result_is_not_a_prerequisite_gap() -> None:
    assert fea.missing_prerequisite({"message_count": 3, "messages": []}) is None


# ---------------------------------------------------------------------------
# E -- the engine records the skip.
# ---------------------------------------------------------------------------


class _FakeMcp:
    """Canned per-tool results; records audit_append payloads."""

    def __init__(self, results: list[dict[str, Any]] | None = None) -> None:
        self._results = list(results or [])
        self.audits: list[tuple[str, dict[str, Any]]] = []
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def call_tool(self, name: str, args: dict[str, Any], timeout: float | None = None):
        self.calls.append((name, args))
        if name == "audit_append":
            self.audits.append((args["kind"], args["payload"]))
            return {}
        return self._results.pop(0) if self._results else {}


def _inv() -> fea.Investigation:
    inv = object.__new__(fea.Investigation)
    inv.handle = {"id": "case-prereq"}
    inv.evidence = "/evidence/disk.E01"
    inv.tcid_counter = 0
    inv.tool_calls = []
    inv.findings_pool_a = []
    inv.findings_pool_b = []
    inv.timeline_events = []
    inv.analysis_limitations = []
    inv.local_artifacts = {}
    inv.audit_path = "/tmp/audit-prereq.jsonl"
    inv._consecutive_failures = 0
    inv._heartbeat_threshold = 99
    inv._heartbeat_escalated = False
    inv._absent_tools = set()
    inv._heartbeat = lambda **_kw: None
    return inv


def _entry(path: str = _STORE) -> dict[str, Any]:
    return {"path": path, "artifact_class": "mail_store", "evidence_type": "extracted_disk"}


def test_mail_lane_records_a_missing_reader_as_a_graceful_skip() -> None:
    inv = _inv()
    rust = _FakeMcp([_prereq_error()])
    py = _FakeMcp()

    fea.Investigation.investigate_mail_stores(inv, rust, py, [_entry()])

    assert len(inv.tool_calls) == 1
    call = inv.tool_calls[0]
    assert call["tool"] == "pst_parse"
    assert call["error"] == _BINARY_NOT_FOUND
    assert call["skipped"] is True, call
    assert call["skip_reason"] == fea.MISSING_PREREQUISITE
    # The gap must be VISIBLE, naming the binary that is absent.
    assert any("pst_parse" in lim and "readpst" in lim for lim in inv.analysis_limitations), (
        inv.analysis_limitations
    )


def test_a_real_pst_parse_failure_is_not_marked_skipped() -> None:
    inv = _inv()
    rust = _FakeMcp([_plain_error()])
    py = _FakeMcp()

    fea.Investigation.investigate_mail_stores(inv, rust, py, [_entry()])

    call = inv.tool_calls[0]
    assert call["error"] == _SUBPROCESS_FAILED
    assert "skipped" not in call, call
    assert "skip_reason" not in call, call


def test_the_skip_is_per_call_not_per_tool() -> None:
    # Store A has no reader; store B parses. The tool SUCCEEDED once, so the
    # engine's own recovery model already covers it -- but the skipped call must
    # still carry its marker rather than be silently dropped.
    inv = _inv()
    rust = _FakeMcp([_prereq_error(), {"message_count": 0, "messages": []}])
    py = _FakeMcp()

    fea.Investigation.investigate_mail_stores(
        inv, rust, py, [_entry(), _entry("/case/extracted/disk/mail_store/b/other.pst")]
    )

    assert [c.get("skipped") for c in inv.tool_calls] == [True, None]


# ---------------------------------------------------------------------------
# A -- the scorer honours the recorded skip.
# ---------------------------------------------------------------------------

_SKIPPED_PST = {
    "tool_call_id": "tc-2",
    "tool": "pst_parse",
    "error": _BINARY_NOT_FOUND,
    "skipped": True,
    "skip_reason": "missing_prerequisite",
}
_FAILED_PST = {"tool_call_id": "tc-2", "tool": "pst_parse", "error": _SUBPROCESS_FAILED}
_OK_TOOL = {"tool_call_id": "tc-1", "tool": "case_open"}


def test_a_recorded_skip_does_not_make_the_run_incomplete() -> None:
    completed, reasons = accuracy._run_completed({"tool_calls": [_OK_TOOL, _SKIPPED_PST]})
    assert completed is True, reasons
    assert reasons == []


def test_an_unmarked_tool_failure_still_makes_the_run_incomplete() -> None:
    completed, reasons = accuracy._run_completed({"tool_calls": [_OK_TOOL, _FAILED_PST]})
    assert completed is False
    assert any("pst_parse" in r for r in reasons), reasons


# ---------------------------------------------------------------------------
# S -- the two regressed goldens are scoreable again.
# ---------------------------------------------------------------------------


def _write_case(case_dir: Path, case_id: str, verdict: str, tool_calls: list[dict]) -> Path:
    case_dir.mkdir(parents=True, exist_ok=True)
    (case_dir / "verdict.json").write_text(
        json.dumps(
            {
                "case_id": case_id,
                "verdict": verdict,
                "findings": [],
                "tool_calls": tool_calls,
            }
        ),
        encoding="utf-8",
    )
    return case_dir


# The two goldens the PST lane regressed. Both carry a mail store on their
# image, so both hit the absent reader on the GN7000 runner.
_REGRESSED_GOLDENS = ["m57-jean", "nist-data-leakage"]


@pytest.mark.parametrize("case_id", _REGRESSED_GOLDENS)
def test_the_regressed_goldens_score_instead_of_refusing(case_id: str, tmp_path: Path) -> None:
    """The exact regression: a case whose ONLY tool failure is the absent reader.

    The honest bar is "scoreable again", not "passes". Both keys were an honest
    ``FAIL recall=0`` before the mail lane existed and are expected to be one
    after -- this run finds nothing because the fixture text is not modelled here.
    What must not happen is the scorer refusing to grade them at all.
    """
    golden = _GOLDENS / case_id / "expected-findings.json"
    if not golden.is_file():  # pragma: no cover - keys are committed
        pytest.skip(f"{case_id} golden not present")
    case = _write_case(tmp_path / case_id, case_id, "INDETERMINATE", [_OK_TOOL, _SKIPPED_PST])

    result = accuracy.score(case, golden)

    assert result["run_completed"] is True, result["run_incomplete_reasons"]
    assert result["recall_percent"] == 0  # honest FAIL, not a refusal


@pytest.mark.parametrize("case_id", _REGRESSED_GOLDENS)
def test_a_real_reader_failure_still_refuses_to_score(case_id: str, tmp_path: Path) -> None:
    """Boundary at the scorer: only the RECORDED skip is forgiven."""
    golden = _GOLDENS / case_id / "expected-findings.json"
    if not golden.is_file():  # pragma: no cover - keys are committed
        pytest.skip(f"{case_id} golden not present")
    case = _write_case(tmp_path / case_id, case_id, "INDETERMINATE", [_OK_TOOL, _FAILED_PST])

    result = accuracy.score(case, golden)

    assert result["run_completed"] is False
    assert result["run_incomplete_reasons"] == [
        "tool call(s) failed and never succeeded: pst_parse"
    ]
