"""Wiring tests for the ``windows.cmdscan`` console-history leg of the memory lane.

``windows.consoles`` reads the conhost screen buffer; ``windows.cmdscan``
brute-force scans for ``CommandHistory`` structures and can recover typed
commands the screen-buffer walk missed. Both are already on the ``vol_run``
allow-list. The lane runs cmdscan as a SECOND attempt when consoles recovered
no command-history row.

One deliberate skip is pinned here. Both plugins reach the same
``consoles.Consoles.create_conhost_symbol_table`` code path, so when consoles
fails with volatility3's unsupported-Windows-version error, cmdscan fails
identically — measured on the lab host against the MemLabs Lab 1 Win7 x64
image (volatility3 2.28.0)::

    NotImplementedError: This version of Windows is not supported: 6.1 15.7601!

Re-running the same doomed symbol-table lookup buys no evidence, so the lane
skips it and records ONE honest limitation instead of two.

Runs the REAL lane method against canned outputs shaped exactly like the Rust
``VolRunOutput`` serialization. This is a controlled harness: it proves the
sequencing and resilience, not behavior on a real image.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402

CASE = "case-mem-cmdscan"
EVIDENCE = "/evidence/memdump.raw"

UNSUPPORTED_VERSION_ERROR = (
    "rust-mcp tools/call: vol_run: volatility exited 1: Volatility 3 Framework 2.28.0\n"
    "NotImplementedError: This version of Windows is not supported: 6.1 15.7601!"
)


def _proc(pid: int, name: str) -> dict:
    return {
        "pid": pid,
        "ppid": 4,
        "image_name": name,
        "create_time_iso": "2019-12-14T10:00:00+00:00",
        "exit_time_iso": None,
        "threads": 4,
        "handles": 100,
        "session_id": 1,
    }


_PROCS = [_proc(4, "System"), _proc(1984, "cmd.exe"), _proc(2692, "conhost.exe")]


def _history_row(index: int, command: str) -> dict:
    return {
        "PID": 2692,
        "Process": "conhost.exe",
        "ConsoleInfo": "0x1e0a70",
        "Property": f"_CONSOLE_INFORMATION.HistoryList.CommandHistory_0_Command_{index}",
        "Address": "0x1e1f80",
        "Data": command,
    }


def _vol_run_out(plugin: str, rows: list[dict]) -> dict:
    return {"plugin": plugin, "rows": rows, "rows_seen": len(rows), "stderr_tail": ""}


class FakeClient:
    def __init__(self, outputs: dict) -> None:
        self.outputs = outputs
        self.calls: list[tuple[str, dict]] = []

    def call_tool(self, tool: str, args: dict, timeout: float | None = None) -> dict:
        self.calls.append((tool, args))
        if tool == "vol_run":
            return self.outputs.get(
                ("vol_run", args.get("plugin")), _vol_run_out(args["plugin"], [])
            )
        return self.outputs.get(tool, {})


def _stub_investigation() -> fea.Investigation:
    inv = object.__new__(fea.Investigation)
    inv.handle = {"id": CASE, "image_hash": "deadbeef", "image_size_bytes": 1}
    inv.evidence = EVIDENCE
    inv.evidence_inventory = None
    inv.tcid_counter = 0
    inv.tool_calls = []
    inv.findings_pool_a = []
    inv.findings_pool_b = []
    inv.timeline_events = []
    inv.analysis_limitations = []
    inv.local_artifacts = {}
    inv.audit_path = "/tmp/audit-mem-cmdscan.jsonl"
    inv._consecutive_failures = 0
    inv._heartbeat_threshold = 99
    inv._heartbeat_escalated = False
    inv._heartbeat = lambda **_kw: None
    return inv


def _base_outputs() -> dict:
    procs = {"processes": list(_PROCS), "processes_seen": len(_PROCS), "stderr_tail": ""}
    return {
        "vol_pslist": procs,
        "vol_psscan": procs,
        "vol_malfind": {"injections": [], "injections_seen": 0, "stderr_tail": ""},
        ("vol_run", "windows.cmdline"): _vol_run_out(
            "windows.cmdline",
            [{"PID": 1984, "Process": "cmd.exe", "Args": '"C:\\Windows\\system32\\cmd.exe" '}],
        ),
    }


def _run_lane(outputs: dict, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(fea, "MEMORY_YARA_RULES", None)
    inv = _stub_investigation()
    rust = FakeClient(outputs)
    fea.Investigation.investigate_memory(inv, rust, FakeClient({}))
    return inv, rust


def _plugins(rust: FakeClient) -> list[str]:
    return [args["plugin"] for tool, args in rust.calls if tool == "vol_run"]


def test_cmdscan_runs_when_consoles_recovered_no_history(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outputs = _base_outputs()
    outputs[("vol_run", "windows.consoles")] = _vol_run_out("windows.consoles", [])
    _inv, rust = _run_lane(outputs, monkeypatch)
    assert _plugins(rust) == ["windows.cmdline", "windows.consoles", "windows.cmdscan"]


def test_cmdscan_is_skipped_when_consoles_hit_unsupported_windows_version(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outputs = _base_outputs()
    outputs[("vol_run", "windows.consoles")] = {"_error": {"message": UNSUPPORTED_VERSION_ERROR}}
    inv, rust = _run_lane(outputs, monkeypatch)
    assert _plugins(rust) == ["windows.cmdline", "windows.consoles"]
    assert any(
        "cmdscan" in lim and "not supported" in lim.lower() for lim in inv.analysis_limitations
    ), inv.analysis_limitations


def test_cmdscan_history_rows_emit_a_recovered_command_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outputs = _base_outputs()
    outputs[("vol_run", "windows.consoles")] = _vol_run_out("windows.consoles", [])
    outputs[("vol_run", "windows.cmdscan")] = _vol_run_out(
        "windows.cmdscan", [_history_row(0, "net user hacker P@ssw0rd /add")]
    )
    inv, rust = _run_lane(outputs, monkeypatch)
    by_base = {f["finding_id"]: f for f in inv.findings_pool_b}
    assert "f-B-recovered-command" in by_base, sorted(by_base)
    f = by_base["f-B-recovered-command"]
    assert f["mitre_technique"] == "T1059.003"
    # The finding cites the cmdscan tool call that actually produced the rows.
    cmdscan_tcid = [
        tc["tool_call_id"]
        for tc in inv.tool_calls
        if tc["tool"] == "vol_run" and tc.get("subtool") == "windows.cmdscan"
    ]
    assert cmdscan_tcid and f["tool_call_id"] == cmdscan_tcid[0]


def test_cmdscan_failure_is_recorded_and_lane_continues(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outputs = _base_outputs()
    outputs[("vol_run", "windows.consoles")] = _vol_run_out("windows.consoles", [])
    outputs[("vol_run", "windows.cmdscan")] = {"_error": {"message": "vol timed out"}}
    inv, rust = _run_lane(outputs, monkeypatch)
    assert _plugins(rust) == ["windows.cmdline", "windows.consoles", "windows.cmdscan"]
    assert any("windows.cmdscan" in lim for lim in inv.analysis_limitations)
    # The presence finding from the earlier detector is unaffected.
    assert "f-B-console-cmdline" in {f["finding_id"] for f in inv.findings_pool_b}
    assert "f-B-recovered-command" not in {f["finding_id"] for f in inv.findings_pool_b}


def test_lane_recovered_command_finding_can_never_escalate_the_verdict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """FP floor for the whole lane. The only corroboration available inside the
    memory lane is other memory-class tool calls, so ``detect_command_execution``
    is called with ``corroborating_classes=("memory",)`` and its output is
    always a HYPOTHESIS lead. ``compute_verdict`` therefore cannot escalate on
    it — not even for an unambiguously hostile recovered command. Escalating a
    memory-only execution claim would need a second artifact class, which is
    exactly SOUL.md's rule."""
    outputs = _base_outputs()
    outputs[("vol_run", "windows.consoles")] = _vol_run_out("windows.consoles", [])
    outputs[("vol_run", "windows.cmdscan")] = _vol_run_out(
        "windows.cmdscan", [_history_row(0, "vssadmin delete shadows /all /quiet")]
    )
    inv, _rust = _run_lane(outputs, monkeypatch)
    recovered = {f["finding_id"]: f for f in inv.findings_pool_b}["f-B-recovered-command"]
    assert recovered["confidence"] == "HYPOTHESIS"
    assert "shadow-copy destruction" in recovered["description"]
    assert fea.Investigation.compute_verdict(inv, inv.findings_pool_b) == "INDETERMINATE"


def test_bare_shell_image_emits_no_recovered_command_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The memlabs shape: console hosts present, both history plugins empty.
    outputs = _base_outputs()
    outputs[("vol_run", "windows.consoles")] = _vol_run_out("windows.consoles", [])
    outputs[("vol_run", "windows.cmdscan")] = _vol_run_out("windows.cmdscan", [])
    inv, _rust = _run_lane(outputs, monkeypatch)
    assert "f-B-recovered-command" not in {f["finding_id"] for f in inv.findings_pool_b}
