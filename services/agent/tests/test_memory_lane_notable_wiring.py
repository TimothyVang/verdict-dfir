"""Wiring tests: ``investigate_memory`` emits the notable-application and
console-activity presence findings and drives ``vol_run`` correctly.

Runs the REAL lane method on a stub Investigation with fake MCP clients whose
canned outputs are shaped exactly like the Rust tools' serialization
(``VolPslistOutput`` / ``VolPsscanOutput`` / ``VolRunOutput``). This is a
controlled harness — it proves the wiring (tool sequencing, tool_call_id
citation, pool-B routing, failure resilience), not behavior on a real memory
image.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402

CASE = "case-mem-wiring"
EVIDENCE = "/evidence/memdump.raw"


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


_PROCS = [
    _proc(4, "System"),
    _proc(500, "svchost.exe"),
    _proc(1984, "cmd.exe"),
    _proc(2424, "mspaint.exe"),
    _proc(3128, "KeePass.exe"),
    _proc(4204, "chrome.exe"),
]


def _pslist_out() -> dict:
    return {"processes": list(_PROCS), "processes_seen": len(_PROCS), "stderr_tail": ""}


def _malfind_out() -> dict:
    return {"injections": [], "injections_seen": 0, "stderr_tail": ""}


def _cmdline_out() -> dict:
    return {
        "plugin": "windows.cmdline",
        "rows": [
            {"PID": 1984, "Process": "cmd.exe", "Args": "C:\\Windows\\system32\\cmd.exe"},
            {"PID": 500, "Process": "svchost.exe", "Args": "svchost.exe -k netsvcs"},
        ],
        "rows_seen": 2,
        "stderr_tail": "",
    }


def _consoles_out() -> dict:
    return {
        "plugin": "windows.consoles",
        "rows": [{"PID": 1984, "Process": "conhost.exe"}],
        "rows_seen": 1,
        "stderr_tail": "",
    }


class FakeClient:
    """Canned-output MCP client; records every call it receives."""

    def __init__(self, outputs: dict) -> None:
        self.outputs = outputs
        self.calls: list[tuple[str, dict]] = []

    def call_tool(self, tool: str, args: dict, timeout: float | None = None) -> dict:
        self.calls.append((tool, args))
        if tool == "vol_run":
            return self.outputs.get(
                ("vol_run", args.get("plugin")),
                {
                    "plugin": args.get("plugin"),
                    "rows": [],
                    "rows_seen": 0,
                    "stderr_tail": "",
                },
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
    inv.audit_path = "/tmp/audit-mem-wiring.jsonl"
    inv._consecutive_failures = 0
    inv._heartbeat_threshold = 99
    inv._heartbeat_escalated = False
    inv._heartbeat = lambda **_kw: None
    return inv


def _rust_outputs() -> dict:
    return {
        "vol_pslist": _pslist_out(),
        "vol_malfind": _malfind_out(),
        "vol_psscan": _pslist_out(),
        ("vol_run", "windows.cmdline"): _cmdline_out(),
        ("vol_run", "windows.consoles"): _consoles_out(),
    }


def _run_lane(rust_outputs: dict, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(fea, "MEMORY_YARA_RULES", None)
    inv = _stub_investigation()
    rust = FakeClient(rust_outputs)
    py = FakeClient({})
    fea.Investigation.investigate_memory(inv, rust, py)
    return inv, rust


def test_memory_lane_emits_notable_and_console_findings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inv, rust = _run_lane(_rust_outputs(), monkeypatch)
    bases = {f["finding_id"] for f in inv.findings_pool_b}
    assert {
        "f-B-notable-browser",
        "f-B-notable-credstore",
        "f-B-notable-userapps",
        "f-B-console-cmdline",
    } <= bases

    # vol_run drove the allow-listed console plugins in order: cmdline, then
    # consoles, then cmdscan — the canned consoles rows carry no CommandHistory
    # entry, so the second command-history attempt is genuinely warranted.
    plugins = [args["plugin"] for tool, args in rust.calls if tool == "vol_run"]
    assert plugins == ["windows.cmdline", "windows.consoles", "windows.cmdscan"]

    # tc-001 pslist, tc-002 malfind, tc-003 psscan, tc-004 cmdline,
    # tc-005 consoles, tc-006 cmdscan
    by_base = {f["finding_id"]: f for f in inv.findings_pool_b}
    assert by_base["f-B-notable-browser"]["derived_from"] == ["tc-001", "tc-003"]
    # console finding: cmdline + consoles + pslist corroboration (cmd.exe is in
    # the pslist view too).
    assert by_base["f-B-console-cmdline"]["derived_from"] == ["tc-004", "tc-005", "tc-001"]

    # The vol_run calls are recorded in the audited tool_calls list.
    vol_run_records = [tc for tc in inv.tool_calls if tc["tool"] == "vol_run"]
    assert [tc["tool_call_id"] for tc in vol_run_records] == ["tc-004", "tc-005", "tc-006"]


def test_memory_lane_skips_consoles_when_no_console_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outputs = _rust_outputs()
    outputs[("vol_run", "windows.cmdline")] = {
        "plugin": "windows.cmdline",
        "rows": [{"PID": 500, "Process": "svchost.exe", "Args": "svchost.exe -k netsvcs"}],
        "rows_seen": 1,
        "stderr_tail": "",
    }
    inv, rust = _run_lane(outputs, monkeypatch)
    plugins = [args["plugin"] for tool, args in rust.calls if tool == "vol_run"]
    assert plugins == ["windows.cmdline"]
    assert "f-B-console-cmdline" not in {f["finding_id"] for f in inv.findings_pool_b}
    # The notable-application findings are unaffected.
    assert "f-B-notable-credstore" in {f["finding_id"] for f in inv.findings_pool_b}


def test_memory_lane_survives_cmdline_failure_without_console_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outputs = _rust_outputs()
    outputs[("vol_run", "windows.cmdline")] = {"_error": {"message": "vol timed out"}}
    inv, rust = _run_lane(outputs, monkeypatch)
    bases = {f["finding_id"] for f in inv.findings_pool_b}
    assert "f-B-console-cmdline" not in bases
    # Notable applications still emitted from the process views.
    assert {"f-B-notable-browser", "f-B-notable-credstore", "f-B-notable-userapps"} <= bases
    assert any("windows.cmdline" in lim for lim in inv.analysis_limitations)
    # consoles is never attempted after a cmdline failure (no readable rows).
    plugins = [args["plugin"] for tool, args in rust.calls if tool == "vol_run"]
    assert plugins == ["windows.cmdline"]


def test_memory_lane_emits_no_notable_findings_on_service_only_image(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # FP floor at the lane level: a Windows image with only core/service
    # processes produces no application-presence findings and no vol_run
    # console finding.
    service_procs = [_proc(4, "System"), _proc(500, "svchost.exe"), _proc(600, "lsass.exe")]
    outputs = _rust_outputs()
    outputs["vol_pslist"] = {
        "processes": service_procs,
        "processes_seen": len(service_procs),
        "stderr_tail": "",
    }
    outputs["vol_psscan"] = outputs["vol_pslist"]
    outputs[("vol_run", "windows.cmdline")] = {
        "plugin": "windows.cmdline",
        "rows": [],
        "rows_seen": 0,
        "stderr_tail": "",
    }
    inv, _rust = _run_lane(outputs, monkeypatch)
    bases = {f["finding_id"] for f in inv.findings_pool_b}
    assert not {b for b in bases if b.startswith("f-B-notable-") or b == "f-B-console-cmdline"}
