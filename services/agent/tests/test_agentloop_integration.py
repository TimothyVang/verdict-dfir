"""Increment 6b (core): the AgentToolBridge — agent claims -> find_evil_auto custody.

The bridge is the seam find_evil_auto.py binds into agent mode. It dispatches product
tool calls through a single ``call_and_record(name, args) -> (tcid, output, error)``
callable (the host wires that to its rust/py MCP clients + _record_tool, so the audit
chain and tool_call_index are the SAME ones the deterministic engine builds), surfaces
each ``tcid`` to the model, and turns record_finding calls into gated finding DICTS in
the exact pool schema reason() consumes. The default-on gate still bites here.
"""

from __future__ import annotations

import pytest

from findevil_agent.agentloop.integration import AgentToolBridge, finding_to_pool_dict
from findevil_agent.events import AssertedValue, Finding

_CASE = "33333333-3333-3333-3333-333333333333"


@pytest.fixture(autouse=True)
def _gate_on(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FIND_EVIL_REQUIRE_ASSERTED_VALUES", "1")


def _fake_call_and_record(
    tcid: str = "tc-001", output: dict | None = None, error: str | None = None
):
    seen: list[tuple[str, dict]] = []

    def call_and_record(name: str, args: dict):
        seen.append((name, args))
        if error is not None:
            return (None, None, error)
        return (tcid, output if output is not None else {"rows": [{"Image": "evil.exe"}]}, None)

    return seen, call_and_record


def test_product_call_records_and_surfaces_tcid() -> None:
    seen, car = _fake_call_and_record(tcid="tc-007")
    bridge = AgentToolBridge(case_id=_CASE, pool_origin="A", call_and_record=car)
    out = bridge.dispatch("evtx_query", {"path": "/e/x.evtx"})
    assert seen == [("evtx_query", {"path": "/e/x.evtx"})]
    assert "tc-007" in out
    assert "evil.exe" in out  # raw output surfaced for asserted-value paths


def test_unadvertised_tool_is_rejected_before_dispatch() -> None:
    seen, car = _fake_call_and_record()
    rejected: list[tuple[str, dict, str]] = []
    bridge = AgentToolBridge(
        case_id=_CASE,
        pool_origin="A",
        call_and_record=car,
        allowed_tool_names={"evtx_query"},
        record_rejection=lambda name, args, reason: rejected.append((name, args, reason)),
    )

    out = bridge.dispatch("disk_unmount", {"case_id": _CASE})

    assert "not available" in out.lower()
    assert seen == []
    assert rejected == [
        (
            "disk_unmount",
            {"case_id": _CASE},
            "tool 'disk_unmount' is not available in this investigation lane",
        )
    ]


def test_record_finding_emits_pool_dict() -> None:
    _seen, car = _fake_call_and_record(tcid="tc-007")
    bridge = AgentToolBridge(case_id=_CASE, pool_origin="A", call_and_record=car)
    bridge.dispatch("evtx_query", {"path": "/e/x.evtx"})
    ack = bridge.dispatch(
        "record_finding",
        {
            "tool_call_id": "tc-007",
            "confidence": "CONFIRMED",
            "artifact_path": "/e/x.evtx",
            "description": "evil.exe process creation",
            "mitre_technique": "T1059",
            "asserted_values": [
                {"path": "rows[*].Image", "expected": "evil.exe", "match": "contains"}
            ],
        },
    )
    assert "recorded" in ack.lower()
    assert len(bridge.findings) == 1
    d = bridge.findings[0]
    assert d["case_id"] == _CASE
    assert d["tool_call_id"] == "tc-007"
    assert d["pool_origin"] == "A"
    assert d["confidence"] == "CONFIRMED"
    assert d["asserted_values"] == [
        {"path": "rows[*].Image", "expected": "evil.exe", "match": "contains"}
    ]
    assert isinstance(d["finding_id"], str) and d["finding_id"]


def test_confirmed_without_asserted_values_rejected_by_gate() -> None:
    _seen, car = _fake_call_and_record(tcid="tc-007")
    bridge = AgentToolBridge(case_id=_CASE, pool_origin="B", call_and_record=car)
    bridge.dispatch("evtx_query", {"path": "/e/x.evtx"})
    ack = bridge.dispatch(
        "record_finding",
        {
            "tool_call_id": "tc-007",
            "confidence": "CONFIRMED",
            "artifact_path": "/e/x.evtx",
            "description": "no value declared",
        },
    )
    assert "error" in ack.lower() and "asserted_values" in ack
    assert bridge.findings == []


def test_record_finding_unseen_tcid_rejected() -> None:
    _seen, car = _fake_call_and_record(tcid="tc-007")
    bridge = AgentToolBridge(case_id=_CASE, pool_origin="A", call_and_record=car)
    ack = bridge.dispatch(
        "record_finding",
        {
            "tool_call_id": "tc-999",
            "confidence": "HYPOTHESIS",
            "artifact_path": "/e",
            "description": "lead",
        },
    )
    assert "error" in ack.lower()
    assert bridge.findings == []


def test_tool_error_surfaced_no_tcid() -> None:
    _seen, car = _fake_call_and_record(error="case not open")
    bridge = AgentToolBridge(case_id=_CASE, pool_origin="A", call_and_record=car)
    out = bridge.dispatch("evtx_query", {"path": "/e"})
    assert "error" in out.lower()
    # nothing citable was recorded
    ack = bridge.dispatch(
        "record_finding",
        {
            "tool_call_id": "tc-001",
            "confidence": "HYPOTHESIS",
            "artifact_path": "/e",
            "description": "x",
        },
    )
    assert "error" in ack.lower()


def test_finding_to_pool_dict_pure() -> None:
    f = Finding(
        case_id=_CASE,
        finding_id="f-1",
        tool_call_id="tc-1",
        artifact_path="/e",
        confidence="INFERRED",
        description="dkom",
        pool_origin="A",
        derived_from=["tc-1", "tc-2"],
        asserted_values=[AssertedValue(path="a", expected="b", match="exact")],
    )
    d = finding_to_pool_dict(f)
    assert d["finding_id"] == "f-1"
    assert d["derived_from"] == ["tc-1", "tc-2"]
    assert d["asserted_values"] == [{"path": "a", "expected": "b", "match": "exact"}]
    assert "mitre_technique" not in d  # None fields omitted
