"""Tests for supervisor reasoning narrative in the audit chain (judging-audit C1).

The committed chains carried essentially one agent_message per run, so the
5-star anchor ("visibly reasons — full arc in the logs") could not be graded
from artifacts. The supervisor now narrates its decision points — lane-plan
rationale, the psxview divergence pivot, and the verdict reasoning — as
kind=agent_message records in the same hash chain as the tool executions.
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


def test_lane_plan_names_present_lanes_with_rationale() -> None:
    msg = fea.build_lane_plan_message(
        memory=1, evtx=12, hayabusa_dirs=1, extracted=0, network=1, velociraptor=0, raw_disk=1
    )
    assert "memory" in msg and "1" in msg
    assert "evtx" in msg.lower() and "12" in msg
    assert "raw disk" in msg.lower()
    # Rationale, not just counts: the volatile-first ordering is stated.
    assert "volatile" in msg.lower()
    # Absent lanes are not advertised as part of the plan.
    assert "velociraptor" not in msg.lower()


def test_lane_plan_empty_when_nothing_supported() -> None:
    assert (
        fea.build_lane_plan_message(
            memory=0, evtx=0, hayabusa_dirs=0, extracted=0, network=0, velociraptor=0, raw_disk=0
        )
        == ""
    )


def test_verdict_reasoning_states_word_and_confidence_mix() -> None:
    merged = [
        {"confidence": "CONFIRMED"},
        {"confidence": "CONFIRMED"},
        {"confidence": "HYPOTHESIS"},
    ]
    msg = fea.build_verdict_reasoning_message(
        "SUSPICIOUS", merged, heartbeat_escalated=False, limitations=1
    )
    assert "SUSPICIOUS" in msg
    assert "2 CONFIRMED" in msg
    assert "1 HYPOTHESIS" in msg


def test_verdict_reasoning_names_heartbeat_partial() -> None:
    msg = fea.build_verdict_reasoning_message(
        "INDETERMINATE", [], heartbeat_escalated=True, limitations=3
    )
    assert "INDETERMINATE" in msg
    assert "partial" in msg.lower()
    assert "3" in msg


def test_narrate_audits_a_supervisor_agent_message() -> None:
    inv = fea.Investigation("/tmp/does-not-exist-evidence", case_id="case-narrate")
    py = _FakePy()
    inv._narrate(py, "evidence is a disk image; planning extraction before registry triage")
    kind, payload = py.audits[0]
    assert kind == "agent_message"
    assert payload["role"] == "supervisor"
    assert "planning extraction" in payload["content"]
