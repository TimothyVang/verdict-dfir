"""Tests for contradiction_resolved audit records (judging-audit gap, C1).

detect_contradictions returns ``contradiction_id`` per record, but the engine
read ``contra.get("id")`` — so every committed contradiction_resolved record
carried id='unknown' and none of the conflicting context, making the records
decorative. The record must use the tool's field and carry the conflicting
claims + tool_call_ids so a judge can see WHAT was contradicted and how it
was settled.
"""

from __future__ import annotations

import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402

_CONTRA = {
    "contradiction_id": "c-001",
    "pool_a_claim": "svchost.exe is benign (pslist baseline match)",
    "pool_b_claim": "svchost.exe beacons to 10.0.0.5 (netscan)",
    "conflicting_tool_call_ids": ["tc-007", "tc-031"],
    "resolution_required": False,
}


class _FakePy:
    """Records every audit_append payload."""

    def __init__(self) -> None:
        self.audits: list[tuple[str, dict]] = []

    def call_tool(self, name: str, args: dict, timeout: float = 600.0) -> dict:
        if name == "audit_append":
            self.audits.append((args["kind"], args["payload"]))
        return {}


def _inv() -> fea.Investigation:
    return fea.Investigation("/tmp/does-not-exist-evidence", case_id="case-contra")


def test_record_uses_the_tools_contradiction_id_field() -> None:
    inv = _inv()
    py = _FakePy()
    inv._audit_contradiction_resolutions(py, [_CONTRA])
    kind, payload = py.audits[0]
    assert kind == "contradiction_resolved"
    assert payload["contradiction_id"] == "c-001"


def test_record_carries_claims_and_conflicting_tool_call_ids() -> None:
    inv = _inv()
    py = _FakePy()
    inv._audit_contradiction_resolutions(py, [_CONTRA])
    _, payload = py.audits[0]
    assert payload["pool_a_claim"] == _CONTRA["pool_a_claim"]
    assert payload["pool_b_claim"] == _CONTRA["pool_b_claim"]
    assert payload["conflicting_tool_call_ids"] == ["tc-007", "tc-031"]


def test_unknown_id_only_when_the_field_is_genuinely_missing() -> None:
    inv = _inv()
    py = _FakePy()
    inv._audit_contradiction_resolutions(py, [{"pool_a_claim": "a", "pool_b_claim": "b"}])
    _, payload = py.audits[0]
    assert payload["contradiction_id"] == "unknown"
