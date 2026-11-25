"""Tests for the counterfactual single-class ablation verdict_revision pass.

A CONFIRMED execution finding that survives on only ONE distinct artifact class
is, by SOUL.md's >=2-fact rule, over-asserted: removing that single class leaves
nothing, so the claim cannot stand at CONFIRMED. The ablation pass recomputes
each CONFIRMED execution finding's distinct class support, and when exactly one
class backs it, organically downgrades CONFIRMED -> INFERRED and commits the flip
as a ``verdict_revision`` (mechanism ``correlation_downgrade``) — turning the
already-correct safe-direction downgrade into offline-verifiable self-correction
evidence instead of leaving it implicit.

Ablation only ever DOWNGRADES and is deterministic: the class count is computed
with the same ``_TOOL_CLASS`` table that ``scripts/check-corroboration.py`` uses,
so re-running that scorer reproduces the same count (judge-reproducible).

These mirror the import pattern of test_verdict_revision.py: the helpers live
inline in ``scripts/find_evil_auto.py`` (which runs under bare python3 and cannot
import the 3.11 ``findevil_agent`` package) and are exercised here under the 3.11
agent venv.
"""

from __future__ import annotations

import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402


def test_finding_classes_counts_distinct_classes_via_tool_call_index() -> None:
    # own tool_call_id (memory) + a derived_from id (filesystem) = 2 classes.
    tc_index = {"tc-1": "vol_pslist", "tc-2": "mft_timeline", "tc-3": "registry_query"}
    finding = {"tool_call_id": "tc-1", "derived_from": ["tc-2"]}
    assert fea.ablation_finding_classes(finding, tc_index) == {"memory", "filesystem"}


def test_finding_classes_single_class_when_derived_share_class() -> None:
    # own tool_call_id + derived_from both map to memory -> 1 distinct class.
    tc_index = {"tc-1": "vol_pslist", "tc-2": "vol_malfind"}
    finding = {"tool_call_id": "tc-1", "derived_from": ["tc-2"]}
    assert fea.ablation_finding_classes(finding, tc_index) == {"memory"}


class _FakePy:
    """Records every audit_append payload (mirrors test_verdict_revision.py)."""

    def __init__(self) -> None:
        self.audits: list[tuple[str, dict]] = []

    def call_tool(self, name: str, args: dict, timeout: float = 600.0) -> dict:
        if name == "audit_append":
            self.audits.append((args["kind"], args["payload"]))
        return {}


def _inv() -> fea.Investigation:
    return fea.Investigation("/tmp/does-not-exist-evidence", case_id="case-abl")


def test_single_class_confirmed_execution_finding_flips_to_inferred() -> None:
    inv = _inv()
    py = _FakePy()
    # A single memory-class tool call backs a CONFIRMED execution claim.
    inv.tool_calls = [{"tool_call_id": "tc-1", "tool": "vol_pslist"}]
    merged = [
        {
            "finding_id": "f-exec",
            "confidence": "CONFIRMED",
            "tool_call_id": "tc-1",
            "mitre_technique": "T1059.001",
            "description": "powershell.exe executed from a memory-only process",
        }
    ]

    out = inv._ablate_single_class_execution(py, merged)

    # The finding's confidence is downgraded in the returned list (safe direction).
    assert out[0]["confidence"] == "INFERRED"
    # Exactly one verdict_revision committed, with the right shape.
    revs = [p for k, p in py.audits if k == "verdict_revision"]
    assert len(revs) == 1
    rev = revs[0]
    assert rev["finding_id"] == "f-exec"
    assert rev["from_verdict"] == "CONFIRMED"
    assert rev["to_verdict"] == "INFERRED"
    assert rev["mechanism"] == "correlation_downgrade"
    assert rev["trigger_tool_call_id"] == "tc-1"
    assert rev["reason"]  # non-empty justification


def test_two_class_confirmed_execution_finding_does_not_flip() -> None:
    inv = _inv()
    py = _FakePy()
    # memory (own) + filesystem (derived_from) = 2 distinct classes -> survives.
    inv.tool_calls = [
        {"tool_call_id": "tc-1", "tool": "vol_pslist"},
        {"tool_call_id": "tc-2", "tool": "mft_timeline"},
    ]
    merged = [
        {
            "finding_id": "f-exec2",
            "confidence": "CONFIRMED",
            "tool_call_id": "tc-1",
            "derived_from": ["tc-2"],
            "mitre_technique": "T1059.001",
            "description": "powershell.exe executed; corroborated by MFT timeline",
        }
    ]

    out = inv._ablate_single_class_execution(py, merged)

    assert out[0]["confidence"] == "CONFIRMED"
    assert [k for k, _ in py.audits] == []  # nothing committed


def test_non_execution_single_class_finding_does_not_flip() -> None:
    inv = _inv()
    py = _FakePy()
    inv.tool_calls = [{"tool_call_id": "tc-1", "tool": "registry_query"}]
    merged = [
        {
            "finding_id": "f-persist",
            "confidence": "CONFIRMED",
            "tool_call_id": "tc-1",
            "mitre_technique": "T1112",
            "description": "Run key persistence value present in the registry",
        }
    ]

    out = inv._ablate_single_class_execution(py, merged)

    assert out[0]["confidence"] == "CONFIRMED"
    assert [k for k, _ in py.audits] == []


def test_already_inferred_single_class_execution_finding_does_not_flip() -> None:
    inv = _inv()
    py = _FakePy()
    inv.tool_calls = [{"tool_call_id": "tc-1", "tool": "vol_pslist"}]
    merged = [
        {
            "finding_id": "f-low",
            "confidence": "INFERRED",  # not CONFIRMED at entry -> no-op
            "tool_call_id": "tc-1",
            "mitre_technique": "T1059.001",
            "description": "powershell.exe likely executed",
        }
    ]

    out = inv._ablate_single_class_execution(py, merged)

    assert out[0]["confidence"] == "INFERRED"
    assert [k for k, _ in py.audits] == []
