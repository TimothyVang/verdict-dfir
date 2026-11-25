"""Tests for committed verdict_revision self-correction records.

VERDICT runs the downgrade machinery (verifier output-hash drift -> judge,
correlate_findings >=2-fact rule) but historically discarded the resulting
conclusion flip instead of committing it. ``verdict_revision`` records freeze
that organic arc into the hash-chained audit log so a judge can verify it
offline (manifest_verify chain replay) rather than take a demo video's word.

These mirror the import pattern of test_contradiction_resolution_record.py:
the record factories live inline in ``scripts/find_evil_auto.py`` (which runs
under bare python3 and cannot import the 3.11 ``findevil_agent`` package), and
are exercised here under the 3.11 agent venv.
"""

from __future__ import annotations

import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402
import pytest  # noqa: E402


def test_build_verdict_revision_record_ok() -> None:
    r = fea.build_verdict_revision_record(
        finding_id="f-1",
        from_verdict="CONFIRMED",
        to_verdict="INFERRED",
        mechanism="verify_hash_drift",
        trigger_tool_call_id="tc-9",
        reason="output_sha256 drift on re-run",
    )
    assert r["kind"] == "verdict_revision"
    assert r["finding_id"] == "f-1"
    assert r["from_verdict"] == "CONFIRMED"
    assert r["to_verdict"] == "INFERRED"
    assert r["mechanism"] == "verify_hash_drift"
    assert r["trigger_tool_call_id"] == "tc-9"


@pytest.mark.parametrize(
    "override",
    [
        {"mechanism": "decorative"},  # unknown mechanism (never-as-decoration guard)
        {"finding_id": ""},  # empty required id
        {"trigger_tool_call_id": ""},  # empty required trigger (must trace)
        {"from_verdict": "BOGUS"},  # out-of-range verdict
        {"to_verdict": "BOGUS"},
        {"to_verdict": "CONFIRMED"},  # no-op flip (from == to)
    ],
)
def test_build_verdict_revision_record_rejects_bad_input(override: dict) -> None:
    base = dict(
        finding_id="f-1",
        from_verdict="CONFIRMED",
        to_verdict="INFERRED",
        mechanism="verify_hash_drift",
        trigger_tool_call_id="tc-9",
    )
    base.update(override)
    with pytest.raises(ValueError):
        fea.build_verdict_revision_record(**base)


def test_snapshot_finding_confidence() -> None:
    snap = fea.snapshot_finding_confidence(
        [
            {"finding_id": "f-1", "confidence": "CONFIRMED"},
            {"finding_id": "f-2", "confidence": "HYPOTHESIS"},
            {"confidence": "CONFIRMED"},  # no finding_id -> skipped
        ]
    )
    assert snap == {"f-1": "CONFIRMED", "f-2": "HYPOTHESIS"}


def test_diff_emits_one_record_per_real_flip() -> None:
    before = {"f-1": "CONFIRMED", "f-2": "INFERRED", "f-3": "CONFIRMED"}
    after = [
        {"finding_id": "f-1", "confidence": "INFERRED", "tool_call_id": "tc-1"},  # flip
        {"finding_id": "f-2", "confidence": "INFERRED", "tool_call_id": "tc-2"},  # same
        {"finding_id": "f-4", "confidence": "HYPOTHESIS", "tool_call_id": "tc-4"},  # new
    ]
    recs = fea.diff_verdict_revisions(before, after, mechanism="verify_hash_drift", reason="x")
    assert len(recs) == 1
    assert recs[0]["finding_id"] == "f-1"
    assert recs[0]["from_verdict"] == "CONFIRMED"
    assert recs[0]["to_verdict"] == "INFERRED"


def test_diff_skips_flip_without_trigger_tool_call_id() -> None:
    before = {"f-1": "CONFIRMED"}
    after = [{"finding_id": "f-1", "confidence": "INFERRED"}]  # no tool_call_id to trace
    assert fea.diff_verdict_revisions(before, after, mechanism="verify_hash_drift") == []


def test_diff_uses_specific_per_finding_reason_when_provided() -> None:
    # tejcodes/EL legibility pattern: each committed flip carries its own reason.
    before = {"f-1": "CONFIRMED"}
    after = [{"finding_id": "f-1", "confidence": "INFERRED", "tool_call_id": "tc-1"}]
    recs = fea.diff_verdict_revisions(
        before,
        after,
        mechanism="correlation_downgrade",
        reason="generic stage reason",
        reason_by_finding={"f-1": "only 1 artifact class; execution needs >=2"},
    )
    assert recs[0]["reason"] == "only 1 artifact class; execution needs >=2"


def test_diff_falls_back_to_generic_reason_without_per_finding() -> None:
    before = {"f-1": "CONFIRMED"}
    after = [{"finding_id": "f-1", "confidence": "INFERRED", "tool_call_id": "tc-1"}]
    recs = fea.diff_verdict_revisions(
        before, after, mechanism="correlation_downgrade", reason="generic stage reason"
    )
    assert recs[0]["reason"] == "generic stage reason"


class _FakePy:
    """Records every audit_append payload (mirrors the sibling record tests)."""

    def __init__(self) -> None:
        self.audits: list[tuple[str, dict]] = []

    def call_tool(self, name: str, args: dict, timeout: float = 600.0) -> dict:
        if name == "audit_append":
            self.audits.append((args["kind"], args["payload"]))
        return {}


def _inv() -> fea.Investigation:
    return fea.Investigation("/tmp/does-not-exist-evidence", case_id="case-vr")


def test_emit_verdict_revisions_audits_each_flip() -> None:
    inv = _inv()
    py = _FakePy()
    before = {"f-1": "CONFIRMED", "f-2": "INFERRED"}
    after = [
        {"finding_id": "f-1", "confidence": "INFERRED", "tool_call_id": "tc-1"},
        {"finding_id": "f-2", "confidence": "INFERRED", "tool_call_id": "tc-2"},  # same
    ]
    inv._emit_verdict_revisions(py, before, after, mechanism="correlation_downgrade", reason="x")
    assert [k for k, _ in py.audits] == ["verdict_revision"]
    _, payload = py.audits[0]
    assert payload["finding_id"] == "f-1"
    assert payload["mechanism"] == "correlation_downgrade"
    assert payload["trigger_tool_call_id"] == "tc-1"
    assert "kind" not in payload  # kind is passed to _audit separately, not in payload


def test_course_correct_enriches_payload_when_mechanism_given() -> None:
    inv = _inv()
    py = _FakePy()
    inv._course_correct(
        py,
        "verify_finding",
        "f-9 rejected after re-dispatch",
        action="reject_after_redispatch",
        mechanism="tool_failure_resequence",
        finding_refs=["f-9"],
    )
    kinds = [k for k, _ in py.audits]
    assert "course_correction" in kinds
    cc = next(p for k, p in py.audits if k == "course_correction")
    assert cc["mechanism"] == "tool_failure_resequence"
    assert cc["finding_refs"] == ["f-9"]
    assert cc["action"] == "reject_after_redispatch"
