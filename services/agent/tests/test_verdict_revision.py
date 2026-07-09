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
import render_report as rr  # noqa: E402


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


# ---------------------------------------------------------------------------
# Rendered Self-Correction narrative block (render_report.py).
#
# The committed verdict_revision records live in audit.jsonl; the report reads
# them back read-only (custody is untouched) and renders the organic arc as a
# prose Self-Correction section: INITIAL claim -> EVIDENCE (trigger
# tool_call_id) -> CORRECTION (mechanism) -> FINAL verdict.
# ---------------------------------------------------------------------------


def _audit_revision(payload: dict, *, seq: int) -> dict:
    """Wrap a verdict_revision payload as it appears in audit.jsonl."""
    return {"kind": "verdict_revision", "payload": payload, "seq": seq, "prev_hash": ""}


def _payload(**override) -> dict:
    base = fea.build_verdict_revision_record(
        finding_id="f-1",
        from_verdict="CONFIRMED",
        to_verdict="INFERRED",
        mechanism="verify_hash_drift",
        trigger_tool_call_id="tc-9",
        reason="output_sha256 drift on re-run",
    )
    # audit.jsonl payloads carry no top-level "kind" (it is the record key).
    base.pop("kind", None)
    base.update(override)
    return base


def test_verdict_revisions_from_audit_extracts_payloads() -> None:
    audit = [
        {"kind": "agent_message", "payload": {"content": "x"}, "seq": 0},
        _audit_revision(_payload(finding_id="f-1", trigger_tool_call_id="tc-1"), seq=1),
        _audit_revision(
            _payload(
                finding_id="f-2",
                from_verdict="CONFIRMED",
                to_verdict="HYPOTHESIS",
                trigger_tool_call_id="tc-2",
                mechanism="correlation_downgrade",
            ),
            seq=2,
        ),
    ]
    revs = rr.verdict_revisions_from_audit(audit)
    assert [r["finding_id"] for r in revs] == ["f-1", "f-2"]
    assert revs[0]["trigger_tool_call_id"] == "tc-1"
    assert revs[1]["to_verdict"] == "HYPOTHESIS"


def test_verdict_revisions_from_audit_ignores_other_kinds_and_bad_rows() -> None:
    audit = [
        {"kind": "course_correction", "payload": {"finding_id": "f-9"}},
        {"kind": "verdict_revision"},  # no payload dict
        {"kind": "verdict_revision", "payload": "not-a-dict"},
    ]
    assert rr.verdict_revisions_from_audit(audit) == []


def test_self_correction_enabled_defaults_on(monkeypatch) -> None:
    monkeypatch.delenv("FINDEVIL_REPORT_SELF_CORRECTION", raising=False)
    assert rr.self_correction_enabled() is True


@pytest.mark.parametrize("value", ["0", "false", "no", "off", "FALSE", " Off "])
def test_self_correction_disabled_by_env(monkeypatch, value: str) -> None:
    monkeypatch.setenv("FINDEVIL_REPORT_SELF_CORRECTION", value)
    assert rr.self_correction_enabled() is False


def test_render_self_correction_section_from_two_audit_records() -> None:
    audit = [
        _audit_revision(
            _payload(
                finding_id="f-aaa",
                from_verdict="CONFIRMED",
                to_verdict="INFERRED",
                trigger_tool_call_id="tc-111",
                mechanism="verify_hash_drift",
            ),
            seq=1,
        ),
        _audit_revision(
            _payload(
                finding_id="f-bbb",
                from_verdict="INFERRED",
                to_verdict="HYPOTHESIS",
                trigger_tool_call_id="tc-222",
                mechanism="correlation_downgrade",
            ),
            seq=2,
        ),
    ]
    section = rr.render_self_correction_section(rr.verdict_revisions_from_audit(audit))
    assert "## Self-Correction" in section
    # both finding_ids present
    assert "f-aaa" in section
    assert "f-bbb" in section
    # both from->to transitions present
    assert "`CONFIRMED` -> `INFERRED`" in section
    assert "`INFERRED` -> `HYPOTHESIS`" in section
    # both trigger tool_call_ids cited as the EVIDENCE step
    assert "tc-111" in section
    assert "tc-222" in section


def test_render_self_correction_section_empty_when_no_records() -> None:
    assert rr.render_self_correction_section([]) == ""
    assert rr.render_self_correction_section(rr.verdict_revisions_from_audit([])) == ""
