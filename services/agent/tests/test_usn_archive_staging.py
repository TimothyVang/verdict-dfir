"""Archive staged-then-deleted detection from the USN journal (T1560.001).

usnjrnl_query returns change records ({usn, timestamp_iso, filename,
reason_flags}). An archive (.rar/.zip/.7z/...) that shows both a create
(FILE_CREATE / DATA_EXTEND) and a later FILE_DELETE is a classic
collect-then-clean-up staging pattern: T1560.001 (Archive Collected Data) with
secondary T1070.004 (file deletion). usn_rows_to_findings emits it as INFERRED
(a two-record correlation over one artifact).
"""

from __future__ import annotations

import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402


def _row(usn: int, filename: str, flags: list[str], ts: str = "2026-07-12T01:58:48Z") -> dict:
    return {"usn": usn, "timestamp_iso": ts, "filename": filename, "reason_flags": flags}


def _staged_deleted_rows(name: str = "stage.rar") -> list[dict]:
    return [
        _row(1, name, ["FILE_CREATE", "DATA_EXTEND"]),
        _row(2, name, ["DATA_EXTEND", "CLOSE"]),
        _row(3, name, ["FILE_DELETE", "CLOSE"]),
    ]


def test_archive_create_then_delete_emits_t1560() -> None:
    findings = fea.usn_rows_to_findings(
        _staged_deleted_rows("stage.rar"), "tc-usn", "case", "/ev/$UsnJrnl-J"
    )
    hit = [f for f in findings if f["finding_id"] == "f-B-usn-archive-staged-deleted"]
    assert len(hit) == 1, [f["finding_id"] for f in findings]
    assert hit[0]["mitre_technique"] == "T1560.001"
    assert hit[0]["confidence"] == "INFERRED"
    assert hit[0]["pool_origin"] == "B"


def test_archive_staging_finding_does_not_claim_unobserved_exfiltration() -> None:
    finding = fea.usn_rows_to_findings(
        _staged_deleted_rows("stage.rar"), "tc-usn", "case", "/ev/$UsnJrnl-J"
    )[0]

    assert not fea._claims_exfiltration(finding)

    report = fea.build_report_qa_signoff(
        findings=[finding],
        tool_calls=[{"tool_call_id": "tc-usn", "tool": "usnjrnl_query"}],
        verdict="SUSPICIOUS",
        case_completeness={"checks": []},
        attack_coverage={"blind_spot_count": 0},
        normalized_timeline={"events": []},
        analysis_limitations=[],
    )
    check = next(
        row
        for row in report["checks"]
        if row["check_id"] == "exfiltration_requires_staging_and_movement"
    )
    assert check["status"] == "PASS"


def test_zip_also_matches() -> None:
    findings = fea.usn_rows_to_findings(
        _staged_deleted_rows("loot.zip"), "tc", "case", "/ev/$UsnJrnl-J"
    )
    assert any(f["finding_id"] == "f-B-usn-archive-staged-deleted" for f in findings)


def test_created_but_not_deleted_does_not_fire() -> None:
    rows = [_row(1, "keep.rar", ["FILE_CREATE", "DATA_EXTEND"]), _row(2, "keep.rar", ["CLOSE"])]
    findings = fea.usn_rows_to_findings(rows, "tc", "case", "/ev/$UsnJrnl-J")
    assert not [f for f in findings if f["finding_id"] == "f-B-usn-archive-staged-deleted"]


def test_delete_before_create_does_not_claim_cleanup_sequence() -> None:
    rows = [
        _row(1, "recreated.rar", ["FILE_DELETE"]),
        _row(2, "recreated.rar", ["FILE_CREATE", "DATA_EXTEND"]),
    ]

    findings = fea.usn_rows_to_findings(rows, "tc", "case", "/ev/$UsnJrnl-J")

    assert not [f for f in findings if f["finding_id"] == "f-B-usn-archive-staged-deleted"]


def test_non_archive_delete_does_not_fire() -> None:
    findings = fea.usn_rows_to_findings(
        [_row(1, "notes.txt", ["FILE_CREATE"]), _row(2, "notes.txt", ["FILE_DELETE"])],
        "tc", "case", "/ev/$UsnJrnl-J",
    )
    assert not [f for f in findings if f["finding_id"] == "f-B-usn-archive-staged-deleted"]
