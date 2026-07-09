import json
from pathlib import Path

from findevil_agent.attackflow.model import load_case
from findevil_agent.attackflow.summary import group_by_technique, summary_html

FIX = Path(__file__).resolve().parent / "fixtures" / "attackflow" / "memory-case"


def test_group_by_technique_memory_case_two_groups():
    model = load_case(FIX)
    groups = group_by_technique(model)

    assert len(groups) == 2
    techniques = [g["technique"] for g in groups]
    assert set(techniques) == {"T1543.003", "T1070.001"}
    for g in groups:
        assert g["count"] == 1
        assert g["best_confidence"] == "CONFIRMED"

    # Deterministic order: tier rank, then count desc, then technique asc.
    # Both groups tie on tier and count, so it falls back to technique asc.
    assert techniques == sorted(techniques)


def test_group_by_technique_collapses_duplicate_techniques(tmp_path):
    verdict = {
        "case_id": "case-fixture-dup",
        "attack_story": {"headline": "Recon sweep", "attack_chain": "discovery"},
        "attack_coverage": {"observed_techniques": ["T1083"]},
        "indicators": {"hosts": ["HOST-B"], "accounts": [], "processes": [], "ip_addresses": []},
        "entity_index": {"hosts": [{"value": "HOST-B"}]},
        "normalized_timeline": {"events": []},
        "findings": [
            {
                "finding_id": "f-10",
                "mitre_technique": "T1083",
                "named_technique": "File and directory discovery (T1083)",
                "description": "Recursive listing of user profile",
                "host": "HOST-B",
                "ts": "2020-02-01T00:00:00Z",
                "confidence": "HYPOTHESIS",
                "tool_call_id": "tc-010",
                "artifact_path": "mft.csv",
            },
            {
                "finding_id": "f-11",
                "mitre_technique": "T1083",
                "named_technique": "File and directory discovery (T1083)",
                "description": "Directory enumeration via cmd.exe",
                "host": "HOST-B",
                "ts": "2020-02-01T00:05:00Z",
                "confidence": "CONFIRMED",
                "tool_call_id": "tc-011",
                "artifact_path": "prefetch.pf",
            },
            {
                "finding_id": "f-12",
                "mitre_technique": "T1083",
                "named_technique": "File and directory discovery (T1083)",
                "description": "Additional listing of temp dir",
                "host": "HOST-B",
                "ts": "2020-02-01T00:10:00Z",
                "confidence": "INFERRED",
                "tool_call_id": "tc-012",
                "artifact_path": "usnjrnl.csv",
            },
        ],
    }
    case = tmp_path / "case"
    case.mkdir()
    (case / "verdict.json").write_text(json.dumps(verdict), encoding="utf-8")

    model = load_case(case)
    groups = group_by_technique(model)

    assert len(groups) == 1
    assert groups[0]["technique"] == "T1083"
    assert groups[0]["count"] == 3
    assert groups[0]["best_confidence"] == "CONFIRMED"


def test_summary_html_has_card_per_group_and_synthesis():
    model = load_case(FIX)
    html = summary_html(model)

    assert "T1543.003" in html
    assert "T1070.001" in html
    assert "1x finding" in html
    assert "<details" in html
    assert "confirmed" in html.lower()
    assert "presentation only" in html.lower()


def test_summary_html_escapes_adversarial_description(tmp_path):
    verdict = {
        "case_id": "case-fixture-esc",
        "attack_story": {"headline": "Escape check", "attack_chain": ""},
        "attack_coverage": {"observed_techniques": []},
        "indicators": {"hosts": [], "accounts": [], "processes": [], "ip_addresses": []},
        "entity_index": {},
        "normalized_timeline": {"events": []},
        "findings": [
            {
                "finding_id": "f-99",
                "mitre_technique": "T1059",
                "named_technique": "Command execution (T1059)",
                "description": "<script>alert(1)</script>",
                "host": "HOST-X",
                "ts": "2020-03-01T00:00:00Z",
                "confidence": "HYPOTHESIS",
                "tool_call_id": "tc-099",
                "artifact_path": "evtx",
            }
        ],
    }
    case = tmp_path / "case"
    case.mkdir()
    (case / "verdict.json").write_text(json.dumps(verdict), encoding="utf-8")

    model = load_case(case)
    html = summary_html(model)

    assert "<script>alert(1)</script>" not in html
    assert "&lt;script" in html


def test_summary_html_empty_findings_notes_no_reportable_findings(tmp_path):
    verdict = {
        "case_id": "case-fixture-empty",
        "attack_story": {},
        "attack_coverage": {},
        "indicators": {},
        "entity_index": {},
        "normalized_timeline": {"events": []},
        "findings": [],
    }
    case = tmp_path / "case"
    case.mkdir()
    (case / "verdict.json").write_text(json.dumps(verdict), encoding="utf-8")

    model = load_case(case)
    html = summary_html(model)

    assert "no reportable findings" in html.lower()
