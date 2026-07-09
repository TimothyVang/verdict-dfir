import json
from pathlib import Path

from findevil_agent.attackflow.mermaid import flow_mermaid
from findevil_agent.attackflow.model import load_case

FIX = Path(__file__).resolve().parent / "fixtures" / "attackflow"


def _empty_findings_case(tmp_path: Path) -> Path:
    case = tmp_path / "empty-findings-case"
    case.mkdir()
    (case / "verdict.json").write_text(
        json.dumps(
            {
                "case_id": "case-fixture-empty",
                "attack_story": {"headline": "No reportable findings"},
                "attack_coverage": {"observed_techniques": []},
                "indicators": {"hosts": []},
                "entity_index": {"hosts": []},
                "normalized_timeline": {"events": []},
                "findings": [],
            }
        ),
        encoding="utf-8",
    )
    return case


def test_flow_mermaid_has_nodes_and_edge():
    m = load_case(FIX / "memory-case")
    out = flow_mermaid(m)
    assert out.startswith("flowchart LR")
    assert "T1543.003" in out
    assert "-->" in out  # chronological edge


def test_flow_mermaid_has_brand_confidence_styling():
    m = load_case(FIX / "memory-case")
    out = flow_mermaid(m)
    assert "classDef confirmed" in out
    assert ":::" in out  # at least one node gets a class application


def test_flow_mermaid_emits_placeholder_when_no_actions(tmp_path):
    m = load_case(_empty_findings_case(tmp_path))
    out = flow_mermaid(m)
    assert out.strip() != "graph LR"
    assert out.startswith("graph LR")
    assert "none[" in out
