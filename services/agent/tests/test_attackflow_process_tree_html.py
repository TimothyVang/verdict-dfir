import json
from pathlib import Path

from findevil_agent.attackflow.model import load_case
from findevil_agent.attackflow.process_tree_html import process_tree_html

FIX = Path(__file__).resolve().parent / "fixtures" / "attackflow"


def _copy_case(src: Path, dst: Path) -> Path:
    dst.mkdir(parents=True, exist_ok=True)
    for f in src.iterdir():
        (dst / f.name).write_bytes(f.read_bytes())
    return dst


def test_process_tree_html_renders_collapsible_tree_with_flagged_lineage_expanded(tmp_path):
    case = _copy_case(FIX / "memory-case", tmp_path / "case")
    model = load_case(case)

    html = process_tree_html(model)

    assert "<details" in html
    assert "<script>" in html
    assert f"{len(model.procs)} processes" in html
    # pid 1200 / svc.exe is the flagged process linked to a finding.
    assert "svc.exe" in html
    assert "flagged" in html
    assert "linked to finding" in html
    # The flagged node's own <details> (if it has children) or its ancestors
    # must be expanded (open) so the flagged lineage is visible on load.
    assert "open" in html


def test_process_tree_html_expands_full_ancestor_chain_to_flagged_node(tmp_path):
    case = _copy_case(FIX / "memory-case", tmp_path / "case")
    model = load_case(case)

    html = process_tree_html(model)

    # pid 4 (System) -> pid 800 (services.exe) -> pid 1200 (svc.exe, flagged).
    # Both ancestors must be <details ... open ...> so pid 1200 is visible.
    services_idx = html.find("services.exe")
    assert services_idx != -1
    # Walk backwards to the nearest preceding <details tag and check it carries open.
    details_start = html.rfind("<details", 0, services_idx)
    assert details_start != -1
    tag_end = html.find(">", details_start)
    assert "open" in html[details_start:tag_end]


def test_process_tree_html_reports_reason_when_source_is_none(tmp_path):
    case = _copy_case(FIX / "disk-case", tmp_path / "case")
    model = load_case(case)

    html = process_tree_html(model)

    assert "<details" not in html
    assert model.proc_reason in html


def test_process_tree_html_escapes_adversary_controlled_image_name(tmp_path):
    case = _copy_case(FIX / "memory-case", tmp_path / "case")
    psscan = json.loads((case / "psscan.json").read_text())
    psscan[2]["image_name"] = "<b>&evil"
    (case / "psscan.json").write_text(json.dumps(psscan), encoding="utf-8")
    model = load_case(case)

    html = process_tree_html(model)

    assert "&lt;b&gt;" in html
    assert "<b>&evil" not in html


def test_process_tree_html_is_deterministic(tmp_path):
    c1 = _copy_case(FIX / "memory-case", tmp_path / "c1")
    c2 = _copy_case(FIX / "memory-case", tmp_path / "c2")
    m1 = load_case(c1)
    m2 = load_case(c2)

    assert process_tree_html(m1) == process_tree_html(m2)
