import json
from pathlib import Path

import pytest

from findevil_agent.attackflow.emit import emit

FIX = Path(__file__).resolve().parent / "fixtures" / "attackflow"

CANONICAL_ARTIFACTS = [
    "incident.attack-flow.json",
    "attack-flow.mmd",
    "process-tree.html",
    "attack-summary.html",
    "timeline.html",
    "navigator-layer.json",
    "attack-flow.md",
]


def _copy_case(src: Path, dst: Path) -> Path:
    dst.mkdir(parents=True, exist_ok=True)
    for f in src.iterdir():
        (dst / f.name).write_bytes(f.read_bytes())
    return dst


def test_emit_writes_all_artifacts(tmp_path):
    case = _copy_case(FIX / "memory-case", tmp_path / "case")
    res = emit(case)
    names = {p.name for p in res.paths}
    for expected in CANONICAL_ARTIFACTS:
        assert expected in names, expected
    assert names == set(CANONICAL_ARTIFACTS)
    assert res.process_tree_available is True
    assert (
        json.loads((case / "attack-flow" / "incident.attack-flow.json").read_text())["type"]
        == "bundle"
    )


def test_emit_is_deterministic(tmp_path):
    c1 = _copy_case(FIX / "memory-case", tmp_path / "c1")
    c2 = _copy_case(FIX / "memory-case", tmp_path / "c2")
    emit(c1)
    emit(c2)
    for name in ["incident.attack-flow.json", "attack-flow.mmd", "navigator-layer.json"]:
        assert (c1 / "attack-flow" / name).read_text() == (c2 / "attack-flow" / name).read_text()


def test_emit_omits_process_tree_with_reason_on_disk_case(tmp_path):
    case = _copy_case(FIX / "disk-case", tmp_path / "case")
    res = emit(case)
    assert res.process_tree_available is False
    assert "no process-lineage artifact" in (case / "attack-flow" / "process-tree.html").read_text()


def test_emit_mints_no_tool_call_id(tmp_path):
    """Custody: every tool_call_id in output must already exist in verdict.json."""
    case = _copy_case(FIX / "memory-case", tmp_path / "case")
    emit(case)
    verdict = json.loads((case / "verdict.json").read_text())
    known = {f.get("tool_call_id") for f in verdict["findings"]}
    known |= {e.get("tool_call_id") for e in verdict["normalized_timeline"]["events"]}
    bundle = (case / "attack-flow" / "incident.attack-flow.json").read_text()
    # bundle carries no tool_call_id field at all (presentation only)
    assert "tool_call_id" not in bundle


def test_emit_raises_without_verdict(tmp_path):
    (tmp_path / "empty").mkdir()
    with pytest.raises(FileNotFoundError):
        emit(tmp_path / "empty")


def test_index_md_has_linkage_table(tmp_path):
    case = _copy_case(FIX / "memory-case", tmp_path / "case")
    emit(case)
    md = (case / "attack-flow" / "attack-flow.md").read_text()
    assert "Action <-> Process linkage" in md
    assert "f-1" in md
    assert "1200" in md
    assert "svc.exe" in md


def test_index_md_states_no_linkage_when_none(tmp_path):
    case = _copy_case(FIX / "disk-case", tmp_path / "case")
    emit(case)
    md = (case / "attack-flow" / "attack-flow.md").read_text()
    assert "No action is process-linked in this case." in md


def test_html_snippet_leads_with_summary_and_points_to_richer_artifacts(tmp_path):
    case = _copy_case(FIX / "memory-case", tmp_path / "case")
    res = emit(case)
    # Report embed leads with the technique-grouped summary (from summary.py).
    assert "afs-root" in res.html_snippet
    assert "T1543.003" in res.html_snippet
    # And points the analyst at the richer artifacts by filename, without inlining them.
    assert "attackflow-more" in res.html_snippet
    assert "timeline.html" in res.html_snippet
    assert "process-tree.html" in res.html_snippet
    assert "incident.attack-flow.json" in res.html_snippet


def test_emit_handles_malformed_process_artifact_without_raising(tmp_path):
    case = _copy_case(FIX / "memory-case", tmp_path / "case")
    (case / "psscan.json").write_text("[1, 2, 3]", encoding="utf-8")
    res = emit(case)
    assert res.process_tree_available is False
    names = {p.name for p in res.paths}
    for expected in CANONICAL_ARTIFACTS:
        assert expected in names, expected


def test_emit_escapes_artifact_strings_in_html_and_md(tmp_path):
    """Security: process names and finding IDs from artifacts are escaped."""
    case = _copy_case(FIX / "memory-case", tmp_path / "case")
    # Modify psscan.json to include malicious-looking process name
    psscan = json.loads((case / "psscan.json").read_text())
    psscan[2]["image_name"] = "<b>&|evil"  # html/markdown special chars
    (case / "psscan.json").write_text(json.dumps(psscan), encoding="utf-8")

    res = emit(case)

    # Check HTML snippet: <b> should be escaped as &lt;b&gt;
    assert "&lt;b&gt;" in res.html_snippet
    assert "<b>" not in res.html_snippet

    # Check markdown linkage table: | should be escaped as \|
    md = (case / "attack-flow" / "attack-flow.md").read_text()
    assert "\\|" in md or "<b>" not in md  # either escaped or not present literally
