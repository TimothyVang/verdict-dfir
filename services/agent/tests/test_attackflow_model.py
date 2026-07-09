import json
import shutil
from pathlib import Path

from findevil_agent.attackflow.model import load_case, stable_id

FIX = Path(__file__).resolve().parent / "fixtures" / "attackflow" / "memory-case"


def test_stable_id_is_deterministic():
    assert stable_id("attack-action", "f-1") == stable_id("attack-action", "f-1")
    assert stable_id("attack-action", "f-1").startswith("attack-action--")


def test_load_case_builds_actions_and_edges():
    m = load_case(FIX)
    assert m.case_id == "case-fixture-mem"
    assert [a.finding_id for a in m.actions] == ["f-1", "f-2"]  # ordered by ts
    assert m.actions[0].technique == "T1543.003"
    assert any(e.src == m.actions[0].id and e.dst == m.actions[1].id for e in m.edges)
    assert m.observed_techniques == ["T1543.003", "T1070.001"]


def test_load_case_builds_process_forest_from_psscan():
    m = load_case(FIX)
    assert m.proc_source == "psscan"
    assert ("HOST-A", 1200) in {(p.host, p.pid) for p in m.procs} or 1200 in {
        p.pid for p in m.procs
    }
    child = next(p for p in m.procs if p.pid == 1200)
    assert child.ppid == 800


def test_action_links_to_process_by_pid():
    m = load_case(FIX)
    # f-1 timeline event carries pid 1200 -> action.process_ref set
    a = m.actions[0]
    assert a.process_ref is not None


def test_load_case_degrades_on_malformed_process_artifact(tmp_path):
    case = tmp_path / "case"
    case.mkdir()
    for f in FIX.iterdir():
        shutil.copy(f, case / f.name)
    (case / "psscan.json").write_text(json.dumps([{"nope": 1}]), encoding="utf-8")
    m = load_case(case)
    assert m.proc_source == "none"
    assert m.procs == []


def test_load_case_degrades_on_non_dict_rows(tmp_path):
    case = tmp_path / "case"
    case.mkdir()
    for f in FIX.iterdir():
        shutil.copy(f, case / f.name)
    (case / "psscan.json").write_text(json.dumps([1, 2, 3]), encoding="utf-8")
    m = load_case(case)
    assert m.proc_source == "none"
    assert m.procs == []
