import importlib.util
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"


def _load_render_report():
    sys.path.insert(0, str(SCRIPTS))
    spec = importlib.util.spec_from_file_location("render_report", SCRIPTS / "render_report.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_emit_attack_flow_helper_is_safe_on_bad_dir(tmp_path):
    rr = _load_render_report()
    # helper must swallow errors and return "" (never break the custody report)
    assert rr._emit_attack_flow(tmp_path / "does-not-exist") == ""


def test_emit_attack_flow_helper_returns_snippet(tmp_path):
    rr = _load_render_report()
    fix = Path(__file__).resolve().parent / "fixtures" / "attackflow" / "memory-case"
    case = tmp_path / "case"
    case.mkdir()
    for f in fix.iterdir():
        (case / f.name).write_bytes(f.read_bytes())
    snippet = rr._emit_attack_flow(case)
    assert "attack-flow" in snippet.lower()
    assert (case / "attack-flow" / "incident.attack-flow.json").exists()
