import subprocess
import sys
from pathlib import Path

FIX = Path(__file__).resolve().parent / "fixtures" / "attackflow" / "memory-case"
AGENT = Path(__file__).resolve().parents[1]  # services/agent


def _copy(src, dst):
    dst.mkdir(parents=True, exist_ok=True)
    for f in src.iterdir():
        (dst / f.name).write_bytes(f.read_bytes())
    return dst


def test_cli_emits_and_reports(tmp_path):
    case = _copy(FIX, tmp_path / "case")
    r = subprocess.run(
        [sys.executable, "-m", "findevil_agent.attackflow", str(case)],
        cwd=AGENT,
        capture_output=True,
        text=True,
    )
    assert r.returncode == 0, r.stderr
    assert (case / "attack-flow" / "incident.attack-flow.json").exists()
