#!/usr/bin/env python3
"""Guard: the attack-flow report hook must work under the ENGINE's host python.

The deterministic engine (`scripts/find_evil_auto.py`) imports `render_report`
and runs under host `python3`, which may be 3.10 — older than `findevil_agent`
(3.11: StrEnum, datetime.UTC). So `render_report._emit_attack_flow` imports
``attackflow`` as a TOP-LEVEL package, not via ``findevil_agent``. A regression
there makes the visualization silently dead in the live pipeline (0 artifacts,
no report summary) while every 3.11-venv test stays green.

This smoke drives the REAL hook (`render_report._emit_attack_flow`) under whatever
`python3` runs it, so that failure fails the gate. Run under host python (NOT the
agent venv): `python3 scripts/attackflow-hostpy-smoke.py`.
"""

from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPTS = REPO / "scripts"
FIXTURE = (
    REPO / "services" / "agent" / "tests" / "fixtures" / "attackflow" / "memory-case"
)

REQUIRED = [
    "incident.attack-flow.json",
    "attack-flow.mmd",
    "attack-summary.html",
    "timeline.html",
    "process-tree.html",
    "navigator-layer.json",
    "attack-flow.md",
]


def main() -> int:
    print(f"host python: {sys.version.split()[0]}")

    if str(SCRIPTS) not in sys.path:
        sys.path.insert(0, str(SCRIPTS))
    try:
        import render_report  # the engine imports this under host python
    except Exception as exc:  # noqa: BLE001
        print(
            f"FAIL: render_report does not import under host python -> {type(exc).__name__}: {exc}"
        )
        return 1

    with tempfile.TemporaryDirectory() as td:
        case = Path(td) / "case"
        case.mkdir()
        for f in FIXTURE.iterdir():
            shutil.copy2(f, case / f.name)

        # The exact call the report makes. It swallows exceptions and returns "",
        # so an empty snippet == the visualization is dead in the pipeline.
        snippet = render_report._emit_attack_flow(case)
        if "afs-" not in (snippet or ""):
            print("FAIL: _emit_attack_flow returned no summary under host python")
            print(
                "      (attack-flow visualization would be silently absent from the live report)"
            )
            return 1

        out = case / "attack-flow"
        missing = [name for name in REQUIRED if not (out / name).exists()]
        if missing:
            print(f"FAIL: hook ran but missing artifacts: {missing}")
            return 1

    print(
        f"attack-flow host-python hook smoke: OK ({len(REQUIRED)} artifacts, report summary present)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
