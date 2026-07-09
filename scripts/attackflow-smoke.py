#!/usr/bin/env python3
"""Smoke: attack-flow visualizer emits parseable artifacts from a fixture case.

Presentation-only, offline. Fails if the CLI errors or an artifact is missing/unparseable.

Run: ``python scripts/attackflow-smoke.py``. Part of ``scripts/run-all-smokes.sh``.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
FIX = REPO / "services" / "agent" / "tests" / "fixtures" / "attackflow" / "memory-case"

REQUIRED = [
    "incident.attack-flow.json",
    "attack-flow.mmd",
    "process-tree.html",
    "attack-summary.html",
    "timeline.html",
    "navigator-layer.json",
    "attack-flow.md",
]


def main() -> int:
    with tempfile.TemporaryDirectory() as td:
        case = Path(td) / "case"
        case.mkdir()
        for f in FIX.iterdir():
            shutil.copy2(f, case / f.name)
        r = subprocess.run(
            [
                "uv",
                "run",
                "--directory",
                str(REPO / "services" / "agent"),
                "python",
                "-m",
                "findevil_agent.attackflow",
                str(case),
            ],
            capture_output=True,
            text=True,
        )
        if r.returncode != 0:
            print("FAIL: CLI errored\n" + r.stderr, file=sys.stderr)
            return 1
        out = case / "attack-flow"
        missing = [n for n in REQUIRED if not (out / n).exists()]
        if missing:
            print(f"FAIL: missing artifacts: {missing}", file=sys.stderr)
            return 1
        json.loads((out / "incident.attack-flow.json").read_text())
        json.loads((out / "navigator-layer.json").read_text())
        print(f"attack-flow smoke: OK ({len(REQUIRED)} artifacts)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
