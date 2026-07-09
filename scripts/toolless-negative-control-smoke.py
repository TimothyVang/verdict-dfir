#!/usr/bin/env python3
"""toolless-negative-control-smoke — pin the deliberate-hallucination floor.

Every accuracy claim needs a negative control proving the harness measures the
FLOOR, not just the ceiling. This smoke locks that control: a run that had NO
usable tools / empty evidence, scored against the committed
``goldens/synthetic-toolless`` golden (which DOES enumerate real expected
findings), MUST score recall=0 — recall is earned only by grounded tool output,
never assumed.

It also pins that the deliberate-hallucination posture is disclosed SEPARATELY
from the headline: ``accuracy.negative_control`` returns ``grounding_empty`` /
``baseline_hallucination_n`` under a dedicated ``negative_control`` key, and an
ungrounded (tool-less) hallucination never inflates the headline recall.

Loads the pure scoring core from
``services/agent/findevil_agent/accuracy.py`` by path (stdlib-only, bare-python3
runnable — same pattern as scripts/score-recall.py), so this smoke needs no venv.

Exit code: 0 on full pass, 1 on first assertion failure.
"""

from __future__ import annotations

import importlib.util
import json
import tempfile
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent
GOLDEN = REPO / "goldens" / "synthetic-toolless" / "expected-findings.json"


def _load_accuracy() -> Any:
    path = REPO / "services" / "agent" / "findevil_agent" / "accuracy.py"
    spec = importlib.util.spec_from_file_location("findevil_accuracy_core", path)
    assert spec and spec.loader, f"cannot load accuracy core at {path}"
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _write_run(case_dir: Path, verdict: str, findings: list[dict[str, Any]]) -> Path:
    case_dir.mkdir(parents=True, exist_ok=True)
    doc = {"case_id": "synthetic-toolless", "verdict": verdict, "findings": findings}
    (case_dir / "verdict.json").write_text(json.dumps(doc), encoding="utf-8")
    return case_dir


def _check(label: str, cond: bool) -> bool:
    print(f"  {'[OK  ]' if cond else '[FAIL]'} {label}")
    return cond


def main() -> int:
    print("=" * 60)
    print("Find Evil! - toolless-negative-control-smoke")
    print("=" * 60)

    if not GOLDEN.is_file():
        print(f"[FAIL] missing committed golden: {GOLDEN.relative_to(REPO).as_posix()}")
        return 1

    accuracy = _load_accuracy()
    golden = json.loads(GOLDEN.read_text(encoding="utf-8"))
    ok = True

    # The control only bites if the golden expects REAL findings (recall=0 is
    # meaningful only when there was something a tooled run should have found).
    ok &= _check(
        "golden enumerates real expected findings",
        len(golden.get("findings") or []) >= 1
        and int(golden.get("min_recall_percent", 0)) > 0,
    )

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)

        # 1. Honest tool-less run: no tools => no findings => recall=0, grounding-empty.
        empty = accuracy.negative_control(
            _write_run(root / "empty", "INDETERMINATE", []), GOLDEN
        )
        nc = empty["negative_control"]
        ok &= _check("empty tool-less run: expected_n >= 1", empty["expected_n"] >= 1)
        ok &= _check(
            "empty tool-less run: recall_percent == 0", empty["recall_percent"] == 0
        )
        ok &= _check("empty tool-less run: tool_less", nc["tool_less"] is True)
        ok &= _check(
            "empty tool-less run: grounding_empty", nc["grounding_empty"] is True
        )
        ok &= _check(
            "empty tool-less run: baseline_hallucination_n == 0",
            nc["baseline_hallucination_n"] == 0,
        )
        ok &= _check("empty tool-less run: floor_proven", nc["floor_proven"] is True)

        # 2. Deliberate-hallucination tool-less run: ungrounded claims disclosed
        #    SEPARATELY, never folded into the headline recall.
        findings = [
            {
                "finding_id": "h-1",
                "description": "fabricated lateral movement, no cited tool",
            },
            {
                "finding_id": "h-2",
                "description": "invented exfiltration over an imagined channel",
            },
        ]
        halluc = accuracy.negative_control(
            _write_run(root / "halluc", "SUSPICIOUS", findings), GOLDEN
        )
        nch = halluc["negative_control"]
        ok &= _check(
            "hallucinating run: grounding_empty", nch["grounding_empty"] is True
        )
        ok &= _check(
            "hallucinating run: baseline_hallucination_n == 2",
            nch["baseline_hallucination_n"] == 2,
        )
        ok &= _check(
            "hallucinating run: headline recall NOT inflated (== 0)",
            halluc["recall_percent"] == 0,
        )

    print()
    if ok:
        print("OK - tool-less negative control proves the recall floor")
        return 0
    print("FAIL - tool-less negative control regressed")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
