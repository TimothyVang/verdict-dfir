#!/usr/bin/env python3
"""VERDICT pre-submission self-score — a maintainer grading tool, NOT the product.

This is run by the maintainer *before submission* to grade a completed
investigation run against the six quality criteria. It is deliberately **not**
part of the investigation pipeline: `find-evil-auto` no longer emits
`judge_selfscore` records, and the dashboard/video never mention it. Grading the
project is a separate step you invoke by hand.

It reads a finished case directory's `audit.jsonl` (+ `verdict.json` if present),
reconstructs the signals, computes each criterion's answer, prints a table, and
writes `<case>/self-score.json`. Unlike the old in-pipeline emitter, it does NOT
append to the audit chain — that chain is sealed at `manifest_finalize`; this is
an after-the-fact assessment.

Usage:
    python scripts/self-score.py <case-dir>
    python scripts/self-score.py                # newest dir under tmp/auto-runs/
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

# The six criteria. Reused from the agent package when importable so there is a
# single source of truth; falls back to an inline copy for a zero-dependency run.
try:  # pragma: no cover - import shim
    sys.path.insert(
        0, str(Path(__file__).resolve().parent.parent / "services" / "agent")
    )
    from findevil_agent.playbook import JUDGE_SELFSCORE_CRITERIA as CRITERIA
except Exception:  # pragma: no cover
    CRITERIA = [
        {
            "criterion": 1,
            "question": (
                "Did any tool call fail this run? If yes, did the audit log show "
                "explicit course-correction or verifier re-dispatch — and was the "
                "trigger natural or an injected fault?"
            ),
            "answer_style": "failures=N corrections=N redispatches=N injected_faults=N",
        },
        {
            "criterion": 2,
            "question": "What % of Findings are CONFIRMED vs INFERRED vs HYPOTHESIS?",
            "answer_style": "C=X% I=Y% H=Z%",
        },
        {
            "criterion": 3,
            "question": "How many artifact classes did this case touch? Which Findings cross >=2?",
            "answer_style": "classes=[…] crossed=[…]",
        },
        {
            "criterion": 4,
            "question": "Were any tool calls rejected by typed-surface validation this run?",
            "answer_style": "rejected=N reasons=[…]",
        },
        {
            "criterion": 5,
            "question": "Does every Finding cite a tool_call_id, and does each cited id resolve to a tool execution in the chain? (must be 100%; verifier vetoes otherwise)",
            "answer_style": "cited=N/N traced=N/N",
        },
        {
            "criterion": 6,
            "question": "Is the run reproducible from the manifest alone (no external state)?",
            "answer_style": "reproducible=yes/no",
        },
    ]

ARTIFACT_CLASS_FOR_TOOL = {
    "vol_pslist": "memory",
    "vol_psscan": "memory",
    "vol_psxview": "memory",
    "vol_malfind": "memory",
    "evtx_query": "evtx",
    "hayabusa_scan": "evtx",
    "mft_timeline": "mft",
    "usnjrnl_query": "usnjrnl",
    "registry_query": "registry",
    "prefetch_parse": "prefetch",
    "yara_scan": "yara",
    "vel_collect": "velociraptor",
}


def _newest_case_dir() -> Path | None:
    root = Path("tmp/auto-runs")
    if not root.is_dir():
        return None
    cases = [d for d in root.iterdir() if d.is_dir() and (d / "audit.jsonl").is_file()]
    return max(cases, key=lambda d: d.stat().st_mtime) if cases else None


def _load_audit(case_dir: Path) -> list[dict[str, Any]]:
    path = case_dir / "audit.jsonl"
    lines: list[dict[str, Any]] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            lines.append(json.loads(raw))
        except json.JSONDecodeError:
            continue
    return lines


def score(case_dir: Path) -> dict[str, Any]:
    """Reconstruct run signals from audit.jsonl and answer the six criteria."""
    lines = _load_audit(case_dir)

    tools: dict[str, str] = {}  # tool_call_id -> tool name
    have_output: set[str] = set()  # tool_call_ids with an output_hash
    findings: list[dict[str, Any]] = []
    rejected = 0
    corrections = 0  # kind=course_correction records (real-time failure recovery)
    redispatches = 0  # kind=verifier_redispatch records (verifier retry recovery)
    revisions = 0  # kind=verdict_revision records (committed conclusion flips)
    injected = 0  # kind=fault_injection records — staged, judges discount these

    for rec in lines:
        kind = rec.get("kind")
        p = rec.get("payload", {}) or {}
        if kind == "tool_call_start":
            tcid = p.get("tool_call_id")
            if tcid:
                tools[tcid] = p.get("tool") or p.get("tool_name") or "?"
        elif kind == "tool_call_output":
            tcid = p.get("tool_call_id")
            if tcid and p.get("output_hash"):
                have_output.add(tcid)
        elif kind == "finding_approved":
            findings.append(p)
        elif kind == "verifier_action" and p.get("action") == "rejected":
            rejected += 1
        elif kind == "course_correction":
            corrections += 1
        elif kind == "verifier_redispatch":
            redispatches += 1
        elif kind == "verdict_revision":
            revisions += 1
        elif kind == "fault_injection":
            injected += 1

    n = max(1, len(findings))
    conf = [f.get("confidence") for f in findings]
    c = conf.count("CONFIRMED")
    i = conf.count("INFERRED")
    h = conf.count("HYPOTHESIS")
    classes = sorted(
        {
            ARTIFACT_CLASS_FOR_TOOL[t]
            for t in tools.values()
            if t in ARTIFACT_CLASS_FOR_TOOL
        }
    )
    failures = sum(1 for tcid in tools if tcid not in have_output)
    cited = sum(1 for f in findings if f.get("tool_call_id"))
    # The judges' three-claim trace, over every finding: the cited id must
    # resolve to a tool_call_start in this same chain (cited != traced).
    traced = sum(1 for f in findings if f.get("tool_call_id") in tools)
    reproducible = "yes" if tools and have_output >= set(tools) else "no"

    answers = [
        (
            f"failures={failures} corrections={corrections} "
            f"redispatches={redispatches} verdict_revisions={revisions} "
            f"injected_faults={injected}"
        ),
        f"C={c * 100 // n}% I={i * 100 // n}% H={h * 100 // n}% (n={len(findings)})",
        f"classes={classes} crossed={'yes' if len(classes) >= 2 else 'no'}",
        f"rejected={rejected} reasons=[]",
        f"cited={cited}/{len(findings)} traced={traced}/{len(findings)}",
        f"reproducible={reproducible}",
    ]
    rows = [
        {
            "criterion": crit["criterion"],
            "question": crit["question"],
            "answer": answers[crit["criterion"] - 1],
        }
        for crit in CRITERIA
    ]
    return {"case_dir": str(case_dir), "rows": rows}


def main(argv: list[str]) -> int:
    if len(argv) > 1:
        case_dir = Path(argv[1])
    else:
        case_dir = _newest_case_dir()
        if case_dir is None:
            print("usage: python scripts/self-score.py <case-dir>", file=sys.stderr)
            print(
                "  (no case dir given and none found under tmp/auto-runs/)",
                file=sys.stderr,
            )
            return 2
    if not (case_dir / "audit.jsonl").is_file():
        print(f"error: {case_dir}/audit.jsonl not found", file=sys.stderr)
        return 2

    result = score(case_dir)
    print(f"=== VERDICT pre-submission self-score — {case_dir} ===")
    for row in result["rows"]:
        print(f"  #{row['criterion']}  {row['answer']}")
        print(f"      {row['question']}")
    out = case_dir / "self-score.json"
    out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"\nwrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
