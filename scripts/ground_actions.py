#!/usr/bin/env python3
"""ground_actions.py — grounding-aware action recommendations (Phase 5).

Reads a judged `grounding.json` and derives **recommended** next actions for the
human, keyed off the grounding statuses and the verdict word. It REPLACES the old
trivial `findevil-finding-to-action` n8n workflow (route -> ticket -> slack) with
grounding-informed routing that knows what was corroborated vs flagged.

Recommendations only — every action is `auto: false` (human-in-the-loop). Nothing
is executed. Per-technique IR steps come from `docs/finding-to-action.md`.

BOUNDARY (agent-config/GROUNDING.md): actions live in the post-verdict
`grounding.json` sidecar — never evidence, never in the audit/crypto chain, and
they never change the verdict. A grounding flag routes a human to look; it never
acts on its own.

Usage:
    python3 scripts/ground_actions.py <case-dir | grounding.json | case-id>
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
AUTO_RUNS = ROOT / "tmp" / "auto-runs"
REF = "docs/finding-to-action.md"

# Headline IR step per technique (full steps in docs/finding-to-action.md).
# Matched by prefix so sub-techniques (T1070.001) fall back to the parent (T1070).
TECH_ACTIONS: dict[str, str] = {
    "T1014": "Hash-sweep \\drivers\\*.sys across the fleet; assume kernel trust is broken on this host",
    "T1055": "Extract + sandbox the injected region; correlate injection time with EVTX 4688 to find the injector",
    "T1547.001": "Collect autoruns; review the Run-key value and its target binary",
    "T1543.003": "Review the service binary + creation event (EVTX 7045); hunt the binary hash",
    "T1053.005": "Review the scheduled-task XML + author; check EVTX 4698",
    "T1546.012": "Audit IFEO Debugger keys; remove the hijack and hunt the debugger binary",
    "T1070": "Treat log/indicator removal as anti-forensics; pull backups / forwarded logs to recover the gap",
    "T1041": "Identify the exfil destination; block it and scope the data loss",
    "T1048": "Identify the alternative-protocol exfil channel; block it and scope the data loss",
}
DEFAULT_TECH_ACTION = "Review the finding and escalate per docs/finding-to-action.md"


def resolve_grounding(arg: str) -> Path:
    p = Path(arg)
    if p.is_file() and p.name == "grounding.json":
        return p
    if p.is_dir():
        return p / "grounding.json"
    cand = AUTO_RUNS / arg / "grounding.json"
    if cand.is_file():
        return cand
    raise SystemExit(f"error: cannot resolve a grounding.json from {arg!r}")


def _tech_action(technique_id: str) -> str:
    tid = (technique_id or "").upper()
    for key, act in TECH_ACTIONS.items():
        if tid == key or tid.startswith(key + "."):
            return act
    return DEFAULT_TECH_ACTION


def derive_actions(grounding: dict[str, Any]) -> list[dict[str, Any]]:
    """Map grounding statuses + verdict -> recommended, human-in-the-loop actions."""
    verdict = (grounding.get("verdict") or "").upper()
    actions: list[dict[str, Any]] = []

    def add(action: str, based_on: str, why: str, route: str) -> None:
        actions.append(
            {
                "action": action,
                "based_on": based_on,
                "why": why,
                "route": route,  # "act" (corroborated) | "review" (flagged/low-confidence)
                "auto": False,
                "ref": REF,
            }
        )

    for g in grounding.get("grounding", []):
        tid = g.get("technique_id", "")
        status = g.get("status")
        if g.get("possible_hallucination"):
            add(
                f"Re-check finding for {tid}: grounding could not corroborate the technique id",
                tid,
                "possible hallucination — MITRE did not confirm this technique id",
                "review",
            )
            continue
        if status == "supported" and verdict == "SUSPICIOUS":
            add(
                _tech_action(tid),
                tid,
                f"{tid} grounded supported on a SUSPICIOUS verdict",
                "act",
            )
        elif status == "supported":
            add(
                f"Review the {tid} lead and corroborate to confirm or dismiss",
                tid,
                f"{tid} grounded supported but verdict is {verdict or 'not SUSPICIOUS'}",
                "review",
            )
        elif status in ("contradicted", "unsupported"):
            add(
                f"Re-examine the {tid} claim — grounding did not support it",
                tid,
                f"{tid} grounded {status}",
                "review",
            )

    for ioc in grounding.get("ioc_grounding", []):
        ind = ioc.get("ioc", "")
        if ioc.get("status") == "malicious":
            add(
                f"Hunt/sweep {ind} across the fleet; block at the perimeter and preserve artifacts",
                ind,
                f"IOC graded malicious ({ioc.get('detections') or 'multi-source'})",
                "act",
            )
        elif ioc.get("possible_overclaim"):
            add(
                f"Re-examine the finding that treated {ind} as malicious",
                ind,
                "grounding found this IOC clean — possible over-claim",
                "review",
            )

    return actions


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print(__doc__)
        return 2
    path = resolve_grounding(argv[0])
    if not path.is_file():
        raise SystemExit(
            f"error: no grounding.json at {path} — run ground_verdict.py + judge first."
        )
    grounding = json.loads(path.read_text())
    actions = derive_actions(grounding)
    grounding["actions"] = actions
    path.write_text(json.dumps(grounding, indent=2))

    acts = sum(1 for a in actions if a["route"] == "act")
    reviews = len(actions) - acts
    print(
        f"{len(actions)} recommended action(s): {acts} act, {reviews} review (all human-in-the-loop)"
    )
    for a in actions:
        print(f"  [{a['route']:<6}] {a['based_on']:<14} {a['action'][:72]}")
    print(f"\nwrote actions[] into {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
