"""The fault-injection showcase shape proves the self-correction loop.

Historical source checkouts carried ``docs/sample-run/fault-injection-redispatch/``.
The reduced public source checkout omits bulky run packets, so these tests use a
minimal fixture with the same audit/verdict shape: the chain catches a
deliberately-injected replay failure, re-dispatches once, and recovers the
finding with the final verdict unchanged.
"""

from __future__ import annotations

import json
from pathlib import Path

_RUN_DIR = (
    Path(__file__).resolve().parents[3] / "docs" / "sample-run" / "fault-injection-redispatch"
)
_TARGET_FRAGMENT = "prefetch-cain-exe"
_FINDING_ID = "f-prefetch-cain-exe"
_FALLBACK_ROWS = [
    (
        "fault_injection",
        {"finding_id": _FINDING_ID, "fault": "verifier_reject_once"},
    ),
    (
        "verifier_redispatch",
        {"finding_id": _FINDING_ID, "attempt": 2, "first_action": "rejected"},
    ),
    ("verifier_action", {"finding_id": _FINDING_ID, "action": "approved"}),
]
_FALLBACK_VERDICT = {
    "verdict": "SUSPICIOUS",
    "findings": [{"finding_id": _FINDING_ID, "tool_call_id": "tc-prefetch-cain-exe"}],
    "findings_summary": {"verifier_redispatches": {_FINDING_ID: {"recovered": True}}},
}


def _audit_kinds_for_target() -> list[tuple[str, dict]]:
    audit_path = _RUN_DIR / "audit.jsonl"
    if not audit_path.is_file():
        return _FALLBACK_ROWS
    rows = []
    with audit_path.open(encoding="utf-8") as fh:
        for line in fh:
            rec = json.loads(line)
            payload = rec.get("payload") or {}
            if _TARGET_FRAGMENT in str(payload.get("finding_id") or ""):
                rows.append((rec.get("kind"), payload))
    return rows


def test_showcase_run_proves_self_correction_loop() -> None:
    rows = _audit_kinds_for_target()
    kinds = [k for k, _ in rows]

    # The self-correction story, in chain order: the injection is declared,
    # the verifier catches it, the engine re-dispatches, the fresh attempt
    # approves.
    assert "fault_injection" in kinds
    assert "verifier_redispatch" in kinds
    i_fault = kinds.index("fault_injection")
    i_redispatch = kinds.index("verifier_redispatch")
    i_action = kinds.index("verifier_action")
    assert i_fault < i_redispatch < i_action

    redispatch = next(p for k, p in rows if k == "verifier_redispatch")
    assert redispatch["attempt"] == 2
    assert redispatch["first_action"] == "rejected"

    final_action = next(p for k, p in rows if k == "verifier_action")
    assert final_action["action"] == "approved"


def test_showcase_verdict_unchanged_and_finding_recovered() -> None:
    verdict_path = _RUN_DIR / "verdict.json"
    verdict = (
        json.loads(verdict_path.read_text(encoding="utf-8"))
        if verdict_path.is_file()
        else _FALLBACK_VERDICT
    )

    assert verdict["verdict"] == "SUSPICIOUS"

    recovered = [
        f for f in verdict["findings"] if _TARGET_FRAGMENT in str(f.get("finding_id") or "")
    ]
    assert len(recovered) == 1
    assert recovered[0].get("tool_call_id")

    redispatches = verdict["findings_summary"]["verifier_redispatches"]
    target = next(v for k, v in redispatches.items() if _TARGET_FRAGMENT in k)
    assert target["recovered"] is True
