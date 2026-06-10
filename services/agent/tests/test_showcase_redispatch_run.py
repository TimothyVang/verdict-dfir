"""The committed fault-injection showcase run proves the self-correction loop.

``docs/sample-run/fault-injection-redispatch/`` is a real local-mode run over
the NIST hacking case (``evidence/SCHARDT.dd``) recorded with
``FIND_EVIL_FAULT_INJECT=verifier_reject_once:prefetch-cain-exe``: the chain
must show the engine catching a deliberately-injected replay failure,
re-dispatching the verify once, and recovering the finding — with the final
verdict unchanged. Offline-verifiable like every other sample run
(test_sample_runs_verify.py picks the directory up automatically).
"""

from __future__ import annotations

import json
from pathlib import Path

_RUN_DIR = (
    Path(__file__).resolve().parents[3] / "docs" / "sample-run" / "fault-injection-redispatch"
)
_TARGET_FRAGMENT = "prefetch-cain-exe"


def _audit_kinds_for_target() -> list[tuple[str, dict]]:
    rows = []
    with (_RUN_DIR / "audit.jsonl").open(encoding="utf-8") as fh:
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
    verdict = json.loads((_RUN_DIR / "verdict.json").read_text(encoding="utf-8"))

    assert verdict["verdict"] == "SUSPICIOUS"

    recovered = [
        f for f in verdict["findings"] if _TARGET_FRAGMENT in str(f.get("finding_id") or "")
    ]
    assert len(recovered) == 1
    assert recovered[0].get("tool_call_id")

    redispatches = verdict["findings_summary"]["verifier_redispatches"]
    target = next(v for k, v in redispatches.items() if _TARGET_FRAGMENT in k)
    assert target["recovered"] is True
