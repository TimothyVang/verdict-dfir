"""Supervisor->pool and pool->judge ACP handoffs (judging-audit C5).

Committed runs only carried verifier->judge acp_handoff records, so the
multi-agent message log the rubric calls out (Pool A/B handoffs) was proven
only by a unit test. The engine now emits the dispatch handoffs
(supervisor->pool_a, supervisor->pool_b) and the merge handoffs
(pool_a->judge, pool_b->judge) into the same audit chain via pool_handoff.
"""

from __future__ import annotations

import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402


class _FakePy:
    """Records every pool_handoff call so we can assert the role pairs."""

    def __init__(self) -> None:
        self.handoffs: list[tuple[str, str, dict]] = []

    def call_tool(self, name: str, args: dict, timeout: float = 600.0) -> dict:
        if name == "pool_handoff":
            self.handoffs.append((args["from_role"], args["to_role"], args.get("payload", {})))
        return {}


def _inv() -> fea.Investigation:
    inv = fea.Investigation("/tmp/does-not-exist-evidence", case_id="case-handoff")
    inv.handle = {"id": "case-handoff"}
    return inv


def test_dispatch_emits_supervisor_to_each_pool() -> None:
    inv = _inv()
    inv.findings_pool_a = [{"finding_id": "f-A-1"}, {"finding_id": "f-A-2"}]
    inv.findings_pool_b = [{"finding_id": "f-B-1"}]
    py = _FakePy()
    inv._emit_pool_dispatch_handoffs(py)
    pairs = {(f, t) for f, t, _ in py.handoffs}
    assert ("supervisor", "pool_a") in pairs
    assert ("supervisor", "pool_b") in pairs
    # the dispatch payload carries the hypothesis + the count handed off
    a_payload = next(p for f, t, p in py.handoffs if t == "pool_a")
    assert a_payload.get("findings") == 2
    assert "persistence" in str(a_payload.get("hypothesis", "")).lower()


def test_merge_emits_each_pool_to_judge() -> None:
    inv = _inv()
    py = _FakePy()
    inv._emit_pool_merge_handoffs(
        py,
        pool_a_verified=[{"finding_id": "f-A-1"}],
        pool_b_verified=[{"finding_id": "f-B-1"}, {"finding_id": "f-B-2"}],
    )
    pairs = {(f, t) for f, t, _ in py.handoffs}
    assert ("pool_a", "judge") in pairs
    assert ("pool_b", "judge") in pairs
    b_payload = next(p for f, t, p in py.handoffs if f == "pool_b")
    assert b_payload.get("findings") == 2
