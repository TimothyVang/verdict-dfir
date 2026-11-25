"""Parity + concurrency tests for the parallel verify phase in find_evil_auto.py.

``_verify_pool`` re-runs every finding's cited tool through ``verify_finding``
(slow, independent) and then records verifier actions to the hash-chained audit
log (must stay serial + ordered). Parallelizing the re-runs must NOT change the
result: the actions list, the audit/handoff call sequence, and the verifier
replays must be byte-identical to the sequential path. These tests pin that:

- V1: parallel vs sequential produce identical actions, audit-call order, and
      verifier_replays (determinism / audit-chain safety).
- V2: with --parallel the verify_finding calls actually overlap (max in-flight
      >= 2); sequentially they never overlap (== 1).
"""

from __future__ import annotations

import sys
import threading
import time
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402


class _FakePy:
    """Stand-in MCP client: deterministic verify_finding, records call order,
    tracks how many verify_finding calls are in flight at once."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []
        self._lock = threading.Lock()
        self._inflight = 0
        self.max_inflight = 0

    def call_tool(self, name: str, args: dict, timeout: float = 600.0) -> dict:
        with self._lock:
            self.calls.append((name, args))
        if name == "verify_finding":
            with self._lock:
                self._inflight += 1
                self.max_inflight = max(self.max_inflight, self._inflight)
            time.sleep(0.05)  # hold the call so concurrent ones overlap
            with self._lock:
                self._inflight -= 1
            fid = str(args["finding"]["finding_id"])
            return {
                "finding_id": fid,
                "action": "approved",
                "reason": "replay matched",
                "replay_matched": True,
                "replay_tool_name": "vol_pslist",
                "replay_expected_sha256": "abc",
                "replay_actual_sha256": "abc",
                "replay_artifact": None,
            }
        return {}

    def stage_b_calls(self) -> list[tuple[str, dict]]:
        """Audit + handoff calls (Stage B) — these must be deterministic."""
        return [c for c in self.calls if c[0] in ("audit_append", "pool_handoff")]


def _fresh_inv(parallel: bool, workers: int = 4) -> fea.Investigation:
    # Pin the case_id so both runs share an audit_path (it is otherwise a random
    # uuid per instance), making the recorded audit-call args comparable.
    inv = fea.Investigation("/tmp/does-not-exist-evidence", case_id="case-fixed")
    inv.handle = {"id": "case-test"}
    inv.parallel = parallel
    inv.workers = workers
    return inv


def _findings(n: int) -> list[dict]:
    return [
        {"finding_id": f"f-{i:02d}", "tool_call_id": f"tc-{i:02d}", "description": f"d{i}"}
        for i in range(n)
    ]


def test_parallel_matches_sequential() -> None:
    findings = _findings(6)

    seq_inv = _fresh_inv(parallel=False)
    seq_py = _FakePy()
    seq_actions = seq_inv._verify_pool(seq_py, findings)

    par_inv = _fresh_inv(parallel=True, workers=4)
    par_py = _FakePy()
    par_actions = par_inv._verify_pool(par_py, findings)

    assert par_actions == seq_actions
    assert par_py.stage_b_calls() == seq_py.stage_b_calls()
    assert par_inv.verifier_replays == seq_inv.verifier_replays
    assert par_inv.verifier_replay_failures == seq_inv.verifier_replay_failures
    # verify_finding ran once per finding in both modes
    assert sum(1 for c in par_py.calls if c[0] == "verify_finding") == len(findings)


def test_parallel_actually_overlaps() -> None:
    findings = _findings(6)

    seq_py = _FakePy()
    _fresh_inv(parallel=False)._verify_pool(seq_py, findings)
    assert seq_py.max_inflight == 1

    par_py = _FakePy()
    _fresh_inv(parallel=True, workers=4)._verify_pool(par_py, findings)
    assert par_py.max_inflight >= 2
