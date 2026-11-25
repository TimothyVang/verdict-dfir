"""Tests for the parallel tool-call helper used by the investigation phase.

The slow investigation calls (mft_timeline / usnjrnl_query / prefetch_parse on
different extracted files) are independent at the tool-call level, but the
recording around them (tcid assignment, disk_summary merge, timeline) is
order-dependent. ``_parallel_tool_calls`` runs the calls concurrently across a
pool of fresh findevil-mcp connections and returns results in INPUT order, so
the caller can record serially and keep the verdict deterministic.

- I1: results are returned in input (spec) order even when calls finish in the
      reverse order (proves index-mapping, not append-on-completion).
- I2: with --parallel the calls actually overlap (max in-flight >= 2) and run on
      pooled connections (the primary client is untouched).
- I3: sequential mode runs every call on the primary client, in order, no pool.
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


class _Shared:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.inflight = 0
        self.max_inflight = 0
        self.closed = 0
        self.factory_calls = 0


class _FakeRust:
    """Records calls; tracks pool-wide concurrency; finishes in reverse order."""

    def __init__(self, shared: _Shared, *, primary: bool = False) -> None:
        self.shared = shared
        self.primary = primary
        self.calls: list[tuple[str, dict]] = []

    def call_tool(self, name: str, args: dict, timeout: float = 600.0) -> dict:
        with self.shared.lock:
            self.calls.append((name, args))
            self.shared.inflight += 1
            self.shared.max_inflight = max(self.shared.max_inflight, self.shared.inflight)
        # Sleep inversely to rank so spec 0 finishes LAST -> reverse completion.
        rank = int(args.get("rank", 0))
        time.sleep(0.02 * (10 - rank))
        with self.shared.lock:
            self.shared.inflight -= 1
        return {"echo": args.get("path"), "tool": name}

    def close(self) -> None:
        with self.shared.lock:
            self.shared.closed += 1


def _inv(parallel: bool, workers: int, shared: _Shared) -> fea.Investigation:
    inv = fea.Investigation("/tmp/does-not-exist-evidence", case_id="case-fixed")
    inv.parallel = parallel
    inv.workers = workers

    def _factory() -> _FakeRust:
        with shared.lock:
            shared.factory_calls += 1
        return _FakeRust(shared)

    inv._rust_factory = _factory
    return inv


def _specs(n: int) -> list[tuple[str, dict]]:
    return [
        ("mft_timeline", {"path": f"/p{i:02d}", "rank": i, "mft_path": f"/p{i:02d}"})
        for i in range(n)
    ]


def test_results_in_input_order_despite_reverse_completion() -> None:
    shared = _Shared()
    inv = _inv(parallel=True, workers=4, shared=shared)
    specs = _specs(6)
    primary = _FakeRust(shared, primary=True)

    results = inv._parallel_tool_calls(primary, specs, timeout=5.0)

    assert [r["echo"] for r in results] == [a["path"] for _, a in specs]
    assert shared.max_inflight >= 2  # really overlapped
    assert shared.factory_calls >= 2  # used pooled connections
    assert shared.closed == shared.factory_calls  # pooled clients cleaned up
    assert primary.calls == []  # primary untouched in parallel mode


def test_sequential_uses_primary_in_order() -> None:
    shared = _Shared()
    inv = _inv(parallel=False, workers=4, shared=shared)
    specs = _specs(5)
    primary = _FakeRust(shared, primary=True)

    results = inv._parallel_tool_calls(primary, specs, timeout=5.0)

    assert [r["echo"] for r in results] == [a["path"] for _, a in specs]
    assert [c[1]["path"] for c in primary.calls] == [a["path"] for _, a in specs]
    assert shared.max_inflight == 1
    assert shared.factory_calls == 0  # no pool spun up
