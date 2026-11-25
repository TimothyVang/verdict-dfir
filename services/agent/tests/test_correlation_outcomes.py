"""Tests for persisting correlate_findings outcomes into the audit chain.

The SOUL.md >=2-artifact-class rule lives in the correlator, but before this
change its per-finding decisions (kept / downgraded / rejected) existed only
as aggregate counts printed to stdout and two integers in verdict.json.
A judge reading audit.jsonl could not see WHICH finding was downgraded or why
(judging-audit gap, IR Accuracy).

The engine now emits one ``correlation_outcomes`` audit record per run (one
entry per finding: finding_id, action, reason) and stores the outcomes on the
Investigation so write_verdict() mirrors them into verdict.json.

- C1: a successful correlate_findings call emits exactly one
      correlation_outcomes audit record listing every per-finding decision.
- C2: the outcomes are stored on the Investigation for the verdict mirror,
      and refined findings replace the merged list.
- C3: a correlator tool error emits no correlation_outcomes record and the
      stored outcomes stay empty (honest absence, not fabricated data).
"""

from __future__ import annotations

import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402

_OUTCOMES = [
    {"finding_id": "f-001", "action": "kept", "reason": "non-execution claim"},
    {
        "finding_id": "f-002",
        "action": "downgraded",
        "reason": "Amcache-only execution claim",
    },
]
_REFINED = [
    {"id": "f-001", "confidence": "CONFIRMED"},
    {"id": "f-002", "confidence": "INFERRED"},
]


class _FakePy:
    """Answers correlate_findings and records every audit_append."""

    def __init__(self, correlator_result: dict) -> None:
        self.audits: list[tuple[str, dict]] = []
        self._correlator_result = correlator_result

    def call_tool(self, name: str, args: dict, timeout: float = 600.0) -> dict:
        if name == "audit_append":
            self.audits.append((args["kind"], args["payload"]))
            return {}
        if name == "correlate_findings":
            return self._correlator_result
        return {}

    def close(self) -> None:  # pragma: no cover - parity with real client
        pass


def _inv() -> fea.Investigation:
    return fea.Investigation("/tmp/does-not-exist-evidence", case_id="case-corr")


_MERGED = [{"id": "f-001"}, {"id": "f-002"}]


def test_correlation_outcomes_audited() -> None:
    inv = _inv()
    py = _FakePy({"refined": _REFINED, "outcomes": _OUTCOMES})

    inv._correlate_merged(py, list(_MERGED))

    records = [p for k, p in py.audits if k == "correlation_outcomes"]
    assert len(records) == 1
    assert records[0]["outcomes"] == _OUTCOMES
    assert records[0]["kept"] == 1
    assert records[0]["downgraded"] == 1


def test_outcomes_stored_and_refined_applied() -> None:
    inv = _inv()
    py = _FakePy({"refined": _REFINED, "outcomes": _OUTCOMES})

    merged, kept, downgraded = inv._correlate_merged(py, list(_MERGED))

    assert merged == _REFINED
    assert (kept, downgraded) == (1, 1)
    assert inv.correlation_outcomes == _OUTCOMES


def test_correlator_error_emits_no_record() -> None:
    inv = _inv()
    py = _FakePy({"_error": "server closed stdout"})

    merged, kept, downgraded = inv._correlate_merged(py, list(_MERGED))

    assert merged == _MERGED  # untouched on error
    assert (kept, downgraded) == (0, 0)
    assert inv.correlation_outcomes == []
    assert "correlation_outcomes" not in [k for k, _ in py.audits]
