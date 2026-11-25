"""Regression: evtx findings pooled from more than one artifact must get
DISTINCT finding_ids.

`evtx_rows_to_findings` emits hardcoded finding_ids (e.g.
``f-A-evtx-audit-log-cleared``). When the same EID is parsed from two EVTX files
(a triage pack with the same log in two dirs, or two logs sharing an EID class),
the pooled ids collide; `judge_findings`' input validator then rejects the WHOLE
batch (duplicate verifier action for a finding_id) and every finding -- including
the CONFIRMED log-clear -- vanishes from verdict.json. The pooling step must
suffix ids per artifact_path (the legacy `.evt` path already does this via
`_finding_id_for(..., force_suffix=True)`).

See diagnosis: dgx-spark-lab/docs/medium-volt-finding-drop-diagnosis.md.
"""

from __future__ import annotations

import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402


def _inv() -> fea.Investigation:
    return fea.Investigation("/tmp/does-not-exist-evidence", case_id="case-collision")


def _finding(base: str, pool: str = "A") -> dict:
    return {"finding_id": base, "pool_origin": pool, "confidence": "CONFIRMED"}


def test_same_base_id_from_two_artifacts_gets_distinct_ids() -> None:
    inv = _inv()
    inv._pool_evtx_findings([_finding("f-A-evtx-audit-log-cleared")], "/ev/Security.evtx")
    inv._pool_evtx_findings(
        [_finding("f-A-evtx-audit-log-cleared")], "/ev/EventLogs/Security.evtx"
    )
    ids = [f["finding_id"] for f in inv.findings_pool_a]
    assert len(ids) == 2, ids
    # Distinct ids -> judge_findings will not reject the batch on a duplicate.
    assert len(set(ids)) == 2, ids
    assert all(i.startswith("f-A-evtx-audit-log-cleared") for i in ids), ids


def test_same_artifact_id_is_stable() -> None:
    inv = _inv()
    inv._pool_evtx_findings([_finding("f-A-evtx-audit-log-cleared")], "/ev/Security.evtx")
    a = inv.findings_pool_a[0]["finding_id"]
    inv2 = _inv()
    inv2._pool_evtx_findings([_finding("f-A-evtx-audit-log-cleared")], "/ev/Security.evtx")
    b = inv2.findings_pool_a[0]["finding_id"]
    assert a == b, (a, b)  # same path -> stable id (verifier linkage holds)


def test_pool_origin_routing_preserved() -> None:
    inv = _inv()
    inv._pool_evtx_findings(
        [
            _finding("f-A-evtx-audit-log-cleared", "A"),
            _finding("f-B-evtx-rdp-lsm-session", "B"),
        ],
        "/ev/Security.evtx",
    )
    assert len(inv.findings_pool_a) == 1
    assert len(inv.findings_pool_b) == 1
