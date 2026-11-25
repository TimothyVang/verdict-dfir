"""NTDS credential-dumping detection via ESENT Application-log events.

An NTDS IFM dump (ntdsutil `ifm create full`) makes the ESENT engine write
Application-log events 216 (DB header), 325 (create/attach), 327 (detach) that
reference the `ntds.dit` database. This emitter catches that as a HYPOTHESIS
lead for T1003.003. It gates on `ntds` in the event data so ordinary ESENT DBs
(Windows Search, etc.) do not trip it.
"""

from __future__ import annotations

import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402


def _esent_row(
    eid: int, db: str = "C:\\Windows\\NTDS\\ntds.dit", client: str = "svc", rid: int = 7
) -> dict:
    return {
        "event_id": eid,
        "ts": "2026-07-12T01:58:47Z",
        "channel": "Application",
        "record_id": rid,
        "data": {
            "Event": {
                "System": {
                    "EventID": eid,
                    "Channel": "Application",
                    "Provider": {"Name": "ESENT"},
                },
                "EventData": {"Data": [client, db, "1272"]},
            }
        },
    }


def test_esent_325_ntds_emits_finding() -> None:
    findings = fea.evtx_rows_to_findings(
        [_esent_row(325)], "tc", "case", "/ev/Application.evtx"
    )
    ntds = [f for f in findings if f["finding_id"] == "f-B-evtx-ntds-esent"]
    assert len(ntds) == 1, [f["finding_id"] for f in findings]
    assert ntds[0]["mitre_technique"] == "T1003.003"
    assert ntds[0]["confidence"] == "HYPOTHESIS"
    assert ntds[0]["pool_origin"] == "B"


def test_esent_216_327_also_match() -> None:
    for eid in (216, 327):
        findings = fea.evtx_rows_to_findings(
            [_esent_row(eid)], "tc", "case", "/ev/Application.evtx"
        )
        assert any(f["finding_id"] == "f-B-evtx-ntds-esent" for f in findings), eid


def test_esent_without_ntds_does_not_fire() -> None:
    # An ESENT DB event for a non-NTDS database must NOT trip the NTDS detector.
    row = _esent_row(325, db="C:\\ProgramData\\Search\\Windows.edb")
    findings = fea.evtx_rows_to_findings([row], "tc", "case", "/ev/Application.evtx")
    assert not [f for f in findings if f["finding_id"] == "f-B-evtx-ntds-esent"]
