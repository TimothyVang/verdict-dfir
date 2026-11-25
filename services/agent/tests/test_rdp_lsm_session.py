"""RDP session detection from the TerminalServices Local Session Manager
Operational channel (EID 21/22/25 -> T1021.001).

The existing RDP detector reads only Security 4624 with logon_type==10. Real RDP
sessions are also (sometimes only) recorded in
``Microsoft-Windows-TerminalServices-LocalSessionManager/Operational`` as EID 21
(session logon), 22 (shell start), 25 (reconnect). This emitter catches that
case as a HYPOTHESIS lead.
"""

from __future__ import annotations

import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402

_LSM = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"


def _lsm_row(eid: int, user: str = "CORP\\alice", rid: int = 5) -> dict:
    return {
        "event_id": eid,
        "ts": "2026-07-12T01:58:40Z",
        "channel": _LSM,
        "record_id": rid,
        "data": {
            "Event": {
                "System": {"EventID": eid, "Channel": _LSM},
                "UserData": {"EventXML": {"User": user, "SessionID": "2"}},
            }
        },
    }


def test_lsm_eid21_emits_rdp_finding() -> None:
    findings = fea.evtx_rows_to_findings(
        [_lsm_row(21)], "tc-lsm", "case-lsm", "/ev/LSM-Operational.evtx"
    )
    rdp = [f for f in findings if f["finding_id"] == "f-B-evtx-rdp-lsm-session"]
    assert len(rdp) == 1, [f["finding_id"] for f in findings]
    assert rdp[0]["mitre_technique"] == "T1021.001"
    assert rdp[0]["confidence"] == "HYPOTHESIS"
    assert rdp[0]["pool_origin"] == "B"


def test_lsm_eid22_also_emits_once() -> None:
    findings = fea.evtx_rows_to_findings(
        [_lsm_row(21), _lsm_row(22, rid=6)], "tc", "case", "/ev/LSM-Operational.evtx"
    )
    rdp = [f for f in findings if f["finding_id"] == "f-B-evtx-rdp-lsm-session"]
    assert len(rdp) == 1, "deduped within a file by seen_kinds"


def test_non_lsm_channel_does_not_emit_lsm_finding() -> None:
    row = _lsm_row(21)
    row["channel"] = "System"
    findings = fea.evtx_rows_to_findings([row], "tc", "case", "/ev/System.evtx")
    assert not [f for f in findings if f["finding_id"] == "f-B-evtx-rdp-lsm-session"]
