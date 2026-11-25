"""Tests for the server-enforced exfil presence-vs-egress two-prong gate.

CLAUDE.md: "Exfiltration claims require finding-specific collection or staging
plus network, tool, or data-movement evidence." An exfiltration finding must
clear TWO independent prongs, mirroring the >=2-artifact-class execution gate:

- PRESENCE  -- collection/staging evidence that the data existed and was gathered
              (disk/filesystem, mft, prefetch, registry, usnjrnl, yara).
- EGRESS    -- a channel that could move it off the host (network, tool, or
              data-movement evidence).

``exfil_prongs_satisfied`` is the single pure predicate that classifies a
finding's artifact-class set into ``(has_presence, has_egress)`` so both the
report-QA gate and any demote-to-lead path agree byte-for-byte. A finding that
clears only one prong is demoted to a lead -- never a standing exfil conclusion.

A single ``velociraptor`` class is deliberately NOT enough for *either* prong on
its own: one artifact class supplying both the "we collected it" and the "it
left" claim is not two-pronged corroboration -- the same reason the execution
gate rejects a single-class CONFIRMED claim.

- E1: presence-only (staging without egress) -> demote (not both prongs).
- E2: egress-only (network without staging) -> demote (not both prongs).
- E3: both prongs (staging + network) -> stands.
- E4: velociraptor-only does not satisfy either prong by itself -> demote.
- E5: the report-QA gate FAILs on a single-prong exfil finding and PASSes on a
      two-prong one (the gate consumes the same predicate).
"""

from __future__ import annotations

import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402


def test_presence_only_is_single_prong() -> None:
    has_presence, has_egress = fea.exfil_prongs_satisfied({"mft", "registry"})
    assert has_presence is True
    assert has_egress is False
    assert not fea.exfil_two_prongs_met({"mft", "registry"})


def test_egress_only_is_single_prong() -> None:
    has_presence, has_egress = fea.exfil_prongs_satisfied({"network"})
    assert has_presence is False
    assert has_egress is True
    assert not fea.exfil_two_prongs_met({"network"})


def test_both_prongs_stand() -> None:
    has_presence, has_egress = fea.exfil_prongs_satisfied({"mft", "network"})
    assert has_presence is True
    assert has_egress is True
    assert fea.exfil_two_prongs_met({"mft", "network"})


def test_velociraptor_alone_satisfies_neither_prong() -> None:
    # One artifact class supplying both the collection and the movement claim is
    # not two-pronged corroboration -- same bar as the execution single-class
    # ablation. velociraptor-only must be demoted to a lead.
    has_presence, has_egress = fea.exfil_prongs_satisfied({"velociraptor"})
    assert has_presence is False
    assert has_egress is False
    assert not fea.exfil_two_prongs_met({"velociraptor"})
    # But velociraptor paired with an independent presence class clears egress.
    assert fea.exfil_two_prongs_met({"velociraptor", "mft"})


def _exfil_finding(fid: str, tcid: str) -> dict[str, object]:
    return {
        "finding_id": fid,
        "tool_call_id": tcid,
        "description": "Observed staged archive uploaded outbound to an external host (exfil).",
    }


def _qa(findings, timeline_events, tool_calls):
    return fea.build_report_qa_signoff(
        findings=findings,
        tool_calls=tool_calls,
        verdict="SUSPICIOUS",
        case_completeness={"checks": []},
        attack_coverage={"blind_spot_count": 0},
        normalized_timeline={"events": timeline_events},
        analysis_limitations=[],
    )


def _check(report, check_id):
    return next(c for c in report["checks"] if c["check_id"] == check_id)


def test_report_qa_fails_single_prong_exfil() -> None:
    # Finding cites a network tool only (egress) -- no presence prong.
    finding = _exfil_finding("f-1", "tc-1")
    tool_calls = [{"tool_call_id": "tc-1", "tool": "pcap_triage"}]
    report = _qa([finding], [], tool_calls)
    check = _check(report, "exfiltration_requires_staging_and_movement")
    assert check["status"] == "FAIL"
    assert "f-1" in check["evidence"]


def test_report_qa_passes_two_prong_exfil() -> None:
    # Finding cites an mft tool (presence) and a timeline event tags a network
    # class (egress) -- both prongs cleared, so the gate PASSes.
    finding = _exfil_finding("f-1", "tc-1")
    tool_calls = [{"tool_call_id": "tc-1", "tool": "mft_timeline"}]
    timeline_events = [
        {"linked_finding_ids": ["f-1"], "artifact_class": "network"},
    ]
    report = _qa([finding], timeline_events, tool_calls)
    check = _check(report, "exfiltration_requires_staging_and_movement")
    assert check["status"] == "PASS"
