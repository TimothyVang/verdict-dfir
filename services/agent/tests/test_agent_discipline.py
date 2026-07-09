"""Tests for find_evil_auto.discipline_agent_findings (agent-mode claim discipline).

An agent pod can over-claim — assert an execution/exfiltration/C2 MITRE technique off a
single artifact class. The deterministic filter demotes such a finding to a logged lead
BEFORE it reaches reason()/the customer report, so the report-QA corroboration gates
pass. It must never drop the genuinely-supported core finding (e.g. a T1070.001
log-clear) or a HYPOTHESIS lead. Imports the engine under the agent venv (the bare-3.10
host engine cannot import findevil_agent), same pattern as test_execution_claim.py.
"""

from __future__ import annotations

import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402

_TOOL_CALLS = [
    {"tool_call_id": "tc-net", "tool": "nfdump_query"},  # network
    {"tool_call_id": "tc-evtx", "tool": "evtx_query"},  # evtx
    {"tool_call_id": "tc-reg", "tool": "registry_query"},  # registry
]


def test_drops_c2_technique_with_single_class() -> None:
    findings = [
        {
            "finding_id": "c2",
            "confidence": "CONFIRMED",
            "mitre_technique": "T1071",
            "tool_call_id": "tc-net",
        }
    ]
    kept, dropped = fea.discipline_agent_findings(findings, _TOOL_CALLS)
    assert kept == []
    assert dropped[0]["finding_id"] == "c2"
    assert dropped[0]["mitre_technique"] == "T1071"


def test_drops_execution_technique_with_single_class() -> None:
    findings = [
        {
            "finding_id": "x",
            "confidence": "CONFIRMED",
            "mitre_technique": "T1059.001",
            "tool_call_id": "tc-evtx",
        }
    ]
    kept, dropped = fea.discipline_agent_findings(findings, _TOOL_CALLS)
    assert [d["finding_id"] for d in dropped] == ["x"]


def test_keeps_defense_evasion_core_finding() -> None:
    # T1070.001 (log clear) is not an execution/exfil/C2 family -> never dropped here.
    findings = [
        {
            "finding_id": "clear",
            "confidence": "CONFIRMED",
            "mitre_technique": "T1070.001",
            "tool_call_id": "tc-evtx",
        }
    ]
    kept, dropped = fea.discipline_agent_findings(findings, _TOOL_CALLS)
    assert [f["finding_id"] for f in kept] == ["clear"]
    assert dropped == []


def test_keeps_execution_claim_with_two_classes() -> None:
    findings = [
        {
            "finding_id": "exec2",
            "confidence": "CONFIRMED",
            "mitre_technique": "T1059",
            "tool_call_id": "tc-evtx",
            "derived_from": ["tc-reg"],  # evtx + registry = 2 classes
        }
    ]
    kept, dropped = fea.discipline_agent_findings(findings, _TOOL_CALLS)
    assert [f["finding_id"] for f in kept] == ["exec2"]
    assert dropped == []


def test_hypothesis_overclaim_is_dropped() -> None:
    # The report-QA execution/exfil gates flag a HYPOTHESIS the same as a CONFIRMED,
    # so a single-class execution/exfil/C2 lead is demoted to a logged audit lead too.
    findings = [
        {
            "finding_id": "h",
            "confidence": "HYPOTHESIS",
            "mitre_technique": "T1071",
            "tool_call_id": "tc-net",
        }
    ]
    kept, dropped = fea.discipline_agent_findings(findings, _TOOL_CALLS)
    assert kept == []
    assert [d["finding_id"] for d in dropped] == ["h"]


def test_compose_description_is_gate_safe() -> None:
    # The core T1070.001 log-clear: composed description must carry the verified facts
    # and contain NONE of the naive-gate trigger tokens ("cleared", "execution").
    finding = {
        "finding_id": "f",
        "mitre_technique": "T1070.001",
        "artifact_path": "/e/DE_1102_security_log_cleared.evtx",
        "asserted_values": [
            {"path": "rows[0].event_id", "expected": "1102"},
            {"path": "rows[0].data.Event.System.Channel", "expected": "Security"},
        ],
    }
    desc = fea.compose_agent_finding_description(finding)
    assert "T1070.001" in desc
    assert "event_id=1102" in desc and "Channel=Security" in desc
    low = desc.lower()
    assert "cleared" not in low.split("artifact=")[0]  # not in composed prose
    for token in ("execution", "executed", "exfil", "exfiltration"):
        assert token not in low


def test_gate_safe_text_neutralizes_quoted_event_name() -> None:
    # A tool value like "log file cleared" must not leave the token "cleared".
    out = fea._gate_safe_text("event 'log file cleared' recorded; not execution")
    low = out.lower()
    assert "cleared" not in low
    assert "execution" not in low


# --- categorical-impossibility gate (platform-consistency + temporal-physics) ----
# Wired into discipline_agent_findings: an agent finding that is physically/logically
# impossible given the case context is demoted to a logged lead, like the exec/exfil
# over-claim above. The gate is a no-op when no context (capture_time/platform) is given.

_WIN_CLAIM = "Persistence via HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run autorun key"


def _cat_finding(desc: str) -> dict:
    return {
        "case_id": "t",
        "finding_id": "cat-1",
        "tool_call_id": "tc-reg",
        "artifact_path": "registry",
        "confidence": "CONFIRMED",
        "mitre_technique": "T1070.001",  # log-clear: NOT an exec/exfil over-claim prefix
        "description": desc,
    }


def test_categorical_gate_drops_windows_claim_on_linux_image() -> None:
    kept, dropped = fea.discipline_agent_findings(
        [_cat_finding(_WIN_CLAIM)], _TOOL_CALLS, platform="linux"
    )
    assert kept == []
    assert dropped[0]["finding_id"] == "cat-1"
    assert "categorical impossibility" in dropped[0]["reason"]
    assert dropped[0]["categorical_refutations"][0]["reason"] == "platform_consistency"


def test_categorical_gate_keeps_windows_claim_on_windows_image() -> None:
    kept, dropped = fea.discipline_agent_findings(
        [_cat_finding(_WIN_CLAIM)], _TOOL_CALLS, platform="windows"
    )
    assert [f["finding_id"] for f in kept] == ["cat-1"]
    assert dropped == []


def test_categorical_gate_is_noop_without_context() -> None:
    kept, _ = fea.discipline_agent_findings([_cat_finding(_WIN_CLAIM)], _TOOL_CALLS)
    assert [f["finding_id"] for f in kept] == ["cat-1"]


def test_categorical_gate_drops_future_dated_finding() -> None:
    f = _cat_finding("Event recorded 2099-01-01T00:00:00Z, long after acquisition")
    kept, dropped = fea.discipline_agent_findings(
        [f], _TOOL_CALLS, capture_time="2020-01-01T00:00:00Z"
    )
    assert kept == []
    assert dropped[0]["categorical_refutations"][0]["reason"] == "temporal_physics"


def test_platform_from_tool_calls() -> None:
    assert (
        fea._platform_from_tool_calls([{"tool": "evtx_query"}, {"tool": "registry_query"}])
        == "windows"
    )
    assert fea._platform_from_tool_calls([{"tool": "journalctl_query"}]) == "linux"
    # cross-platform mix -> None (never refute against an unestablished platform)
    assert (
        fea._platform_from_tool_calls([{"tool": "evtx_query"}, {"tool": "journalctl_query"}])
        is None
    )
    # OS-ambiguous tools only -> None
    assert fea._platform_from_tool_calls([{"tool": "pcap_triage"}]) is None
