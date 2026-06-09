"""Tests for the shared execution-claim predicate and engine/correlator parity.

``findevil_agent.execution_claim.is_execution_claim`` is the single source of
truth. Two gates must agree with it:

- ``correlator._is_execution_claim`` (agent venv).
- ``find_evil_auto._claims_execution`` (inline mirror; the bare-3.10 host engine
  cannot import findevil_agent). This module imports the engine under the agent
  venv and pins the two predicates to identical behavior — the enforcement that
  replaces a literal shared call.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import ClassVar

from findevil_agent.execution_claim import is_execution_claim

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402


class TestSharedPredicate:
    def test_execution_verbs_trigger(self) -> None:
        for text in (
            "cain.exe executed on this host",
            "the binary ran at 02:11",
            "Prefetch run count = 3",
            "EID 4688 process creation of calc.exe",
            "powershell was invoked with an encoded command",
            "service launched a child process",
            "calc.exe spawned by WmiPrvSE.exe",
            "the service started cmd.exe",
        ):
            assert is_execution_claim(text) is True, text

    def test_non_execution_prose_does_not_trigger(self) -> None:
        for text in (
            "Scheduled task created in the Windows namespace",
            "registry Run key persists attacker.exe",
            "the narrow typed tool surface has no execute_shell verb",
            "outbound connection to a C2 domain",
        ):
            assert is_execution_claim(text) is False, text

    def test_execution_mitre_triggers_without_prose(self) -> None:
        # A scheduled-task finding (T1053) is an execution claim even when the
        # prose carries no execution verb.
        assert is_execution_claim("Scheduled task created", "T1053.005") is True
        assert is_execution_claim("autostart Run key set", "T1547.001") is True

    def test_non_execution_mitre_does_not_trigger(self) -> None:
        assert is_execution_claim("data archived for staging", "T1560") is False
        assert is_execution_claim("benign", None) is False


def _finding(description: str, mitre: str | None = None) -> dict:
    return {
        "finding_id": "f-1",
        "tool_call_id": "tc-1",
        "description": description,
        "confidence": "CONFIRMED",
        "mitre_technique": mitre,
    }


class TestEngineCorrelatorParity:
    """The engine's inline gate must agree with the shared predicate on the very
    cases that historically diverged (spawned / invoked / started / MITRE-only)."""

    CASES: ClassVar[list[tuple[str, str | None]]] = [
        ("cain.exe executed on this host", None),
        ("calc.exe spawned by WmiPrvSE.exe", None),
        ("powershell invoked with -enc", None),
        ("the service started cmd.exe", None),
        ("Prefetch run count = 3", None),
        ("EID 4688 process creation", None),
        ("Scheduled task created in the Windows namespace", "T1053.005"),
        ("autostart Run key set", "T1547.001"),
        ("Scheduled task created in the Windows namespace", None),
        ("the narrow typed tool surface has no execute_shell verb", None),
        ("outbound connection to a C2 domain", "T1041"),
    ]

    def test_engine_matches_shared_predicate(self) -> None:
        for description, mitre in self.CASES:
            finding = _finding(description, mitre)
            expected = is_execution_claim(fea._finding_text(finding), mitre)
            assert fea._claims_execution(finding) is expected, (description, mitre)
