"""Phase 2b: every CONFIRMED-tier emitter must declare ``asserted_values`` that
genuinely resolve against the RAW tool output the finding cites.

The verifier re-extracts each asserted value from the re-run tool output (not
the bare row list the Python emitter happens to iterate), so a path that does
not resolve against the real serialized output shape silently fails entailment.
These tests pin each emitter's paths to a fixture shaped EXACTLY like the Rust
tool's serialized output — proving the paths are correct, not merely present.

Reference pattern: ``test_registry_persistence.py``.
"""

from __future__ import annotations

import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402

from findevil_agent.entailment import check_entailment  # noqa: E402
from findevil_agent.events import AssertedValue  # noqa: E402


def _avs(finding: dict) -> list[AssertedValue]:
    return [AssertedValue(**av) for av in finding.get("asserted_values", [])]


class TestEvtxAuditLogClearedAssertedValues:
    """EID 1102 audit-log-cleared (``evtx_rows_to_findings``). The finding cites
    ``evtx_query`` whose RAW output is ``{"rows": [EvtxRow, ...], ...}`` with each
    ``EvtxRow`` serializing a FLAT ``event_id: u32`` (Rust ``pick_event_id``
    collapses the nested EVTX-XML ``EventID.#text`` to a scalar before
    serialization — see ``services/mcp/src/tools/evtx_query.rs``), plus
    ``channel: String`` and ``record_id: u64``."""

    def _raw_evtx_output(self) -> dict:
        """Mirror the serialized ``EvtxQueryOutput``: a ``rows`` list of
        ``EvtxRow`` (event_id is a flat scalar, never nested)."""
        return {
            "rows": [
                {
                    "event_id": 1102,
                    "ts": "2018-09-06T19:05:11Z",
                    "channel": "Security",
                    "record_id": 4242,
                    "data": {"Event": {"System": {"EventID": 1102}}},
                }
            ],
            "parse_errors": 0,
            "row_count": 1,
            "records_seen": 1,
        }

    def _finding(self) -> dict:
        out = self._raw_evtx_output()
        findings = fea.evtx_rows_to_findings(
            out["rows"], "tc-evtx-1", "case-evtxtest", "/evidence/Security.evtx"
        )
        cleared = [f for f in findings if f["finding_id"] == "f-A-evtx-audit-log-cleared"]
        assert len(cleared) == 1, "EID 1102 row must yield the audit-log-cleared finding"
        return cleared[0]

    def test_finding_declares_non_empty_asserted_values(self) -> None:
        f = self._finding()
        assert f["confidence"] == "CONFIRMED"
        assert f.get("asserted_values"), "CONFIRMED audit-log-cleared finding must assert values"

    def test_asserted_values_pass_entailment_against_raw_evtx_output(self) -> None:
        f = self._finding()
        out = self._raw_evtx_output()
        result = check_entailment(_avs(f), out)
        assert result.passed, result.reason

    def test_misread_caught_when_eid_1102_absent_from_output(self) -> None:
        # A logon row, not a log-clear — the asserted EID 1102 is not entailed.
        f = self._finding()
        out = {
            "rows": [
                {
                    "event_id": 4624,
                    "ts": "2018-09-06T19:05:11Z",
                    "channel": "Security",
                    "record_id": 4242,
                    "data": {},
                }
            ],
            "parse_errors": 0,
            "row_count": 1,
            "records_seen": 1,
        }
        result = check_entailment(_avs(f), out)
        assert not result.passed, "entailment must reject when EID 1102 is absent from rows"


class TestPrefetchExecAssertedValues:
    """The prefetch execution lead (created INFERRED, upgraded to CONFIRMED at
    the UserAssist corroboration). It cites ``prefetch_parse`` whose RAW output
    has top-level ``executable_name: String`` and ``run_count: u32`` (see
    ``services/mcp/src/tools/prefetch_parse.rs`` ``PrefetchOutput``)."""

    def _inv(self):
        inv = fea.Investigation("memory.img", unattended=True, with_report=False)
        inv.handle = {"id": "case-pftest"}
        return inv

    def _raw_prefetch_output(self) -> dict:
        return {
            "executable_name": "CAIN.EXE",
            "version": 23,
            "run_count": 7,
            "last_run_times_iso": ["2018-09-06T19:00:00Z"],
            "file_references": [],
            "volume_paths": [],
        }

    def _finding(self, inv) -> dict:
        out = self._raw_prefetch_output()
        return inv._build_prefetch_exec_finding(
            executable_name=out["executable_name"],
            run_count=out["run_count"],
            tool_description="Cain password-recovery/network hacking tool",
            technique="T1588.002",
            tcid="tc-pf-1",
            path="/evidence/CAIN.EXE-AAAA1111.pf",
        )

    def test_finding_declares_non_empty_asserted_values(self) -> None:
        f = self._finding(self._inv())
        assert f.get("asserted_values"), "prefetch exec finding must assert values"

    def test_asserted_values_pass_entailment_against_raw_prefetch_output(self) -> None:
        f = self._finding(self._inv())
        out = self._raw_prefetch_output()
        result = check_entailment(_avs(f), out)
        assert result.passed, result.reason

    def test_asserted_values_survive_the_confirmed_upgrade(self) -> None:
        # The upgrade flips confidence + description + derived_from but leaves the
        # primary tool_call_id (the prefetch replay) untouched, so the same
        # prefetch-shaped assertions must still entail after the upgrade.
        f = self._finding(self._inv())
        avs_before = list(f["asserted_values"])
        f["confidence"] = "CONFIRMED"  # mirror the line ~8818 in-place upgrade
        assert f["asserted_values"] == avs_before
        out = self._raw_prefetch_output()
        assert check_entailment(_avs(f), out).passed

    def test_misread_caught_when_run_count_differs(self) -> None:
        f = self._finding(self._inv())
        out = self._raw_prefetch_output()
        out["run_count"] = 99  # the cited output says 99, the finding asserted 7
        result = check_entailment(_avs(f), out)
        assert not result.passed, "entailment must reject a run_count that differs"

    def test_misread_caught_when_executable_name_differs(self) -> None:
        f = self._finding(self._inv())
        out = self._raw_prefetch_output()
        out["executable_name"] = "NOTEPAD.EXE"
        result = check_entailment(_avs(f), out)
        assert not result.passed, "entailment must reject an executable_name that differs"
