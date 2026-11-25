"""Tests for the memory-lane notable-application presence detectors.

The deterministic memory lane collects process names from vol_pslist and
vol_psscan but historically never stated an application-level claim — a run
could observe ``KeePass.exe, cmd.exe, chrome.exe`` in its own tool output and
still emit zero findings about them. ``detect_notable_applications`` turns the
already-collected process names into Pool-B PRESENCE findings (browser /
credential-store / interactive user application), and
``detect_console_activity`` does the same for ``vol_run`` windows.cmdline /
windows.consoles rows.

Load-bearing properties pinned here:

* PRESENCE wording only — no finding may trip the execution-claim predicate
  (``_claims_execution``): the >=2-artifact-class execution gate would
  correctly flag a memory-only "ran/executed" claim.
* ``derived_from`` cites ONLY the tool calls whose output actually contains
  the observation — a process seen only by psscan must not fabricate a
  pslist corroboration.
* Confidence is INFERRED, NEVER CONFIRMED. "A process named keepass.exe is
  present" is a genuine tool observation, but in this engine the CONFIRMED
  tier drives verdict escalation (any CONFIRMED finding => SUSPICIOUS), and a
  password manager in the process list is ubiquitous legitimate software — a
  CONFIRMED presence finding would mark every healthy machine that runs
  KeePass as SUSPICIOUS. The FP-floor tests below pin that decision.
* The findings genuinely satisfy the offline recall scorer's eligibility
  matcher against the real memlabs goldens (measured with the scorer's own
  ``_is_eligible``, not hoped for).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[3]
_SCRIPTS = _REPO / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402

from findevil_agent.accuracy import _is_eligible  # noqa: E402

CASE = "case-mem-notable"
EVIDENCE = "/evidence/memdump.raw"
TCID_PSLIST = "tc-001"
TCID_PSSCAN = "tc-002"
TCID_CMDLINE = "tc-003"
TCID_CONSOLES = "tc-004"


def _proc(pid: int, name: str) -> dict:
    """A row shaped like the Rust ``VolProcess`` serialization."""
    return {
        "pid": pid,
        "ppid": 4,
        "image_name": name,
        "create_time_iso": "2019-12-14T10:00:00+00:00",
        "exit_time_iso": None,
        "threads": 4,
        "handles": 100,
        "session_id": 1,
    }


def _cmdline_row(pid: int, process: str, args: str) -> dict:
    """A row shaped like Vol3 ``windows.cmdline -r json`` output (vol_run rows)."""
    return {"PID": pid, "Process": process, "Args": args}


def _notable(ps, psscan, **kwargs):
    return fea.detect_notable_applications(
        ps,
        psscan,
        TCID_PSLIST,
        TCID_PSSCAN,
        CASE,
        EVIDENCE,
        **kwargs,
    )


def _by_base(findings: list[dict]) -> dict[str, dict]:
    return {f["finding_id"]: f for f in findings}


# ---------------------------------------------------------------------------
# Category detection
# ---------------------------------------------------------------------------


class TestCategoryDetection:
    def test_browser_process_in_both_views_emits_browser_presence_finding(self) -> None:
        ps = [_proc(4204, "chrome.exe"), _proc(500, "svchost.exe")]
        findings = _notable(ps, ps)
        assert len(findings) == 1
        f = findings[0]
        assert f["finding_id"] == "f-B-notable-browser"
        assert f["case_id"] == CASE
        assert f["artifact_path"] == EVIDENCE
        assert f["confidence"] == "INFERRED"
        assert f["pool_origin"] == "B"
        assert f["mitre_technique"] is None
        assert "chrome.exe" in f["description"]
        assert f["derived_from"] == [TCID_PSLIST, TCID_PSSCAN]
        assert f["tool_call_id"] == TCID_PSLIST

    def test_credential_store_process_emits_t1555_tagged_finding(self) -> None:
        ps = [_proc(3128, "KeePass.exe"), _proc(500, "svchost.exe")]
        findings = _notable(ps, ps)
        assert len(findings) == 1
        f = findings[0]
        assert f["finding_id"] == "f-B-notable-credstore"
        assert f["mitre_technique"] == "T1555"
        assert "keepass.exe" in f["description"].lower()

    def test_interactive_user_app_emits_user_application_finding(self) -> None:
        ps = [_proc(2424, "mspaint.exe"), _proc(500, "svchost.exe")]
        findings = _notable(ps, ps)
        assert len(findings) == 1
        f = findings[0]
        assert f["finding_id"] == "f-B-notable-userapps"
        assert f["mitre_technique"] is None
        assert "mspaint.exe" in f["description"]

    def test_all_three_categories_fire_independently(self) -> None:
        ps = [
            _proc(1, "chrome.exe"),
            _proc(2, "KeePass.exe"),
            _proc(3, "mspaint.exe"),
        ]
        bases = set(_by_base(_notable(ps, ps)))
        assert bases == {
            "f-B-notable-browser",
            "f-B-notable-credstore",
            "f-B-notable-userapps",
        }

    def test_common_windows_procs_only_emit_nothing(self) -> None:
        # FP floor: a plain Windows service surface must not produce
        # application-presence findings.
        ps = [_proc(4, "System"), _proc(500, "svchost.exe"), _proc(600, "lsass.exe")]
        assert _notable(ps, ps) == []

    def test_empty_views_emit_nothing(self) -> None:
        assert _notable([], []) == []

    def test_name_matching_is_case_insensitive(self) -> None:
        ps = [_proc(1, "CHROME.EXE")]
        findings = _notable(ps, ps)
        assert [f["finding_id"] for f in findings] == ["f-B-notable-browser"]

    def test_finding_id_for_callable_is_applied(self) -> None:
        ps = [_proc(1, "chrome.exe")]
        findings = _notable(ps, ps, finding_id_for=lambda base: f"{base}-abcd1234")
        assert findings[0]["finding_id"] == "f-B-notable-browser-abcd1234"


# ---------------------------------------------------------------------------
# Citation honesty — derived_from only cites tools that saw the process
# ---------------------------------------------------------------------------


class TestDerivedFromHonesty:
    def test_psscan_only_observation_cites_only_psscan(self) -> None:
        findings = _notable([], [_proc(1, "chrome.exe")])
        f = findings[0]
        assert f["derived_from"] == [TCID_PSSCAN]
        assert f["tool_call_id"] == TCID_PSSCAN

    def test_pslist_only_observation_cites_only_pslist(self) -> None:
        findings = _notable([_proc(1, "chrome.exe")], [])
        f = findings[0]
        assert f["derived_from"] == [TCID_PSLIST]
        assert f["tool_call_id"] == TCID_PSLIST

    def test_cross_validated_wording_only_when_both_views_observe(self) -> None:
        both = _notable([_proc(1, "chrome.exe")], [_proc(1, "chrome.exe")])[0]
        single = _notable([], [_proc(1, "chrome.exe")])[0]
        assert "cross-validated" in both["description"]
        assert "cross-validated" not in single["description"]


# ---------------------------------------------------------------------------
# Presence wording — never an execution claim
# ---------------------------------------------------------------------------


class TestPresenceWordingDiscipline:
    def test_no_notable_finding_trips_the_execution_claim_predicate(self) -> None:
        ps = [
            _proc(1, "chrome.exe"),
            _proc(2, "KeePass.exe"),
            _proc(3, "mspaint.exe"),
        ]
        for f in _notable(ps, ps):
            assert not fea._claims_execution(f), f["description"]

    def test_console_finding_does_not_trip_the_execution_claim_predicate(self) -> None:
        rows = [_cmdline_row(1984, "cmd.exe", "C:\\Windows\\system32\\cmd.exe")]
        for f in fea.detect_console_activity(rows, [], TCID_CMDLINE, None, CASE, EVIDENCE):
            assert not fea._claims_execution(f), f["description"]


# ---------------------------------------------------------------------------
# Console / command-line detector (vol_run windows.cmdline + windows.consoles)
# ---------------------------------------------------------------------------


class TestConsoleActivityDetector:
    def test_cmd_with_recorded_command_line_emits_presence_finding(self) -> None:
        rows = [
            _cmdline_row(1984, "cmd.exe", "C:\\Windows\\system32\\cmd.exe"),
            _cmdline_row(500, "svchost.exe", "svchost.exe -k netsvcs"),
        ]
        findings = fea.detect_console_activity(rows, [], TCID_CMDLINE, None, CASE, EVIDENCE)
        assert len(findings) == 1
        f = findings[0]
        assert f["finding_id"] == "f-B-console-cmdline"
        assert f["confidence"] == "INFERRED"
        assert f["pool_origin"] == "B"
        assert f["mitre_technique"] is None  # T1059 would trip the exec gate
        assert "cmd.exe" in f["description"]
        assert f["derived_from"] == [TCID_CMDLINE]

    def test_consoles_rows_are_cited_when_present(self) -> None:
        rows = [_cmdline_row(1984, "cmd.exe", "C:\\Windows\\system32\\cmd.exe")]
        consoles = [{"PID": 1984, "Process": "conhost.exe"}]
        f = fea.detect_console_activity(
            rows, consoles, TCID_CMDLINE, TCID_CONSOLES, CASE, EVIDENCE
        )[0]
        assert f["derived_from"] == [TCID_CMDLINE, TCID_CONSOLES]
        assert "windows.consoles" in f["description"]

    def test_no_console_host_rows_emit_nothing(self) -> None:
        rows = [_cmdline_row(500, "svchost.exe", "svchost.exe -k netsvcs")]
        assert fea.detect_console_activity(rows, [], TCID_CMDLINE, None, CASE, EVIDENCE) == []

    def test_unreadable_args_rows_are_ignored(self) -> None:
        rows = [
            _cmdline_row(1984, "cmd.exe", "Required memory at 0x7f0000 is not valid"),
        ]
        assert fea.detect_console_activity(rows, [], TCID_CMDLINE, None, CASE, EVIDENCE) == []

    def test_corroborating_tcids_are_appended(self) -> None:
        rows = [_cmdline_row(1984, "cmd.exe", "C:\\Windows\\system32\\cmd.exe")]
        f = fea.detect_console_activity(
            rows,
            [],
            TCID_CMDLINE,
            None,
            CASE,
            EVIDENCE,
            corroborating_tcids=(TCID_PSLIST,),
        )[0]
        assert f["derived_from"] == [TCID_CMDLINE, TCID_PSLIST]


# ---------------------------------------------------------------------------
# Verdict discipline — deliberately NO CONFIRMED tier for presence findings
# ---------------------------------------------------------------------------


class TestVerdictFpFloor:
    """Presence of legitimate software is not evil. CONFIRMED would escalate
    every benign host running a browser or password manager to SUSPICIOUS via
    ``compute_verdict`` (any CONFIRMED finding => SUSPICIOUS). Pin INFERRED and
    pin the verdict outcome so a future 'make the golden green' edit has to
    delete these tests to sneak the escalation in."""

    def _all_findings(self) -> list[dict]:
        ps = [
            _proc(1, "chrome.exe"),
            _proc(2, "KeePass.exe"),
            _proc(3, "mspaint.exe"),
        ]
        cmd = [_cmdline_row(1984, "cmd.exe", "C:\\Windows\\system32\\cmd.exe")]
        return _notable(ps, ps) + fea.detect_console_activity(
            cmd, [], TCID_CMDLINE, None, CASE, EVIDENCE
        )

    def test_no_presence_finding_is_ever_confirmed(self) -> None:
        for f in self._all_findings():
            assert f["confidence"] == "INFERRED", f["finding_id"]

    def test_presence_only_merged_set_does_not_escalate_verdict(self) -> None:
        stub = object.__new__(fea.Investigation)
        verdict = fea.Investigation.compute_verdict(stub, self._all_findings())
        assert verdict == "INDETERMINATE"


# ---------------------------------------------------------------------------
# Golden eligibility — measured with the recall scorer's own matcher
# ---------------------------------------------------------------------------


def _golden_findings(case_id: str) -> dict[str, dict]:
    path = _REPO / "goldens" / case_id / "expected-findings.json"
    doc = json.loads(path.read_text(encoding="utf-8"))
    return {f["finding_id"]: f for f in doc["findings"]}


class TestGoldenEligibility:
    """The detectors must genuinely satisfy the offline scorer's eligibility
    matcher (token coverage over description+hint) for the memlabs claims they
    are meant to recall. Uses the scorer's real ``_is_eligible`` so the
    match is measured, not asserted by hand."""

    def test_lab2_browser_claim_ml2_001_is_recalled(self) -> None:
        # Lab2's real run observed chrome.exe in both process views.
        ps = [_proc(4204, "chrome.exe")]
        f = _by_base(_notable(ps, ps))["f-B-notable-browser"]
        assert _is_eligible(_golden_findings("memlabs-lab2")["ml2-001"], f)

    def test_lab2_credential_store_claim_ml2_002_is_recalled(self) -> None:
        ps = [_proc(3128, "KeePass.exe")]
        f = _by_base(_notable(ps, ps))["f-B-notable-credstore"]
        assert _is_eligible(_golden_findings("memlabs-lab2")["ml2-002"], f)

    def test_lab1_paint_activity_claim_ml1_002_is_recalled(self) -> None:
        ps = [_proc(2424, "mspaint.exe")]
        f = _by_base(_notable(ps, ps))["f-B-notable-userapps"]
        assert _is_eligible(_golden_findings("memlabs-lab1")["ml1-002"], f)

    def test_lab1_command_window_claim_ml1_001_is_recalled(self) -> None:
        rows = [_cmdline_row(1984, "cmd.exe", "C:\\Windows\\system32\\cmd.exe")]
        consoles = [{"PID": 1984, "Process": "conhost.exe"}]
        f = fea.detect_console_activity(
            rows, consoles, TCID_CMDLINE, TCID_CONSOLES, CASE, EVIDENCE
        )[0]
        assert _is_eligible(_golden_findings("memlabs-lab1")["ml1-001"], f)
