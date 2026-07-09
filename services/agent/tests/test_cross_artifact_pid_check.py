"""Tests for findevil_agent.correlator.cross_artifact_pid_check.

The check is a cross-source DEPTH lead: a memory process that is INDEPENDENTLY
suspicious (an injected region via ``vol_malfind`` / hidden via ``vol_psxview``)
AND has no matching on-disk execution record (Prefetch / Amcache) is a
fileless/injected discrepancy worth a HYPOTHESIS lead. A plain memory-vs-disk gap
(not suspicious) is common/benign and must be suppressed. It is deliberately NOT
an execution claim, so the correlator's >=2-artifact downgrade path must leave it
untouched.
"""

from __future__ import annotations

from findevil_agent.correlator import (
    MemoryProcess,
    build_cross_artifact_findings,
    correlate,
    cross_artifact_pid_check,
)
from findevil_agent.execution_claim import is_execution_claim

_REASON = "shows an injected memory region (malfind)"


def _proc(
    name: str,
    pid: int = 100,
    *,
    source: str = "pslist",
    tcid: str = "tc-7",
    suspicious: bool = True,
    reason: str = _REASON,
) -> MemoryProcess:
    return MemoryProcess(
        pid=pid,
        name=name,
        source=source,
        tool_call_id=tcid,
        suspicious=suspicious,
        suspicion_reason=reason,
    )


CASE = {"case_id": "c", "memory_artifact_path": "memory.raw"}


class TestGating:
    def test_suspicious_process_with_no_disk_record_flags(self) -> None:
        findings = cross_artifact_pid_check(
            [_proc("evil.exe", 1337)], {"cmd.exe", "explorer.exe"}, **CASE
        )
        assert len(findings) == 1
        f = findings[0]
        assert f.confidence == "HYPOTHESIS"
        assert f.description.startswith("hypothesis:")
        assert "evil.exe" in f.description
        assert "1337" in f.description
        assert "injected" in f.description  # cites the corroborating signal

    def test_non_suspicious_gap_is_suppressed(self) -> None:
        # The core redesign: a plain memory-vs-disk gap WITHOUT an independent
        # injection/hidden signal is common/benign on real hosts -> suppress.
        assert (
            cross_artifact_pid_check(
                [_proc("randomapp.exe", suspicious=False)], {"cmd.exe"}, **CASE
            )
            == []
        )

    def test_emitted_finding_cites_memory_tool_call_id(self) -> None:
        findings = cross_artifact_pid_check([_proc("evil.exe", tcid="tc-42")], {"cmd.exe"}, **CASE)
        assert findings[0].tool_call_id == "tc-42"
        assert findings[0].artifact_path == "memory.raw"

    def test_finding_is_not_an_execution_claim(self) -> None:
        # Critical: description must stay verb-neutral so the correlator's
        # execution >=2-artifact gate does not fire on it.
        findings = cross_artifact_pid_check([_proc("evil.exe")], {"cmd.exe"}, **CASE)
        assert is_execution_claim(findings[0].description, findings[0].mitre_technique) is False
        # correlate() should pass it through unchanged (non-execution claim, kept).
        refined, outcomes = correlate(findings)
        assert refined[0].confidence == "HYPOTHESIS"
        assert outcomes[0].action == "kept"


class TestSuppression:
    def test_corroborated_process_suppressed(self) -> None:
        assert cross_artifact_pid_check([_proc("cmd.exe")], {"cmd.exe"}, **CASE) == []

    def test_case_insensitive_corroboration(self) -> None:
        assert cross_artifact_pid_check([_proc("EVIL.EXE")], {"evil.exe"}, **CASE) == []

    def test_basename_normalization_on_disk_paths(self) -> None:
        # Disk record carried as a full path still corroborates the bare process name.
        assert (
            cross_artifact_pid_check(
                [_proc("evil.exe")], {r"C:\\Windows\\System32\\evil.exe"}, **CASE
            )
            == []
        )

    def test_truncated_name_matches_full_disk_name(self) -> None:
        # psscan truncates image_name to ~14 chars; a truncated memory name must
        # still corroborate against its full disk executable name (no false gap).
        assert (
            cross_artifact_pid_check(
                [_proc("applicationfra")], {"applicationframehost.exe"}, **CASE
            )
            == []
        )

    def test_no_disk_records_returns_empty(self) -> None:
        # Prefetch may be disabled (SSD / EnablePrefetcher=0). With zero disk
        # execution records, absence proves nothing -> suppress entirely.
        assert cross_artifact_pid_check([_proc("evil.exe")], set(), **CASE) == []

    def test_no_memory_processes_returns_empty(self) -> None:
        assert cross_artifact_pid_check([], {"cmd.exe"}, **CASE) == []

    def test_system_processes_skipped(self) -> None:
        procs = [_proc("System", 4), _proc("lsass.exe", 612), _proc("svchost.exe", 800)]
        assert cross_artifact_pid_check(procs, {"cmd.exe"}, **CASE) == []

    def test_truncated_system_name_still_excluded(self) -> None:
        # fontdrvhost.exe truncates to 'fontdrvhost.ex' -> must still be excluded.
        assert cross_artifact_pid_check([_proc("fontdrvhost.ex")], {"cmd.exe"}, **CASE) == []


class TestDedup:
    def test_dedupe_across_pslist_and_psscan(self) -> None:
        procs = [
            _proc("evil.exe", 1337, source="pslist"),
            _proc("evil.exe", 1337, source="psscan"),
        ]
        findings = cross_artifact_pid_check(procs, {"cmd.exe"}, **CASE)
        assert len(findings) == 1

    def test_distinct_processes_each_emit(self) -> None:
        procs = [_proc("evil.exe", 1), _proc("nc.exe", 2)]
        findings = cross_artifact_pid_check(procs, {"cmd.exe"}, **CASE)
        assert len(findings) == 2
        assert {"evil.exe", "nc.exe"} <= {tok for f in findings for tok in f.description.split()}


class TestBuildFromRows:
    """build_cross_artifact_findings: derive suspicion from raw malfind/psxview
    rows (the engine-facing entry point), using the real tool-output shapes."""

    def _build(self, psscan, malfind, psxview, disk, tcid="tc-mem"):
        return build_cross_artifact_findings(
            psscan,
            malfind,
            psxview,
            set(disk),
            memory_tool_call_id=tcid,
            memory_artifact_path="mem.raw",
            case_id="c",
        )

    def test_malfind_injected_process_flags(self) -> None:
        f = self._build(
            [{"pid": 1337, "image_name": "evil.exe"}],
            [{"pid": 1337, "image_name": "evil.exe", "protection": "PAGE_EXECUTE_READ"}],
            [],
            {"cmd.exe"},
        )
        assert len(f) == 1
        assert "injected" in f[0].description
        assert f[0].tool_call_id == "tc-mem"

    def test_psxview_hidden_process_flags(self) -> None:
        f = self._build(
            [{"pid": 628, "image_name": "putty.exe"}],
            [],
            [{"pid": 628, "image_name": "putty.exe", "psscan": True, "pslist": False}],
            {"cmd.exe"},
        )
        assert len(f) == 1
        assert "hidden" in f[0].description

    def test_non_suspicious_process_ignored(self) -> None:
        # in memory, not on disk, but neither injected nor hidden -> no lead.
        f = self._build(
            [{"pid": 900, "image_name": "onedrive.exe"}],
            [],
            [{"pid": 900, "image_name": "onedrive.exe", "psscan": True, "pslist": True}],
            {"cmd.exe"},
        )
        assert f == []

    def test_truncated_suspicious_name_still_matches_disk(self) -> None:
        # injected process whose 14-char psscan name is a prefix of its full disk
        # name -> corroborated on disk -> suppressed (no false discrepancy).
        f = self._build(
            [{"pid": 5, "image_name": "applicationfra"}],
            [{"pid": 5, "image_name": "applicationfra"}],
            [],
            {"applicationframehost.exe"},
        )
        assert f == []
