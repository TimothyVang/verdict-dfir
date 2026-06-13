"""Tests for findevil_agent.playbook — canonical DFIR rules module."""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar

import pytest

from findevil_agent.playbook import (
    JUDGE_SELFSCORE_CRITERIA,
    TOOL_SEQUENCES,
    classify_artifact_path,
    detect_evidence_type,
)

REPO_ROOT = Path(__file__).parent.parent.parent.parent
JUDGING_MD = REPO_ROOT / "agent-config" / "JUDGING.md"
PLAYBOOK_MD = REPO_ROOT / "agent-config" / "PLAYBOOK.md"


class TestDetectEvidenceType:
    """detect_evidence_type must match the legacy behaviour in find_evil_auto.py."""

    CASES: ClassVar[list[tuple[str, str]]] = [
        # memory
        ("memdump.mem", "memory"),
        ("win10.raw", "memory"),
        ("vm.vmem", "memory"),
        ("crash.dmp", "memory"),
        # sysmon EVTX → network lane
        ("sysmon.evtx", "network"),
        ("Microsoft-Windows-Sysmon%4Operational.evtx", "network"),
        # plain EVTX
        ("Security.evtx", "evtx"),
        ("System.evtx", "evtx"),
        # pcap
        ("capture.pcap", "network"),
        ("traffic.pcapng", "network"),
        ("dump.cap", "network"),
        # disk images
        ("image.e01", "disk"),
        ("disk.dd", "disk"),
        ("forensic.aff", "disk"),
        # velociraptor zip
        ("collection.zip", "velociraptor"),
        # unknown
        ("readme.txt", "unknown"),
        ("amcache.hve", "unknown"),  # registry hive — classified by classify_artifact_path
    ]

    @pytest.mark.parametrize("filename,expected", CASES)
    def test_detect_evidence_type_matches_legacy_cases(self, filename: str, expected: str) -> None:
        assert detect_evidence_type(filename) == expected

    def test_windows_path_separator(self) -> None:
        assert detect_evidence_type(r"C:\cases\dump.mem") == "memory"

    def test_posix_path(self) -> None:
        assert detect_evidence_type("/cases/Security.evtx") == "evtx"


class TestClassifyArtifactPath:
    """classify_artifact_path must agree with the legacy in find_evil_auto.py."""

    @pytest.mark.parametrize(
        "path,expected_class,expected_tool",
        [
            ("dump.mem", "memory", "memory_playbook"),
            ("sysmon.evtx", "sysmon_network", "sysmon_network_query"),
            ("Security.evtx", "evtx", "evtx_query"),
            ("capture.pcap", "pcap", "pcap_triage"),
            ("capture.pcapng", "pcap", "pcap_triage"),
            ("conn.log", "zeek", "zeek_summary"),
            ("disk.e01", "raw_disk", None),
            ("$MFT", "mft", "mft_timeline"),
            ("SVCHOST.EXE-ABCDEF12.pf", "prefetch", "prefetch_parse"),
            ("NTUSER.DAT", "registry", "registry_query"),
            ("amcache.hve", "amcache", "ez_parse"),
            ("$UsnJrnl", "usnjrnl", "usnjrnl_query"),
            (
                "Documents and Settings/Mr. Evil/Recent/staged-files.lnk",
                "lnk",
                "ez_parse",
            ),
            (
                "RECYCLER/S-1-5-21-1000/INFO2",
                "recyclebin",
                "plaso_parse",
            ),
            (
                "$Recycle.Bin/S-1-5-21-1004/$IABC123.txt",
                "recyclebin",
                "ez_parse",
            ),
            ("Windows/System32/config/SecEvent.Evt", "legacy_evt", "plaso_parse"),
            (
                "Documents and Settings/Mr. Evil/Local Settings/History/History.IE5/index.dat",
                "ie_history",
                "plaso_parse",
            ),
            ("Documents and Settings/Mr. Evil/My Documents/Thumbs.db", "thumbnail", None),
            ("malware.exe", "yara_target", "yara_scan"),
            ("collection.zip", "velociraptor", "vel_collect"),
            ("History", "browser_db", "browser_history"),
            ("places.sqlite", "browser_db", "browser_history"),
            ("Archived History.sqlite", "browser_db", "browser_history"),
            ("readme.txt", "unknown", None),
        ],
    )
    def test_classify_returns_expected(
        self, path: str, expected_class: str, expected_tool: str | None
    ) -> None:
        result = classify_artifact_path(path)
        assert result["artifact_class"] == expected_class
        assert result["parser_tool"] == expected_tool

    def test_zeek_by_path_component(self) -> None:
        result = classify_artifact_path("/zeek/logs/weird.log")
        assert result["artifact_class"] == "zeek"

    def test_windows_backslash_paths(self) -> None:
        result = classify_artifact_path(r"C:\cases\NTUSER.DAT")
        assert result["artifact_class"] == "registry"


class TestToolSequences:
    def test_tool_sequences_cover_all_evidence_types(self) -> None:
        required = {
            "disk",
            "memory",
            "evtx",
            "network",
            "velociraptor",
            "extracted_disk",
            "directory",
            "unknown",
        }
        assert required.issubset(set(TOOL_SEQUENCES.keys()))

    def test_memory_sequence_has_pslist_and_psscan(self) -> None:
        tools = [s.tool for s in TOOL_SEQUENCES["memory"]]
        assert "vol_pslist" in tools
        assert "vol_psscan" in tools

    def test_disk_sequence_has_mft_and_registry(self) -> None:
        tools = [s.tool for s in TOOL_SEQUENCES["disk"]]
        assert "mft_timeline" in tools
        assert "registry_query" in tools

    def test_playbook_steps_are_frozen(self) -> None:
        step = TOOL_SEQUENCES["evtx"][0]
        with pytest.raises((AttributeError, TypeError)):
            step.tool = "something_else"  # type: ignore[misc]


class TestJudgeSelfscoreCriteria:
    def test_exactly_six_criteria(self) -> None:
        assert len(JUDGE_SELFSCORE_CRITERIA) == 6

    def test_criteria_numbers_are_1_to_6(self) -> None:
        nums = [c["criterion"] for c in JUDGE_SELFSCORE_CRITERIA]
        assert nums == [1, 2, 3, 4, 5, 6]

    def test_judge_selfscore_criteria_match_judging_md(self) -> None:
        """Criteria questions must match the JUDGING.md self-check table."""
        if not JUDGING_MD.exists():
            pytest.skip("agent-config/JUDGING.md not found relative to repo root")
        judging_text = JUDGING_MD.read_text()
        for entry in JUDGE_SELFSCORE_CRITERIA:
            # Each question should appear (at least partially) in JUDGING.md.
            # We check the first 40 chars to be resilient to minor wording.
            snippet = entry["question"][:40]
            assert (
                snippet in judging_text
            ), f"Criterion {entry['criterion']} question not found in JUDGING.md: {snippet!r}"

    def test_playbook_md_tables_match_module(self) -> None:
        """PLAYBOOK.md must reference the canonical tool names from TOOL_SEQUENCES."""
        if not PLAYBOOK_MD.exists():
            pytest.skip("agent-config/PLAYBOOK.md not found relative to repo root")
        playbook_text = PLAYBOOK_MD.read_text()
        # The key mandatory tools should appear in PLAYBOOK.md prose.
        mandatory = ["vol_pslist", "vol_psscan", "evtx_query", "mft_timeline"]
        for tool in mandatory:
            assert tool in playbook_text, f"{tool!r} missing from PLAYBOOK.md"
