"""Decoded disk artifact emitters for NIST recall gaps."""

from __future__ import annotations

import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402


class TestLnkRemovableMediaCandidates:
    def test_volume_serial_lnk_row_is_candidate(self) -> None:
        rows = [
            {
                "Source File": "Recent\\staged-files.lnk",
                "Target Path": "E:\\staged\\tools.zip",
                "Volume Serial Number": "A1B2-C3D4",
                "Drive Type": "Removable",
            }
        ]

        cands = fea.lnk_removable_media_candidates(rows)

        assert len(cands) == 1
        assert cands[0]["source"] == "Recent\\staged-files.lnk"
        assert cands[0]["target"] == "E:\\staged\\tools.zip"
        assert cands[0]["volume_serial"] == "A1B2-C3D4"

    def test_plain_local_lnk_is_not_candidate(self) -> None:
        rows = [
            {"Source File": "Recent\\calc.lnk", "Target Path": "C:\\Windows\\System32\\calc.exe"}
        ]

        assert fea.lnk_removable_media_candidates(rows) == []

    def test_path_only_recent_nethood_fallback_is_candidate(self) -> None:
        # A NetHood shortcut to a network staging share, recovered from path text
        # only (LECmd could not decode target metadata). The generic "staging"
        # tell keys the candidacy on any host.
        rows = [
            {
                "Source File": (
                    "Documents and Settings\\Suspect User\\NetHood\\"
                    "staging share on fileserver\\target.lnk"
                ),
                "Fallback Basis": "path_name",
                "Fallback Warning": "LECmd not found; target metadata was not decoded.",
            }
        ]

        cands = fea.lnk_removable_media_candidates(rows)

        assert len(cands) == 1
        assert cands[0]["basis"] == "path_name"
        assert cands[0]["source"].endswith("target.lnk")
        assert not cands[0]["volume_serial"]

    def test_lnk_triage_prioritizes_recent_and_nethood(self) -> None:
        # A Recent/NetHood shortcut carrying a staging tell ranks ahead of a
        # generic All Users Start Menu shortcut on any Windows host.
        entries = [
            {
                "path": "/case/lnk/Documents and Settings/All Users/Start Menu/Programs/Calculator.lnk"
            },
            {
                "path": (
                    "/case/lnk/Documents and Settings/Suspect User/NetHood/"
                    "staging share on fileserver/target.lnk"
                )
            },
        ]

        ordered = sorted(entries, key=fea._lnk_triage_sort_key)

        assert "NetHood" in ordered[0]["path"]


class TestRecycleBinCandidates:
    def test_info2_deleted_tool_artifact_is_candidate(self) -> None:
        events = [
            {
                "data_type": "windows:metadata:deleted_item",
                "parser": "recycle_bin_info2",
                "filename": "C:\\Documents and Settings\\Mr. Evil\\Desktop\\ethereal-setup.exe",
                "timestamp": "2004-08-27T15:45:00Z",
            }
        ]

        cands = fea.recyclebin_staging_candidates(events)

        assert len(cands) == 1
        assert cands[0]["path"].endswith("ethereal-setup.exe")
        assert cands[0]["parser"] == "recycle_bin_info2"

    def test_benign_deleted_document_is_not_candidate(self) -> None:
        events = [
            {
                "data_type": "windows:metadata:deleted_item",
                "parser": "recycle_bin_info2",
                "filename": "C:\\Documents and Settings\\Alice\\My Documents\\budget.doc",
            }
        ]

        assert fea.recyclebin_staging_candidates(events) == []


class TestDecodedDiskArtifactEmitters:
    def _inv(self):
        inv = fea.Investigation("disk.dd", unattended=True, with_report=False)
        inv.handle = {"id": "case-decoded"}
        return inv

    def test_record_tool_keeps_mcp_tool_when_extra_has_subtool(self) -> None:
        class FakePy:
            def call_tool(self, _tool: str, _args: dict) -> dict:
                return {}

        inv = self._inv()
        tcid = inv._record_tool(
            FakePy(),
            "ez_parse",
            "a" * 64,
            {"tool": "lecmd", "rows_seen": 1},
            {"tool": "lecmd", "artifact_path": "/evidence/a.lnk"},
        )

        assert tcid == "tc-001"
        assert inv.tool_calls[0]["tool"] == "ez_parse"
        assert inv.tool_calls[0]["subtool"] == "lecmd"

    def test_lnk_candidate_becomes_hypothesis_pool_b_finding(self) -> None:
        inv = self._inv()
        inv._emit_lnk_removable_media_finding(
            [
                {
                    "source": "Recent\\staged-files.lnk",
                    "target": "E:\\staged\\tools.zip",
                    "volume_serial": "A1B2-C3D4",
                }
            ],
            "/evidence/Recent/staged-files.lnk",
            "tc-lnk-1",
        )

        assert len(inv.findings_pool_b) == 1
        f = inv.findings_pool_b[0]
        assert f["tool_call_id"] == "tc-lnk-1"
        assert f["confidence"] == "HYPOTHESIS"
        assert f["description"].startswith("hypothesis: ")
        desc = f["description"].lower()
        for token in ("lnk", "shortcut", "removable", "volume serial", "recent"):
            assert token in desc
        assert "user's recent items" not in desc
        assert "execution" not in desc
        assert "exfiltrat" not in desc

    def test_lnk_path_only_candidate_does_not_claim_decoded_volume_serial(self) -> None:
        inv = self._inv()
        inv._emit_lnk_removable_media_finding(
            [
                {
                    "source": (
                        "Documents and Settings\\Mr. Evil\\NetHood\\"
                        "Temp on m1200 (4.12.220.254)\\target.lnk"
                    ),
                    "target": "",
                    "volume_serial": "",
                    "basis": "path_name",
                }
            ],
            "/evidence/NetHood/Temp on m1200/target.lnk",
            "tc-lnk-path-1",
        )

        assert len(inv.findings_pool_b) == 1
        desc = inv.findings_pool_b[0]["description"].lower()
        assert "lnk" in desc and "nethood" in desc
        assert "volume serial is not claimed" in desc
        assert "execution" not in desc
        assert "exfiltrat" not in desc

    def test_repeated_lnk_findings_get_artifact_scoped_ids(self) -> None:
        inv = self._inv()
        for lnk_path in (
            "/evidence/NetHood/Temp on m1200/target.lnk",
            "/evidence/Recent/CD Drive.lnk",
        ):
            inv._emit_lnk_removable_media_finding(
                [
                    {
                        "source": lnk_path,
                        "target": "",
                        "volume_serial": "",
                        "basis": "path_name",
                    }
                ],
                lnk_path,
                f"tc-{len(inv.findings_pool_b) + 1}",
            )

        ids = [f["finding_id"] for f in inv.findings_pool_b]
        assert len(ids) == len(set(ids))
        assert all(finding_id.startswith("f-B-lnk-removable-media-") for finding_id in ids)

    def test_recyclebin_candidate_becomes_hypothesis_pool_b_finding(self) -> None:
        inv = self._inv()
        inv._emit_recyclebin_staging_finding(
            [
                {
                    "path": "C:\\Documents and Settings\\Mr. Evil\\Desktop\\ethereal-setup.exe",
                    "parser": "recycle_bin_info2",
                    "timestamp": "2004-08-27T15:45:00Z",
                }
            ],
            "/evidence/RECYCLER/S-1-5-21/INFO2",
            "tc-recycle-1",
        )

        assert len(inv.findings_pool_b) == 1
        f = inv.findings_pool_b[0]
        assert f["tool_call_id"] == "tc-recycle-1"
        assert f["confidence"] == "HYPOTHESIS"
        desc = f["description"].lower()
        for token in ("recycle bin", "deleted", "staging", "artifact", "info2"):
            assert token in desc
        assert "exfiltrat" not in desc

    def test_same_hive_shellbag_keys_get_distinct_finding_ids(self) -> None:
        inv = self._inv()
        for key in (
            r"Software\Microsoft\Windows\Shell\BagMRU",
            r"Software\Microsoft\Windows\ShellNoRoam\BagMRU",
        ):
            inv._emit_registry_activity_findings(
                [
                    {
                        "kind": "shellbag",
                        "folder": r"\\m1200\Temp\staging",
                        "hive_key": key,
                        "last_write_time_iso": "2004-08-27T12:00:00Z",
                    }
                ],
                "/evidence/registry/Mr. Evil/NTUSER.DAT",
                key,
                f"tc-{len(inv.findings_pool_b) + 1}",
            )

        ids = [f["finding_id"] for f in inv.findings_pool_b]
        assert len(ids) == len(set(ids))
        assert all(finding_id.startswith("f-B-shellbag-") for finding_id in ids)
