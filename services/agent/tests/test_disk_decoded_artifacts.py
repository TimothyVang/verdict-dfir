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
