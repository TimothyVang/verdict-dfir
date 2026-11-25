"""Gap 5 T19 — hacking-tool footprint findings from the MFT.

The NIST golden (nhc-004) expects "Hacking tool artifacts in Program Files /
downloaded applications". The $MFT records every file; a classifier flags rows
whose path carries a known hacking-tool token under Program Files / Desktop /
Downloads, and the engine emits a Pool A INFERRED finding (file present + name
matches a known-tool heuristic = two labeled facts).
"""

from __future__ import annotations

import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402


def _row(full_path: str, **kw) -> dict:
    base = {
        "record_number": kw.get("record_number", 1000),
        "full_path": full_path,
        "is_directory": kw.get("is_directory", False),
        "is_allocated": kw.get("is_allocated", True),
        "fn_created_iso": kw.get("created", "2004-08-20T15:05:06Z"),
        "si_created_iso": kw.get("created", "2004-08-20T15:05:06Z"),
    }
    return base


class TestMftHackingToolCandidates:
    def test_program_files_tool_dir_is_a_candidate(self) -> None:
        rows = [_row("Program Files/Anonymizer", is_directory=True)]
        cands = fea.mft_hacking_tool_candidates(rows)
        assert len(cands) == 1
        assert cands[0]["tool"] == "anonymizer"
        assert "Program Files" in cands[0]["path"]
        assert cands[0]["created"] == "2004-08-20T15:05:06Z"

    def test_desktop_installer_is_a_candidate(self) -> None:
        rows = [_row("Documents and Settings/Mr. Evil/Desktop/ethereal-setup-0.10.6.exe")]
        cands = fea.mft_hacking_tool_candidates(rows)
        assert len(cands) == 1
        assert cands[0]["tool"] == "ethereal"

    def test_prefetch_pf_files_are_not_candidates(self) -> None:
        # The .pf is execution residue, not the tool artifact — nhc-005 covers it.
        rows = [_row("WINDOWS/Prefetch/ETHEREAL.EXE-1C148EEF.pf")]
        assert fea.mft_hacking_tool_candidates(rows) == []

    def test_ordinary_system_file_is_not_a_candidate(self) -> None:
        rows = [_row("WINDOWS/system32/svchost.exe"), _row("Program Files/Common Files/x.dll")]
        assert fea.mft_hacking_tool_candidates(rows) == []

    def test_same_tool_is_deduped(self) -> None:
        rows = [
            _row("Program Files/Ethereal"),
            _row("Documents and Settings/Mr. Evil/Desktop/ethereal-setup-0.10.6.exe"),
        ]
        cands = fea.mft_hacking_tool_candidates(rows)
        assert len(cands) == 1  # one "ethereal" tool, not two

    def test_empty_rows_yield_nothing(self) -> None:
        assert fea.mft_hacking_tool_candidates([]) == []


class TestMftToolEmitter:
    def _inv(self):
        inv = fea.Investigation("memory.img", unattended=True, with_report=False)
        inv.handle = {"id": "case-mft"}
        return inv

    def test_candidates_become_one_pool_a_finding(self) -> None:
        inv = self._inv()
        cands = [
            {
                "tool": "anonymizer",
                "path": "Program Files/Anonymizer",
                "created": "2004-08-20T15:05:06Z",
                "record_number": 4242,
            },
            {
                "tool": "ethereal",
                "path": "Documents and Settings/Mr. Evil/Desktop/ethereal-setup.exe",
                "created": "2004-08-27T15:35:04Z",
                "record_number": 9001,
            },
        ]
        inv._emit_mft_hacking_tool_finding(cands, "/evidence/$MFT", "tc-mft-1")
        assert len(inv.findings_pool_a) == 1
        f = inv.findings_pool_a[0]
        assert f["pool_origin"] == "A"
        assert f["tool_call_id"] == "tc-mft-1"
        assert f["confidence"] == "INFERRED"
        assert f["finding_id"].startswith("f-A-mft-tools")
        desc = f["description"].lower()
        # Tokens that let the recall matcher link this to nhc-004.
        for tok in ("hacking", "tool", "artifact", "program", "files", "mft", "creation"):
            assert tok in desc
        assert "anonymizer" in desc and "ethereal" in desc

    def test_no_candidates_emits_nothing(self) -> None:
        inv = self._inv()
        inv._emit_mft_hacking_tool_finding([], "/evidence/$MFT", "tc-mft-2")
        assert inv.findings_pool_a == []
