"""Finding-side contract: a finalized Finding keeps the signed chain /home-free.

ROUND 1 (PR #92) relativized the per-tool-call ``*_path`` arguments + the
``extra["artifact_path"]`` display copy at ``_record_tool``. But a live SCHARDT.dd
re-run showed the leak persists in the FINDINGS themselves: on disk/memory cases
each Finding records the operator's extracted-artifact ABSOLUTE path in two places
the signed chain then leaks:

- ``Finding.artifact_path`` (echoed into the ``finding_approved`` audit record
  ``.payload.finding.artifact_path`` AND ``verdict.json .findings[].artifact_path``)
- ``Finding.description`` free text that embeds that same absolute path.

``relativize_finding_paths`` is the finding-side mirror of the ROUND 1 record-side
fix: it relativizes the finding's ``artifact_path`` to ``cases/<id>/extracted/...``
(the same ``case_home`` anchor / same helper) AND rewrites any verbatim occurrence
of that original absolute path inside the description to its relative form, so both
the field and the prose go /home-free in one place.

``Finding.artifact_path`` is display / citation metadata, NOT replay-bearing: the
verifier replays a finding by re-running its cited ``tool_call_id`` (the recorded
``arguments`` ROUND 1 already relativizes + resolves on replay), never by opening
``finding.artifact_path``. The one place it is read is the opt-in re-bind gate
(``FIND_EVIL_REQUIRE_ARTIFACT_REBIND=1``), which compares it to the cited call's
RECORDED (already-relativized) ``*_path`` by basename OR full-path equality — so a
relativized finding ``artifact_path`` still matches (basename unchanged; full path
now matches the relativized record too). Hence a PLAIN relativize is correct: no
resolve-on-read is needed, unlike the tool_call replay path.

These tests pin:

- F1: an extracted-style absolute ``artifact_path`` is recorded /home-free and
      relative, and the SAME path embedded in the description is rewritten too.
- F2: a forensic in-image path in the description (e.g. ``C:\\...`` or a deleted
      file path) that is NOT the finding's operator artifact_path is left untouched
      (no blind /home-or-path scrub that would mangle forensic text).
- F3: a ``/evidence/`` single-file finding is unaffected (its artifact_path is not
      under case_home, so it survives verbatim, and its description is untouched).
"""

from __future__ import annotations

import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402


def test_extracted_finding_path_and_description_home_free(monkeypatch, tmp_path: Path) -> None:
    # F1: an extracted-style absolute artifact_path under case_home is recorded
    # relative, and the same absolute path embedded in the description is rewritten.
    monkeypatch.setenv("FINDEVIL_HOME", str(tmp_path / ".findevil"))
    absolute = str(tmp_path / ".findevil/cases/db256d79/extracted/disk/disk-extract-3bb2/mft/$MFT")
    expected_rel = "cases/db256d79/extracted/disk/disk-extract-3bb2/mft/$MFT"

    finding = {
        "case_id": "case-paths",
        "finding_id": "f-A-mft-tools",
        "tool_call_id": "a" * 64,
        "artifact_path": absolute,
        "description": (
            f"Hacking-tool artifacts recovered from the MFT at {absolute}. "
            "Presence is not execution."
        ),
        "confidence": "INFERRED",
    }

    normalized = fea.relativize_finding_paths(finding)

    assert normalized["artifact_path"] == expected_rel
    assert "/home/" not in normalized["artifact_path"]
    assert str(tmp_path) not in normalized["artifact_path"]
    # Description prose goes /home-free too: the verbatim absolute path is rewritten.
    assert absolute not in normalized["description"]
    assert "/home/" not in normalized["description"]
    assert str(tmp_path) not in normalized["description"]
    assert expected_rel in normalized["description"]
    # Non-path fields untouched; input never mutated.
    assert normalized["confidence"] == "INFERRED"
    assert normalized["tool_call_id"] == "a" * 64
    assert finding["artifact_path"] == absolute


def test_forensic_in_image_path_in_description_untouched(monkeypatch, tmp_path: Path) -> None:
    # F2: a forensic in-image path that is NOT the finding's operator artifact_path
    # must survive verbatim — the fix rewrites only the finding's own extracted
    # artifact_path, never a blind /home-or-path scrub that would mangle evidence.
    monkeypatch.setenv("FINDEVIL_HOME", str(tmp_path / ".findevil"))
    absolute = str(tmp_path / ".findevil/cases/x/extracted/disk/dx/recyclebin/$I")
    in_image = r"C:\Users\suspect\Desktop\hacktool.exe"

    finding = {
        "case_id": "case-paths",
        "finding_id": "f-B-recyclebin-staging",
        "tool_call_id": "b" * 64,
        "artifact_path": absolute,
        "description": (
            f"Recycle Bin deleted-item artifact records a deleted staging file: "
            f"{in_image} (deleted 2026-06-19T00:00:00Z)."
        ),
        "confidence": "HYPOTHESIS",
    }

    normalized = fea.relativize_finding_paths(finding)

    assert normalized["artifact_path"] == "cases/x/extracted/disk/dx/recyclebin/$I"
    # The forensic in-image path is preserved exactly.
    assert in_image in normalized["description"]
    # And no operator /home leak is introduced or left behind.
    assert "/home/" not in normalized["description"]
    assert str(tmp_path) not in normalized["description"]


def test_evidence_single_file_finding_unaffected(monkeypatch, tmp_path: Path) -> None:
    # F3: a /evidence/ source-path finding is not under case_home, so artifact_path
    # survives verbatim and the description is untouched (documented not-a-/home-leak).
    monkeypatch.setenv("FINDEVIL_HOME", str(tmp_path / ".findevil"))
    finding = {
        "case_id": "case-paths",
        "finding_id": "f-A-memory",
        "tool_call_id": "c" * 64,
        "artifact_path": "/evidence/Rocba-Memory.raw",
        "description": "Process injection lead in /evidence/Rocba-Memory.raw.",
        "confidence": "INFERRED",
    }

    normalized = fea.relativize_finding_paths(finding)

    assert normalized["artifact_path"] == "/evidence/Rocba-Memory.raw"
    assert normalized["description"] == finding["description"]


def test_local_mode_home_evidence_path_basenamed(monkeypatch, tmp_path: Path) -> None:
    # F4: a LOCAL-mode evidence source path under the operator's /home but NOT under
    # case_home (e.g. scripts/verdict /home/user/.../evidence/nitroba.pcap) must not
    # leak /home into the customer report. Its artifact_path is reduced to the
    # basename and any verbatim occurrence in the description is rewritten. The
    # replay path is unaffected (verifier replays by tool_call_id; the rebind gate
    # matches by basename), so a basename is a correct /home-free display value.
    monkeypatch.setenv("FINDEVIL_HOME", str(tmp_path / ".findevil"))
    leaky = "/home/assessor/Desktop/PUG-Projects/dev-verdict-github/evidence/nitroba.pcap"

    finding = {
        "case_id": "case-paths",
        "finding_id": "f-A-pcap",
        "tool_call_id": "d" * 64,
        "artifact_path": leaky,
        "description": f"Anonymous-email contact observed in {leaky}.",
        "confidence": "HYPOTHESIS",
    }

    normalized = fea.relativize_finding_paths(finding)

    assert normalized["artifact_path"] == "nitroba.pcap"
    assert "/home/" not in normalized["artifact_path"]
    assert leaky not in normalized["description"]
    assert "/home/" not in normalized["description"]
    assert "nitroba.pcap" in normalized["description"]
    # input never mutated
    assert finding["artifact_path"] == leaky
