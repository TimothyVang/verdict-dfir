"""Disk-summary contract: ``verdict.json`` keeps the signed chain /home-free.

ROUND 1 (PR #92) relativized the per-tool-call ``*_path`` arguments + the
``extra["artifact_path"]`` display copy at ``_record_tool``. ROUND 2 (PR #93)
mirrored that on the FINDINGS (``relativize_finding_paths``). A live SCHARDT.dd
re-run then showed the chain itself is clean but ``verdict.json`` still leaks the
operator's ``/home/<user>/.findevil/cases/<id>/extracted/...`` paths in two
STRUCTURED metadata spots (display/citation only, never replay-bearing):

- ``verdict.json.disk_artifact_summary.tool_summaries.<tool>[].artifact_path``
  (the bulk: ez_parse / registry_query / prefetch_parse / plaso_parse /
  mft_timeline rows), assembled at ``_merge_disk_tool_summary``.
- ``verdict.json.tool_calls[].fs_root`` (the disk_mount mount-root display copy),
  set in ``_record_tool``'s ``extra`` next to the already-relativized
  ``artifact_path``.

Both are the same root cause as ROUND 1/2 and are fixed with the same record-side
helper (``_relativize_extracted_path``): an extracted path under ``case_home`` is
recorded RELATIVE (``cases/<id>/extracted/...``); a ``/evidence/`` source path or
any path outside the case store passes through verbatim.

Neither field is read by the verifier/replay path (the verifier replays via a
finding's ``tool_call_id`` + the cited call's recorded ``arguments``, which ROUND 1
relativizes AND resolves on replay). So a PLAIN relativize is correct here — no
resolve-on-read. These tests pin:

- D1: an extracted-style absolute ``artifact_path`` merged into the disk summary is
      recorded /home-free and relative.
- D2: a forensic in-image registry ``key_path`` (e.g. ``Software\\...``) and the
      ``sample_paths`` in-image strings (``C:\\...``) ride along untouched — only the
      operator's extracted ``artifact_path`` is rewritten, never a blind scrub.
- D3: a ``/evidence/`` single-file ``artifact_path`` (documented not-a-/home-leak)
      survives verbatim.
- D4: ``tool_calls[].fs_root`` (the disk_mount mount-root display copy) is recorded
      /home-free in BOTH the ``tool_call_output`` audit record and ``self.tool_calls``.
- D5: a ``fs_root`` outside the case store survives verbatim.
"""

from __future__ import annotations

import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402


class _FakePy:
    def __init__(self) -> None:
        self.audits: list[tuple[str, dict]] = []

    def call_tool(self, name: str, args: dict, timeout: float = 600.0) -> dict:
        if name == "audit_append":
            self.audits.append((args["kind"], args["payload"]))
        return {}

    def close(self) -> None:  # pragma: no cover - parity with real client
        pass


def _inv() -> fea.Investigation:
    return fea.Investigation("/tmp/does-not-exist-evidence", case_id="case-paths")


def _records(py: _FakePy, kind: str) -> list[dict]:
    return [payload for k, payload in py.audits if k == kind]


def test_disk_summary_artifact_path_home_free(monkeypatch, tmp_path: Path) -> None:
    # D1: an extracted-style absolute artifact_path merged into the disk summary is
    # recorded relative to case_home (cases/<id>/extracted/...) — no /home leak in
    # verdict.json.disk_artifact_summary.tool_summaries.<tool>[].artifact_path.
    monkeypatch.setenv("FINDEVIL_HOME", str(tmp_path / ".findevil"))
    absolute = str(tmp_path / ".findevil/cases/db256d79/extracted/disk/disk-extract-3bb2/mft/$MFT")
    expected_rel = "cases/db256d79/extracted/disk/disk-extract-3bb2/mft/$MFT"

    disk_summary = fea._disk_summary_template()
    fea._merge_disk_tool_summary(
        disk_summary,
        "mft_timeline",
        "a" * 64,
        {"artifact_path": absolute, "row_count": 12, "records_seen": 12},
    )

    row = disk_summary["tool_summaries"]["mft_timeline"][0]
    assert row["artifact_path"] == expected_rel
    assert "/home/" not in row["artifact_path"]
    assert str(tmp_path) not in row["artifact_path"]
    # Non-path fields untouched; tool_call_id preserved.
    assert row["row_count"] == 12
    assert row["records_seen"] == 12
    assert row["tool_call_id"] == "a" * 64


def test_disk_summary_forensic_in_image_paths_untouched(monkeypatch, tmp_path: Path) -> None:
    # D2: the forensic in-image registry key_path and the in-image sample_paths ride
    # along verbatim — only the operator's extracted artifact_path is rewritten, never
    # a blind /home-or-path scrub that would mangle forensic strings.
    monkeypatch.setenv("FINDEVIL_HOME", str(tmp_path / ".findevil"))
    absolute = str(tmp_path / ".findevil/cases/x/extracted/disk/dx/registry/NTUSER.DAT")
    in_image_key = r"Software\Microsoft\Windows\CurrentVersion\Run"
    in_image_files = [r"C:\Users\suspect\Desktop\hacktool.exe", r"C:\Windows\evil.dll"]

    disk_summary = fea._disk_summary_template()
    fea._merge_disk_tool_summary(
        disk_summary,
        "registry_query",
        "b" * 64,
        {
            "artifact_path": absolute,
            "key_path": in_image_key,
            "sample_paths": list(in_image_files),
            "row_count": 2,
        },
    )

    row = disk_summary["tool_summaries"]["registry_query"][0]
    assert row["artifact_path"] == "cases/x/extracted/disk/dx/registry/NTUSER.DAT"
    # Forensic in-image strings preserved exactly.
    assert row["key_path"] == in_image_key
    assert row["sample_paths"] == in_image_files
    # No operator /home leak introduced or left behind.
    assert "/home/" not in row["artifact_path"]
    assert str(tmp_path) not in row["artifact_path"]


def test_disk_summary_evidence_path_verbatim(monkeypatch, tmp_path: Path) -> None:
    # D3: a /evidence/ source-path artifact_path is not under case_home, so it survives
    # verbatim (documented not-a-/home-leak).
    monkeypatch.setenv("FINDEVIL_HOME", str(tmp_path / ".findevil"))
    disk_summary = fea._disk_summary_template()
    fea._merge_disk_tool_summary(
        disk_summary,
        "evtx_query",
        "c" * 64,
        {"artifact_path": "/evidence/SCHARDT.dd", "row_count": 7},
    )
    row = disk_summary["tool_summaries"]["evtx_query"][0]
    assert row["artifact_path"] == "/evidence/SCHARDT.dd"


def test_tool_calls_fs_root_home_free(monkeypatch, tmp_path: Path) -> None:
    # D4: tool_calls[].fs_root (the disk_mount mount-root display copy) is recorded
    # /home-free in BOTH the tool_call_output audit record and self.tool_calls.
    monkeypatch.setenv("FINDEVIL_HOME", str(tmp_path / ".findevil"))
    absolute = str(tmp_path / ".findevil/cases/db256d79/extracted/disk/disk-extract-3bb2/mount")
    expected_rel = "cases/db256d79/extracted/disk/disk-extract-3bb2/mount"
    inv = _inv()
    py = _FakePy()

    inv._record_tool(
        py,
        "disk_mount",
        "d" * 64,
        {
            "artifact_path": "/evidence/SCHARDT.dd",
            "status": "ok",
            "fs_root": absolute,
        },
        arguments={
            "case_id": "case-paths",
            "image_path": "/evidence/SCHARDT.dd",
            "mode": "auto",
        },
    )

    out = _records(py, "tool_call_output")[0]
    assert out["fs_root"] == expected_rel
    assert "/home/" not in out["fs_root"]
    assert str(tmp_path) not in out["fs_root"]

    recorded = inv.tool_calls[0]
    assert recorded["fs_root"] == expected_rel
    assert "/home/" not in recorded["fs_root"]
    # The /evidence/ source image (not under case_home) still rides verbatim.
    assert recorded["artifact_path"] == "/evidence/SCHARDT.dd"
    assert recorded["arguments"]["image_path"] == "/evidence/SCHARDT.dd"


def test_tool_calls_fs_root_outside_case_store_verbatim(monkeypatch, tmp_path: Path) -> None:
    # D5: an fs_root that is not under case_home (e.g. a SIFT guest mount point)
    # survives verbatim — relativizing it would leak nothing and could break a
    # human reader's path. Documented not-a-/home-leak.
    monkeypatch.setenv("FINDEVIL_HOME", str(tmp_path / ".findevil"))
    inv = _inv()
    py = _FakePy()

    inv._record_tool(
        py,
        "disk_mount",
        "e" * 64,
        {"artifact_path": "/evidence/SCHARDT.dd", "fs_root": "/mnt/sift-mount-3bb2"},
        arguments={"case_id": "case-paths", "image_path": "/evidence/SCHARDT.dd"},
    )

    assert _records(py, "tool_call_output")[0]["fs_root"] == "/mnt/sift-mount-3bb2"
    assert inv.tool_calls[0]["fs_root"] == "/mnt/sift-mount-3bb2"
