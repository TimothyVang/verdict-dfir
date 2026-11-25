"""Tests for type verification from bytes rather than from the filename.

`classify_artifact_path` decides a lane from the extension. An extension is an
attacker-controlled label: a PE named `notes.txt` routes to a text lane and its
imports are never read. These assert the bytes win, that a disagreement is
REPORTED rather than repaired, and that unknown stays unknown.
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import content_type as ct  # noqa: E402


def _pe(tmp: Path, name: str) -> Path:
    """A minimal but genuine PE: MZ, e_lfanew, and the PE signature."""
    p = tmp / name
    head = bytearray(b"MZ" + b"\x00" * 0x3E)
    head[0x3C:0x40] = struct.pack("<I", 0x40)
    p.write_bytes(bytes(head) + b"PE\x00\x00" + b"\x00" * 16)
    return p


def test_a_pe_named_txt_is_detected_as_a_pe(tmp_path: Path) -> None:
    """The headline case: the extension lies, the bytes do not."""
    p = _pe(tmp_path, "notes.txt")
    assert ct.sniff_content_type(p) == "pe"


def test_a_mismatch_is_reported_not_repaired(tmp_path: Path) -> None:
    """A PE named .pdf must surface as a mismatch. Silently reclassifying it
    would erase the signal -- the lie is the finding."""
    p = _pe(tmp_path, "invoice.pdf")
    got = ct.verify_declared_type(p)
    assert got["agreement"] == "mismatch"
    assert got["content_type"] == "pe"
    assert got["extension_expects"] == ["pdf"]


def test_an_honest_file_agrees(tmp_path: Path) -> None:
    p = _pe(tmp_path, "tool.exe")
    assert ct.verify_declared_type(p)["agreement"] == "agree"


def test_mz_without_a_pe_signature_is_not_called_a_pe(tmp_path: Path) -> None:
    """MZ alone is any DOS executable. Reporting it as pe would be a guess."""
    p = tmp_path / "old.exe"
    p.write_bytes(b"MZ" + b"\x00" * 0x80)
    assert ct.sniff_content_type(p) == "dos-mz"


def test_unrecognised_bytes_report_unknown_not_a_guess(tmp_path: Path) -> None:
    p = tmp_path / "mystery.bin"
    p.write_bytes(b"\x11\x22\x33\x44" * 40)
    assert ct.sniff_content_type(p) is None
    assert ct.verify_declared_type(p)["agreement"] == "unknown"


def test_unknown_never_reads_as_agreement(tmp_path: Path) -> None:
    """A .zip full of noise must not pass as agreeing just because we cannot
    identify it. Unknown is not clean."""
    p = tmp_path / "archive.zip"
    p.write_bytes(b"\x11\x22\x33\x44" * 40)
    assert ct.verify_declared_type(p)["agreement"] == "unknown"


def test_an_empty_file_is_empty_not_unknown(tmp_path: Path) -> None:
    p = tmp_path / "nothing.bin"
    p.write_bytes(b"")
    assert ct.sniff_content_type(p) == "empty"


def test_containers_are_flagged_so_intake_knows_to_descend(tmp_path: Path) -> None:
    z = tmp_path / "bundle.zip"
    z.write_bytes(b"PK\x03\x04" + b"\x00" * 32)
    got = ct.verify_declared_type(z)
    assert got["is_container"] is True
    plain = _pe(tmp_path, "tool.exe")
    assert ct.verify_declared_type(plain)["is_container"] is False


def test_an_office_doc_is_a_zip_and_that_is_agreement(tmp_path: Path) -> None:
    """docx really is a zip; the table must not call that a mismatch."""
    p = tmp_path / "report.docx"
    p.write_bytes(b"PK\x03\x04" + b"\x00" * 32)
    got = ct.verify_declared_type(p)
    assert got["agreement"] == "agree"
    assert got["is_container"] is True


def test_an_unreadable_path_is_unknown_not_a_crash(tmp_path: Path) -> None:
    assert ct.sniff_content_type(tmp_path / "absent") is None


def test_a_program_wearing_a_document_name_is_a_mismatch(tmp_path: Path) -> None:
    """The single most useful thing this module can notice, and the case the
    first version missed: `.txt` implies no ONE type, so the comparison fell
    through to "unchecked" -- no opinion on a PE called notes.txt."""
    for name in ("notes.txt", "report.log", "data.csv", "photo.png", "readme.md"):
        p = _pe(tmp_path, name)
        got = ct.verify_declared_type(p)
        assert got["agreement"] == "mismatch", f"{name} reported {got['agreement']}"
        assert got["content_type"] == "pe"


def test_an_elf_named_txt_is_also_caught(tmp_path: Path) -> None:
    p = tmp_path / "notes.txt"
    p.write_bytes(b"\x7fELF" + b"\x00" * 60)
    assert ct.verify_declared_type(p)["agreement"] == "mismatch"


def test_ordinary_data_under_an_inert_extension_is_not_flagged(tmp_path: Path) -> None:
    """The rule must not fire on honest files -- a false mismatch on every
    text file would train an analyst to ignore the field."""
    p = tmp_path / "notes.txt"
    p.write_text("perfectly ordinary text")
    assert ct.verify_declared_type(p)["agreement"] == "unknown"
