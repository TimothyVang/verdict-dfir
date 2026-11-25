"""Tests for bounded container descent.

Two failures these exist to prevent, both already seen in this codebase:
a container counted as ONE object (so a verdict describes the wrapper, not the
contents), and absence rendered as clean (an archive we could not open
reported as nothing found).

The load-bearing invariant is that EVERY path produces a record. There is no
branch that drops an object quietly.
"""

from __future__ import annotations

import io
import sys
import tarfile
import zipfile
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import container_intake as ci  # noqa: E402


def _zip(tmp: Path, name: str, members: dict[str, bytes]) -> Path:
    p = tmp / name
    with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as zf:
        for member, data in members.items():
            zf.writestr(member, data)
    return p


def test_a_container_is_not_one_object(tmp_path: Path) -> None:
    """The core of item 3: three files in a zip are three objects."""
    z = _zip(tmp_path, "bundle.zip", {"a.txt": b"a", "b.txt": b"b", "c.txt": b"c"})
    recs = ci.inspect_container(z, tmp_path / "out")
    extracted = [r for r in recs if r["state"] == ci.EXTRACTED]
    assert len(extracted) == 3


def test_an_encrypted_archive_is_reported_not_skipped(tmp_path: Path) -> None:
    """Item 3's named acceptance case. An encrypted zip must appear as a thing
    we SAW and could not read -- silence here is the recurring bug."""
    p = tmp_path / "locked.zip"
    # Craft a member with the encryption bit set; no password support needed.
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("secret.txt", b"x" * 32)
    raw = bytearray(p.read_bytes())
    idx = raw.find(b"PK\x03\x04")
    raw[idx + 6] |= 0x1                      # general purpose bit 0 = encrypted
    cd = raw.find(b"PK\x01\x02")
    raw[cd + 8] |= 0x1
    p.write_bytes(bytes(raw))

    recs = ci.inspect_container(p, tmp_path / "out")
    assert len(recs) == 1
    assert recs[0]["state"] == ci.ENCRYPTED
    assert "encrypted" in recs[0]["reason"]


def test_an_unsupported_format_is_reported_not_skipped(tmp_path: Path) -> None:
    p = tmp_path / "archive.7z"
    p.write_bytes(b"7z\xbc\xaf\x27\x1c" + b"\x00" * 64)
    recs = ci.inspect_container(p, tmp_path / "out")
    assert len(recs) == 1
    assert recs[0]["state"] == ci.UNSUPPORTED


def test_an_archive_bomb_is_refused_before_it_is_written(tmp_path: Path) -> None:
    """A bomb detected after filling the disk was not detected."""
    z = _zip(tmp_path, "bomb.zip", {"huge": b"\x00" * (5 * 1024 * 1024)})
    budget = ci.Budget(max_ratio=10)
    recs = ci.inspect_container(z, tmp_path / "out", budget=budget)
    refused = [r for r in recs if r["state"] == ci.REFUSED]
    assert refused, "a 5 MiB run of zeros compresses far past a 10x ratio"
    assert "bomb" in refused[0]["reason"]
    assert "max_ratio" in budget.exhausted
    assert not (tmp_path / "out" / "huge").exists(), "refused member must not be written"


def test_nesting_beyond_max_depth_is_refused(tmp_path: Path) -> None:
    inner = _zip(tmp_path, "inner.zip", {"deep.txt": b"deep"})
    outer = _zip(tmp_path, "outer.zip", {"inner.zip": inner.read_bytes()})
    budget = ci.Budget(max_depth=0)
    recs = ci.inspect_container(outer, tmp_path / "out", budget=budget)
    assert any(r["state"] == ci.REFUSED and "max_depth" in r["reason"] for r in recs)


def test_recursion_finds_nested_members(tmp_path: Path) -> None:
    inner = _zip(tmp_path, "inner.zip", {"deep.txt": b"deep"})
    outer = _zip(tmp_path, "outer.zip", {"inner.zip": inner.read_bytes()})
    recs = ci.inspect_container(outer, tmp_path / "out")
    names = [Path(r["path"]).name for r in recs if r["state"] == ci.EXTRACTED]
    assert "deep.txt" in names, f"nested member not enumerated: {names}"


def test_zip_slip_is_refused(tmp_path: Path) -> None:
    """A member named ../../escape must never be written outside the root."""
    p = tmp_path / "evil.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("../../escaped.txt", b"pwned")
    recs = ci.inspect_container(p, tmp_path / "out")
    assert any(r["state"] == ci.REFUSED and "escapes" in r["reason"] for r in recs)
    assert not (tmp_path.parent / "escaped.txt").exists()


def test_the_object_budget_stops_enumeration_and_says_so(tmp_path: Path) -> None:
    z = _zip(tmp_path, "many.zip", {f"f{i}.txt": b"x" for i in range(50)})
    budget = ci.Budget(max_objects=10)
    recs = ci.inspect_container(z, tmp_path / "out", budget=budget)
    assert any(r["state"] == ci.REFUSED for r in recs)
    assert "max_objects" in budget.exhausted


def test_no_object_is_ever_dropped(tmp_path: Path) -> None:
    """The invariant. Whatever we hand it, at least one record comes back --
    an object that produces no record is one a verdict cannot account for."""
    cases = []
    cases.append(_zip(tmp_path, "ok.zip", {"a": b"a"}))
    seven = tmp_path / "x.7z"; seven.write_bytes(b"7z\xbc\xaf\x27\x1c"); cases.append(seven)
    junk = tmp_path / "junk.bin"; junk.write_bytes(b"\x00\x01\x02"); cases.append(junk)
    empty = tmp_path / "empty.zip"; empty.write_bytes(b""); cases.append(empty)
    for c in cases:
        recs = ci.inspect_container(c, tmp_path / f"out_{c.name}")
        assert recs, f"{c.name} produced NO record; it would vanish from coverage"


def test_a_tar_is_enumerated(tmp_path: Path) -> None:
    p = tmp_path / "bundle.tar"
    with tarfile.open(p, "w") as tf:
        for name, data in (("x.txt", b"x"), ("y.txt", b"y")):
            info = tarfile.TarInfo(name); info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    recs = ci.inspect_container(p, tmp_path / "out")
    assert len([r for r in recs if r["state"] == ci.EXTRACTED]) == 2
