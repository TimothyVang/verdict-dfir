"""Item 3's definition of done, asserted directly.

  "the coverage ledger accounts for 100 % of objects in a nested fixture and
   flags an encrypted archive as UNSUPPORTED rather than skipping it"

Before this, every lane reported discovered=1, inspected=1 -- a constant no
real change in coverage could move. It rendered as 100 %, reconciled
perfectly, validated, and got signed. A number nothing can falsify is not
accounting, and four reviewers said so.
"""

from __future__ import annotations

import struct
import sys
import zipfile
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import object_ledger as ol  # noqa: E402


def _pe_bytes() -> bytes:
    head = bytearray(b"MZ" + b"\x00" * 0x3E)
    head[0x3C:0x40] = struct.pack("<I", 0x40)
    return bytes(head) + b"PE\x00\x00" + b"\x00" * 16


def _encrypted_zip(path: Path) -> None:
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("secret.txt", b"x" * 32)
    raw = bytearray(path.read_bytes())
    raw[raw.find(b"PK\x03\x04") + 6] |= 0x1
    raw[raw.find(b"PK\x01\x02") + 8] |= 0x1
    path.write_bytes(bytes(raw))


def _nested_fixture(tmp: Path) -> Path:
    """A root shaped like real evidence: a disguised binary, a nested archive,
    an encrypted archive, and an ordinary file."""
    root = tmp / "evidence"
    root.mkdir()
    (root / "notes.txt").write_bytes(_pe_bytes())          # PE wearing .txt
    (root / "readme.md").write_text("ordinary text")

    inner = tmp / "inner.zip"
    with zipfile.ZipFile(inner, "w") as zf:
        zf.writestr("payload.bin", _pe_bytes())
        zf.writestr("note.txt", b"harmless")
    with zipfile.ZipFile(root / "outer.zip", "w") as zf:
        zf.writestr("inner.zip", inner.read_bytes())

    _encrypted_zip(root / "locked.zip")
    return root


def test_the_ledger_accounts_for_every_object(tmp_path: Path) -> None:
    """100 % accounting: every discovered object lands in exactly one bucket."""
    root = _nested_fixture(tmp_path)
    led = ol.build_object_ledger(root, tmp_path / "work")
    c = led["counts"]
    accounted = sum(v for k, v in c.items() if k != "discovered")
    assert led["reconciles"] is True, f"{led['unaccounted']} object(s) unaccounted"
    assert accounted == c["discovered"]
    assert led["unaccounted"] == 0


def test_an_encrypted_archive_is_unsupported_not_skipped(tmp_path: Path) -> None:
    """Item 3's named acceptance case, at the ledger level."""
    root = _nested_fixture(tmp_path)
    led = ol.build_object_ledger(root, tmp_path / "work")
    locked = [o for o in led["objects"] if o["path"].endswith("locked.zip")]
    assert locked, "the encrypted archive vanished from the ledger entirely"
    assert locked[0]["state"] == "unsupported"
    assert led["counts"]["unsupported"] >= 1


def test_nested_members_are_counted_not_collapsed(tmp_path: Path) -> None:
    """outer.zip -> inner.zip -> payload.bin must appear as objects, not as one."""
    root = _nested_fixture(tmp_path)
    led = ol.build_object_ledger(root, tmp_path / "work")
    names = [Path(o["path"]).name for o in led["objects"]]
    assert "payload.bin" in names, f"nested member missing: {names}"
    assert led["counts"]["discovered"] > 4, "a container counted as one object"


def test_a_disguised_binary_routes_by_its_bytes(tmp_path: Path) -> None:
    """The payoff of piece 1: a PE named notes.txt reaches the binary lane."""
    root = _nested_fixture(tmp_path)
    led = ol.build_object_ledger(root, tmp_path / "work")
    disguised = [o for o in led["objects"] if o["path"].endswith("notes.txt")][0]
    assert disguised["content_type"] == "pe"
    assert disguised["lane"] == "binary", "routed on extension, not on bytes"
    assert disguised["type_agreement"] == "mismatch"


def test_nested_objects_carry_a_byte_range(tmp_path: Path) -> None:
    """Without it a finding about a child object cannot cite the bytes it came
    from."""
    root = _nested_fixture(tmp_path)
    led = ol.build_object_ledger(root, tmp_path / "work")
    children = [o for o in led["objects"] if o["member_of"]]
    assert children, "no child objects recorded"
    for child in children:
        assert child["byte_range"] is not None, f"{child['path']} has no byte range"
        assert child["byte_range"]["length"] >= 0


def test_an_unidentified_object_is_not_routed_to_a_default_lane(tmp_path: Path) -> None:
    """Routing an unidentified object anywhere produces a confident parse of
    something we never identified."""
    root = tmp_path / "ev"
    root.mkdir()
    (root / "mystery.bin").write_bytes(b"\x11\x22\x33\x44" * 40)
    led = ol.build_object_ledger(root, tmp_path / "work")
    obj = led["objects"][0]
    assert obj["content_type"] is None
    assert obj["lane"] is None
    assert led["unrouted"] == 1


def test_the_coverage_block_is_the_real_count(tmp_path: Path) -> None:
    """What replaces discovered=1, inspected=1."""
    root = _nested_fixture(tmp_path)
    led = ol.build_object_ledger(root, tmp_path / "work")
    block = ol.coverage_objects_from_ledger(led)
    assert block["discovered"] == led["counts"]["discovered"]
    assert block["discovered"] > 1, "still a placeholder"
    buckets = ("inspected", "failed", "skipped", "over_budget", "unsupported")
    assert sum(block[b] for b in buckets) == block["discovered"]


class ReconciliationIsFalsifiable:
    """Placeholder to keep pytest from collecting this as a test class."""


def test_reconcile_reports_a_shortfall(tmp_path: Path) -> None:
    """The flag must be computed, not asserted.

    Hardcoding `reconciles: True` passed the earlier test, because that test
    checked the flag on counts that genuinely added up. A flag nothing can
    falsify is the same defect this whole ledger exists to remove -- found in
    my own code, twenty minutes after fixing it elsewhere.
    """
    ok, missing = ol.reconcile(
        {"discovered": 10, "inspected": 4, "failed": 0,
         "skipped": 0, "over_budget": 0, "unsupported": 1})
    assert ok is False
    assert missing == 5, "five objects went somewhere the buckets do not name"


def test_reconcile_accepts_a_ledger_that_adds_up(tmp_path: Path) -> None:
    ok, missing = ol.reconcile(
        {"discovered": 5, "inspected": 3, "failed": 1,
         "skipped": 0, "over_budget": 0, "unsupported": 1})
    assert ok is True and missing == 0


def test_an_overcount_is_also_a_failure(tmp_path: Path) -> None:
    """Buckets summing to MORE than discovered means an object was counted
    twice -- equally a broken ledger, and equally not 100 % coverage."""
    ok, missing = ol.reconcile(
        {"discovered": 2, "inspected": 3, "failed": 0,
         "skipped": 0, "over_budget": 0, "unsupported": 0})
    assert ok is False and missing == -1


def test_write_object_ledger_to_case_persists_reconciled_json(tmp_path: Path) -> None:
    """The case dir must carry object-ledger.json so gn7000 seal_case can load it.

    build_object_ledger alone is not enough: orchestrator_common.load_object_ledger
    reads <case_dir>/object-ledger.json. Without a writer, every sealed case still
    omits the objects block.
    """
    root = _nested_fixture(tmp_path)
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    path = ol.write_object_ledger_to_case(root, case_dir, tmp_path / "work")
    assert path == case_dir / "object-ledger.json"
    assert path.is_file()
    import json
    led = json.loads(path.read_text())
    assert led["schema"] == "gn7000.object-ledger/v1"
    assert led["reconciles"] is True
    assert led["counts"]["unsupported"] >= 1
    assert led["counts"]["discovered"] > 1
