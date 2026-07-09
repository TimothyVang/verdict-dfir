"""Tests for the volatile-file exclusion in the evidence-integrity inventory.

``build_local_evidence_inventory`` custody-hashes every file under the evidence
root and folds those hashes into ``inventory_sha256`` -- the value an offline
re-verification reproduces. VERDICT also writes its own transient liveness/temp
files (``status.json``, ``.status.json.tmp``) into a run/case directory. If that
directory ever overlaps the inventoried tree, those files -- rewritten on every
tool call -- would be custody-hashed and ``inventory_sha256`` would differ
run-to-run, *spuriously* breaking re-verification of unchanged evidence.

``VOLATILE_EXCLUDE`` is a small, explicit allow-list of known VERDICT-emitted
transient filenames. ``is_volatile_run_file`` is the single predicate the walk
consults. CRITICAL: the list is narrowly VERDICT's own run-dir transients -- it
never names a real evidence/artifact file, so custody of source evidence is
never weakened (excluding a real artifact would be a custody hole, not a fix).

- V1: status.json / .status.json.tmp classify volatile; real artifacts do not.
- V2: a tree with only volatile files inventories to zero entries.
- V3: dropping a volatile file into an inventoried tree does NOT change
      inventory_sha256 (re-verification stays stable).
"""

from __future__ import annotations

import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402


def test_volatile_filenames_classify() -> None:
    assert fea.is_volatile_run_file("status.json")
    assert fea.is_volatile_run_file(".status.json.tmp")
    # Real evidence / artifact files must NOT be excluded.
    assert not fea.is_volatile_run_file("memory.raw")
    assert not fea.is_volatile_run_file("Security.evtx")
    assert not fea.is_volatile_run_file("verdict.json")
    assert not fea.is_volatile_run_file("$MFT")


def test_volatile_only_tree_inventories_empty(tmp_path: Path) -> None:
    (tmp_path / "status.json").write_text("{}", encoding="utf-8")
    (tmp_path / ".status.json.tmp").write_text("{}", encoding="utf-8")

    inventory = fea.build_local_evidence_inventory(tmp_path)

    assert inventory["entries"] == []


def test_volatile_file_does_not_perturb_inventory_sha(tmp_path: Path) -> None:
    artifact = tmp_path / "evidence.bin"
    artifact.write_bytes(b"real evidence bytes")

    before = fea.build_local_evidence_inventory(tmp_path)["inventory_sha256"]

    # A liveness write lands in the same tree between verifications.
    (tmp_path / "status.json").write_text('{"updated": "now"}', encoding="utf-8")

    after = fea.build_local_evidence_inventory(tmp_path)["inventory_sha256"]

    assert before == after
