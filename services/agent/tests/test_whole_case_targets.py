"""Target enumeration for local whole-case runs."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, _SCRIPTS / f"{name}.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


whole_case_targets = _load("whole_case_targets")


def _write(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"fixture")


def test_enumerates_hosts_disks_and_root_base_file_pair(tmp_path: Path) -> None:
    root = tmp_path / "SRL 2018 Case"
    out = tmp_path / "run output"
    (root / "hosts" / "base-admin-memory").mkdir(parents=True)
    _write(root / "disks" / "dmz-ftp-cdrive.E01")
    _write(root / "base-file-cdrive.E01")
    _write(root / "base-file-memory.img")

    targets = whole_case_targets.enumerate_targets(root, out)
    by_label = {target.label: target.path for target in targets}

    assert by_label["mem:base-admin-memory"] == root / "hosts" / "base-admin-memory"
    assert by_label["disk:dmz-ftp-cdrive"] == root / "disks" / "dmz-ftp-cdrive.E01"
    assert by_label["disk:base-file-cdrive"] == root / "base-file-cdrive.E01"
    assert by_label["mem:base-file-memory"] == root / "base-file-memory.img"
    assert by_label["xart:base-file"] == out / "_xartifact" / "base-file"
    assert not (root / "_xartifact").exists()
    assert (out / "_xartifact" / "base-file" / "base-file-cdrive.E01").exists()
    assert (out / "_xartifact" / "base-file" / "base-file-memory.img").exists()


def test_does_not_duplicate_base_file_disk_when_it_is_in_disks_dir(tmp_path: Path) -> None:
    root = tmp_path / "case"
    out = tmp_path / "out"
    _write(root / "disks" / "base-file-cdrive.E01")
    _write(root / "base-file-memory.img")

    targets = whole_case_targets.enumerate_targets(root, out)
    labels = [target.label for target in targets]

    assert labels.count("disk:base-file-cdrive") == 1
    assert "mem:base-file-memory" in labels
