"""Target enumeration for local whole-case runs."""

from __future__ import annotations

import importlib.util
import stat
import subprocess
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[3]
_SCRIPTS = _ROOT / "scripts"


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
    staged_disk = out / "_xartifact" / "base-file" / "base-file-cdrive.E01"
    staged_memory = out / "_xartifact" / "base-file" / "base-file-memory.img"
    assert staged_disk.exists()
    assert staged_memory.exists()
    assert staged_disk.stat().st_ino != (root / "base-file-cdrive.E01").stat().st_ino
    assert not (staged_disk.stat().st_mode & stat.S_IWUSR)


def test_does_not_duplicate_base_file_disk_when_it_is_in_disks_dir(tmp_path: Path) -> None:
    root = tmp_path / "case"
    out = tmp_path / "out"
    _write(root / "disks" / "base-file-cdrive.E01")
    _write(root / "base-file-memory.img")

    targets = whole_case_targets.enumerate_targets(root, out)
    labels = [target.label for target in targets]

    assert labels.count("disk:base-file-cdrive") == 1
    assert "mem:base-file-memory" in labels


def test_rejects_output_directory_inside_case_root(tmp_path: Path) -> None:
    root = tmp_path / "case"
    out = root / "derived-output"
    _write(root / "base-file-cdrive.E01")
    _write(root / "base-file-memory.img")

    with pytest.raises(ValueError, match="out_dir must not be inside"):
        whole_case_targets.enumerate_targets(root, out)


def test_rejects_source_disk_symlink_escape(tmp_path: Path) -> None:
    root = tmp_path / "case"
    out = tmp_path / "out"
    escaped = tmp_path / "outside-secret.E01"
    _write(escaped)
    _write(root / "base-file-memory.img")
    disk = root / "base-file-cdrive.E01"
    disk.parent.mkdir(parents=True, exist_ok=True)
    disk.symlink_to(escaped)

    with pytest.raises(RuntimeError, match="source evidence must not be a symlink"):
        whole_case_targets.enumerate_targets(root, out)

    assert not (out / "_xartifact" / "base-file" / "base-file-cdrive.E01").exists()


def test_rejects_source_host_symlink_escape(tmp_path: Path) -> None:
    root = tmp_path / "case"
    out = tmp_path / "out"
    escaped_host = tmp_path / "escaped-host"
    escaped_host.mkdir()
    hosts_dir = root / "hosts"
    hosts_dir.mkdir(parents=True)
    (hosts_dir / "linked-host").symlink_to(escaped_host, target_is_directory=True)

    with pytest.raises(RuntimeError, match="source evidence must not be a symlink"):
        whole_case_targets.enumerate_targets(root, out)


def test_rejects_target_labels_with_tsv_delimiters(tmp_path: Path) -> None:
    root = tmp_path / "case"
    out = tmp_path / "out"
    (root / "hosts" / "bad\tlabel").mkdir(parents=True)

    with pytest.raises(ValueError, match="target label contains unsafe characters"):
        whole_case_targets.enumerate_targets(root, out)


def test_run_whole_case_local_rejects_inside_output_before_mutation(
    tmp_path: Path,
) -> None:
    root = tmp_path / "case"
    out = root / "derived-output"
    _write(root / "base-file-cdrive.E01")
    _write(root / "base-file-memory.img")

    result = subprocess.run(
        ["bash", str(_SCRIPTS / "run-whole-case-local.sh"), str(root), str(out)],
        capture_output=True,
        check=False,
        text=True,
    )

    assert result.returncode != 0
    assert not out.exists()


def test_rejects_stale_existing_xartifact_copy(tmp_path: Path) -> None:
    root = tmp_path / "case"
    out = tmp_path / "out"
    _write(root / "base-file-cdrive.E01")
    _write(root / "base-file-memory.img")
    stale = out / "_xartifact" / "base-file" / "base-file-cdrive.E01"
    stale.parent.mkdir(parents=True)
    stale.write_bytes(b"stale")

    with pytest.raises(RuntimeError, match="staged xartifact file does not match"):
        whole_case_targets.enumerate_targets(root, out)


def test_rejects_xartifact_destination_symlink_escape(tmp_path: Path) -> None:
    root = tmp_path / "case"
    out = tmp_path / "out"
    escaped = tmp_path / "escaped" / "base-file-cdrive.E01"
    _write(root / "base-file-cdrive.E01")
    _write(root / "base-file-memory.img")
    staged = out / "_xartifact" / "base-file" / "base-file-cdrive.E01"
    staged.parent.mkdir(parents=True)
    try:
        staged.symlink_to(escaped)
    except OSError:
        pytest.skip("symlinks are not supported on this filesystem")

    with pytest.raises(RuntimeError, match="symlink"):
        whole_case_targets.enumerate_targets(root, out)

    assert not escaped.exists()


def test_rejects_xartifact_parent_symlink_escape(tmp_path: Path) -> None:
    root = tmp_path / "case"
    out = tmp_path / "out"
    escaped_dir = tmp_path / "escaped"
    escaped_dir.mkdir()
    _write(root / "base-file-cdrive.E01")
    _write(root / "base-file-memory.img")
    xartifact_dir = out / "_xartifact"
    xartifact_dir.parent.mkdir(parents=True)
    try:
        xartifact_dir.symlink_to(escaped_dir, target_is_directory=True)
    except OSError:
        pytest.skip("symlinks are not supported on this filesystem")

    with pytest.raises(RuntimeError, match="symlink|escapes output dir"):
        whole_case_targets.enumerate_targets(root, out)

    assert not (escaped_dir / "base-file" / "base-file-cdrive.E01").exists()


def test_rejects_xartifact_symlink_without_writing_through_it(
    tmp_path: Path,
) -> None:
    root = tmp_path / "case"
    out = tmp_path / "out"
    _write(root / "base-file-cdrive.E01")
    _write(root / "base-file-memory.img")
    external_target = tmp_path / "outside-target.E01"
    symlink = out / "_xartifact" / "base-file" / "base-file-cdrive.E01"
    symlink.parent.mkdir(parents=True)
    symlink.symlink_to(external_target)

    with pytest.raises(RuntimeError, match="symlink"):
        whole_case_targets.enumerate_targets(root, out)

    assert not external_target.exists()
