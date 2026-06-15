#!/usr/bin/env python3
"""Enumerate local whole-case verdict targets without mutating evidence roots."""

from __future__ import annotations

import argparse
import hashlib
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path

BASE_FILE_DISK = "base-file-cdrive.E01"
BASE_FILE_MEMORY = "base-file-memory.img"
UNSAFE_TSV_CHARS = frozenset({"\t", "\n", "\r"})


@dataclass(frozen=True)
class Target:
    label: str
    path: Path


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _same_content(source: Path, destination: Path) -> bool:
    return source.stat().st_size == destination.stat().st_size and _sha256(
        source
    ) == _sha256(destination)


def _make_read_only(path: Path) -> None:
    path.chmod(path.stat().st_mode & ~0o222)


def _reject_symlink(path: Path) -> None:
    if path.is_symlink():
        raise RuntimeError(f"staged xartifact path must not be a symlink: {path}")


def _reject_source_symlink(path: Path) -> None:
    if path.is_symlink():
        raise RuntimeError(f"source evidence must not be a symlink: {path}")


def _require_source_inside_root(path: Path, root: Path) -> None:
    resolved = path.resolve(strict=True)
    if resolved != root and root not in resolved.parents:
        raise RuntimeError(f"source evidence escapes evidence root: {path}")


def _require_source_file(path: Path, root: Path) -> None:
    _reject_source_symlink(path)
    if not path.is_file():
        raise RuntimeError(f"source evidence file must be regular: {path}")
    _require_source_inside_root(path, root)


def _require_source_dir(path: Path, root: Path) -> None:
    _reject_source_symlink(path)
    if not path.is_dir():
        raise RuntimeError(f"source evidence directory must be a directory: {path}")
    _require_source_inside_root(path, root)


def _reject_unsafe_tsv_field(kind: str, value: str) -> None:
    if any(char in value for char in UNSAFE_TSV_CHARS):
        raise ValueError(f"target {kind} contains unsafe characters: {value!r}")


def _reject_staging_symlinks(path: Path, out_dir: Path) -> None:
    current = out_dir
    for part in path.relative_to(out_dir).parts:
        current = current / part
        _reject_symlink(current)


def _copy_read_only(source: Path, destination: Path) -> None:
    _reject_symlink(destination)
    if destination.exists():
        if source.samefile(destination):
            raise RuntimeError(
                f"staged xartifact file must not hardlink source evidence: {destination}"
            )
        if not _same_content(source, destination):
            raise RuntimeError(
                f"staged xartifact file does not match source evidence: {destination}"
            )
        _make_read_only(destination)
        return
    shutil.copy2(source, destination)
    _make_read_only(destination)


def _add_target(targets: list[Target], seen: set[str], label: str, path: Path) -> None:
    _reject_unsafe_tsv_field("label", label)
    _reject_unsafe_tsv_field("path", str(path))
    if label in seen:
        return
    targets.append(Target(label=label, path=path))
    seen.add(label)


def _stage_base_file_xartifact(disk: Path, memory: Path, out_dir: Path) -> Path:
    xartifact_dir = out_dir / "_xartifact" / "base-file"
    _reject_staging_symlinks(xartifact_dir, out_dir)
    xartifact_dir.mkdir(parents=True, exist_ok=True)
    _copy_read_only(disk, xartifact_dir / BASE_FILE_DISK)
    _copy_read_only(memory, xartifact_dir / BASE_FILE_MEMORY)
    return xartifact_dir


def enumerate_targets(root: Path, out_dir: Path) -> list[Target]:
    root = root.resolve(strict=True)
    out_dir = out_dir.resolve()
    if out_dir == root or root in out_dir.parents:
        raise ValueError("out_dir must not be inside the evidence root")
    targets: list[Target] = []
    seen: set[str] = set()

    hosts_dir = root / "hosts"
    if hosts_dir.is_symlink():
        _reject_source_symlink(hosts_dir)
    if hosts_dir.exists():
        _require_source_dir(hosts_dir, root)
        for host_dir in sorted(hosts_dir.iterdir()):
            if host_dir.is_symlink():
                _reject_source_symlink(host_dir)
            if not host_dir.is_dir():
                continue
            _require_source_dir(host_dir, root)
            _add_target(targets, seen, f"mem:{host_dir.name}", host_dir)

    disks_dir = root / "disks"
    disk_candidates: dict[str, Path] = {}
    if disks_dir.is_symlink():
        _reject_source_symlink(disks_dir)
    if disks_dir.exists():
        _require_source_dir(disks_dir, root)
        for disk in sorted(disks_dir.glob("*.E01")):
            _require_source_file(disk, root)
            disk_candidates[disk.name] = disk
            _add_target(targets, seen, f"disk:{disk.stem}", disk)

    root_base_disk = root / BASE_FILE_DISK
    root_base_memory = root / BASE_FILE_MEMORY
    if root_base_disk.is_symlink():
        _reject_source_symlink(root_base_disk)
    if root_base_disk.exists():
        _require_source_file(root_base_disk, root)
        disk_candidates[BASE_FILE_DISK] = root_base_disk
        _add_target(targets, seen, "disk:base-file-cdrive", root_base_disk)
    if root_base_memory.is_symlink():
        _reject_source_symlink(root_base_memory)
    if root_base_memory.exists():
        _require_source_file(root_base_memory, root)
        _add_target(targets, seen, "mem:base-file-memory", root_base_memory)

    base_disk = disk_candidates.get(BASE_FILE_DISK)
    if base_disk is not None and root_base_memory.exists():
        xartifact_path = _stage_base_file_xartifact(
            base_disk, root_base_memory, out_dir
        )
        _add_target(targets, seen, "xart:base-file", xartifact_path)

    return targets


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("out_dir", type=Path)
    args = parser.parse_args(argv)

    try:
        targets = enumerate_targets(args.root, args.out_dir)
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"[whole-case-targets] ERROR: {exc}", file=sys.stderr)
        return 1
    for target in targets:
        print(f"{target.label}\t{target.path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
