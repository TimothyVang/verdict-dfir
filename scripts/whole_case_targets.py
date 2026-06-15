#!/usr/bin/env python3
"""Enumerate local whole-case verdict targets without mutating evidence roots."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import os
from pathlib import Path
import shutil
import sys


BASE_FILE_DISK = "base-file-cdrive.E01"
BASE_FILE_MEMORY = "base-file-memory.img"


@dataclass(frozen=True)
class Target:
    label: str
    path: Path


def _link_or_copy(source: Path, destination: Path) -> None:
    if destination.exists():
        return
    try:
        os.link(source, destination)
    except OSError:
        shutil.copy2(source, destination)


def _add_target(targets: list[Target], seen: set[str], label: str, path: Path) -> None:
    if label in seen:
        return
    targets.append(Target(label=label, path=path))
    seen.add(label)


def _stage_base_file_xartifact(disk: Path, memory: Path, out_dir: Path) -> Path:
    xartifact_dir = out_dir / "_xartifact" / "base-file"
    xartifact_dir.mkdir(parents=True, exist_ok=True)
    _link_or_copy(disk, xartifact_dir / BASE_FILE_DISK)
    _link_or_copy(memory, xartifact_dir / BASE_FILE_MEMORY)
    return xartifact_dir


def enumerate_targets(root: Path, out_dir: Path) -> list[Target]:
    root = root.resolve(strict=True)
    out_dir = out_dir.resolve()
    targets: list[Target] = []
    seen: set[str] = set()

    hosts_dir = root / "hosts"
    if hosts_dir.exists():
        for host_dir in sorted(path for path in hosts_dir.iterdir() if path.is_dir()):
            _add_target(targets, seen, f"mem:{host_dir.name}", host_dir)

    disks_dir = root / "disks"
    disk_candidates: dict[str, Path] = {}
    if disks_dir.exists():
        for disk in sorted(disks_dir.glob("*.E01")):
            disk_candidates[disk.name] = disk
            _add_target(targets, seen, f"disk:{disk.stem}", disk)

    root_base_disk = root / BASE_FILE_DISK
    root_base_memory = root / BASE_FILE_MEMORY
    if root_base_disk.exists():
        disk_candidates[BASE_FILE_DISK] = root_base_disk
        _add_target(targets, seen, "disk:base-file-cdrive", root_base_disk)
    if root_base_memory.exists():
        _add_target(targets, seen, "mem:base-file-memory", root_base_memory)

    base_disk = disk_candidates.get(BASE_FILE_DISK)
    if base_disk is not None and root_base_memory.exists():
        xartifact_path = _stage_base_file_xartifact(base_disk, root_base_memory, out_dir)
        _add_target(targets, seen, "xart:base-file", xartifact_path)

    return targets


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("out_dir", type=Path)
    args = parser.parse_args(argv)

    for target in enumerate_targets(args.root, args.out_dir):
        print(f"{target.label}\t{target.path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
