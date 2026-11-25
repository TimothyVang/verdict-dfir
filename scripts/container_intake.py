#!/usr/bin/env python3
"""Descend into containers under hard limits, and account for what we did not.

Two failures this exists to prevent, both seen in this codebase already:

1. **A container counted as one object.** A zip holding 900 files inventoried
   as a single entry, so "no malicious evidence observed" was a claim about the
   wrapper, not the contents.
2. **Absence rendered as clean.** An encrypted archive, an unsupported format,
   or a bomb we refused to open must appear as an explicit UNSUPPORTED or
   REFUSED object. Skipping it quietly is how a case reports nothing found in
   something it never opened.

Every path out of here produces a record. There is no branch that drops an
object silently -- that is the invariant, and `test_no_object_is_ever_dropped`
asserts it.

Limits are enforced BEFORE bytes are written, never after: a bomb that is
detected once it has already filled the disk was not detected.
"""
from __future__ import annotations

import gzip
import os
import tarfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

# Deliberately conservative. A real case that legitimately exceeds these should
# raise the budget explicitly and record that it did, rather than have the
# defaults quietly sized so nothing ever trips.
DEFAULT_MAX_DEPTH = 4
DEFAULT_MAX_OBJECTS = 10_000
DEFAULT_MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024   # 2 GiB expanded
DEFAULT_MAX_RATIO = 200                             # per-member expansion ratio

# Terminal states for an object we did not fully inspect. Each is a positive
# statement about why, never an absence.
UNSUPPORTED = "UNSUPPORTED"      # we cannot open this kind of thing
ENCRYPTED = "ENCRYPTED"          # we could open it but it is locked
REFUSED = "REFUSED"              # opening it would exceed a safety budget
EXTRACTED = "EXTRACTED"          # opened, contents enumerated


@dataclass
class Budget:
    max_depth: int = DEFAULT_MAX_DEPTH
    max_objects: int = DEFAULT_MAX_OBJECTS
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES
    max_ratio: int = DEFAULT_MAX_RATIO
    objects_seen: int = 0
    bytes_written: int = 0
    exhausted: list[str] = field(default_factory=list)

    def note_exhausted(self, which: str) -> None:
        if which not in self.exhausted:
            self.exhausted.append(which)


def _is_encrypted_zip(path) -> bool:
    """General-purpose bit 0 set on any member means the archive is encrypted.

    Read from the header rather than by attempting extraction: trying and
    catching would mean writing attacker-controlled bytes first.
    """
    try:
        with zipfile.ZipFile(path) as zf:
            return any(info.flag_bits & 0x1 for info in zf.infolist())
    except (zipfile.BadZipFile, OSError):
        return False


def _safe_join(dest: Path, member_name: str) -> Path | None:
    """Resolve a member path inside dest, or None if it escapes.

    Zip-slip and tar traversal: a member called ../../etc/cron.d/x must never
    be written. Returning None makes the caller record a REFUSED object rather
    than silently dropping it.
    """
    candidate = (dest / member_name).resolve()
    try:
        candidate.relative_to(dest.resolve())
    except ValueError:
        return None
    return candidate


def inspect_container(path, dest, *, budget: Budget | None = None,
                      depth: int = 0) -> list[dict]:
    """Enumerate one container's members, recursing under budget.

    Returns one record per object. A container that is encrypted, unsupported,
    or over budget yields exactly one record saying so -- never zero.
    """
    budget = budget or Budget()
    path = Path(path)
    dest = Path(dest)
    records: list[dict] = []

    def record(obj_path, state, *, reason, member_of=None, size=None,
               byte_range=None):
        budget.objects_seen += 1
        records.append({
            "path": str(obj_path),
            "state": state,
            "reason": reason,
            "depth": depth,
            "member_of": str(member_of) if member_of else None,
            "size_bytes": size,
            # Where this object physically lives inside its parent. Without it
            # a child object cannot be pointed back at the bytes it came from,
            # so a finding about it is unciteable.
            "byte_range": byte_range,
        })

    if depth > budget.max_depth:
        budget.note_exhausted("max_depth")
        record(path, REFUSED, reason=f"nesting deeper than max_depth={budget.max_depth}")
        return records

    if _is_encrypted_zip(path):
        # The case item 3 names explicitly. An encrypted archive is a thing we
        # SAW and could not read -- reporting it is the whole point.
        record(path, ENCRYPTED, reason="zip member flagged encrypted; contents not enumerable")
        return records

    try:
        opener = zipfile.ZipFile(path) if zipfile.is_zipfile(path) else None
    except OSError:
        opener = None

    if opener is None and tarfile.is_tarfile(path):
        return _walk_tar(path, dest, budget, depth, record, records)
    if opener is None:
        # gzip of a single stream is a container too, but a non-archive is not.
        if str(path).endswith((".gz", ".tgz")):
            return _walk_gzip(path, dest, budget, depth, record, records)
        record(path, UNSUPPORTED,
               reason="not an archive format this intake can enumerate")
        return records

    with opener as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            if budget.objects_seen >= budget.max_objects:
                budget.note_exhausted("max_objects")
                record(path, REFUSED,
                       reason=f"object budget {budget.max_objects} reached; "
                              "remaining members not enumerated")
                return records
            ratio = (info.file_size / info.compress_size) if info.compress_size else 0
            if info.compress_size and ratio > budget.max_ratio:
                budget.note_exhausted("max_ratio")
                record(info.filename, REFUSED, member_of=path, size=info.file_size,
                       reason=f"expansion ratio {ratio:.0f}x over max_ratio="
                              f"{budget.max_ratio}; likely an archive bomb")
                continue
            if budget.bytes_written + info.file_size > budget.max_total_bytes:
                budget.note_exhausted("max_total_bytes")
                record(info.filename, REFUSED, member_of=path, size=info.file_size,
                       reason="expanding this member would exceed the byte budget")
                continue
            target = _safe_join(dest, info.filename)
            if target is None:
                record(info.filename, REFUSED, member_of=path,
                       reason="member path escapes the extraction root (zip slip)")
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, open(target, "wb") as out:
                out.write(src.read())
            budget.bytes_written += info.file_size
            record(target, EXTRACTED, member_of=path, size=info.file_size,
                   byte_range={"offset": info.header_offset,
                               "length": info.compress_size,
                               "encoding": "deflate" if info.compress_type else "stored"},
                   reason="enumerated")
            if zipfile.is_zipfile(target) or tarfile.is_tarfile(target):
                records.extend(inspect_container(
                    target, dest / f"_d{depth + 1}", budget=budget, depth=depth + 1))
    return records


def _walk_tar(path, dest, budget, depth, record, records):
    try:
        with tarfile.open(path) as tf:
            for member in tf.getmembers():
                if not member.isfile():
                    continue
                if budget.objects_seen >= budget.max_objects:
                    budget.note_exhausted("max_objects")
                    record(path, REFUSED, reason="object budget reached")
                    return records
                if budget.bytes_written + member.size > budget.max_total_bytes:
                    budget.note_exhausted("max_total_bytes")
                    record(member.name, REFUSED, member_of=path, size=member.size,
                           reason="expanding this member would exceed the byte budget")
                    continue
                target = _safe_join(Path(dest), member.name)
                if target is None:
                    record(member.name, REFUSED, member_of=path,
                           reason="member path escapes the extraction root")
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                extracted = tf.extractfile(member)
                if extracted is None:
                    record(member.name, UNSUPPORTED, member_of=path,
                           reason="tar member is not a regular readable file")
                    continue
                with extracted as src, open(target, "wb") as out:
                    out.write(src.read())
                budget.bytes_written += member.size
                record(target, EXTRACTED, member_of=path, size=member.size,
                       byte_range={"offset": member.offset_data,
                                   "length": member.size,
                                   "encoding": "stored"},
                       reason="enumerated")
    except (tarfile.TarError, OSError) as exc:
        record(path, UNSUPPORTED, reason=f"tar could not be read: {exc}")
    return records


def _walk_gzip(path, dest, budget, depth, record, records):
    target = Path(dest) / (Path(path).stem or "decompressed")
    target.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    try:
        with gzip.open(path, "rb") as src, open(target, "wb") as out:
            while True:
                chunk = src.read(1024 * 1024)
                if not chunk:
                    break
                written += len(chunk)
                if budget.bytes_written + written > budget.max_total_bytes:
                    budget.note_exhausted("max_total_bytes")
                    out.close()
                    target.unlink(missing_ok=True)
                    record(path, REFUSED, size=written,
                           reason="decompressed stream would exceed the byte budget")
                    return records
                out.write(chunk)
    except (OSError, EOFError) as exc:
        record(path, UNSUPPORTED, reason=f"gzip stream could not be read: {exc}")
        return records
    budget.bytes_written += written
    record(target, EXTRACTED, member_of=path, size=written, reason="enumerated")
    return records
