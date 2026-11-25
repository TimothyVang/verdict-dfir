#!/usr/bin/env python3
"""Decide an object's type from its BYTES, and say so when they disagree.

Intake classified evidence from the path alone (`classify_artifact_path`
matches extensions). An extension is an attacker-controlled label: a PE named
`notes.txt` routes to a text lane and its imports are never read, and an
`invoice.pdf` that is really a zip is how a container goes uninspected.

Design constraints this file honours deliberately:

* **No new dependency.** python-magic/libmagic are absent from the venv and
  this repo runs contained and often air-gapped.
* **No subprocess.** Shelling `file(1)` on attacker-named paths inside a
  malware pipeline adds an execution surface for no benefit at this precision.
* **Unknown is a real answer.** Every sniffer here returns None rather than a
  best guess. Reporting a guessed type as fact is the failure this codebase
  keeps rediscovering: absence rendered as certainty.

Precision over recall: the signatures are ones that do not collide. A type not
listed reports `unknown`, and `unknown` never becomes agreement.
"""
from __future__ import annotations

from pathlib import Path

# (offset, magic bytes, content type). Ordered; first match wins.
_SIGNATURES: tuple[tuple[int, bytes, str], ...] = (
    (0, b"MZ", "pe"),                     # DOS header; PE/COFF confirmed below
    (0, b"\x7fELF", "elf"),
    (0, b"\xca\xfe\xba\xbe", "macho-fat"),
    (0, b"\xcf\xfa\xed\xfe", "macho"),
    (0, b"PK\x03\x04", "zip"),
    (0, b"PK\x05\x06", "zip-empty"),
    (0, b"\x1f\x8b", "gzip"),
    (0, b"BZh", "bzip2"),
    (0, b"\xfd7zXZ\x00", "xz"),
    (0, b"7z\xbc\xaf\x27\x1c", "7z"),
    (0, b"Rar!\x1a\x07", "rar"),
    (0, b"%PDF-", "pdf"),
    (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole"),   # legacy Office / MSI
    (0, b"SQLite format 3\x00", "sqlite"),
    (0, b"regf", "registry-hive"),
    (0, b"ElfFile\x00", "evtx"),
    (0, b"EMDF", "memory-dump"),
    (0, b"PAGEDU", "memory-dump"),        # PAGEDU64 / PAGEDUMP
    (0, b"\x53\xef", "ext-superblock"),
    (0, b"KDMV", "vmdk"),
    (0, b"QFI\xfb", "qcow"),
    (0, b"conectix", "vhd"),
    (0, b"\x89PNG\r\n\x1a\n", "png"),
    (0, b"\xff\xd8\xff", "jpeg"),
    (0, b"#!", "script-shebang"),
    (257, b"ustar", "tar"),
)

_MAX_SNIFF = 512

# Content types that are executable code, whatever the file is called.
EXECUTABLE_TYPES = frozenset({"pe", "dos-mz", "elf", "macho", "macho-fat"})

# Extensions that promise inert data. Executable bytes under one of these is a
# disguise, and it is the single most useful thing this module can notice --
# so it must not fall through to "unchecked" merely because the extension
# implies no ONE specific type. `.txt` does not promise a type; it promises
# NOT-a-program, and that is checkable.
INERT_EXTENSIONS = frozenset({
    ".txt", ".log", ".md", ".csv", ".tsv", ".json", ".xml", ".yaml", ".yml",
    ".ini", ".cfg", ".conf", ".html", ".htm", ".rtf", ".pdf", ".png", ".jpg",
    ".jpeg", ".gif", ".bmp", ".svg", ".doc", ".docx", ".xls", ".xlsx", ".ppt",
    ".pptx", ".eml", ".msg", ".sql", ".bak", ".dat",
})



def sniff_content_type(path) -> str | None:
    """Return a content type read from the file's bytes, or None if unknown.

    None means "these bytes match no signature I am sure about" -- not "empty"
    and not "text". Callers must not treat it as agreement.
    """
    try:
        with open(path, "rb") as handle:
            head = handle.read(_MAX_SNIFF)
    except OSError:
        return None
    if not head:
        return "empty"
    for offset, magic, name in _SIGNATURES:
        if head[offset:offset + len(magic)] == magic:
            if name == "pe":
                # MZ alone is any DOS executable. The PE signature lives at the
                # offset in e_lfanew; without it this is dos-mz, not pe.
                if len(head) >= 0x40:
                    e_lfanew = int.from_bytes(head[0x3C:0x40], "little")
                    try:
                        with open(path, "rb") as handle:
                            handle.seek(e_lfanew)
                            if handle.read(4) == b"PE\x00\x00":
                                return "pe"
                    except OSError:
                        return "dos-mz"
                return "dos-mz"
            return name
    return None


# Content types that ARE containers: an intake that stops at one has not seen
# what is inside it, and must say so rather than reporting the container clean.
CONTAINER_TYPES = frozenset({
    "zip", "gzip", "bzip2", "xz", "7z", "rar", "tar", "ole", "zip-empty",
})

# Extension -> the content type(s) that extension honestly implies.
_EXTENSION_EXPECTS: dict[str, frozenset[str]] = {
    ".exe": frozenset({"pe", "dos-mz"}),
    ".dll": frozenset({"pe", "dos-mz"}),
    ".sys": frozenset({"pe", "dos-mz"}),
    ".zip": frozenset({"zip", "zip-empty"}),
    ".jar": frozenset({"zip"}),
    ".docx": frozenset({"zip"}),
    ".xlsx": frozenset({"zip"}),
    ".pptx": frozenset({"zip"}),
    ".doc": frozenset({"ole"}),
    ".xls": frozenset({"ole"}),
    ".msi": frozenset({"ole"}),
    ".gz": frozenset({"gzip"}),
    ".tgz": frozenset({"gzip"}),
    ".bz2": frozenset({"bzip2"}),
    ".xz": frozenset({"xz"}),
    ".7z": frozenset({"7z"}),
    ".rar": frozenset({"rar"}),
    ".tar": frozenset({"tar"}),
    ".pdf": frozenset({"pdf"}),
    ".evtx": frozenset({"evtx"}),
    ".sqlite": frozenset({"sqlite"}),
    ".db": frozenset({"sqlite"}),
    ".vmdk": frozenset({"vmdk"}),
    ".qcow2": frozenset({"qcow"}),
    ".vhd": frozenset({"vhd"}),
    ".png": frozenset({"png"}),
    ".jpg": frozenset({"jpeg"}),
    ".jpeg": frozenset({"jpeg"}),
}


def verify_declared_type(path) -> dict[str, object]:
    """Compare what the name claims against what the bytes say.

    Returns a record with an explicit `agreement` of:
      "agree"        the extension and the content match
      "mismatch"     they disagree -- a strong signal, never resolved silently
      "unknown"      the bytes match no signature we trust
      "unchecked"    the extension implies nothing in particular

    A mismatch is REPORTED, never repaired. `notes.txt` containing a PE is a
    finding; quietly reclassifying it would erase the very thing worth seeing.
    """
    suffix = Path(str(path)).suffix.lower()
    sniffed = sniff_content_type(path)
    expected = _EXTENSION_EXPECTS.get(suffix)

    if sniffed is None:
        agreement = "unknown"
    elif expected is not None:
        agreement = "agree" if sniffed in expected else "mismatch"
    elif suffix in INERT_EXTENSIONS and sniffed in EXECUTABLE_TYPES:
        # A program wearing a document's name. The extension implies no single
        # type, but it does imply "not executable", and that is checkable.
        agreement = "mismatch"
    else:
        agreement = "unchecked"

    return {
        "path": str(path),
        "extension": suffix or None,
        "content_type": sniffed,
        "extension_expects": (
            sorted(expected) if expected
            else ("not-executable" if suffix in INERT_EXTENSIONS else None)
        ),
        "agreement": agreement,
        "is_container": sniffed in CONTAINER_TYPES if sniffed else False,
    }
