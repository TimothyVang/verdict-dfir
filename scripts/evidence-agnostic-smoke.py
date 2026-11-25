#!/usr/bin/env python3
"""Evidence-agnostic guard (CLAUDE.md hard rule enforcement).

VERDICT must work for ANY evidence name and type in ``/evidence`` — not just the
image it was last tested on. This smoke fails if production code, docstrings, or
finding descriptions hard-code values keyed to one specific image (the NIST
"Hacking Case" / SCHARDT.dd it was tuned on) or reference golden/benchmark IDs.

Scope: ``scripts/`` and ``services/`` ``.py``/``.rs`` PRODUCTION code. Test files,
``goldens/``, build output, and this script are excluded (benchmark coupling is
allowed there). Detection must key on general DFIR signatures; descriptions must
report what was actually parsed — see CLAUDE.md "Evidence-agnostic (hard rule)".

Run: ``python scripts/evidence-agnostic-smoke.py`` (exit 1 on any violation).
Part of ``scripts/run-all-smokes.sh``.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# Image-specific patterns that must never appear in production detection code.
# Each is keyed to the one SCHARDT / NIST Hacking Case image and generalizes
# nothing on any other evidence.
PATTERNS: list[tuple[str, str]] = [
    (r"SCHARDT", "image name (use a generic path / $FINDEVIL_EVIDENCE_ROOT)"),
    (r"[Mm]r\.?\s?[Ee]vil|MR-EVIL", "one image's username/hostname"),
    (r"anonyymizer", "one user's misspelling (use the general 'anonym' root)"),
    (r"\bnhc-\d{2,}\b", "golden/benchmark ID (use general technique language)"),
    (r"NIST Hacking Case", "benchmark name (describe the artifact, not the benchmark)"),
    (r'"4\.12\."', "version/IP fragment from one image (not a DFIR signature)"),
    (
        r'"temp on"|"cd drive"',
        "one image's LECmd drive-label text (gate on drive-type instead)",
    ),
]

INCLUDE_DIRS = ("scripts", "services")
EXCLUDE_DIR_PARTS = {
    "tests",
    "test",
    "node_modules",
    "target",
    ".venv",
    "__pycache__",
    "goldens",
    "migrations",
}
EXCLUDE_FILES = {"evidence-agnostic-smoke.py"}
EXTS = {".py", ".rs"}


def _eligible(path: Path) -> bool:
    if path.suffix not in EXTS or path.name in EXCLUDE_FILES:
        return False
    parts = {p.lower() for p in path.relative_to(REPO).parts}
    if parts & EXCLUDE_DIR_PARTS:
        return False
    # A *_test.rs / test_*.py file outside a tests/ dir is still test code.
    name = path.name.lower()
    return not (
        name.startswith("test_")
        or name.endswith("_test.py")
        or name.endswith("_test.rs")
    )


def main() -> int:
    compiled = [(re.compile(p), why) for p, why in PATTERNS]
    violations: list[str] = []
    scanned = 0
    for inc in INCLUDE_DIRS:
        for path in sorted((REPO / inc).rglob("*")):
            if not path.is_file() or not _eligible(path):
                continue
            scanned += 1
            try:
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            for lineno, line in enumerate(lines, 1):
                for rx, why in compiled:
                    if rx.search(line):
                        rel = path.relative_to(REPO)
                        violations.append(
                            f"  {rel}:{lineno}: {why}\n      {line.strip()[:120]}"
                        )

    print("=== evidence-agnostic smoke ===")
    print(
        f"  scanned {scanned} production .py/.rs files under {', '.join(INCLUDE_DIRS)}/"
    )
    if violations:
        print(
            f"  FAIL: {len(violations)} image-specific literal(s) in production code:\n"
        )
        print("\n".join(violations))
        print(
            "\n  Fix: key detection on general DFIR signatures, describe what was actually\n"
            "  parsed, and keep golden/benchmark coupling under goldens/ and tests only.\n"
            "  See CLAUDE.md 'Evidence-agnostic (hard rule)'."
        )
        return 1
    print("  PASS: no image-specific hard-coding in production code.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
