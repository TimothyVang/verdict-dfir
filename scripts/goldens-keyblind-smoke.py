#!/usr/bin/env python3
"""Key-blind run-engine guard (P0-6 / P0-3 adopt item).

The investigation engine must NEVER read the golden answer key: the run produces
findings blind, and only the post-run scorer tier (``findevil_agent.accuracy``,
``scripts/score-recall.py``, ``scripts/score-overclaim.py``) is allowed to look at
``goldens/``. Today the engine is already key-blind by convention, but nothing
enforces it — a future import of the scorer into the run path would silently turn
the accuracy numbers into a self-graded tautology.

This smoke statically scans the run-engine surface — ``scripts/find_evil_auto.py``
(the deterministic engine) plus the ``findevil_agent`` runtime package, EXCLUDING
``accuracy.py`` (the scorer core that legitimately reads the key) and test
directories — and fails if any file references the answer-key surface.

Scope is deliberately narrow: the scorer scripts under ``scripts/`` (score-recall,
score-overclaim, generate-accuracy-report, …) and ``goldens/`` are NOT scanned —
reading the key there is their job.

Run: ``python scripts/goldens-keyblind-smoke.py`` (exit 1 on any violation).
Part of ``scripts/run-all-smokes.sh``.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# Answer-key surface that must not appear in the run engine. Keyed to how the
# scorer is reached, not to any one image.
FORBIDDEN: list[tuple[str, str]] = [
    (r"\bgoldens\b", "references the goldens/ answer-key tree"),
    (r"expected-findings", "reads the golden expected-findings key"),
    (r"resolve_golden", "resolves a golden answer key"),
    (r"accuracy\.score", "calls the post-run scorer (accuracy.score)"),
    (r"accuracy\.resolve", "resolves goldens via the scorer (accuracy.resolve_*)"),
    (r"import\s+accuracy\b|from\s+\S*accuracy\s+import", "imports the scorer module"),
]

# The single deterministic-engine file + the runtime package root.
_ENGINE_FILE = REPO / "scripts" / "find_evil_auto.py"
_RUNTIME_PKG = REPO / "services" / "agent" / "findevil_agent"

# Inside the runtime package, accuracy.py IS the scorer (it reads the key by
# design); test code may reference goldens freely.
EXCLUDE_FILES = {"accuracy.py"}
EXCLUDE_DIR_PARTS = {"tests", "test", "__pycache__"}


def is_excluded(path: Path) -> bool:
    """True if a runtime-package path is the scorer core or test code."""
    if path.name in EXCLUDE_FILES:
        return True
    parts = {p.lower() for p in path.parts}
    return bool(parts & EXCLUDE_DIR_PARTS)


def violations_in(text: str) -> list[str]:
    """Return the reasons each forbidden answer-key pattern matched in ``text``."""
    hits: list[str] = []
    for lineno, line in enumerate(text.splitlines(), 1):
        for pat, why in FORBIDDEN:
            if re.search(pat, line):
                hits.append(f"L{lineno}: {why} -> {line.strip()[:100]}")
    return hits


def run_engine_files() -> list[Path]:
    """The run-engine surface scanned by this gate (key-blind by contract)."""
    files: list[Path] = []
    if _ENGINE_FILE.is_file():
        files.append(_ENGINE_FILE)
    if _RUNTIME_PKG.is_dir():
        files.extend(
            p for p in sorted(_RUNTIME_PKG.rglob("*.py")) if not is_excluded(p)
        )
    return files


def main() -> int:
    violations: list[str] = []
    scanned = 0
    for path in run_engine_files():
        scanned += 1
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for hit in violations_in(text):
            violations.append(f"  {path.relative_to(REPO)}:{hit}")

    print("=== goldens-keyblind smoke ===")
    print(
        f"  scanned {scanned} run-engine file(s); scorer (accuracy.py) + tests excluded"
    )
    if violations:
        print(
            f"  FAIL: the run engine reaches the answer key in {len(violations)} place(s):\n"
        )
        print("\n".join(violations))
        print(
            "\n  The investigation must run BLIND. Move any goldens/scorer use into the\n"
            "  post-run scorer tier (findevil_agent.accuracy / scripts/score-*.py)."
        )
        return 1
    print("  PASS: run engine is key-blind (no goldens/scorer references).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
