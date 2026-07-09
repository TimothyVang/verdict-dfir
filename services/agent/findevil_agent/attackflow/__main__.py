"""CLI: python -m findevil_agent.attackflow <case-dir>"""

from __future__ import annotations

import sys
from pathlib import Path

from .emit import emit


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: python -m findevil_agent.attackflow <case-dir>", file=sys.stderr)
        return 2
    try:
        result = emit(Path(argv[0]))
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    tree = "yes" if result.process_tree_available else f"omitted ({result.proc_reason})"
    print(f"attack-flow artifacts: {len(result.paths)} -> {result.out_dir}")
    print(f"process tree: {tree}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
