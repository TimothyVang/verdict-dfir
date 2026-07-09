#!/usr/bin/env python3
"""guard-root-writes - PreToolUse hook that blocks an agent (Claude Code,
Codex, ...) from creating a NEW file or folder directly at the repo root
unless its name is sanctioned.

The repo root is config + public docs + known top-level dirs only (see
docs/repo-layout.md). `scripts/repo-layout-smoke.py` enforces that *after the
fact* in the smoke gate; this hook enforces it *at write time* so a stray
`notes.md`, `scratch/`, or `foo_asset_folder/` never lands at the root in the
first place.

Wire it as a PreToolUse hook on the Write tool (and any other file-creating
tool). It reads the hook JSON on stdin, looks at `tool_input.file_path`, and:
  * exit 0  - allow (path is not a new root entry, or its name is sanctioned).
  * exit 2  - block, with a message telling the agent where to put the file.

It only blocks *new* root entries: editing an existing, already-sanctioned
root file (CLAUDE.md, README.md, ...) is always allowed. The allow-list is
imported from scripts/repo-layout-smoke.py so the hook and the smoke can never
drift apart.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent


def _load_allowlist() -> frozenset[str]:
    """Import ROOT_ALLOWLIST from the smoke (single source of truth). On any
    failure, fall back to an empty set, which makes the hook fail OPEN (allow)
    rather than wedge the agent."""
    smoke = REPO / "scripts" / "repo-layout-smoke.py"
    try:
        spec = importlib.util.spec_from_file_location("repo_layout_smoke", smoke)
        if spec is None or spec.loader is None:
            return frozenset()
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return frozenset(mod.ROOT_ALLOWLIST)
    except Exception:
        return frozenset()


def main() -> int:
    try:
        data = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        return 0  # not a hook payload we understand -> don't interfere

    file_path = (data.get("tool_input") or {}).get("file_path")
    if not file_path:
        return 0

    target = Path(file_path)
    if not target.is_absolute():
        target = (REPO / target).resolve()
    else:
        target = target.resolve()

    # Map the write to the top-level component it would touch under the repo
    # root. A write to `foo.md` introduces root entry `foo.md`; a write to
    # `my_assets/logo.svg` introduces root entry `my_assets/`. Both are guarded.
    try:
        rel = target.relative_to(REPO)
    except ValueError:
        return 0  # outside the repo entirely -> not our concern
    if not rel.parts:
        return 0
    top = rel.parts[0]

    # If the top-level entry already exists, the write lands inside an existing
    # (sanctioned or already-present) tree -> always fine. We only guard the
    # creation of a NEW, unsanctioned root entry.
    if (REPO / top).exists():
        return 0

    if top in _load_allowlist():
        return 0

    label = f"{top}/" if len(rel.parts) > 1 else top
    sys.stderr.write(
        f"[guard-root-writes] BLOCKED: refusing to create '{label}' at the repo root.\n"
        "The root holds only config files, public docs, and known top-level dirs.\n"
        "Put this file in a sanctioned subtree instead, e.g.:\n"
        "  * scripts/   - tooling and scripts\n"
        "  * docs/      - documentation\n"
        "  * assets/    - shared assets\n"
        "  * services/ , apps/  - code\n"
        "If it is genuinely a new root citizen, add its exact name to\n"
        "ROOT_ALLOWLIST in scripts/repo-layout-smoke.py first. See docs/repo-layout.md.\n"
    )
    return 2


if __name__ == "__main__":
    sys.exit(main())
