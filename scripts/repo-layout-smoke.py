#!/usr/bin/env python3
"""repo-layout-smoke - assert no un-sanctioned entry lives at the repo root.

VERDICT already guards the *published* surface (.githooks/pre-push,
scripts/ship-beta.sh, .gitattributes export-ignore). What it lacked was a
guard for *where files live in the working tree*. Nothing stopped a stray
asset folder, a loose scratch note, or a duplicate `*_asset_folder/` from
landing at the repo root and sitting in `git status` forever - which is
exactly how the root accumulated `verdict_svg_asset_folder/` +
`verdict_dfir_svg_asset_folder.zip` (stale duplicates of the canonical
`VERDICT_DFIR_SVG_Assets_v2/`).

This smoke locks the root layout: the repo root may only contain
explicitly-sanctioned config files, public docs, and known top-level
directories (ROOT_ALLOWLIST). Anything else that is tracked OR untracked-
but-not-ignored is a violation.

Scope is the repo root ONLY (the stated pain point). Entries that git
already ignores - runtime drops like `*.ova`, plaso `log2timeline-*` /
`psort-*` logs, `evidence/`, `tmp/`, `target/`, `node_modules/`,
`release-assets/`, `graphify-out/` - are intentionally out of scope: they
never enter git and the layout doc documents where they go.

To fix a failure: move the entry into a sanctioned subtree (scripts/,
docs/, assets/, ...), add it to .gitignore if it's local-only output, or -
if it is genuinely a new sanctioned root citizen - add its exact name to
ROOT_ALLOWLIST below with a one-line justification comment. Same convention
as the ALLOW_PATTERNS list in scripts/path-existence-smoke.py.

Wall-clock: ~30ms (two `git` calls + set membership). Wired into
scripts/run-all-smokes.sh beside path-existence-smoke.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# Exact top-level names allowed at the repo root. Seeded from the tracked
# top-level set (`git ls-tree --name-only HEAD`) - i.e. the sanctioned,
# committed layout. Grouped for readability; every entry is here because it
# is a real, intentional root citizen.
ROOT_ALLOWLIST: frozenset[str] = frozenset(
    {
        # --- Config / manifests (build, deps, tooling) ---
        "Cargo.toml",
        "Cargo.lock",
        "pnpm-workspace.yaml",
        "pnpm-lock.yaml",
        "rust-toolchain.toml",
        "requirements.txt",
        "mkdocs.yml",
        "Dockerfile",
        ".dockerignore",
        ".mcp.json",
        ".mcp.json.sift",
        ".mcp.json.docker",
        ".gitignore",
        ".gitattributes",
        ".yamllint",
        "install.sh",
        ".envrc",  # direnv: auto-loads scripts/lib/project-env.sh (containment)
        # --- Public root docs (the load-bearing top-level Markdown) ---
        "README.md",
        "CHANGELOG.md",
        "LICENSE",
        "NOTICE",
        "CODE_OF_CONDUCT.md",
        "CONTRIBUTING.md",
        "SECURITY.md",
        "INSTALL.md",
        "QUICKSTART.md",
        "CLAUDE.md",
        "AGENTS.md",
        "llms.txt",
        # --- Sanctioned top-level directories ---
        "agent-config",
        "apps",
        "assets",
        "ci",
        "docker",
        "docs",
        "evidence",  # ships as README + .gitkeep; contents are gitignored
        "goldens",
        "packer",
        "scripts",
        "services",
        "VERDICT_DFIR_SVG_Assets_v2",  # canonical brand dir (CLAUDE.md)
        ".claude",  # only .claude/skills/** ships; rest gitignored
        ".githooks",
        ".github",
    }
)

OK = "[OK  ]"
FAIL = "[FAIL]"


def _git_lines(args: list[str]) -> list[str] | None:
    """Run a git command at REPO and return NUL-split tokens, or None if
    git is unavailable / this isn't a checkout (smoke degrades to a pass)."""
    try:
        out = subprocess.run(
            ["git", *args],
            cwd=REPO,
            capture_output=True,
            text=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    return [tok for tok in out.stdout.split("\0") if tok]


def _top_component(path: str) -> str:
    """First path component of a repo-relative path (strip trailing slash
    git appends to untracked directories)."""
    return path.rstrip("/").split("/", 1)[0]


def _root_state() -> tuple[set[str], set[str]] | None:
    """Return (tracked_top, untracked_top): the sets of top-level names that
    are tracked, and that are untracked-and-NOT-ignored. None if git is
    unavailable."""
    tracked = _git_lines(["ls-files", "-z"])
    if tracked is None:
        return None
    tracked_top = {_top_component(p) for p in tracked}

    # `??` = untracked-not-ignored. `--ignored` is omitted on purpose: we do
    # NOT want ignored entries reported, since they're out of scope.
    status = _git_lines(["status", "--porcelain=v1", "-z"])
    if status is None:
        return None
    untracked_top: set[str] = set()
    for entry in status:
        # Porcelain v1: "XY <path>"; untracked rows are "?? <path>".
        if entry.startswith("?? "):
            untracked_top.add(_top_component(entry[3:]))

    return tracked_top, untracked_top


def main() -> int:
    print("=" * 60)
    print("VERDICT - repo-layout-smoke")
    print("=" * 60)

    state = _root_state()
    if state is None:
        print(f"{OK} git unavailable - layout check skipped (not a checkout).")
        print("=" * 60)
        return 0

    tracked_top, untracked_top = state
    # An entry counts toward the layout check if git tracks it OR it is
    # untracked-and-not-ignored. Ignored-only entries never appear in either
    # set, so they're skipped exactly as intended.
    in_scope = sorted(tracked_top | untracked_top)
    violations = [name for name in in_scope if name not in ROOT_ALLOWLIST]

    print(f"checked {len(in_scope)} root entries against the allow-list")
    print()

    if violations:
        for name in violations:
            kind = "tracked" if name in tracked_top else "untracked"
            print(f"{FAIL} unsanctioned root entry ({kind}): {name!r}")
        print()
        print("=" * 60)
        print(f"FAIL - {len(violations)} un-sanctioned root entry(ies).")
        print("Fix each by ONE of:")
        print("  * move it into a sanctioned subtree (scripts/, docs/,")
        print("    assets/, services/, ...);")
        print("  * add it to .gitignore if it's local-only output;")
        print("  * if it's a genuine new root citizen, add its exact name")
        print("    to ROOT_ALLOWLIST in scripts/repo-layout-smoke.py with a")
        print("    one-line justification. See docs/repo-layout.md.")
        print("=" * 60)
        return 1

    print("=" * 60)
    print(f"OK - all {len(in_scope)} root entries are sanctioned.")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
