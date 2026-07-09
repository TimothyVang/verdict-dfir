#!/usr/bin/env python3
"""containment-smoke - assert the project-local containment wiring stays intact.

scripts/lib/project-env.sh redirects every runtime + toolchain path into
.project-local/ (see docs/repo-layout.md). That only holds if every entrypoint
keeps sourcing it and .mcp.json keeps launching through the wrappers. This smoke
is the regression lock: it fails the moment a seam is removed or a new MCP
server is added that bypasses containment, so "everything stays in here" can't
silently rot.

Checks:
  1. scripts/lib/project-env.sh exports the expected containment variables.
  2. Every scripts/run-mcp-*.sh sources project-env.sh.
  3. scripts/verdict sources project-env.sh.
  4. .mcp.json launches every server through a bash wrapper (no bare npx/npm/
     uvx that would inherit the un-contained global environment).
  5. .gitignore ignores /.project-local/ (nothing leaks into git).

Wall-clock: a few ms. Wired into scripts/run-all-smokes.sh.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
ENV_LIB = REPO / "scripts" / "lib" / "project-env.sh"

# Variables the bootstrap must export to keep state in-project. If any of these
# stops being set, something starts escaping to $HOME / /tmp again.
REQUIRED_EXPORTS: tuple[str, ...] = (
    "TMPDIR",
    "XDG_DATA_HOME",
    "XDG_STATE_HOME",
    "XDG_CACHE_HOME",
    "FINDEVIL_HOME",
    "HAYABUSA_RULES_BASE",
    "npm_config_cache",
    "PLAYWRIGHT_BROWSERS_PATH",
    "PUPPETEER_CACHE_DIR",
    "CARGO_HOME",
    "RUSTUP_HOME",
    "UV_CACHE_DIR",
    "PNPM_HOME",
)

# A launcher "sources" the bootstrap if it references project-env.sh on a
# `source`/`.` line.
SOURCE_RE = re.compile(r"^\s*(?:source|\.)\s+.*project-env\.sh", re.MULTILINE)

OK = "[OK  ]"
FAIL = "[FAIL]"


def _sources_bootstrap(path: Path) -> bool:
    try:
        return bool(SOURCE_RE.search(path.read_text(encoding="utf-8")))
    except OSError:
        return False


def main() -> int:
    print("=" * 60)
    print("VERDICT - containment-smoke")
    print("=" * 60)
    failures: list[str] = []

    # 1. Bootstrap exports every required variable.
    if not ENV_LIB.exists():
        failures.append(f"missing bootstrap: {ENV_LIB.relative_to(REPO)}")
    else:
        body = ENV_LIB.read_text(encoding="utf-8")
        for var in REQUIRED_EXPORTS:
            if not re.search(rf"^\s*export\s+{re.escape(var)}=", body, re.MULTILINE):
                failures.append(f"project-env.sh does not export {var}")

    # 2. Every MCP launcher sources the bootstrap.
    launchers = sorted(REPO.glob("scripts/run-mcp-*.sh"))
    if not launchers:
        failures.append("no scripts/run-mcp-*.sh launchers found")
    for sh in launchers:
        if not _sources_bootstrap(sh):
            failures.append(f"{sh.relative_to(REPO)} does not source project-env.sh")

    # 3. scripts/verdict sources the bootstrap.
    verdict = REPO / "scripts" / "verdict"
    if not verdict.exists():
        failures.append("missing scripts/verdict")
    elif not _sources_bootstrap(verdict):
        failures.append("scripts/verdict does not source project-env.sh")

    # 4. .mcp.json launches every server through a bash wrapper.
    mcp = REPO / ".mcp.json"
    if not mcp.exists():
        failures.append("missing .mcp.json")
    else:
        servers = json.loads(mcp.read_text(encoding="utf-8")).get("mcpServers", {})
        for name, spec in servers.items():
            cmd = spec.get("command", "")
            if cmd in {"npx", "npm", "uvx", "uv", "node", "python", "python3"}:
                failures.append(
                    f".mcp.json server {name!r} uses bare {cmd!r} "
                    "(launch via a scripts/run-mcp-*.sh wrapper so it inherits containment)"
                )

    # 5. .project-local/ is gitignored.
    gi = REPO / ".gitignore"
    if not (
        gi.exists()
        and re.search(
            r"^/?\.project-local/?\s*$", gi.read_text(encoding="utf-8"), re.MULTILINE
        )
    ):
        failures.append(".gitignore does not ignore /.project-local/")

    # 6. Every project hook must work INSIDE this project: its command must
    #    reference an in-repo path ($CLAUDE_PROJECT_DIR/... or scripts/...), and
    #    must not point at an absolute path outside the repo. Keeps the hooks
    #    self-contained and portable for anyone who installs the repo.
    for cfg_name in (".claude/settings.json", ".claude/settings.local.json"):
        cfg = REPO / cfg_name
        if not cfg.exists():
            continue
        try:
            hooks_cfg = json.loads(cfg.read_text(encoding="utf-8")).get("hooks", {})
        except json.JSONDecodeError:
            failures.append(f"{cfg_name} is not valid JSON")
            continue
        for event, matchers in hooks_cfg.items():
            for matcher in matchers:
                for hook in matcher.get("hooks", []):
                    cmd = hook.get("command", "")
                    references_project = (
                        "$CLAUDE_PROJECT_DIR" in cmd or "${CLAUDE_PROJECT_DIR}" in cmd
                    )
                    # An absolute path that isn't under $CLAUDE_PROJECT_DIR escapes the project.
                    abs_outside = re.search(
                        r"(?<!CLAUDE_PROJECT_DIR)(?<!_DIR\}\")\s/(?:home|usr|etc|opt|root|var)/",
                        cmd,
                    )
                    if not references_project or abs_outside:
                        failures.append(
                            f"{cfg_name} hook [{event}] is not project-contained: {cmd[:80]!r} "
                            "(reference $CLAUDE_PROJECT_DIR/scripts/... so it works inside any install)"
                        )

    if failures:
        for f in failures:
            print(f"{FAIL} {f}")
        print()
        print("=" * 60)
        print(f"FAIL - {len(failures)} containment regression(s).")
        print("Re-wire the seam (source scripts/lib/project-env.sh) or route the")
        print("server through a scripts/run-mcp-*.sh wrapper. See docs/repo-layout.md.")
        print("=" * 60)
        return 1

    print(
        f"checked bootstrap + {len(launchers)} launchers + verdict + .mcp.json "
        "+ .gitignore + project hooks (all in-project)"
    )
    print("=" * 60)
    print(
        "OK - containment wiring intact; runtime + toolchain stay in .project-local/."
    )
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
