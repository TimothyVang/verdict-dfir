#!/usr/bin/env python3
"""guard-outside-project - PreToolUse hook that blocks Claude's built-in
Write/Edit/Read tools from touching paths OUTSIDE the project directory.

Claude's built-in file tools bypass the OS sandbox (that only covers Bash and
its child processes), so the only way to confine them is a permission rule or a
hook. Permission globs can't express "everywhere except this dir" cleanly when
the project lives under $HOME, so this hook resolves the target path in code and
blocks anything that escapes the project root.

Scope by tool (set via the matcher in settings):
  * Write / Edit  -> block if the resolved target is outside the project.
  * Read          -> block only the explicit SECRET_DENY paths (reads are
                     otherwise allowed, because forensic/toolchain binaries the
                     agent runs legitimately live outside the repo).

Symlinks are resolved (realpath) before the check, so a symlink inside the
project that points outside is still caught.

Exit codes: 0 = allow, 2 = block (stderr shown to the user/agent).
This is the boundary for the BUILT-IN FILE TOOLS only. Bash + subprocess
containment is the OS sandbox's job (see docs/repo-layout.md / settings).
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

# Reads are allowed broadly (toolchain/forensic binaries live outside the repo),
# but these sensitive locations are always denied so secrets can't be read out.
SECRET_DENY = (
    Path.home() / ".ssh",
    Path.home() / ".aws",
    Path.home() / ".gnupg",
    Path.home() / ".config" / "gh",
    Path.home() / ".claude" / ".credentials.json",
    Path.home() / ".netrc",
)


def _resolve(file_path: str) -> Path:
    p = Path(file_path)
    if not p.is_absolute():
        p = PROJECT_ROOT / p
    # Resolve symlinks/.. without requiring the file to exist yet.
    return Path(os.path.realpath(p))


def _is_inside(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def main() -> int:
    try:
        data = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        return 0

    tool = data.get("tool_name", "")
    file_path = (data.get("tool_input") or {}).get("file_path")
    if not file_path:
        return 0

    target = _resolve(file_path)

    if tool == "Read":
        for secret in SECRET_DENY:
            secret_real = Path(os.path.realpath(secret))
            if target == secret_real or _is_inside(target, secret_real):
                sys.stderr.write(
                    f"[guard-outside-project] BLOCKED: refusing to read secret path "
                    f"{file_path!r} (credentials/keys are never readable by the agent).\n"
                )
                return 2
        return 0

    # Write / Edit: must stay inside the project.
    if not _is_inside(target, PROJECT_ROOT):
        sys.stderr.write(
            f"[guard-outside-project] BLOCKED: {tool} target {file_path!r} is OUTSIDE "
            f"the project ({PROJECT_ROOT}).\n"
            "The agent is confined to this project folder. Write only inside it.\n"
        )
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
