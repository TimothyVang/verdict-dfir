#!/usr/bin/env python3
"""injection-self-attack - replay prompt-injection / Trojan-Source attacks
against VERDICT's OWN sealed custody artifacts and assert the neutralizer +
audit chain hold. No LLM, fully offline, deterministic.

This is the demoable architectural proof behind the sanitizer boundary
(``services/mcp/src/sanitize.rs`` mirrored by
``services/agent_mcp/findevil_agent_mcp/sanitize.py``) and the signed manifest
(``manifest_finalize`` / ``manifest_verify``). For each attack it:

  1. pushes attacker-controlled evidence text -- chat/role control tokens
     (``<|im_start|>``, ``[INST]``, ``<<SYS>>``) and invisible/BIDI
     Trojan-Source code points -- through the SAME sanitizer the product uses;
  2. asserts every control token is neutralized to the inert
     ``[neutralized:<id>]`` marker and every invisible code point is stripped;
  3. proves the transform is DETERMINISTIC (a re-run yields the identical
     ``output_sha256`` over the canonical serialized output); and
  4. seals a run manifest whose ``tool_call_output`` leaf is that very hash and
     verifies it offline (``manifest_verify`` overall=True) -- so the injection
     cannot alter what the audit chain attests.

The harness logic lives in
``services/agent_mcp/findevil_agent_mcp/injection_self_attack.py`` and is
regression-tested by ``services/agent_mcp/tests/test_injection_self_attack.py``
(including a negative control: a no-op sanitizer must leak, proving the green
result is load-bearing). This script is a thin runner so the proof is one
command for a demo or CI:

    python scripts/injection-self-attack.py

It re-execs itself under the agent_mcp uv environment (which carries both the
sanitizer and the crypto-manifest helpers) and prints a HOLD/FAIL summary,
exiting non-zero if any attack breaches custody.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
AGENT_MCP_DIR = REPO / "services" / "agent_mcp"


def _in_harness_env() -> bool:
    try:
        import findevil_agent  # noqa: F401
        import findevil_agent_mcp.injection_self_attack  # noqa: F401
    except ImportError:
        return False
    return True


def _reexec_under_uv() -> int:
    """Re-run this script inside the agent_mcp uv env, which resolves both the
    sanitizer (findevil_agent_mcp) and the crypto-manifest helpers
    (findevil_agent, a path dep). --no-sync avoids dropping the editable dep."""
    cmd = [
        "uv",
        "run",
        "--no-sync",
        "--directory",
        str(AGENT_MCP_DIR),
        "python",
        str(Path(__file__).resolve()),
    ]
    try:
        return subprocess.run(cmd, check=False).returncode
    except FileNotFoundError:
        print(
            "[FAIL] `uv` not found on PATH; cannot launch the harness env",
            file=sys.stderr,
        )
        return 2


def main() -> int:
    if not _in_harness_env():
        return _reexec_under_uv()

    from findevil_agent_mcp.injection_self_attack import format_summary, run_corpus

    with tempfile.TemporaryDirectory() as td:
        results = run_corpus(Path(td))
        print(format_summary(results))
    return 0 if all(r.custody_held for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
