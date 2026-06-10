"""Regression: the MCP client must drain the server's stderr.

The client spawns the findevil-mcp server with stderr=PIPE. If nothing reads
that pipe, a verbose tool (registry_query on a 100 MB SOFTWARE hive) fills the
64 KB OS pipe buffer, the server blocks on write(stderr), and — unable to emit
its stdout response — the whole investigation deadlocks. This reproduces that
shape with a fake server that floods stderr *before* answering: without the
drain thread the call times out; with it, the call returns normally.

Reproduces the rocba-cdrive.e01 registry-phase hang (3+ hours, 0% CPU).
"""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402

# Fake MCP server: read one JSON-RPC request line, write 300 KB to stderr
# (>> the 64 KB pipe buffer, so an undrained pipe blocks the writer), THEN
# write the matching JSON-RPC response to stdout.
_FAKE_SERVER = textwrap.dedent(
    """
    import sys, json
    line = sys.stdin.readline()
    req = json.loads(line)
    sys.stderr.write("x" * 300_000)
    sys.stderr.flush()
    resp = {"jsonrpc": "2.0", "id": req["id"], "result": {"ok": True}}
    sys.stdout.write(json.dumps(resp) + "\\n")
    sys.stdout.flush()
    """
)


def test_call_does_not_deadlock_when_server_floods_stderr(tmp_path: Path) -> None:
    server = tmp_path / "fake_mcp.py"
    server.write_text(_FAKE_SERVER)

    client = fea.StdioMcpClient(f"{sys.executable} {server}", "fake")
    try:
        # A 10s timeout: without the stderr drain the server blocks on its
        # 300 KB stderr write, never answers, and this raises "timed out".
        result = client.call("tools/call", {"name": "x", "arguments": {}}, timeout=10.0)
        assert result == {"ok": True}
    finally:
        client.close()
