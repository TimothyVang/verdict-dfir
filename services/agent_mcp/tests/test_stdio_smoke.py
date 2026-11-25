"""End-to-end stdio smoke test.

Spawns ``python -m findevil_agent_mcp.server`` as a subprocess and
drives the JSON-RPC handshake by hand: ``initialize`` → ``tools/list``
→ one ``tools/call``. This catches "did the MCP SDK API change under
us" and "does the wire format actually round-trip end-to-end".

Wire format reminder: MCP stdio is line-delimited JSON (one object
per line), NOT LSP-style Content-Length framing. See
``services/agent/findevil_agent/mcp_client.py`` for the canonical
description.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from queue import Empty, Queue
from typing import Any

import pytest

pytestmark = [
    pytest.mark.integration,
    # Subprocess pipe cleanup on Windows can leak file handles which
    # the project-wide filterwarnings=error config would otherwise
    # promote to test failures. Suppress just for this file.
    pytest.mark.filterwarnings("ignore::ResourceWarning"),
    pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning"),
]


class _LineReader:
    """Background-thread line reader so we can poll with a timeout."""

    def __init__(self, stream: Any) -> None:
        self._stream = stream
        self._queue: Queue[str | None] = Queue()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def _loop(self) -> None:
        try:
            for line in iter(self._stream.readline, ""):
                if not line:
                    break
                self._queue.put(line)
        except Exception:
            pass
        finally:
            self._queue.put(None)  # EOF sentinel

    def readline(self, timeout_s: float) -> str:
        try:
            line = self._queue.get(timeout=timeout_s)
        except Empty as exc:
            raise TimeoutError(
                f"timed out waiting for MCP server stdout line after {timeout_s}s"
            ) from exc
        if line is None:
            raise RuntimeError("MCP server closed stdout")
        return line


def _send_line(proc: subprocess.Popen[str], message: dict[str, Any]) -> None:
    """Write one JSON message followed by a newline to the server's stdin."""
    assert proc.stdin is not None
    proc.stdin.write(json.dumps(message, separators=(",", ":")) + "\n")
    proc.stdin.flush()


def _read_message(reader: _LineReader, timeout_s: float = 15.0) -> dict[str, Any]:
    """Read one JSON line, skipping any blank/non-JSON lines."""
    deadline = time.monotonic() + timeout_s
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("timed out waiting for MCP message")
        line = reader.readline(remaining)
        line = line.strip()
        if not line:
            continue
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            # The server may emit logs to stderr only, but be defensive.
            continue


def test_stdio_initialize_and_list_tools(tmp_path: Path) -> None:
    """Boot the server, complete initialize, list tools, call audit_verify."""
    env = os.environ.copy()
    env["FINDEVIL_LOG_LEVEL"] = "WARNING"
    env["PYTHONUNBUFFERED"] = "1"

    cmd = [sys.executable, "-m", "findevil_agent_mcp.server"]
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        text=True,
        encoding="utf-8",
        bufsize=1,
    )
    reader = _LineReader(proc.stdout)
    try:
        _send_line(
            proc,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "smoke-test", "version": "0.0.0"},
                },
            },
        )
        init_resp = _read_message(reader)
        assert init_resp.get("id") == 1, init_resp
        assert "result" in init_resp, init_resp
        assert "capabilities" in init_resp["result"]

        _send_line(
            proc,
            {
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
            },
        )

        _send_line(
            proc,
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        )
        list_resp = _read_message(reader)
        assert list_resp.get("id") == 2, list_resp
        tools = list_resp["result"]["tools"]
        names = sorted(t["name"] for t in tools)
        assert names == sorted(
            [
                "audit_append",
                "audit_verify",
                "manifest_finalize",
                "manifest_verify",
                "verify_finding",
                "detect_contradictions",
                "judge_findings",
                "correlate_findings",
                "memory_remember",
                "memory_recall",
                "pool_handoff",
                "expert_miss_capture",
                "accuracy_compare",
            ]
        )

        _send_line(
            proc,
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "audit_verify",
                    "arguments": {"path": str(tmp_path / "nope.jsonl")},
                },
            },
        )
        call_resp = _read_message(reader)
        assert call_resp.get("id") == 3, call_resp
        content = call_resp["result"]["content"]
        assert len(content) == 1
        body = json.loads(content[0]["text"])
        assert body == {"ok": True, "record_count": 0, "error": None}
    finally:
        if proc.stdin is not None and not proc.stdin.closed:
            proc.stdin.close()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
