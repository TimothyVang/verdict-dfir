"""Tests for findevil_agent.mcp_client.

The MockMcpClient gets full coverage; StdioMcpClient is exercised
only for argument validation + closed-state semantics — the real
subprocess path requires the Rust binary at a known location, which
the integration suite covers.
"""

from __future__ import annotations

import json
import sys
import textwrap
from pathlib import Path

import pytest

from findevil_agent.mcp_client import (
    McpClientError,
    McpRpcError,
    MockMcpClient,
    StdioMcpClient,
    ToolCallResult,
)


class TestMockMcpClient:
    def test_call_tool_dict_handler(self) -> None:
        c = MockMcpClient()
        c.register("evtx_query", lambda args: {"row_count": 42, "rows": []})
        r = c.call_tool("evtx_query", {"case_id": "c1", "evtx_path": "x"})
        assert isinstance(r, ToolCallResult)
        assert r.tool_name == "evtx_query"
        assert r.parsed == {"row_count": 42, "rows": []}
        assert len(r.output_sha256) == 64
        assert len(r.tool_call_id) == 36

    def test_call_tool_string_handler(self) -> None:
        c = MockMcpClient()
        c.register("hayabusa_scan", "raw text output")
        r = c.call_tool("hayabusa_scan", {})
        assert r.raw_output_text == "raw text output"
        assert r.parsed is None  # string isn't valid JSON

    def test_call_tool_records_call(self) -> None:
        c = MockMcpClient()
        c.register("x", {"k": 1})
        c.call_tool("x", {"a": 1})
        c.call_tool("x", {"a": 2})
        assert len(c.calls) == 2
        assert c.calls[0][0] == "x"
        assert c.calls[0][1] == {"a": 1}
        assert c.calls[1][1] == {"a": 2}

    def test_unknown_tool_raises_rpc_error(self) -> None:
        c = MockMcpClient()
        with pytest.raises(McpRpcError) as exc:
            c.call_tool("nope", {})
        assert exc.value.code == -32601

    def test_handler_can_be_callable_with_args(self) -> None:
        c = MockMcpClient()
        c.register(
            "echo",
            lambda args: {"echo": args["msg"]} if "msg" in args else {"echo": ""},
        )
        r = c.call_tool("echo", {"msg": "hello"})
        assert r.parsed == {"echo": "hello"}

    def test_output_sha_changes_with_payload(self) -> None:
        c = MockMcpClient()
        c.register(
            "var",
            lambda args: {"row_count": args.get("count", 0)},
        )
        r1 = c.call_tool("var", {"count": 1})
        r2 = c.call_tool("var", {"count": 99})
        assert r1.output_sha256 != r2.output_sha256

    def test_same_payload_same_sha(self) -> None:
        c = MockMcpClient()
        c.register("same", {"x": 1})
        r1 = c.call_tool("same", {})
        r2 = c.call_tool("same", {})
        # tool_call_ids differ (UUIDs) but output_sha256 matches
        # because the response payload is identical.
        assert r1.tool_call_id != r2.tool_call_id
        assert r1.output_sha256 == r2.output_sha256


class TestStdioMcpClientArgValidation:
    def test_close_idempotent(self) -> None:
        c = StdioMcpClient(["/nonexistent/findevil-mcp"])
        c.close()
        c.close()  # second close must not raise

    def test_call_after_close_raises(self) -> None:
        c = StdioMcpClient(["/nonexistent/findevil-mcp"])
        c.close()
        with pytest.raises(McpClientError):
            c.call_tool("evtx_query", {})

    def test_unspawnable_binary_surfaces_clean_error(self) -> None:
        c = StdioMcpClient(["/this/path/definitely/does/not/exist/findevil-mcp"])
        with pytest.raises(McpClientError) as exc:
            c.call_tool("evtx_query", {})
        assert "could not spawn MCP server" in str(exc.value)

    def test_drains_stderr_before_reading_response(self, tmp_path: Path) -> None:
        server = tmp_path / "stderr_flood_server.py"
        server.write_text(
            textwrap.dedent(
                """
                import json
                import sys

                request = json.loads(sys.stdin.readline())
                for _ in range(300):
                    sys.stderr.write("x" * 1024 + "\\n")
                sys.stderr.flush()
                response = {
                    "jsonrpc": "2.0",
                    "id": request["id"],
                    "result": {
                        "content": [{"type": "text", "text": '{"ok": true}'}]
                    },
                }
                sys.stdout.write(json.dumps(response) + "\\n")
                sys.stdout.flush()
                """
            )
        )

        client = StdioMcpClient(
            [sys.executable, str(server)],
            request_timeout_s=1.0,
        )
        try:
            result = client.call_tool("test", {})
            assert result.parsed == {"ok": True}
        finally:
            client.close()


class TestParsing:
    """White-box coverage of _parse_response error paths."""

    def test_rpc_error_response_raises(self) -> None:
        c = StdioMcpClient(["/nonexistent"])
        try:
            with pytest.raises(McpRpcError) as exc:
                c._parse_response(  # type: ignore[attr-defined]
                    response={
                        "jsonrpc": "2.0",
                        "id": 1,
                        "error": {"code": -32602, "message": "bad params"},
                    },
                    tool_call_id="tc-1",
                    tool_name="evtx_query",
                    wall_ms=0,
                )
            assert exc.value.code == -32602
            assert "bad params" in str(exc.value)
        finally:
            c.close()

    def test_parsed_dict_when_json_text(self) -> None:
        c = StdioMcpClient(["/nonexistent"])
        try:
            r = c._parse_response(  # type: ignore[attr-defined]
                response={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps({"row_count": 7}),
                            }
                        ],
                        "_meta": {"ui": {"resourceUri": "ui://timeline"}},
                    },
                },
                tool_call_id="tc-1",
                tool_name="evtx_query",
                wall_ms=42,
            )
            assert r.parsed == {"row_count": 7}
            assert r.wall_clock_ms == 42
            assert r.meta["ui"]["resourceUri"] == "ui://timeline"
        finally:
            c.close()

    def test_non_json_text_leaves_parsed_none(self) -> None:
        c = StdioMcpClient(["/nonexistent"])
        try:
            r = c._parse_response(  # type: ignore[attr-defined]
                response={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {"content": [{"type": "text", "text": "raw bytes"}]},
                },
                tool_call_id="tc-2",
                tool_name="hayabusa_scan",
                wall_ms=10,
            )
            assert r.parsed is None
            assert r.raw_output_text == "raw bytes"
            assert len(r.output_sha256) == 64
        finally:
            c.close()
