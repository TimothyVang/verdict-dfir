"""Tests for the server bootstrap path.

We don't run the stdio loop here (that needs a paired client). The
check is structural: ``build_server`` returns a Server with all 12
tools registered, and the in-process error-mapping code paths
behave correctly.
"""

from __future__ import annotations

import json

from findevil_agent_mcp.server import (
    SERVER_NAME,
    SERVER_VERSION,
    _error_content,
    _to_text_content,
    build_server,
)
from findevil_agent_mcp.tools.audit_verify import AuditVerifyOutput


class TestBuildServer:
    def test_returns_thirteen_specs(self) -> None:
        _server, specs = build_server()
        assert len(specs) == 13

    def test_server_name_constant(self) -> None:
        assert SERVER_NAME == "findevil-agent-mcp"

    def test_server_version_set(self) -> None:
        assert SERVER_VERSION
        # Semver-ish.
        assert SERVER_VERSION.count(".") == 2


class TestTextContent:
    def test_pydantic_model_serializes_canonically(self) -> None:
        out = AuditVerifyOutput(ok=True, record_count=3, error=None)
        result = _to_text_content(out)
        assert len(result) == 1
        body = json.loads(result[0].text)
        assert body == {"ok": True, "record_count": 3, "error": None}

    def test_dict_serializes_canonically(self) -> None:
        result = _to_text_content({"a": 1, "b": 2})
        assert json.loads(result[0].text) == {"a": 1, "b": 2}

    def test_scalar_wrapped_under_value(self) -> None:
        result = _to_text_content(42)
        assert json.loads(result[0].text) == {"value": 42}


class TestErrorContent:
    def test_validation_error_shape(self) -> None:
        result = _error_content("missing field 'path'", kind="validation")
        body = json.loads(result[0].text)
        assert body == {"error": {"kind": "validation", "message": "missing field 'path'"}}

    def test_unknown_tool_shape(self) -> None:
        result = _error_content("unknown tool: 'foo'", kind="unknown_tool")
        body = json.loads(result[0].text)
        assert body["error"]["kind"] == "unknown_tool"

    def test_handler_error_shape(self) -> None:
        result = _error_content("RuntimeError: boom", kind="handler")
        body = json.loads(result[0].text)
        assert body["error"]["kind"] == "handler"
