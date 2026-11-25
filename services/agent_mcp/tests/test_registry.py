"""Tests for the tool registry and ToolSpec primitives."""

from __future__ import annotations

import inspect

import pytest

from findevil_agent_mcp.tools import all_specs
from findevil_agent_mcp.tools._base import ToolSpec

EXPECTED_TOOL_NAMES = {
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
}


class TestRegistry:
    def test_all_specs_returns_thirteen_tools(self) -> None:
        specs = all_specs()
        assert len(specs) == 13

    def test_all_specs_returns_only_tool_specs(self) -> None:
        specs = all_specs()
        assert all(isinstance(s, ToolSpec) for s in specs)

    def test_tool_names_match_expected_set(self) -> None:
        names = {s.name for s in all_specs()}
        assert names == EXPECTED_TOOL_NAMES

    def test_tool_names_are_unique(self) -> None:
        names = [s.name for s in all_specs()]
        assert len(names) == len(set(names))

    def test_every_tool_has_nonempty_description(self) -> None:
        for spec in all_specs():
            assert spec.description.strip(), f"{spec.name} description empty"

    def test_every_input_model_uses_extra_forbid(self) -> None:
        # deny_unknown_fields at the boundary — Spec #2 invariant.
        for spec in all_specs():
            cfg = spec.input_model.model_config
            assert cfg.get("extra") == "forbid", f"{spec.name} input allows extra"

    def test_every_handler_is_async(self) -> None:
        for spec in all_specs():
            assert inspect.iscoroutinefunction(
                spec.handler
            ), f"{spec.name} handler must be `async def`"

    def test_input_schema_is_json_serializable(self) -> None:
        import json

        for spec in all_specs():
            schema = spec.input_schema()
            assert isinstance(schema, dict)
            json.dumps(schema)  # raises if not JSON-safe


class TestToolSpec:
    def test_input_schema_contains_field_descriptions(self) -> None:
        # Spot check: pick a known-rich tool and verify its schema
        # carries the descriptions we wrote.
        from findevil_agent_mcp.tools.audit_append import SPEC

        schema = SPEC.input_schema()
        # JSON Schema places field descriptions under properties.
        properties = schema.get("properties", {})
        assert "path" in properties
        assert properties["path"].get("description")

    def test_spec_is_frozen(self) -> None:
        from dataclasses import FrozenInstanceError

        from findevil_agent_mcp.tools.audit_append import SPEC

        with pytest.raises(FrozenInstanceError):
            SPEC.name = "renamed"  # type: ignore[misc]
