"""Tests for the find_ai_signatures MCP tool shim.

Boundary-focused (the scan logic itself is covered in
``services/agent/tests/test_ai_signatures.py``): input validation,
unknown-field denial, the at-least-one-source rule, category validation, the
typed output shape, the HYPOTHESIS-tier epistemic envelope, and registration.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from findevil_agent_mcp.tools import all_specs
from findevil_agent_mcp.tools.find_ai_signatures import (
    SPEC,
    FindAiSignaturesInput,
    FindAiSignaturesOutput,
)


class TestRegistration:
    def test_tool_is_registered(self) -> None:
        assert any(s.name == "find_ai_signatures" for s in all_specs())

    def test_input_model_forbids_unknown_fields(self) -> None:
        assert SPEC.input_model.model_config.get("extra") == "forbid"
        with pytest.raises(ValidationError):
            FindAiSignaturesInput(case_id="c", text="x", bogus_field=1)  # type: ignore[call-arg]

    def test_handler_is_async(self) -> None:
        import inspect

        assert inspect.iscoroutinefunction(SPEC.handler)


class TestInputValidation:
    def test_requires_at_least_one_source(self) -> None:
        with pytest.raises(ValidationError, match="at least one"):
            FindAiSignaturesInput(case_id="c")

    def test_text_only_is_valid(self) -> None:
        inp = FindAiSignaturesInput(case_id="c", text="import langchain")
        assert inp.text == "import langchain"

    def test_paths_only_is_valid(self) -> None:
        inp = FindAiSignaturesInput(case_id="c", paths=["/evidence/foo.py"])
        assert inp.paths == ["/evidence/foo.py"]

    def test_unknown_category_rejected(self) -> None:
        with pytest.raises(ValidationError, match="unknown signature categories"):
            FindAiSignaturesInput(case_id="c", text="x", categories=["not_a_category"])

    def test_known_category_accepted(self) -> None:
        inp = FindAiSignaturesInput(case_id="c", text="x", categories=["agent_framework"])
        assert inp.categories == ["agent_framework"]

    def test_limit_bounds_enforced(self) -> None:
        with pytest.raises(ValidationError):
            FindAiSignaturesInput(case_id="c", text="x", limit=0)
        with pytest.raises(ValidationError):
            FindAiSignaturesInput(case_id="c", text="x", limit=10_001)


class TestHandler:
    @pytest.mark.asyncio
    async def test_returns_matches_for_ai_text(self) -> None:
        out = await SPEC.handler(
            FindAiSignaturesInput(
                case_id="case-001",
                text="As an AI language model, I cannot assist with that.",
            )
        )
        assert isinstance(out, FindAiSignaturesOutput)
        assert out.case_id == "case-001"
        ids = {m.signature_id for m in out.matches}
        assert "llm_output_boilerplate.language_model_persona" in ids

    @pytest.mark.asyncio
    async def test_epistemic_envelope_is_hypothesis_lead(self) -> None:
        out = await SPEC.handler(FindAiSignaturesInput(case_id="c", text="import langchain"))
        assert out.confidence_tier == "HYPOTHESIS"
        assert out.lead_only is True
        assert "HYPOTHESIS" in out.disclaimer

    @pytest.mark.asyncio
    async def test_envelope_present_even_with_no_matches(self) -> None:
        out = await SPEC.handler(FindAiSignaturesInput(case_id="c", text="a benign forensic note"))
        assert out.matches == []
        assert out.confidence_tier == "HYPOTHESIS"
        assert out.lead_only is True

    @pytest.mark.asyncio
    async def test_reads_path_and_reports_read_errors(self, tmp_path: Path) -> None:
        good = tmp_path / "good.py"
        good.write_text("from anthropic import Anthropic")
        missing = tmp_path / "missing.py"
        out = await SPEC.handler(
            FindAiSignaturesInput(case_id="c", paths=[str(good), str(missing)])
        )
        ids = {m.signature_id for m in out.matches}
        assert "llm_api_client.sdk_import" in ids
        assert len(out.read_errors) == 1
        assert "not found" in out.read_errors[0]

    @pytest.mark.asyncio
    async def test_category_filter_scopes_output(self) -> None:
        out = await SPEC.handler(
            FindAiSignaturesInput(
                case_id="c",
                text="import langchain\nas an ai language model",
                categories=["agent_framework"],
            )
        )
        assert {m.category for m in out.matches} == {"agent_framework"}

    @pytest.mark.asyncio
    async def test_output_is_json_serializable(self) -> None:
        import json

        out = await SPEC.handler(FindAiSignaturesInput(case_id="c", text="import openai"))
        json.dumps(out.model_dump())
