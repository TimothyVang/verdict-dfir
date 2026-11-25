"""Tests for audit_append + audit_verify wrappers."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from findevil_agent.crypto.audit_log import canonicalize_json

from findevil_agent_mcp.tools.audit_append import (
    SPEC as APPEND_SPEC,
)
from findevil_agent_mcp.tools.audit_append import (
    AuditAppendInput,
    AuditAppendOutput,
)
from findevil_agent_mcp.tools.audit_verify import (
    SPEC as VERIFY_SPEC,
)
from findevil_agent_mcp.tools.audit_verify import (
    AuditVerifyInput,
    AuditVerifyOutput,
)


class TestAuditAppend:
    async def test_first_record_has_empty_prev_hash(self, tmp_path: Path) -> None:
        path = tmp_path / "audit.jsonl"
        result = await APPEND_SPEC.handler(
            AuditAppendInput(path=str(path), kind="agent_message", payload={"hello": "world"})
        )
        assert isinstance(result, AuditAppendOutput)
        assert result.seq == 0
        assert result.prev_hash == ""
        assert len(result.line_hash) == 64
        assert result.kind == "agent_message"

    async def test_chained_appends_link_correctly(self, tmp_path: Path) -> None:
        path = tmp_path / "audit.jsonl"
        first = await APPEND_SPEC.handler(
            AuditAppendInput(path=str(path), kind="k1", payload={"a": 1})
        )
        second = await APPEND_SPEC.handler(
            AuditAppendInput(path=str(path), kind="k2", payload={"b": 2})
        )
        assert isinstance(second, AuditAppendOutput)
        assert second.seq == 1
        assert second.prev_hash == first.line_hash

    async def test_explicit_timestamp_is_honored(self, tmp_path: Path) -> None:
        path = tmp_path / "audit.jsonl"
        ts = "2026-04-25T12:00:00Z"
        result = await APPEND_SPEC.handler(
            AuditAppendInput(path=str(path), kind="k", payload={}, ts=ts)
        )
        assert isinstance(result, AuditAppendOutput)
        assert result.ts == ts


class TestAuditVerify:
    async def test_verifies_seeded_log(self, seeded_audit_log: Path) -> None:
        result = await VERIFY_SPEC.handler(AuditVerifyInput(path=str(seeded_audit_log)))
        assert isinstance(result, AuditVerifyOutput)
        assert result.ok is True
        assert result.record_count == 7
        assert result.error is None

    async def test_detects_chain_break(self, seeded_audit_log: Path) -> None:
        # Tamper with the first record's payload — prev_hash chain breaks.
        lines = seeded_audit_log.read_bytes().splitlines()
        first = json.loads(lines[0])
        first["payload"]["tool"] = "TAMPERED"
        lines[0] = canonicalize_json(first)
        seeded_audit_log.write_bytes(b"\n".join(lines) + b"\n")

        result = await VERIFY_SPEC.handler(AuditVerifyInput(path=str(seeded_audit_log)))
        assert isinstance(result, AuditVerifyOutput)
        assert result.ok is False
        assert result.error is not None
        assert "prev_hash break" in result.error or "canonical" in result.error

    async def test_missing_file_returns_zero_records(self, tmp_path: Path) -> None:
        result = await VERIFY_SPEC.handler(
            AuditVerifyInput(path=str(tmp_path / "nonexistent.jsonl"))
        )
        assert isinstance(result, AuditVerifyOutput)
        assert result.ok is True
        assert result.record_count == 0


class TestSchemaShape:
    def test_append_input_rejects_extra_fields(self) -> None:
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            AuditAppendInput.model_validate(
                {
                    "path": "/x",
                    "kind": "k",
                    "payload": {},
                    "extra_field": "boom",
                }
            )

    def test_verify_input_rejects_extra_fields(self) -> None:
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            AuditVerifyInput.model_validate({"path": "/x", "extra": True})
