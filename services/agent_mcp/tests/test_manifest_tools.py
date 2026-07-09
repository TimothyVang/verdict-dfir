"""Tests for manifest_finalize + manifest_verify wrappers."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from findevil_agent_mcp.tools.manifest_finalize import (
    SPEC as FINALIZE_SPEC,
)
from findevil_agent_mcp.tools.manifest_finalize import (
    ManifestFinalizeInput,
    ManifestFinalizeOutput,
)
from findevil_agent_mcp.tools.manifest_verify import (
    SPEC as VERIFY_SPEC,
)
from findevil_agent_mcp.tools.manifest_verify import (
    ManifestVerifyInput,
    ManifestVerifyOutput,
)


class TestManifestFinalize:
    async def test_clean_finalize_returns_signed_manifest(
        self, seeded_audit_log: Path, tmp_path: Path
    ) -> None:
        out_path = tmp_path / "run.manifest.json"
        result = await FINALIZE_SPEC.handler(
            ManifestFinalizeInput(
                case_id="case-001",
                run_id="run-1",
                started_at="2026-04-25T00:00:00Z",
                audit_log_path=str(seeded_audit_log),
                output_path=str(out_path),
                signer="stub",
                extra={"image_path": "/tmp/x.e01"},
            )
        )
        assert isinstance(result, ManifestFinalizeOutput)
        assert Path(result.manifest_path).is_file()
        assert len(result.merkle_root_hex) == 64
        assert result.leaf_count == 4  # 2 tool_outputs + 2 findings
        assert result.audit_log_record_count == 7
        assert len(result.signature_payload_sha256) == 64
        # Stub signer produces a deterministic cert fingerprint.
        assert result.signature_cert_fingerprint is not None
        assert len(result.signature_cert_fingerprint) == 64

    async def test_extra_metadata_round_trips(self, seeded_audit_log: Path, tmp_path: Path) -> None:
        out_path = tmp_path / "run.manifest.json"
        await FINALIZE_SPEC.handler(
            ManifestFinalizeInput(
                case_id="case-002",
                run_id="run-2",
                started_at="2026-04-25T00:00:00Z",
                audit_log_path=str(seeded_audit_log),
                output_path=str(out_path),
                signer="stub",
                extra={"model": "claude-opus", "image_hash": "deadbeef" * 8},
            )
        )
        loaded = json.loads(out_path.read_text(encoding="utf-8"))
        assert loaded["extra"]["model"] == "claude-opus"
        assert loaded["extra"]["image_hash"] == "deadbeef" * 8


class TestEd25519Tier:
    async def test_ed25519_finalize_then_cryptographic_verify(
        self, seeded_audit_log: Path, tmp_path: Path, monkeypatch
    ) -> None:
        monkeypatch.setenv("FINDEVIL_SIGNING_KEY", str(tmp_path / "signing.key"))
        out_path = tmp_path / "run.manifest.json"
        result = await FINALIZE_SPEC.handler(
            ManifestFinalizeInput(
                case_id="case-ed",
                run_id="run-ed",
                started_at="2026-04-25T00:00:00Z",
                audit_log_path=str(seeded_audit_log),
                output_path=str(out_path),
                signer="ed25519",
            )
        )
        assert result.signer_effective == "ed25519"
        assert result.fallback_reason is None
        verify = await VERIFY_SPEC.handler(ManifestVerifyInput(manifest_path=str(out_path)))
        assert verify.overall is True
        assert verify.signature_kind == "ed25519"
        # The genuine offline cryptographic pass — not a presence check.
        assert verify.signature_verified is True

    async def test_default_signer_is_ed25519(
        self, seeded_audit_log: Path, tmp_path: Path, monkeypatch
    ) -> None:
        monkeypatch.setenv("FINDEVIL_SIGNING_KEY", str(tmp_path / "signing.key"))
        out_path = tmp_path / "run.manifest.json"
        result = await FINALIZE_SPEC.handler(
            ManifestFinalizeInput(
                case_id="case-def",
                run_id="run-def",
                started_at="2026-04-25T00:00:00Z",
                audit_log_path=str(seeded_audit_log),
                output_path=str(out_path),
                # no signer given — the default must be the real local tier
            )
        )
        assert result.signer_effective == "ed25519"

    async def test_ed25519_degrades_to_stub_when_key_parent_is_not_directory(
        self, seeded_audit_log: Path, tmp_path: Path, monkeypatch
    ) -> None:
        # Point the key under a regular file: parent creation fails on
        # Linux/macOS/Windows, so the run honestly degrades to stub and says
        # why — never crashes.
        not_a_dir = tmp_path / "not-a-dir"
        not_a_dir.write_text("blocking file", encoding="utf-8")
        monkeypatch.setenv("FINDEVIL_SIGNING_KEY", str(not_a_dir / "signing.key"))

        out_path = tmp_path / "run.manifest.json"
        result = await FINALIZE_SPEC.handler(
            ManifestFinalizeInput(
                case_id="case-ro",
                run_id="run-ro",
                started_at="2026-04-25T00:00:00Z",
                audit_log_path=str(seeded_audit_log),
                output_path=str(out_path),
                signer="ed25519",
            )
        )
        assert result.signer_effective == "stub"
        assert result.fallback_reason


class TestManifestVerify:
    def test_tool_description_names_current_signature_tiers(self) -> None:
        description = VERIFY_SPEC.description
        assert "ed25519/sigstore/stub" in description
        assert "offline-verified Ed25519 signature" in description
        assert "sigstore/stub bundle" not in description

    async def test_clean_manifest_verifies(self, seeded_audit_log: Path, tmp_path: Path) -> None:
        out_path = tmp_path / "run.manifest.json"
        await FINALIZE_SPEC.handler(
            ManifestFinalizeInput(
                case_id="case-100",
                run_id="run-100",
                started_at="2026-04-25T00:00:00Z",
                audit_log_path=str(seeded_audit_log),
                output_path=str(out_path),
                signer="stub",
            )
        )
        result = await VERIFY_SPEC.handler(ManifestVerifyInput(manifest_path=str(out_path)))
        assert isinstance(result, ManifestVerifyOutput)
        assert result.overall is True
        assert result.audit_chain_ok is True
        assert result.merkle_root_ok is True
        assert result.leaf_count_ok is True
        assert result.signature_present is True

    async def test_path_is_accepted_as_alias_for_manifest_path(
        self, seeded_audit_log: Path, tmp_path: Path
    ) -> None:
        # Local models routinely call manifest_verify with {"path": ...} instead
        # of {"manifest_path": ...}. With extra="forbid" that used to hard-fail
        # ('path' was unexpected), derailing the seal sequence and forcing the
        # deterministic fallback. Accept `path` as an alias so one arg slip does
        # not cost a tool call.
        out_path = tmp_path / "run.manifest.json"
        await FINALIZE_SPEC.handler(
            ManifestFinalizeInput(
                case_id="case-alias",
                run_id="run-alias",
                started_at="2026-04-25T00:00:00Z",
                audit_log_path=str(seeded_audit_log),
                output_path=str(out_path),
                signer="stub",
            )
        )
        # `path` alias must resolve to the same field.
        aliased = ManifestVerifyInput(path=str(out_path))
        assert aliased.manifest_path == str(out_path)
        result = await VERIFY_SPEC.handler(aliased)
        assert result.overall is True

    def test_manifest_path_and_path_conflict_is_rejected(self, tmp_path: Path) -> None:
        import pytest
        from pydantic import ValidationError

        # Supplying both keys with different values is ambiguous — reject it
        # rather than silently pick one.
        with pytest.raises(ValidationError):
            ManifestVerifyInput(manifest_path="/a/run.manifest.json", path="/b/run.manifest.json")

    def test_unrelated_extra_field_still_rejected(self, tmp_path: Path) -> None:
        import pytest
        from pydantic import ValidationError

        # The alias must not open the door to arbitrary extra keys.
        with pytest.raises(ValidationError):
            ManifestVerifyInput(manifest_path="/a/run.manifest.json", bogus="x")

    async def test_tampered_merkle_root_caught(
        self, seeded_audit_log: Path, tmp_path: Path
    ) -> None:
        out_path = tmp_path / "run.manifest.json"
        await FINALIZE_SPEC.handler(
            ManifestFinalizeInput(
                case_id="case-101",
                run_id="run-101",
                started_at="2026-04-25T00:00:00Z",
                audit_log_path=str(seeded_audit_log),
                output_path=str(out_path),
                signer="stub",
            )
        )
        loaded = json.loads(out_path.read_text(encoding="utf-8"))
        loaded["merkle_root_hex"] = "ff" * 32
        out_path.write_text(json.dumps(loaded, indent=2), encoding="utf-8")

        result = await VERIFY_SPEC.handler(ManifestVerifyInput(manifest_path=str(out_path)))
        assert result.overall is False
        assert result.merkle_root_ok is False
        assert result.merkle_root_detail is not None
        assert "ff" in result.merkle_root_detail


class TestStubSignerCoercion:
    async def test_stub_coerced_to_ed25519_without_allow_env(
        self,
        seeded_audit_log: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Agent-supplied signer:stub must not produce a non-proof seal by default."""
        monkeypatch.delenv("FINDEVIL_ALLOW_STUB_SIGNER", raising=False)
        out_path = tmp_path / "run.manifest.json"
        result = await FINALIZE_SPEC.handler(
            ManifestFinalizeInput(
                case_id="case-coerce",
                run_id="run-coerce",
                started_at="2026-04-25T00:00:00Z",
                audit_log_path=str(seeded_audit_log),
                output_path=str(out_path),
                signer="stub",
            )
        )
        assert result.signer_effective == "ed25519"
        assert result.fallback_reason is not None
        assert "stub coerced to ed25519" in result.fallback_reason
        assert out_path.is_file()


class TestCitationGateAtToolBoundary:
    async def test_finalize_refuses_uncited_finding(self, tmp_path: Path) -> None:
        import pytest
        from findevil_agent.crypto.audit_log import AuditLog
        from findevil_agent.crypto.manifest import UncitedFindingError

        log_path = tmp_path / "audit.jsonl"
        log = AuditLog(log_path)
        log.append("tool_call_start", {"tool_call_id": "tc-1", "tool": "evtx_query"})
        log.append("tool_call_output", {"tool_call_id": "tc-1", "output_hash": "a" * 64})
        log.append("finding_approved", {"finding_id": "f-uncited"})

        with pytest.raises(UncitedFindingError, match="f-uncited"):
            await FINALIZE_SPEC.handler(
                ManifestFinalizeInput(
                    case_id="case-gate",
                    run_id="run-gate",
                    started_at="2026-04-25T00:00:00Z",
                    audit_log_path=str(log_path),
                    output_path=str(tmp_path / "run.manifest.json"),
                    signer="stub",
                )
            )
        assert not (tmp_path / "run.manifest.json").exists()
