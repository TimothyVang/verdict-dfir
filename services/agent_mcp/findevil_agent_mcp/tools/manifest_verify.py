"""``manifest_verify`` tool — offline verification of run.manifest.json.

Wraps :func:`findevil_agent.crypto.manifest.verify_manifest`. Runs
the audit-chain replay, the Merkle-root rebuild, the leaf-count
sanity check, and the signature presence check. Stays offline.
"""

from __future__ import annotations

from pathlib import Path

from findevil_agent.crypto.manifest import verify_manifest
from pydantic import BaseModel, ConfigDict, Field

from findevil_agent_mcp.tools._base import ToolSpec


class ManifestVerifyInput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    manifest_path: str = Field(..., description="Absolute path to run.manifest.json.")
    audit_log_path: str | None = Field(
        default=None,
        description=(
            "Override audit_log_path embedded in the manifest. Useful when "
            "verifying a manifest copied to a different directory."
        ),
    )


class ManifestVerifyOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    overall: bool
    audit_chain_ok: bool
    audit_chain_detail: str | None
    merkle_root_ok: bool
    merkle_root_detail: str | None
    leaf_count_ok: bool
    leaf_count_detail: str | None
    signature_present: bool
    signature_kind: str
    signature_verified: bool
    signature_verified_detail: str | None
    entailment_ok: bool
    entailment_ok_detail: str | None


async def _handle(inp: BaseModel) -> ManifestVerifyOutput:
    assert isinstance(inp, ManifestVerifyInput)
    audit_path = Path(inp.audit_log_path) if inp.audit_log_path else None
    result = verify_manifest(Path(inp.manifest_path), audit_log_path=audit_path)

    def _split(value: bool | str) -> tuple[bool, str | None]:
        if value is True:
            return True, None
        if value is False:
            return False, None
        return False, str(value)

    audit_ok, audit_detail = _split(result.audit_chain_ok)
    merkle_ok, merkle_detail = _split(result.merkle_root_ok)
    count_ok, count_detail = _split(result.leaf_count_ok)
    sig_verified, sig_verified_detail = _split(result.signature_verified)
    entail_ok, entail_detail = _split(result.entailment_ok)
    return ManifestVerifyOutput(
        overall=result.overall,
        audit_chain_ok=audit_ok,
        audit_chain_detail=audit_detail,
        merkle_root_ok=merkle_ok,
        merkle_root_detail=merkle_detail,
        leaf_count_ok=count_ok,
        leaf_count_detail=count_detail,
        signature_present=result.signature_present,
        signature_kind=result.signature_kind,
        signature_verified=sig_verified,
        signature_verified_detail=sig_verified_detail,
        entailment_ok=entail_ok,
        entailment_ok_detail=entail_detail,
    )


SPEC = ToolSpec(
    name="manifest_verify",
    description=(
        "Offline verify of run.manifest.json — the FRE 902(14) self-authentication step "
        "any third party can run without contacting our servers. Performs four "
        "independent checks: (1) audit_chain_ok — replays the linked audit.jsonl; "
        "(2) merkle_root_ok — rebuilds the tree from declared leaves and compares to "
        "merkle_root_hex; (3) leaf_count_ok — sanity check on the leaves array length; "
        "(4) signature_present — confirms a signer bundle is attached; "
        "signature_kind reports ed25519/sigstore/stub and signature_verified is True "
        "only when the manifest carries an offline-verified Ed25519 signature. "
        "Sigstore bundles are recorded for identity-policy-aware verification, while "
        "stub bundles are dev placeholders. overall=True only if the chain, Merkle, "
        "leaf-count, and signature-presence checks pass. "
        "If the manifest was moved/renamed, pass audit_log_path explicitly to override "
        "the path embedded in the manifest. "
        "On verify failure: the per-field detail string identifies which check failed "
        "and shows the specific mismatch (e.g. 'declared root abc... != rebuilt def...')."
    ),
    input_model=ManifestVerifyInput,
    output_model=ManifestVerifyOutput,
    handler=_handle,
)

__all__ = ["SPEC", "ManifestVerifyInput", "ManifestVerifyOutput"]
