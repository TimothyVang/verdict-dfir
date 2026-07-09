"""``manifest_finalize`` tool — build, sign, and write run.manifest.json.

Wraps :func:`findevil_agent.crypto.manifest.build_manifest` plus
:func:`write_manifest`. Three signer modes are exposed:

* ``signer="ed25519"`` — default real local-keypair signature; verifies
  offline from the public key embedded in the manifest bundle.
* ``signer="sigstore"`` — keyless sigstore signing via Fulcio + Rekor;
  the customer-release identity + transparency-log tier.
* ``signer="stub"`` — deterministic ``StubSigner``; used by tests
  and explicit dry-runs. Requires no network and produces a deterministic
  bundle keyed on the ``run_id`` for replay, but is never cryptographic proof.

The choice is exposed at the tool boundary because the agent often
wants to distinguish local integrity proof, customer-release identity proof,
and test-only placeholders.
"""

from __future__ import annotations

import os
from dataclasses import replace
from pathlib import Path
from typing import Any, Literal

from findevil_agent.crypto.anchor import (
    anchor_merkle_root,
    require_rekor_enabled,
)
from findevil_agent.crypto.audit_log import AuditLog
from findevil_agent.crypto.manifest import build_manifest, write_manifest
from findevil_agent.crypto.signer import FallbackSigner, Signer, StubSigner, make_signer
from pydantic import BaseModel, ConfigDict, Field

from findevil_agent_mcp.tools._base import ToolSpec

# Explicit opt-in for tests / deterministic dry-runs. Without this, a model
# that passes signer:"stub" is coerced to ed25519 so local seals stay real.
_STUB_ALLOW_ENV = "FINDEVIL_ALLOW_STUB_SIGNER"


def _stub_signer_allowed() -> bool:
    return os.environ.get(_STUB_ALLOW_ENV, "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _resolve_signer_request(requested: str) -> tuple[str, str | None]:
    """Return (effective_request, coerce_reason).

    Coerces ``stub`` → ``ed25519`` unless :envvar:`FINDEVIL_ALLOW_STUB_SIGNER`
    is set. Does not alter sigstore/ed25519 requests.
    """
    if requested != "stub":
        return requested, None
    if _stub_signer_allowed():
        return "stub", None
    return (
        "ed25519",
        "stub coerced to ed25519 "
        f"(set {_STUB_ALLOW_ENV}=1 for the test-only stub placeholder)",
    )


class ManifestFinalizeInput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: str = Field(..., description="UUID4 of the case.", min_length=1)
    run_id: str = Field(..., description="Run identifier (UUID4 or ULID).", min_length=1)
    started_at: str = Field(..., description="UTC ISO-8601Z timestamp of run start.", min_length=1)
    audit_log_path: str = Field(..., description="Absolute path to audit.jsonl.")
    output_path: str = Field(..., description="Where to write run.manifest.json.")
    signer: Literal["stub", "ed25519", "sigstore"] = Field(
        default="ed25519",
        description=(
            "ed25519 = REAL local-keypair signature, verifies offline (default); "
            "sigstore = keyless Fulcio+Rekor, identity + transparency log "
            "(Spec #2 §7.1 tier 1; the customer-release tier); "
            "stub = deterministic test placeholder (explicit opt-in, never proof)."
        ),
    )
    extra: dict[str, Any] = Field(
        default_factory=dict,
        description="Free-form metadata embedded in the manifest (image_path, model, etc.).",
    )
    anchor_transparency: bool = Field(
        default=False,
        description=(
            "OPT-IN: publish the audit Merkle root to a public Sigstore Rekor "
            "transparency log (RFC-3161 TSA fallback) so a third party can prove "
            "when the sealed root existed. Absent by default — when false the "
            "manifest is byte-identical and no network is touched. Requires the "
            "operator to also set FINDEVIL_REKOR_ENABLE=1; requesting it without "
            "that opt-in fails closed. Only the bare 32-byte SHA-256 root leaves "
            "the host (no evidence text). The anchor is attached AFTER signing "
            "and excluded from the signed body, so it never alters the signature."
        ),
    )


class ManifestFinalizeOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    manifest_path: str
    merkle_root_hex: str
    leaf_count: int
    audit_log_record_count: int
    audit_log_final_hash: str
    signature_payload_sha256: str = Field(
        ..., description="SHA-256 of the canonicalized signed body."
    )
    signature_cert_fingerprint: str | None = Field(
        default=None,
        description=(
            "SHA-256 fingerprint of the Sigstore certificate or Ed25519 public key; "
            "null only when the signer produced no fingerprint."
        ),
    )
    signer_effective: str = Field(
        default="stub",
        description=(
            "Signer that ACTUALLY sealed the run ('sigstore', 'ed25519' or 'stub'). "
            "May differ from the requested signer: a failed request honestly degrades "
            "(sigstore -> ed25519 -> stub) when Fulcio/Rekor, an OIDC token, or the "
            "local signing key is unavailable."
        ),
    )
    fallback_reason: str | None = Field(
        default=None,
        description="Why the requested signer degraded, when it did; null otherwise.",
    )
    transparency_anchored: bool = Field(
        default=False,
        description=(
            "True iff a transparency anchor was successfully attached (Rekor or "
            "RFC-3161 TSA fallback). False when anchoring was not requested or the "
            "attempt honestly failed (see the manifest's transparency_log block)."
        ),
    )
    transparency_kind: str | None = Field(
        default=None,
        description=(
            "The transparency anchor kind actually recorded: 'rekor', 'rfc3161', "
            "'none' (attempted but failed), or null when anchoring was not requested."
        ),
    )


async def _handle(inp: BaseModel) -> ManifestFinalizeOutput:
    assert isinstance(inp, ManifestFinalizeInput)
    log = AuditLog(Path(inp.audit_log_path))
    # sigstore lazy-imports its identity token from $SIGSTORE_ID_TOKEN inside
    # the signer; ed25519 signs with the local keypair (offline). Requests are
    # wrapped so a failed signer honestly degrades — sigstore -> ed25519 ->
    # stub, ed25519 -> stub — with the reason recorded; never crashes the run.
    # Agent-supplied signer:"stub" is coerced to ed25519 unless the operator
    # explicitly opts into the test placeholder via FINDEVIL_ALLOW_STUB_SIGNER.
    requested, coerce_reason = _resolve_signer_request(inp.signer)
    if requested == "stub":
        signer: Signer = StubSigner(run_id=inp.run_id)
    elif requested == "ed25519":
        signer = FallbackSigner(make_signer(kind="ed25519"), StubSigner(run_id=inp.run_id))
    else:  # sigstore
        signer = FallbackSigner(
            make_signer(kind="sigstore"),
            FallbackSigner(make_signer(kind="ed25519"), StubSigner(run_id=inp.run_id)),
        )

    manifest = build_manifest(
        case_id=inp.case_id,
        run_id=inp.run_id,
        started_at=inp.started_at,
        audit_log=log,
        signer=signer,
        extra=inp.extra,
    )
    out_path = write_manifest(manifest, Path(inp.output_path))

    # Optional, opt-in transparency anchoring. Absent by default: with
    # anchor_transparency=False (the default) NOTHING below runs, so the manifest
    # stays byte-identical and no network is touched. When requested, the env
    # opt-in must also be set (fail-closed), then the anchor is attached AFTER
    # signing and the manifest is RE-WRITTEN — the anchor is excluded from the
    # already-computed signed body, so the re-write does NOT invalidate the
    # signature.
    transparency_anchored = False
    transparency_kind: str | None = None
    if inp.anchor_transparency:
        require_rekor_enabled()  # fail-closed when the network action lacks the opt-in
        block = anchor_merkle_root(manifest.merkle_root_hex)
        if block is not None:
            manifest = replace(manifest, transparency_log=block)
            out_path = write_manifest(manifest, Path(inp.output_path))
            transparency_kind = str(block.get("kind") or "none")
            transparency_anchored = bool(block.get("anchored"))

    sig = manifest.signature or {}
    degrade_reason = (
        str(sig.get("fallback_reason")) if sig.get("fallback_reason") else None
    )
    if coerce_reason and degrade_reason:
        combined_reason = f"{coerce_reason}; {degrade_reason}"
    else:
        combined_reason = coerce_reason or degrade_reason
    return ManifestFinalizeOutput(
        manifest_path=str(out_path),
        merkle_root_hex=manifest.merkle_root_hex,
        leaf_count=manifest.leaf_count,
        audit_log_record_count=manifest.audit_log_record_count,
        audit_log_final_hash=manifest.audit_log_final_hash,
        signature_payload_sha256=str(sig.get("payload_sha256", "")),
        signature_cert_fingerprint=(
            str(sig.get("cert_fingerprint")) if sig.get("cert_fingerprint") else None
        ),
        signer_effective=str(sig.get("kind") or "stub"),
        fallback_reason=combined_reason,
        transparency_anchored=transparency_anchored,
        transparency_kind=transparency_kind,
    )


SPEC = ToolSpec(
    name="manifest_finalize",
    description=(
        "TERMINAL crypto-custody step (M2). Call this AFTER every finding is verified, "
        "every contradiction is resolved, and the audit chain is settled — once the "
        "manifest is written, no further tool calls should append to the audit log for "
        "this run. Builds run.manifest.json by: (1) iterating the audit log, (2) "
        "extracting tool_call_output digests + finding digests as Merkle leaves, (3) "
        "computing the SHA-256 root, (4) signing the canonicalized body. "
        "signer='ed25519' (default) is a REAL local-keypair signature that verifies "
        "offline; signer='sigstore' for production identity + transparency log "
        "(keyless Fulcio/Rekor — requires $SIGSTORE_ID_TOKEN); signer='stub' is an "
        "explicit dev placeholder. This is the terminal step — once the manifest is signed "
        "the run is closed. REFUSES to seal a run containing any finding_approved "
        "record without a tool_call_id recorded earlier in the audit chain — the "
        "'every Finding cites a tool_call_id' invariant is enforced here in code, "
        "not just by prompts. "
        "On error: most common cause is the audit_log_path doesn't exist or has been "
        "tampered with — run audit_verify first to confirm the chain is clean."
    ),
    input_model=ManifestFinalizeInput,
    output_model=ManifestFinalizeOutput,
    handler=_handle,
)

__all__ = ["SPEC", "ManifestFinalizeInput", "ManifestFinalizeOutput"]
