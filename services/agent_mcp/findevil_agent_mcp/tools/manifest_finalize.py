"""``manifest_finalize`` tool — build, sign, and write run.manifest.json.

Wraps :func:`findevil_agent.crypto.manifest.build_manifest` plus
:func:`write_manifest`. Two signer modes are exposed:

* ``signer="stub"`` — deterministic ``StubSigner``; used by tests
  and the offline demo path. Requires no network and produces a
  deterministic bundle keyed on the ``run_id`` for replay.
* ``signer="sigstore"`` — keyless sigstore signing via Fulcio +
  Rekor (Spec #2 §7.1 first tier). Requires interactive browser
  auth on first run; in CI we use a cached identity token.

The choice is exposed at the tool boundary because the agent often
wants to dry-run with the stub before committing to a real
sigstore round-trip.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from findevil_agent.crypto.audit_log import AuditLog
from findevil_agent.crypto.manifest import build_manifest, write_manifest
from findevil_agent.crypto.signer import Signer, StubSigner, make_signer
from pydantic import BaseModel, ConfigDict, Field

from findevil_agent_mcp.tools._base import ToolSpec


class ManifestFinalizeInput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: str = Field(..., description="UUID4 of the case.", min_length=1)
    run_id: str = Field(..., description="Run identifier (UUID4 or ULID).", min_length=1)
    started_at: str = Field(..., description="UTC ISO-8601Z timestamp of run start.", min_length=1)
    audit_log_path: str = Field(..., description="Absolute path to audit.jsonl.")
    output_path: str = Field(..., description="Where to write run.manifest.json.")
    signer: Literal["stub", "sigstore"] = Field(
        default="stub",
        description=(
            "stub = deterministic test signer (no network); "
            "sigstore = keyless Fulcio+Rekor (Spec #2 §7.1 tier 1)."
        ),
    )
    extra: dict[str, Any] = Field(
        default_factory=dict,
        description="Free-form metadata embedded in the manifest (image_path, model, etc.).",
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
        description="Fulcio cert fingerprint when signer=sigstore; null for stub.",
    )


async def _handle(inp: BaseModel) -> ManifestFinalizeOutput:
    assert isinstance(inp, ManifestFinalizeInput)
    log = AuditLog(Path(inp.audit_log_path))
    # sigstore lazy-imports identity token from $SIGSTORE_ID_TOKEN inside
    # the signer; stub is deterministic and offline-friendly for tests.
    signer: Signer = (
        StubSigner(run_id=inp.run_id) if inp.signer == "stub" else make_signer(kind="sigstore")
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

    sig = manifest.signature or {}
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
        "signer='stub' for offline/test runs (deterministic, no network); "
        "signer='sigstore' for production (keyless Fulcio/Rekor — requires "
        "$SIGSTORE_ID_TOKEN). This is the terminal step — once the manifest is signed "
        "the run is closed. "
        "On error: most common cause is the audit_log_path doesn't exist or has been "
        "tampered with — run audit_verify first to confirm the chain is clean."
    ),
    input_model=ManifestFinalizeInput,
    output_model=ManifestFinalizeOutput,
    handler=_handle,
)

__all__ = ["SPEC", "ManifestFinalizeInput", "ManifestFinalizeOutput"]
