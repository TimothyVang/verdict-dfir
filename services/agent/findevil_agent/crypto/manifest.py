"""Run manifest assembly + verification.

Spec #2 §7.1 + §7.2. Ties the four M2 layers together:

  * walks the hash-chained ``audit.jsonl``
  * extracts every ``tool_call_output_hash`` and every approved-
    finding hash into a Merkle tree
  * asks the ``Signer`` to sign the canonicalized manifest body
  * writes ``run.manifest.json`` (used as the OTS stamp target)

Verification is the symmetric operation:

  * ``audit.verify()`` replays the chain
  * ``MerkleTree`` rebuilds from the leaves declared in the
    manifest, comparing the recomputed root to the manifest's
    ``merkle_root``
  * The manifest's signature is validated against the manifest body
    (signer-specific)
  * Spec #2 §7.2 step 3 (OTS verify) is delegated to
    ``crypto.ots.verify`` and not required here — verification
    happens in tiers 1+2 offline; tier 3 is the OTS dance.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from findevil_agent.crypto.audit_log import (
    AuditLog,
    AuditLogError,
    canonicalize_json,
    hash_line,
)
from findevil_agent.crypto.merkle import MerkleError, MerkleTree
from findevil_agent.crypto.signer import SignedBundle, Signer, StubSigner

MANIFEST_VERSION = "1"


# ---------------------------------------------------------------------------
# Dataclasses (frozen — manifests are immutable once finalized).
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ManifestLeaf:
    """One Merkle leaf — sourced from an audit-log record."""

    seq: int
    """Audit-log sequence number."""

    kind: str
    """One of: ``tool_call_output``, ``finding``."""

    digest_hex: str
    """SHA-256 hex of the leaf payload (the canonicalized record)."""

    record_id: str
    """For tool_call_output: the tool_call_id. For finding: the
    finding_id. Required for audit-trail traceability — every
    Merkle leaf links back to a specific event."""


@dataclass(frozen=True)
class RunManifest:
    """The single artifact ``ots stamp`` anchors to Bitcoin.

    Field ordering matters here for human readability of the
    written JSON — sort_keys still applies during canonicalization.
    """

    version: str
    case_id: str
    run_id: str
    started_at: str
    finalized_at: str
    audit_log_path: str
    audit_log_final_hash: str
    audit_log_record_count: int
    merkle_root_hex: str
    leaf_count: int
    leaves: list[ManifestLeaf]
    signature: dict[str, Any] = field(default_factory=dict)
    """SignedBundle of the canonicalized manifest body (without the
    ``signature`` field). Filled by ``finalize`` after signing."""

    extra: dict[str, Any] = field(default_factory=dict)
    """Free-form metadata: image_path, image_hash, model name,
    agent version, etc. Captured but not part of Merkle leaves —
    if you want it tamper-evident, sign the manifest body."""


# ---------------------------------------------------------------------------
# Build path.
# ---------------------------------------------------------------------------


def build_manifest(
    *,
    case_id: str,
    run_id: str,
    started_at: str,
    audit_log: AuditLog,
    signer: Signer,
    extra: dict[str, Any] | None = None,
) -> RunManifest:
    """Assemble + sign a RunManifest from a finalized audit log.

    Caller is responsible for not appending to the audit log after
    this returns — manifests describe a snapshot.
    """
    leaves: list[ManifestLeaf] = []
    record_count = 0
    final_hash = ""
    for record in audit_log.iter_records():
        record_count += 1
        # The audit log final hash is the hash of the line bytes for
        # the last record, computed on-the-fly because AuditLog only
        # remembers ``last_hash`` for newly-appended records, and
        # we want a value that works for the reader path too.
        canonical_line = canonicalize_json(record.to_canonical_dict())
        final_hash = hash_line(canonical_line)

        # Identify Merkle-eligible records.
        if record.kind == "tool_call_output":
            digest = _payload_digest(record.payload, "output_hash") or _record_digest(
                canonical_line
            )
            leaves.append(
                ManifestLeaf(
                    seq=record.seq,
                    kind="tool_call_output",
                    digest_hex=digest,
                    record_id=str(record.payload.get("tool_call_id", "")),
                )
            )
        elif record.kind == "finding_approved":
            digest = _record_digest(canonical_line)
            leaves.append(
                ManifestLeaf(
                    seq=record.seq,
                    kind="finding",
                    digest_hex=digest,
                    record_id=str(record.payload.get("finding_id", "")),
                )
            )
        # Other kinds (agent_message, plan_proposed, etc.) are in
        # the audit chain but not in the Merkle root — they're
        # observable via the chain hash, not separately.

    tree = MerkleTree()
    for leaf in leaves:
        tree.append(bytes.fromhex(leaf.digest_hex))
    root_hex = tree.root_hex()

    finalized_at = _utc_iso()

    body = RunManifest(
        version=MANIFEST_VERSION,
        case_id=case_id,
        run_id=run_id,
        started_at=started_at,
        finalized_at=finalized_at,
        audit_log_path=str(audit_log.path),
        audit_log_final_hash=final_hash,
        audit_log_record_count=record_count,
        merkle_root_hex=root_hex,
        leaf_count=len(leaves),
        leaves=leaves,
        signature={},
        extra=extra or {},
    )

    # Sign the canonicalized body sans signature.
    body_bytes = canonicalize_json(_to_json_safe(body, exclude_signature=True))
    bundle: SignedBundle = signer.sign(body_bytes)

    # Re-construct with signature populated.
    signed_body = RunManifest(
        version=body.version,
        case_id=body.case_id,
        run_id=body.run_id,
        started_at=body.started_at,
        finalized_at=body.finalized_at,
        audit_log_path=body.audit_log_path,
        audit_log_final_hash=body.audit_log_final_hash,
        audit_log_record_count=body.audit_log_record_count,
        merkle_root_hex=body.merkle_root_hex,
        leaf_count=body.leaf_count,
        leaves=body.leaves,
        signature={
            "payload_sha256": bundle.payload_sha256,
            "bundle_b64": bundle.bundle_b64,
            "cert_fingerprint": bundle.cert_fingerprint,
            "signed_at": bundle.signed_at,
        },
        extra=body.extra,
    )
    return signed_body


def write_manifest(manifest: RunManifest, path: Path) -> Path:
    """Write the manifest to ``path`` as canonical pretty JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(_to_json_safe(manifest), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return path


# ---------------------------------------------------------------------------
# Verify path.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ManifestVerification:
    """Result of ``verify_manifest``. Each field is either ``True``
    (passed) or a reason string explaining the failure."""

    audit_chain_ok: bool | str
    merkle_root_ok: bool | str
    leaf_count_ok: bool | str
    signature_present: bool
    overall: bool


def verify_manifest(
    manifest_path: Path,
    *,
    audit_log_path: Path | None = None,
) -> ManifestVerification:
    """Run the offline-verifiable parts of Spec #2 §7.2.

    Returns:
      * ``audit_chain_ok``: True if the linked audit log replays
        cleanly, else the AuditLogError message.
      * ``merkle_root_ok``: True if leaves declared in the manifest
        rebuild to the manifest's ``merkle_root_hex``, else a reason.
      * ``leaf_count_ok``: True if ``leaves`` length matches
        ``leaf_count``, else a reason.
      * ``signature_present``: True if ``signature`` is non-empty —
        signature *validity* is signer-specific and lives in the
        signer module; here we only check presence.
      * ``overall``: AND of the above.
    """
    obj = json.loads(manifest_path.read_text(encoding="utf-8"))

    # 1. Audit chain. Precedence: explicit override → the audit log sitting
    # next to the manifest (a copied case dir verifies on any machine; the
    # chain itself proves it is the right file) → the embedded absolute path.
    embedded = Path(obj.get("audit_log_path") or "")
    sibling = manifest_path.parent / (embedded.name or "audit.jsonl")
    log_path = audit_log_path or (sibling if sibling.is_file() else embedded)
    audit_status: bool | str = "audit_log_path missing"
    if log_path and log_path.is_file():
        try:
            AuditLog(log_path).verify()
            audit_status = True
        except AuditLogError as exc:
            audit_status = f"audit chain break: {exc}"

    # 2. Merkle root.
    declared_root = obj.get("merkle_root_hex", "")
    leaves = obj.get("leaves", [])
    tree = MerkleTree()
    rebuild_status: bool | str = True
    try:
        for leaf in leaves:
            digest_hex = leaf.get("digest_hex", "")
            tree.append(bytes.fromhex(digest_hex))
        rebuilt = tree.root_hex()
        if rebuilt != declared_root:
            rebuild_status = f"declared root {declared_root} != rebuilt {rebuilt}"
    except (MerkleError, ValueError) as exc:
        rebuild_status = f"merkle rebuild failed: {exc}"

    # 3. Leaf count.
    declared_count = obj.get("leaf_count")
    actual_count = len(leaves)
    count_status: bool | str = True
    if declared_count != actual_count:
        count_status = f"leaf_count {declared_count} != actual {actual_count}"

    # 4. Signature presence.
    sig = obj.get("signature") or {}
    sig_present = bool(sig.get("bundle_b64") and sig.get("payload_sha256"))

    overall = (
        audit_status is True and rebuild_status is True and count_status is True and sig_present
    )
    return ManifestVerification(
        audit_chain_ok=audit_status,
        merkle_root_ok=rebuild_status,
        leaf_count_ok=count_status,
        signature_present=sig_present,
        overall=overall,
    )


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------


def _payload_digest(payload: dict[str, Any], key: str) -> str | None:
    val = payload.get(key)
    if isinstance(val, str) and len(val) == 64:
        try:
            bytes.fromhex(val)
            return val
        except ValueError:
            return None
    return None


def _record_digest(canonical_line: bytes) -> str:
    return hashlib.sha256(canonical_line).hexdigest()


def _to_json_safe(manifest: RunManifest, *, exclude_signature: bool = False) -> dict[str, Any]:
    """Convert the dataclass to a JSON-safe dict.

    Used both for canonicalizing-then-signing (with
    ``exclude_signature=True``) and for the on-disk write (with
    the signature included).
    """
    out: dict[str, Any] = asdict(manifest)
    if exclude_signature:
        out.pop("signature", None)
    return out


def _utc_iso() -> str:
    from datetime import UTC, datetime

    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


__all__ = [
    "MANIFEST_VERSION",
    "ManifestLeaf",
    "ManifestVerification",
    "RunManifest",
    "build_manifest",
    "verify_manifest",
    "write_manifest",
]


# Convenience for one-shot demo.
def _demo_run() -> None:  # pragma: no cover
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        log = AuditLog(Path(td) / "audit.jsonl")
        log.append(
            "tool_call_start",
            {"tool_call_id": "tc-1", "tool": "evtx_query"},
        )
        log.append(
            "tool_call_output",
            {
                "tool_call_id": "tc-1",
                "output_hash": "a" * 64,
            },
        )
        log.append(
            "finding_approved",
            {"finding_id": "f-1", "tool_call_id": "tc-1"},
        )
        signer = StubSigner(run_id="demo")
        m = build_manifest(
            case_id="case-1",
            run_id="demo",
            started_at="2026-04-24T00:00:00Z",
            audit_log=log,
            signer=signer,
            extra={"image_path": "/tmp/x.e01"},
        )
        path = write_manifest(m, Path(td) / "run.manifest.json")
        result = verify_manifest(path)
        print(result)
