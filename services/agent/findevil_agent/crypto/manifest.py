"""Run manifest assembly + verification.

Spec #2 §7.1 + §7.2. Ties the current custody layers together:

  * walks the hash-chained ``audit.jsonl``
  * extracts every ``tool_call_output_hash`` and every approved-
    finding hash into a Merkle tree
  * asks the ``Signer`` to sign the canonicalized manifest body
  * writes ``run.manifest.json``

Verification is the symmetric operation:

  * ``audit.verify()`` replays the chain
  * ``MerkleTree`` rebuilds from the leaves declared in the
    manifest, comparing the recomputed root to the manifest's
    ``merkle_root``
  * the signature tier is reported honestly: Ed25519 is verified
    cryptographically offline, Sigstore is recorded for an
    identity-aware verifier, and stub remains a dev placeholder
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
from findevil_agent.entailment import recheck_entailment_slice

MANIFEST_VERSION = "1"


class UncitedFindingError(ValueError):
    """Refusal to seal: a ``finding_approved`` record does not cite a
    ``tool_call_id`` recorded earlier in the audit chain. Sealing is the
    last code-enforced citation gate ("every Finding cites a
    tool_call_id"), independent of prompt discipline in interactive
    mode."""


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
    """The signed run manifest.

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


def _uncited_findings(audit_log: AuditLog) -> list[str]:
    """finding_approved records whose tool_call_id is absent from the chain
    so far. Chain order matters: a finding cannot cite a future tool call."""
    seen_tool_calls: set[str] = set()
    uncited: list[str] = []
    for record in audit_log.iter_records():
        if record.kind == "tool_call_output":
            tcid = str(record.payload.get("tool_call_id") or "")
            if tcid:
                seen_tool_calls.add(tcid)
        elif record.kind == "finding_approved":
            cited = str(record.payload.get("tool_call_id") or "")
            if not cited or cited not in seen_tool_calls:
                uncited.append(str(record.payload.get("finding_id") or f"seq-{record.seq}"))
    return uncited


def _walk_audit_log(audit_log: AuditLog) -> tuple[list[ManifestLeaf], int, str]:
    """Replay the audit log once: derive the Merkle-eligible leaves, count the
    records, and compute the final line hash. Shared by the build path and by
    ``verify_manifest`` so the verifier re-derives the same values the sealer
    declared, instead of trusting the manifest's own copies."""
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
    return leaves, record_count, final_hash


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

    Raises :class:`UncitedFindingError` when the log contains a
    ``finding_approved`` record without a ``tool_call_id`` recorded
    earlier in the chain — an uncited finding must never be sealed.
    """
    uncited = _uncited_findings(audit_log)
    if uncited:
        raise UncitedFindingError(
            "refusing to seal: finding(s) without a tool_call_id recorded "
            f"earlier in the audit chain: {', '.join(uncited[:5])}"
        )
    leaves, record_count, final_hash = _walk_audit_log(audit_log)

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
        audit_log_path=audit_log.path.name,
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
            "kind": bundle.kind,
            # Only present when a sigstore attempt honestly degraded to stub.
            **(
                {"fallback_reason": bundle.fallback_reason}
                if bundle.fallback_reason is not None
                else {}
            ),
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
    signature_kind: str = "stub"
    """Which signer sealed the run: ``"ed25519"``, ``"sigstore"``, or
    ``"stub"`` (default for pre-``kind`` manifests)."""
    signature_verified: bool | str = (
        "stub signature: deterministic dev/offline placeholder, not cryptographic proof"
    )
    """Honest cryptographic-verification status. ``True`` only when a real
    Ed25519 bundle verifies offline; otherwise a reason string. A stub bundle
    is never ``True``, and a Sigstore bundle reports that identity-policy-aware
    verification is required — this field stops the chain from *implying* proof
    a placeholder or unbound identity bundle can't provide. Does NOT gate
    ``overall`` (presence-based), so dev/offline stub runs still verify
    end-to-end."""
    entailment_ok: bool | str = True
    """Offline re-verification of the sealed entailment slices: re-runs the
    matcher over the matched evidence values recorded in the audit chain
    (no tool re-run) and confirms each still entails its finding. ``True`` when
    every slice re-checks (and vacuously when a run carries none). Like
    ``signature_verified`` it is a separate honest signal and does NOT gate
    ``overall``; byte-tampering of a slice is already caught by the Merkle
    root, so this reports the semantic check."""
    overall: bool = False


def _verify_entailment_slices(audit_log: AuditLog) -> bool | str:
    """Re-verify every sealed entailment slice in the audit chain offline.

    Each ``replay`` record carries the replay artifact, whose ``entailment``
    slice (when present) is the value the parser re-extracted from the evidence.
    Re-running the matcher over those sealed values confirms — with no tool
    re-run — that the facts sealed into the signed chain still entail their
    findings. Returns ``True`` (all slices re-check, or none present) or the
    first failure reason."""
    for record in audit_log.iter_records():
        if record.kind != "replay":
            continue
        artifact = record.payload.get("replay_artifact")
        if not isinstance(artifact, dict):
            continue
        slice_ = artifact.get("entailment")
        if slice_ is None:
            continue
        result = recheck_entailment_slice(slice_)
        if result is not True:
            fid = (
                record.payload.get("finding_id")
                or artifact.get("tool_call_id")
                or f"seq-{record.seq}"
            )
            return f"entailment re-check failed for {fid}: {result}"
    return True


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
      * ``signature_present``: True if ``signature`` is non-empty.
      * ``signature_verified``: True only for a cryptographically verified
        Ed25519 manifest; Sigstore and stub return explicit reason strings.
      * ``overall``: chain + Merkle root + leaf count verify and a signature
        bundle is present, and no present signature failed verification
        (``stub`` / recorded ``sigstore`` are advisory). ``signature_verified``
        and ``entailment_ok`` are reported as separate side-signals.
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

    # 1b. Log-vs-manifest consistency. A tail-truncated log still replays
    # prefix-cleanly, and a forged-but-internally-consistent leaf set still
    # rebuilds its own root — so re-derive count, final hash, and leaves from
    # the actual log and compare them to what the manifest declared.
    if audit_status is True:
        derived, replayed_count, replayed_final = _walk_audit_log(AuditLog(log_path))
        declared_count = obj.get("audit_log_record_count")
        declared_final = str(obj.get("audit_log_final_hash") or "")
        declared_leaves = [
            (
                int(leaf.get("seq", -1)),
                str(leaf.get("kind", "")),
                str(leaf.get("digest_hex", "")),
                str(leaf.get("record_id", "")),
            )
            for leaf in obj.get("leaves", [])
        ]
        derived_leaves = [
            (leaf.seq, leaf.kind, leaf.digest_hex, leaf.record_id) for leaf in derived
        ]
        if replayed_count != declared_count:
            audit_status = (
                f"audit log has {replayed_count} record(s) but the manifest "
                f"declares {declared_count} (tail truncation or post-seal append)"
            )
        elif replayed_final != declared_final:
            audit_status = "audit log final hash does not match the manifest's audit_log_final_hash"
        elif derived_leaves != declared_leaves:
            audit_status = (
                "leaves re-derived from the audit log do not match the manifest's declared leaves"
            )

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

    # 4. Signature presence + honest verification status.
    sig = obj.get("signature") or {}
    sig_present = bool(sig.get("bundle_b64") and sig.get("payload_sha256"))
    sig_kind = str(sig.get("kind") or "stub")
    sig_verified = _signature_verified(sig_present, sig_kind, sig, obj)

    # 5. Offline entailment re-verification (separate honest signal, like
    # signature_verified — does NOT gate overall). Vacuously True when the log
    # is unreadable (the chain failure above is the real error) or carries no
    # slices (pre-entailment runs stay verifiable end-to-end).
    entailment_status: bool | str = True
    if log_path and log_path.is_file():
        try:
            entailment_status = _verify_entailment_slices(AuditLog(log_path))
        except AuditLogError as exc:
            entailment_status = f"entailment re-check could not read the audit log: {exc}"

    # `overall` requires the chain, Merkle root, and leaf count to verify and a
    # signature bundle to be present. A `stub` (dev/offline placeholder) or a
    # recorded `sigstore` bundle is advisory — it does not gate `overall`, so
    # dev/offline stub runs still verify end-to-end. But a signature that is
    # present and was cryptographically checked yet did NOT verify (a forged or
    # corrupted `ed25519` bundle, or an unknown signer kind) is a hard failure:
    # `overall` must not stay true for a signature that fails verification.
    # `signature_verified` remains the separate, field-level crypto signal.
    advisory_sig_kinds = ("stub", "sigstore")
    sig_failed = sig_present and sig_kind not in advisory_sig_kinds and sig_verified is not True
    overall = (
        audit_status is True
        and rebuild_status is True
        and count_status is True
        and sig_present
        and not sig_failed
    )
    return ManifestVerification(
        audit_chain_ok=audit_status,
        merkle_root_ok=rebuild_status,
        leaf_count_ok=count_status,
        signature_present=sig_present,
        signature_kind=sig_kind,
        signature_verified=sig_verified,
        entailment_ok=entailment_status,
        overall=overall,
    )


def _signature_verified(
    present: bool,
    kind: str,
    sig: dict[str, Any] | None = None,
    manifest_obj: dict[str, Any] | None = None,
) -> bool | str:
    """Honest answer to 'was the signature cryptographically verified?'.

    Never returns ``True`` for a stub (a deterministic placeholder is not
    proof) and never falsely claims to have verified a sigstore bundle it did
    not. An ``ed25519`` bundle embeds its public key, so it IS verified here,
    offline: the canonical manifest body (everything except ``signature``) is
    rebuilt and checked against the embedded signature. A real sigstore bundle
    is *recorded* for offline verification by a party that supplies the
    expected signer identity (a deployment policy this library can't assume) —
    so we report that explicitly rather than overclaim.
    """
    if not present:
        return "no signature bundle present"
    if kind == "stub":
        return "stub signature: deterministic dev/offline placeholder, not cryptographic proof"
    if kind == "ed25519":
        return _verify_ed25519_signature(sig or {}, manifest_obj or {})
    if kind == "sigstore":
        return (
            "sigstore bundle present and recorded; offline cryptographic verification "
            "requires the verifier to supply the expected signer identity (deployment policy)"
        )
    return f"unknown signer kind {kind!r}"


def _verify_ed25519_signature(sig: dict[str, Any], manifest_obj: dict[str, Any]) -> bool | str:
    """Offline cryptographic verification of a LocalEd25519Signer bundle.

    Rebuilds the exact bytes that were signed — the JCS-canonicalized manifest
    body with the ``signature`` field removed (mirror of ``build_manifest``,
    which signs ``canonicalize_json(_to_json_safe(body, exclude_signature=True))``)
    — and verifies the embedded Ed25519 signature against the embedded public
    key. Returns ``True`` only on a genuine cryptographic pass.
    """
    import base64

    try:
        bundle = json.loads(base64.b64decode(str(sig.get("bundle_b64") or "")))
        public_key_b64 = bundle["public_key_b64"]
        signature_b64 = bundle["signature_b64"]
    except (KeyError, ValueError, TypeError) as exc:
        return f"ed25519 bundle malformed: {exc}"
    body = {k: v for k, v in manifest_obj.items() if k != "signature"}
    body_bytes = canonicalize_json(body)
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64))
        pub.verify(base64.b64decode(signature_b64), body_bytes)
    except InvalidSignature:
        return "ed25519 signature verification FAILED: manifest body does not match the signature"
    except Exception as exc:  # key decode / import errors — honest reason, never a crash
        return f"ed25519 signature verification failed: {exc}"
    return True


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
    "UncitedFindingError",
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
