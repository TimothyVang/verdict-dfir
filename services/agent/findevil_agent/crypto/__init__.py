"""M2 cryptographic chain-of-custody layer.

Three tiers, each independently testable and composable:

  * ``audit_log`` — hash-chained JSONL writer with ``prev_hash``
    linking every record to the previous line. Append-only. The
    forensic audit file Spec #2 §4.2 mandates for every case.
  * ``merkle``   — append-only Merkle tree (SHA-256) that roots all
    tool-call hashes + approved-finding hashes per run. Emits O(log
    n) inclusion proofs that ``verify_manifest`` (this module's
    own ``verify_manifest`` re-export, also exposed via the
    ``manifest_verify`` MCP tool in ``services/agent_mcp``) replays.
  * ``signer``   — Ed25519/Sigstore/stub signer tiers over the
    JCS-canonicalized manifest body. Ed25519 verifies offline by
    default; Sigstore is the identity + transparency-log tier; stub is
    an explicit dev placeholder.

The OpenTimestamps + Bitcoin anchoring tier was removed in
Amendment A5; design rationale and the current trade-off live in
``docs/cryptographic-attestation.md``.

See ``docs/cryptographic-attestation.md`` for the public verification model.
"""

from findevil_agent.crypto.audit_log import (
    AuditLog,
    AuditLogError,
    AuditRecord,
    canonicalize_json,
    hash_line,
)
from findevil_agent.crypto.manifest import (
    MANIFEST_VERSION,
    ManifestLeaf,
    ManifestVerification,
    RunManifest,
    build_manifest,
    verify_manifest,
    write_manifest,
)
from findevil_agent.crypto.merkle import (
    MerkleError,
    MerkleTree,
    verify_inclusion_proof,
)
from findevil_agent.crypto.signer import (
    SignedBundle,
    Signer,
    SigstoreSigner,
    StubSigner,
    make_signer,
)

__all__ = [
    "MANIFEST_VERSION",
    "AuditLog",
    "AuditLogError",
    "AuditRecord",
    "ManifestLeaf",
    "ManifestVerification",
    "MerkleError",
    "MerkleTree",
    "RunManifest",
    "SignedBundle",
    "Signer",
    "SigstoreSigner",
    "StubSigner",
    "build_manifest",
    "canonicalize_json",
    "hash_line",
    "make_signer",
    "verify_inclusion_proof",
    "verify_manifest",
    "write_manifest",
]
