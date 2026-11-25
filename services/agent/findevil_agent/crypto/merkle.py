"""Append-only Merkle tree over SHA-256 leaves.

Spec #2 §7.1 "Finding + manifest Merkle root". Every tool call's
output hash + every approved finding's hash is a leaf. ``root()``
gives the single value sealed in ``run.manifest.json``. ``inclusion_proof(i)``
yields the O(log n) sibling path the verifier replays offline.

Matches the Rust-side `rs_merkle` semantics so a manifest built by
the Python agent is bit-for-bit reproducible from the Rust MCP
server — required for independent verification via either path.

Conventions (same as `rs_merkle` default):

* Leaf ordering is insertion order.
* Internal nodes: ``H(left || right)`` where ``||`` is raw-byte
  concatenation of the two child digests.
* When the current tier has an odd number of nodes, the last node
  is duplicated to form the pair (the duplicate-last rule; matches
  ``rs_merkle`` when used with an empty-leaf policy).
* Empty tree: root is 32 bytes of zero.

Pure stdlib — no external crypto dep.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass


class MerkleError(RuntimeError):
    """Raised on inclusion-proof verification failure or bad inputs."""


@dataclass(frozen=True)
class InclusionProof:
    """The sibling path from a leaf up to the root.

    ``siblings[i]`` is the sibling digest at tier i (0 = leaf's
    pair). ``directions[i]`` is True if our node was on the right
    at that tier (so the hash is ``H(sibling || us)``), False if on
    the left (``H(us || sibling)``).
    """

    leaf_index: int
    leaf_hash: bytes
    siblings: list[bytes]
    directions: list[bool]
    root: bytes
    leaf_count: int


class MerkleTree:
    """Append-only Merkle tree over SHA-256.

    Usage:
        t = MerkleTree()
        for h in hashes:
            t.append(h)
        root = t.root()            # bytes
        proof = t.inclusion_proof(4)
        assert verify_inclusion_proof(proof)
    """

    _EMPTY_ROOT = b"\x00" * 32

    def __init__(self) -> None:
        self._leaves: list[bytes] = []

    # --- writing ---

    def append(self, leaf_hash: bytes) -> int:
        """Append one leaf. Returns its index."""
        if not isinstance(leaf_hash, bytes | bytearray) or len(leaf_hash) != 32:
            raise MerkleError("leaf_hash must be 32-byte SHA-256 digest")
        self._leaves.append(bytes(leaf_hash))
        return len(self._leaves) - 1

    def extend(self, leaves: list[bytes]) -> None:
        for h in leaves:
            self.append(h)

    # --- reading ---

    @property
    def leaf_count(self) -> int:
        return len(self._leaves)

    @property
    def leaves(self) -> list[bytes]:
        return list(self._leaves)

    def root(self) -> bytes:
        if not self._leaves:
            return self._EMPTY_ROOT
        tier = list(self._leaves)
        while len(tier) > 1:
            if len(tier) % 2:
                tier.append(tier[-1])  # duplicate-last compatibility rule
            tier = [_sha256(tier[i] + tier[i + 1]) for i in range(0, len(tier), 2)]
        return tier[0]

    def root_hex(self) -> str:
        return self.root().hex()

    # --- proofs ---

    def inclusion_proof(self, index: int) -> InclusionProof:
        if index < 0 or index >= len(self._leaves):
            raise MerkleError(f"leaf index {index} out of range (0..{len(self._leaves) - 1})")
        tier = list(self._leaves)
        siblings: list[bytes] = []
        directions: list[bool] = []
        i = index
        while len(tier) > 1:
            if len(tier) % 2:
                tier.append(tier[-1])
            is_right = i % 2 == 1
            sibling_i = i - 1 if is_right else i + 1
            siblings.append(tier[sibling_i])
            directions.append(is_right)
            tier = [_sha256(tier[j] + tier[j + 1]) for j in range(0, len(tier), 2)]
            i //= 2
        return InclusionProof(
            leaf_index=index,
            leaf_hash=self._leaves[index],
            siblings=siblings,
            directions=directions,
            root=self.root(),
            leaf_count=len(self._leaves),
        )


def verify_inclusion_proof(proof: InclusionProof) -> bool:
    """Return True iff the proof correctly reconstructs the root.

    Stateless — you don't need the MerkleTree instance; only the
    proof + the claimed leaf hash + the expected root. This is what
    ``verify_manifest`` (and the ``manifest_verify`` MCP tool) call
    when re-validating an inclusion proof during third-party offline
    verification.
    """
    if len(proof.leaf_hash) != 32:
        return False
    h = proof.leaf_hash
    for sibling, was_right in zip(proof.siblings, proof.directions, strict=True):
        if len(sibling) != 32:
            return False
        h = _sha256(sibling + h) if was_right else _sha256(h + sibling)
    return h == proof.root


def _sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()
