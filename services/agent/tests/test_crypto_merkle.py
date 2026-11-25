"""Tests for findevil_agent.crypto.merkle."""

from __future__ import annotations

import hashlib

import pytest

from findevil_agent.crypto.merkle import (
    MerkleError,
    MerkleTree,
    verify_inclusion_proof,
)


def sha(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


class TestTreeBasics:
    def test_empty_root_is_zero(self) -> None:
        t = MerkleTree()
        assert t.root() == b"\x00" * 32
        assert t.leaf_count == 0

    def test_single_leaf_root_equals_leaf(self) -> None:
        t = MerkleTree()
        leaf = sha(b"only")
        t.append(leaf)
        # With a single leaf, the duplicate-last rule at tier 0
        # hashes H(leaf || leaf). We test both: either the leaf itself
        # or H(leaf||leaf) is valid depending on the spec variant. Our
        # impl goes into the while-loop only when len(tier) > 1; with
        # 1 leaf it returns tier[0] == leaf directly.
        assert t.root() == leaf

    def test_two_leaves_root(self) -> None:
        t = MerkleTree()
        a = sha(b"a")
        b = sha(b"b")
        t.append(a)
        t.append(b)
        assert t.root() == sha(a + b)

    def test_three_leaves_duplicates_last(self) -> None:
        t = MerkleTree()
        a, b, c = sha(b"a"), sha(b"b"), sha(b"c")
        t.append(a)
        t.append(b)
        t.append(c)
        # Tier 0: [a, b, c, c]  (duplicate c)
        # Tier 1: [H(a||b), H(c||c)]
        # Root:   H(H(a||b) || H(c||c))
        ab = sha(a + b)
        cc = sha(c + c)
        assert t.root() == sha(ab + cc)


class TestInclusionProofs:
    def test_two_leaf_proofs_round_trip(self) -> None:
        t = MerkleTree()
        a, b = sha(b"a"), sha(b"b")
        t.append(a)
        t.append(b)
        for i in (0, 1):
            proof = t.inclusion_proof(i)
            assert verify_inclusion_proof(proof) is True

    def test_eight_leaf_proofs_all_round_trip(self) -> None:
        t = MerkleTree()
        for i in range(8):
            t.append(sha(f"leaf-{i}".encode()))
        for i in range(8):
            assert verify_inclusion_proof(t.inclusion_proof(i)) is True

    def test_odd_count_proofs_round_trip(self) -> None:
        # Exercises the duplicate-last-leaf path at multiple tiers.
        t = MerkleTree()
        for i in range(7):
            t.append(sha(f"x-{i}".encode()))
        for i in range(7):
            assert verify_inclusion_proof(t.inclusion_proof(i)) is True

    def test_tampered_leaf_fails_verification(self) -> None:
        t = MerkleTree()
        for i in range(4):
            t.append(sha(f"y-{i}".encode()))
        proof = t.inclusion_proof(2)
        # Swap in a different leaf hash.
        import dataclasses

        tampered = dataclasses.replace(proof, leaf_hash=sha(b"impostor"))
        assert verify_inclusion_proof(tampered) is False

    def test_tampered_sibling_fails_verification(self) -> None:
        t = MerkleTree()
        for i in range(4):
            t.append(sha(f"z-{i}".encode()))
        proof = t.inclusion_proof(2)
        import dataclasses

        # Flip a bit in the first sibling.
        bad_siblings = list(proof.siblings)
        bad_siblings[0] = bytes([bad_siblings[0][0] ^ 1]) + bad_siblings[0][1:]
        tampered = dataclasses.replace(proof, siblings=bad_siblings)
        assert verify_inclusion_proof(tampered) is False


class TestErrorPaths:
    def test_rejects_wrong_leaf_size(self) -> None:
        t = MerkleTree()
        with pytest.raises(MerkleError):
            t.append(b"short")

    def test_inclusion_proof_out_of_range(self) -> None:
        t = MerkleTree()
        t.append(sha(b"x"))
        with pytest.raises(MerkleError):
            t.inclusion_proof(1)
        with pytest.raises(MerkleError):
            t.inclusion_proof(-1)


class TestFrozenCrossLanguageVector:
    """Frozen cross-language Merkle vectors (C4/C5 drift guard).

    The Python ``merkle.py`` and the Rust ``services/mcp/src/crypto/merkle.rs``
    mirror are kept in sync by review, not a build guard. These hex roots are
    FROZEN constants computed once over fixed inputs; the identical constants
    are asserted by a ``#[test]`` in ``merkle.rs``. If either canonicalization
    (leaf order, ``H(left || right)`` concat, duplicate-last odd-tier rule, or
    the SHA-256 primitive) ever drifts on one side, that side's frozen test
    fails red and the silent-divergence risk surfaces in CI instead of in a
    third-party manifest verification.

    Do NOT recompute these constants from the implementation under test to
    "fix" a failure: a changed root means the canonicalization changed, which
    is exactly what the guard exists to catch. Each value below was also
    hand-derived from ``hashlib.sha256`` outside ``MerkleTree``.
    """

    # 3-leaf vector: SHA-256(b"a"), b"b", b"c". Mirrored by the Rust
    # `cross_lang_three_leaf_root_matches_python` test.
    FROZEN_THREE_LEAF_ROOT = "d31a37ef6ac14a2db1470c4316beb5592e6afd4465022339adafda76a18ffabe"
    # 5-leaf vector: exercises the duplicate-last odd-tier rule at TWO tiers
    # (5 -> 6 -> 3 -> 4 -> 2 -> 1), a stronger drift probe than the 3-leaf case.
    FROZEN_FIVE_LEAF_ROOT = "305b1e31a691e2aef1c9734f73e5d92936f51fa552d87cbca23a50955b84f42b"

    def test_three_leaf_frozen_root(self) -> None:
        t = MerkleTree()
        for leaf in (b"a", b"b", b"c"):
            t.append(sha(leaf))
        assert t.root_hex() == self.FROZEN_THREE_LEAF_ROOT

    def test_five_leaf_frozen_root(self) -> None:
        t = MerkleTree()
        for leaf in (b"alpha", b"bravo", b"charlie", b"delta", b"echo"):
            t.append(sha(leaf))
        assert t.root_hex() == self.FROZEN_FIVE_LEAF_ROOT


class TestDeterminism:
    def test_two_trees_same_input_same_root(self) -> None:
        leaves = [sha(f"d-{i}".encode()) for i in range(13)]
        t1 = MerkleTree()
        for h in leaves:
            t1.append(h)
        t2 = MerkleTree()
        t2.extend(leaves)
        assert t1.root() == t2.root()

    def test_extend_produces_same_root(self) -> None:
        # Append order must not affect root — same input → same root.
        leaves = [sha(f"e-{i}".encode()) for i in range(5)]
        t1 = MerkleTree()
        t1.extend(leaves)
        t2 = MerkleTree()
        for h in leaves:
            t2.append(h)
        assert t1.root() == t2.root()
