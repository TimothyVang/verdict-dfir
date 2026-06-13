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
