//! Append-only Merkle tree over SHA-256.
//!
//! Mirrors ``findevil_agent.crypto.merkle`` byte-for-byte. The
//! Python and Rust implementations MUST produce the same root for
//! any sequence of identical leaves — this is what makes
//! cross-language manifest verification possible.
//!
//! Conventions:
//!
//! * Leaf order = insertion order.
//! * Internal hash = ``SHA-256(left || right)`` over raw 32-byte
//!   digests.
//! * Odd tier size: duplicate the last node.
//! * Empty tree root: 32 zero bytes.
//!
//! Pure stdlib + ``sha2`` (already a Spec #2 §16 dependency).

use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MerkleError {
    #[error("leaf must be 32 bytes (SHA-256 digest), got {0}")]
    LeafSize(usize),

    #[error("leaf index {0} out of range (0..{1})")]
    IndexOutOfRange(usize, usize),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InclusionProof {
    pub leaf_index: usize,
    pub leaf_hash: [u8; 32],
    pub siblings: Vec<[u8; 32]>,
    /// ``directions[i]`` is ``true`` if our node was on the right
    /// at tier ``i`` (so the parent hash is ``H(sibling || us)``).
    pub directions: Vec<bool>,
    pub root: [u8; 32],
    pub leaf_count: usize,
}

#[derive(Clone, Default, Debug)]
pub struct MerkleTree {
    leaves: Vec<[u8; 32]>,
}

impl MerkleTree {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append one leaf. Returns its index. ``leaf_hash`` must be a
    /// 32-byte SHA-256 digest.
    pub fn append(&mut self, leaf_hash: [u8; 32]) -> usize {
        self.leaves.push(leaf_hash);
        self.leaves.len() - 1
    }

    /// Append multiple leaves. Returns the first inserted index.
    pub fn extend(&mut self, leaves: &[[u8; 32]]) -> usize {
        let start = self.leaves.len();
        self.leaves.extend_from_slice(leaves);
        start
    }

    /// Append from arbitrary byte slices, validating each is 32 bytes.
    pub fn append_bytes(&mut self, leaf_hash: &[u8]) -> Result<usize, MerkleError> {
        if leaf_hash.len() != 32 {
            return Err(MerkleError::LeafSize(leaf_hash.len()));
        }
        let mut buf = [0u8; 32];
        buf.copy_from_slice(leaf_hash);
        Ok(self.append(buf))
    }

    #[must_use]
    pub const fn leaf_count(&self) -> usize {
        self.leaves.len()
    }

    #[must_use]
    pub fn leaves(&self) -> &[[u8; 32]] {
        &self.leaves
    }

    /// Compute the current Merkle root.
    #[must_use]
    pub fn root(&self) -> [u8; 32] {
        if self.leaves.is_empty() {
            return [0u8; 32];
        }
        let mut tier: Vec<[u8; 32]> = self.leaves.clone();
        while tier.len() > 1 {
            if tier.len() % 2 == 1 {
                let last = *tier.last().expect("non-empty");
                tier.push(last);
            }
            tier = tier
                .chunks_exact(2)
                .map(|pair| sha256_pair(&pair[0], &pair[1]))
                .collect();
        }
        tier[0]
    }

    /// Hex-encoded root for human-readable manifest fields.
    #[must_use]
    pub fn root_hex(&self) -> String {
        hex_lower(&self.root())
    }

    /// Build an inclusion proof for ``index``.
    pub fn inclusion_proof(&self, index: usize) -> Result<InclusionProof, MerkleError> {
        if index >= self.leaves.len() {
            return Err(MerkleError::IndexOutOfRange(index, self.leaves.len()));
        }
        let mut tier: Vec<[u8; 32]> = self.leaves.clone();
        let mut siblings: Vec<[u8; 32]> = Vec::new();
        let mut directions: Vec<bool> = Vec::new();
        let mut i = index;

        while tier.len() > 1 {
            if tier.len() % 2 == 1 {
                let last = *tier.last().expect("non-empty");
                tier.push(last);
            }
            let is_right = i % 2 == 1;
            let sibling_i = if is_right { i - 1 } else { i + 1 };
            siblings.push(tier[sibling_i]);
            directions.push(is_right);

            tier = tier
                .chunks_exact(2)
                .map(|pair| sha256_pair(&pair[0], &pair[1]))
                .collect();
            i /= 2;
        }

        Ok(InclusionProof {
            leaf_index: index,
            leaf_hash: self.leaves[index],
            siblings,
            directions,
            root: self.root(),
            leaf_count: self.leaves.len(),
        })
    }
}

/// Stateless verifier — given a proof, reconstruct the root and
/// compare. Matches the Python ``verify_inclusion_proof`` exactly.
#[must_use]
pub fn verify_inclusion_proof(proof: &InclusionProof) -> bool {
    if proof.siblings.len() != proof.directions.len() {
        return false;
    }
    let mut h = proof.leaf_hash;
    for (sibling, was_right) in proof.siblings.iter().zip(proof.directions.iter()) {
        h = if *was_right {
            sha256_pair(sibling, &h)
        } else {
            sha256_pair(&h, sibling)
        };
    }
    h == proof.root
}

fn sha256_pair(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(a);
    hasher.update(b);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

#[must_use]
fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

// --------------------------------------------------------------------
// Unit tests.
// --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sha(b: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b);
        let d = h.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&d);
        out
    }

    #[test]
    fn empty_tree_root_is_zero() {
        let t = MerkleTree::new();
        assert_eq!(t.root(), [0u8; 32]);
        assert_eq!(t.leaf_count(), 0);
    }

    #[test]
    fn single_leaf_root_is_leaf() {
        let mut t = MerkleTree::new();
        let leaf = sha(b"only");
        t.append(leaf);
        assert_eq!(t.root(), leaf);
    }

    #[test]
    fn two_leaves_root_is_concat_hash() {
        let mut t = MerkleTree::new();
        let a = sha(b"a");
        let b = sha(b"b");
        t.append(a);
        t.append(b);
        assert_eq!(t.root(), sha256_pair(&a, &b));
    }

    #[test]
    fn three_leaves_duplicate_last() {
        let mut t = MerkleTree::new();
        let a = sha(b"a");
        let b = sha(b"b");
        let c = sha(b"c");
        t.append(a);
        t.append(b);
        t.append(c);
        let ab = sha256_pair(&a, &b);
        let cc = sha256_pair(&c, &c);
        let root = sha256_pair(&ab, &cc);
        assert_eq!(t.root(), root);
    }

    #[test]
    fn eight_leaves_all_proofs_roundtrip() {
        let mut t = MerkleTree::new();
        for i in 0..8u8 {
            t.append(sha(&[i]));
        }
        for i in 0..8 {
            let p = t.inclusion_proof(i).unwrap();
            assert!(verify_inclusion_proof(&p), "proof {i} failed");
        }
    }

    #[test]
    fn seven_leaves_odd_count_proofs_roundtrip() {
        let mut t = MerkleTree::new();
        for i in 0..7u8 {
            t.append(sha(&[i]));
        }
        for i in 0..7 {
            let p = t.inclusion_proof(i).unwrap();
            assert!(verify_inclusion_proof(&p), "odd-count proof {i} failed");
        }
    }

    #[test]
    fn tampered_leaf_fails_verification() {
        let mut t = MerkleTree::new();
        for i in 0..4u8 {
            t.append(sha(&[i]));
        }
        let mut p = t.inclusion_proof(2).unwrap();
        p.leaf_hash = sha(b"impostor");
        assert!(!verify_inclusion_proof(&p));
    }

    #[test]
    fn tampered_sibling_fails_verification() {
        let mut t = MerkleTree::new();
        for i in 0..4u8 {
            t.append(sha(&[i]));
        }
        let mut p = t.inclusion_proof(1).unwrap();
        // Flip a bit in the first sibling.
        p.siblings[0][0] ^= 1;
        assert!(!verify_inclusion_proof(&p));
    }

    #[test]
    fn append_bytes_validates_size() {
        let mut t = MerkleTree::new();
        let err = t.append_bytes(b"too short").unwrap_err();
        match err {
            MerkleError::LeafSize(n) => assert_eq!(n, 9),
            MerkleError::IndexOutOfRange(..) => panic!("expected LeafSize"),
        }
    }

    #[test]
    fn out_of_range_index_errors() {
        let mut t = MerkleTree::new();
        t.append(sha(b"x"));
        assert!(t.inclusion_proof(1).is_err());
    }

    #[test]
    fn root_hex_lowercase_64_chars() {
        let mut t = MerkleTree::new();
        t.append(sha(b"x"));
        let hex = t.root_hex();
        assert_eq!(hex.len(), 64);
        assert!(hex
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    /// Cross-language parity sanity: SHA-256 of "abc" matches the
    /// known vector. If THIS test ever drifts, the Python `merkle.py`
    /// and Rust `merkle.rs` will produce different roots for the
    /// same inputs — the M2 verification path silently breaks.
    #[test]
    fn sha256_known_vector() {
        let h = sha(b"abc");
        assert_eq!(
            hex_lower(&h),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    /// Cross-language parity check: same leaves, both languages
    /// must produce the same root. The Python side hashes b"a", b"b",
    /// b"c" and produces this expected root (computed offline).
    ///
    /// FROZEN VECTOR — mirrored by the Python
    /// `TestFrozenCrossLanguageVector::test_three_leaf_frozen_root` in
    /// `services/agent/tests/test_crypto_merkle.py`. If this constant
    /// drifts on either side, that side fails red and the silent
    /// Rust/Python mirror divergence (C4/C5 risk) surfaces in CI.
    #[test]
    fn cross_lang_three_leaf_root_matches_python() {
        let mut t = MerkleTree::new();
        t.append(sha(b"a"));
        t.append(sha(b"b"));
        t.append(sha(b"c"));
        // Computed once via Python: hashlib.sha256(...) chain over
        // the same inputs. If this constant drifts vs Python, the
        // cross-lang invariant is broken.
        let py_root = "d31a37ef6ac14a2db1470c4316beb5592e6afd4465022339adafda76a18ffabe";
        assert_eq!(t.root_hex(), py_root, "cross-lang Merkle root drift");
    }

    /// FROZEN VECTOR — 5 leaves exercise the duplicate-last odd-tier
    /// rule at TWO tiers (5 -> 6 -> 3 -> 4 -> 2 -> 1), a stronger
    /// drift probe than the 3-leaf case. The identical hex constant is
    /// asserted by the Python
    /// `TestFrozenCrossLanguageVector::test_five_leaf_frozen_root`.
    /// A divergence in either canonicalization (leaf order,
    /// `H(left || right)` concat order, the odd-tier duplicate rule,
    /// or the SHA-256 primitive) fails this test red instead of
    /// silently breaking offline manifest verification. Do NOT
    /// recompute this from the impl to "fix" a failure — a changed
    /// root means the canonicalization changed.
    #[test]
    fn cross_lang_five_leaf_root_matches_python() {
        let mut t = MerkleTree::new();
        for leaf in [b"alpha".as_slice(), b"bravo", b"charlie", b"delta", b"echo"] {
            t.append(sha(leaf));
        }
        let py_root = "305b1e31a691e2aef1c9734f73e5d92936f51fa552d87cbca23a50955b84f42b";
        assert_eq!(t.root_hex(), py_root, "cross-lang Merkle root drift");
    }
}
