//! M2 cryptographic chain-of-custody — Rust side.
//!
//! Spec #2 §7.1. Mirrors the Python ``findevil_agent.crypto``
//! package so the Rust MCP server can independently produce the
//! same audit-log line hashes + Merkle roots over the same input
//! events. Cross-language byte-identical output is required for
//! ``verify_manifest`` (in Python ``findevil_agent.crypto.manifest``,
//! also exposed via the ``manifest_verify`` MCP tool) to replay
//! a manifest produced by either side.
//!
//! Sub-modules:
//!
//! * ``merkle`` — append-only SHA-256 Merkle tree with O(log n)
//!   inclusion proofs. Duplicate-last when a tier
//!   has odd cardinality. Empty root is 32 zero bytes.
//! * ``manifest`` — JCS canonicalization helpers for the run
//!   manifest. (Lands in a follow-up.)

pub mod merkle;

pub use merkle::{verify_inclusion_proof, InclusionProof, MerkleError, MerkleTree};
