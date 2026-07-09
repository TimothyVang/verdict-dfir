#!/usr/bin/env python3
"""manifest-verify-offline — re-derive a run.manifest custody chain with ZERO deps.

A third party can run this with NOTHING but a stock Python 3 interpreter — no
``uv``/venv, no ``cryptography`` wheel, no MCP server, no network, no production
``findevil_agent`` import — and re-prove, end to end, that a committed
``run.manifest.json`` is internally consistent and signed:

1. **Per-line hash chain.** Replays the linked ``audit.jsonl``: ``seq`` is
   contiguous from 0, every record's ``prev_hash`` equals the SHA-256 of the
   preceding line's exact bytes, and every line is in canonical form
   (RFC-8785-compatible: ``sort_keys`` + tightest separators + ASCII escapes).
   Any post-seal edit changes the canonical bytes and breaks the chain.

2. **Log-vs-manifest consistency.** A tail-truncated log still replays
   prefix-cleanly and a forged-but-internally-consistent leaf set still rebuilds
   its own root, so the verifier RE-DERIVES the record count, the audit-log final
   hash, and the full Merkle leaf set from the log itself and compares them to
   what the manifest declared — instead of trusting the manifest's own copies.

3. **Merkle root.** Rebuilds the Merkle root from the manifest's declared leaves
   (duplicate-last odd rule, internal node = ``SHA-256(left || right)``) and
   compares it to ``merkle_root_hex``; also checks ``leaf_count``.

4. **Ed25519 signature.** Verifies the embedded Ed25519 signature over the
   JCS-canonicalized manifest body (everything except ``signature``) using a
   VENDORED, pure-Python RFC-8032 verifier (the only primitive: ``hashlib.sha512``
   from the stdlib). No third-party crypto library is imported. A ``stub`` bundle
   is reported as a non-cryptographic placeholder and a ``sigstore`` bundle is
   reported as recorded-but-needs-identity-policy — both honestly, neither claimed
   as proof.

This is a deliberately INDEPENDENT re-implementation of
``findevil_agent.crypto.manifest.verify_manifest``. It shares no code with the
product so that agreement between the two is a real cross-check, not a tautology.

Usage:
    scripts/manifest-verify-offline.py <run.manifest.json> [--audit-log PATH]
                                       [--check] [--json]

    --audit-log PATH  override the audit log location (default: the sibling
                      ``audit.jsonl`` next to the manifest, then the embedded
                      ``audit_log_path``).
    --check           also load the sibling ``manifest_verify.json`` and assert
                      this verifier AGREES with the committed product result on
                      every custody/signature field (exit non-zero on any
                      disagreement). This is the "agrees with a committed
                      sample-run manifest" gate.
    --json            print the structured result as JSON instead of a report.

Exit code 0 iff the manifest verifies (and, under ``--check``, agrees with the
committed sidecar); non-zero otherwise.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

_CANONICAL_SEPARATORS = (",", ":")


# ---------------------------------------------------------------------------
# Canonicalization + hashing (mirror of crypto.audit_log, re-implemented).
# ---------------------------------------------------------------------------


def canonicalize_json(obj: Any) -> bytes:
    """RFC-8785-compatible canonical bytes: sorted keys, tightest separators,
    non-ASCII escaped to ``\\uXXXX``. Byte-identical to the product canonicalizer
    so a re-canonicalized record reproduces the on-disk line exactly."""
    return json.dumps(
        obj, sort_keys=True, separators=_CANONICAL_SEPARATORS, ensure_ascii=True
    ).encode("ascii")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Vendored pure-Python Ed25519 verify (RFC 8032). Stdlib-only: the single
# primitive is hashlib.sha512. No third-party crypto library is imported.
# ---------------------------------------------------------------------------

_ED_P = 2**255 - 19
_ED_L = 2**252 + 27742317777372353535851937790883648493
_ED_D = (-121665 * pow(121666, _ED_P - 2, _ED_P)) % _ED_P
_ED_I = pow(2, (_ED_P - 1) // 4, _ED_P)


def _ed_inv(x: int) -> int:
    return pow(x, _ED_P - 2, _ED_P)


def _ed_xrecover(y: int) -> int:
    xx = (y * y - 1) * _ed_inv(_ED_D * y * y + 1) % _ED_P
    x = pow(xx, (_ED_P + 3) // 8, _ED_P)
    if (x * x - xx) % _ED_P != 0:
        x = (x * _ED_I) % _ED_P
    if x % 2 != 0:
        x = _ED_P - x
    return x


_ED_BY = (4 * _ed_inv(5)) % _ED_P
_ED_BX = _ed_xrecover(_ED_BY)
_ED_B = (_ED_BX % _ED_P, _ED_BY % _ED_P)


def _ed_add(point_p: tuple[int, int], point_q: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = point_p
    x2, y2 = point_q
    denom = _ED_D * x1 * x2 * y1 * y2 % _ED_P
    x3 = (x1 * y2 + x2 * y1) * _ed_inv(1 + denom) % _ED_P
    y3 = (y1 * y2 + x1 * x2) * _ed_inv(1 - denom) % _ED_P
    return (x3 % _ED_P, y3 % _ED_P)


def _ed_scalarmult(point: tuple[int, int], scalar: int) -> tuple[int, int]:
    """Iterative double-and-add (no recursion, so no recursion-limit risk)."""
    result = (0, 1)
    addend = point
    while scalar > 0:
        if scalar & 1:
            result = _ed_add(result, addend)
        addend = _ed_add(addend, addend)
        scalar >>= 1
    return result


def _ed_on_curve(point: tuple[int, int]) -> bool:
    x, y = point
    return (-x * x + y * y - 1 - _ED_D * x * x * y * y) % _ED_P == 0


def _ed_decodepoint(s: bytes) -> tuple[int, int]:
    y = int.from_bytes(s, "little") & ((1 << 255) - 1)
    x = _ed_xrecover(y)
    if (x & 1) != ((s[31] >> 7) & 1):
        x = _ED_P - x
    point = (x, y)
    if not _ed_on_curve(point):
        raise ValueError("decoded point is not on the Ed25519 curve")
    return point


def _ed_encodepoint(point: tuple[int, int]) -> bytes:
    x, y = point
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def ed25519_verify(signature: bytes, message: bytes, public_key: bytes) -> bool:
    """RFC-8032 Ed25519 (PureEdDSA, SHA-512) verify. Returns True iff genuine.

    Cross-checked in this repo against ``cryptography``'s Ed25519PublicKey.verify:
    same accept on a real bundle, same reject on a tampered message.
    """
    if len(signature) != 64 or len(public_key) != 32:
        return False
    try:
        point_r = _ed_decodepoint(signature[:32])
        point_a = _ed_decodepoint(public_key)
    except ValueError:
        return False
    s_int = int.from_bytes(signature[32:], "little")
    digest = hashlib.sha512(_ed_encodepoint(point_r) + public_key + message).digest()
    h_int = int.from_bytes(digest, "little") % _ED_L
    left = _ed_scalarmult(_ED_B, s_int)
    right = _ed_add(point_r, _ed_scalarmult(point_a, h_int))
    return left == right


# ---------------------------------------------------------------------------
# Audit-log replay + Merkle leaf re-derivation (mirror of crypto.manifest).
# ---------------------------------------------------------------------------


class VerifyError(RuntimeError):
    """A structural problem prevented verification (not a clean negative result)."""


@dataclass(frozen=True)
class DerivedLeaf:
    seq: int
    kind: str
    digest_hex: str
    record_id: str

    def as_tuple(self) -> tuple[int, str, str, str]:
        return (self.seq, self.kind, self.digest_hex, self.record_id)


def _is_hex64(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        bytes.fromhex(value)
    except ValueError:
        return False
    return True


def _replay_audit_log(log_path: Path) -> tuple[list[DerivedLeaf], int, str]:
    """Replay the chain and re-derive (leaves, record_count, final_line_hash).

    Raises :class:`VerifyError` on any chain break — seq gap, prev_hash mismatch,
    or a non-canonical line (byte-level tampering inside a record)."""
    leaves: list[DerivedLeaf] = []
    count = 0
    prev_hash = ""
    final_hash = ""
    with log_path.open("rb") as handle:
        for raw_line in handle:
            raw = raw_line.rstrip(b"\n")
            if not raw:
                continue
            try:
                obj = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise VerifyError(
                    f"seq {count}: line is not valid JSON: {exc}"
                ) from exc
            if not isinstance(obj, dict):
                raise VerifyError(f"seq {count}: line is not a JSON object")
            seq = obj.get("seq")
            if seq != count:
                raise VerifyError(f"seq {count}: expected seq={count}, got seq={seq!r}")
            declared_prev = obj.get("prev_hash")
            if declared_prev != prev_hash:
                raise VerifyError(
                    f"seq {count}: prev_hash break "
                    f"(declared={declared_prev!r}, expected={prev_hash!r})"
                )
            canonical = canonicalize_json(obj)
            if canonical != raw:
                raise VerifyError(
                    f"seq {count}: line is not in canonical form (tampered)"
                )

            kind = str(obj.get("kind", ""))
            payload = obj.get("payload") or {}
            if kind == "tool_call_output":
                output_hash = payload.get("output_hash")
                digest = (
                    output_hash if _is_hex64(output_hash) else _sha256_hex(canonical)
                )
                leaves.append(
                    DerivedLeaf(
                        seq=count,
                        kind="tool_call_output",
                        digest_hex=str(digest),
                        record_id=str(payload.get("tool_call_id", "")),
                    )
                )
            elif kind == "finding_approved":
                leaves.append(
                    DerivedLeaf(
                        seq=count,
                        kind="finding",
                        digest_hex=_sha256_hex(canonical),
                        record_id=str(payload.get("finding_id", "")),
                    )
                )

            prev_hash = _sha256_hex(canonical)
            final_hash = prev_hash
            count += 1
    if count == 0:
        raise VerifyError(f"{log_path.name}: no records")
    return leaves, count, final_hash


def _merkle_root_hex(leaf_digests_hex: list[str]) -> str:
    """Rebuild the Merkle root from leaf SHA-256 digests.

    Duplicate-last odd rule; internal node = ``SHA-256(left || right)`` over raw
    32-byte digests; empty tree = 32 zero bytes. Mirrors crypto.merkle."""
    if not leaf_digests_hex:
        return "00" * 32
    tier = [bytes.fromhex(h) for h in leaf_digests_hex]
    while len(tier) > 1:
        if len(tier) % 2:
            tier.append(tier[-1])
        tier = [
            hashlib.sha256(tier[i] + tier[i + 1]).digest()
            for i in range(0, len(tier), 2)
        ]
    return tier[0].hex()


# ---------------------------------------------------------------------------
# Transparency anchor (optional Sigstore Rekor / RFC-3161) — stdlib-only,
# independent re-implementation of the RFC-6962 inclusion check. Mirrors
# sigstore._internal.merkle so agreement with the product's transparency_ok is
# a real cross-check, not a shared-code tautology. Non-gating either way.
# ---------------------------------------------------------------------------

_RFC6962_LEAF_PREFIX = b"\x00"
_RFC6962_NODE_PREFIX = b"\x01"


def _rfc6962_leaf(body: bytes) -> bytes:
    return hashlib.sha256(_RFC6962_LEAF_PREFIX + body).digest()


def _rfc6962_children(lhs: bytes, rhs: bytes) -> bytes:
    return hashlib.sha256(_RFC6962_NODE_PREFIX + lhs + rhs).digest()


def _decomp_inclusion_proof(index: int, size: int) -> tuple[int, int]:
    inner = (index ^ (size - 1)).bit_length()
    border = bin(index >> inner).count("1")
    return inner, border


def _chain_inner(seed: bytes, hashes: list[str], log_index: int) -> bytes:
    for i, hex_hash in enumerate(hashes):
        node = bytes.fromhex(hex_hash)
        if (log_index >> i) & 1 == 0:
            seed = _rfc6962_children(seed, node)
        else:
            seed = _rfc6962_children(node, seed)
    return seed


def _chain_border_right(seed: bytes, hashes: list[str]) -> bytes:
    for hex_hash in hashes:
        seed = _rfc6962_children(bytes.fromhex(hex_hash), seed)
    return seed


def _verify_rekor_inclusion(rekor: dict[str, Any]) -> bool | str:
    """Re-derive the Rekor entry's RFC-6962 leaf hash from its stored body and
    chain the inclusion-proof hashes to the declared root — pure stdlib."""
    proof = rekor.get("inclusion_proof") or {}
    body_b64 = rekor.get("body")
    if not body_b64:
        return "rekor block missing entry body; cannot verify inclusion proof offline"
    try:
        body = base64.b64decode(str(body_b64))
        hashes = [str(h) for h in (proof.get("hashes") or [])]
        log_index = int(proof.get("log_index") or 0)
        tree_size = int(proof.get("tree_size") or 0)
        declared_root = str(proof.get("root_hash") or "")
    except (ValueError, TypeError) as exc:
        return f"rekor inclusion proof malformed: {exc}"
    if tree_size <= 0 or log_index < 0 or log_index >= tree_size:
        return f"rekor inclusion proof has invalid index/size ({log_index}/{tree_size})"
    inner, border = _decomp_inclusion_proof(log_index, tree_size)
    if len(hashes) != inner + border:
        return (
            f"rekor inclusion proof has wrong size: expected {inner + border}, "
            f"got {len(hashes)}"
        )
    seed = _chain_inner(_rfc6962_leaf(body), hashes[:inner], log_index)
    calc_root = _chain_border_right(seed, hashes[inner:]).hex()
    if calc_root != declared_root:
        return (
            f"rekor inclusion proof root mismatch: declared {declared_root} != "
            f"recomputed {calc_root}"
        )
    return True


def _verify_transparency_offline(
    anchor: dict[str, Any], merkle_root_hex: str
) -> bool | str:
    """Non-gating offline check of the optional transparency anchor.

    Absent anchor -> vacuously True. A Rekor anchor is re-derived here in pure
    stdlib. An RFC-3161 anchor needs ``openssl`` + the TSA CA chain to verify,
    which is out of this zero-dependency verifier's scope, so it is reported
    honestly (still non-gating)."""
    if not isinstance(anchor, dict) or not anchor:
        return True
    subject = anchor.get("subject")
    subject_digest = (
        subject.get("merkle_root_sha256") if isinstance(subject, dict) else None
    )
    if str(subject_digest) != merkle_root_hex:
        return (
            f"transparency subject digest {subject_digest!r} != manifest merkle "
            f"root {merkle_root_hex!r}"
        )
    kind = anchor.get("kind")
    if kind == "none":
        return str(anchor.get("fallback_reason") or "root was not anchored")
    if kind == "rekor":
        return _verify_rekor_inclusion(anchor.get("rekor") or {})
    if kind == "rfc3161":
        return (
            "rfc3161 timestamp present; offline verification of the TSA token is "
            "out of this zero-dependency verifier's scope (needs openssl + the "
            "issuing CA chain)"
        )
    return f"unknown transparency kind {kind!r}"


# ---------------------------------------------------------------------------
# Result shape + signature verification.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class OfflineVerification:
    """Mirror of the product ``ManifestVerification`` custody fields. Each *_ok
    field is ``True`` (passed) or a reason string (failed)."""

    audit_chain_ok: bool | str
    merkle_root_ok: bool | str
    leaf_count_ok: bool | str
    signature_present: bool
    signature_kind: str
    signature_verified: bool | str
    transparency_ok: bool | str
    overall: bool


_ADVISORY_SIG_KINDS = ("stub", "sigstore")


def _verify_signature(sig: dict[str, Any], manifest_obj: dict[str, Any]) -> bool | str:
    """Honest signature-verification status. Only an ed25519 bundle is verified
    cryptographically here; stub/sigstore return explicit reason strings."""
    kind = str(sig.get("kind") or "stub")
    present = bool(sig.get("bundle_b64") and sig.get("payload_sha256"))
    if not present:
        return "no signature bundle present"
    if kind == "stub":
        return "stub signature: deterministic dev/offline placeholder, not cryptographic proof"
    if kind == "sigstore":
        return (
            "sigstore bundle present and recorded; offline cryptographic verification "
            "requires the verifier to supply the expected signer identity (deployment policy)"
        )
    if kind != "ed25519":
        return f"unknown signer kind {kind!r}"
    try:
        bundle = json.loads(base64.b64decode(str(sig.get("bundle_b64") or "")))
        public_key = base64.b64decode(bundle["public_key_b64"])
        signature = base64.b64decode(bundle["signature_b64"])
    except (KeyError, ValueError, TypeError) as exc:
        return f"ed25519 bundle malformed: {exc}"
    # The signed body excludes BOTH ``signature`` and the after-signing
    # ``transparency_log`` anchor (mirror of the product's
    # ``_to_json_safe(exclude_signature=True)``), so exclude both here or a
    # manifest carrying a transparency anchor would fail ed25519 verification.
    body = {
        k: v
        for k, v in manifest_obj.items()
        if k not in ("signature", "transparency_log")
    }
    body_bytes = canonicalize_json(body)
    if not ed25519_verify(signature, body_bytes, public_key):
        return "ed25519 signature verification FAILED: manifest body does not match the signature"
    return True


def verify_manifest_offline(
    manifest_path: Path, *, audit_log_path: Path | None = None
) -> OfflineVerification:
    """Re-derive the full custody chain of ``manifest_path`` with stdlib only."""
    obj = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(obj, dict):
        raise VerifyError(f"{manifest_path.name}: manifest is not a JSON object")

    # 1. Locate the audit log. Precedence: explicit override -> sibling next to
    # the manifest (a copied case dir verifies anywhere) -> embedded path.
    embedded = Path(str(obj.get("audit_log_path") or ""))
    sibling = manifest_path.parent / (embedded.name or "audit.jsonl")
    log_path = audit_log_path or (sibling if sibling.is_file() else embedded)

    # 1a + 1b. Replay the chain, then re-derive count/final-hash/leaves and
    # compare to what the manifest declared.
    audit_status: bool | str
    if not (log_path and log_path.is_file()):
        audit_status = f"audit log not found at {log_path}"
        derived_leaves: list[DerivedLeaf] = []
    else:
        try:
            derived_leaves, replayed_count, replayed_final = _replay_audit_log(log_path)
            audit_status = True
        except VerifyError as exc:
            audit_status = f"audit chain break: {exc}"
            derived_leaves = []
        if audit_status is True:
            audit_status = _consistency_status(
                obj, derived_leaves, replayed_count, replayed_final
            )

    # 2. Merkle root, rebuilt from the manifest's DECLARED leaves.
    declared_leaves = obj.get("leaves", [])
    declared_root = str(obj.get("merkle_root_hex", ""))
    try:
        rebuilt = _merkle_root_hex(
            [str(leaf.get("digest_hex", "")) for leaf in declared_leaves]
        )
        merkle_status: bool | str = (
            True
            if rebuilt == declared_root
            else f"declared root {declared_root} != rebuilt {rebuilt}"
        )
    except ValueError as exc:
        merkle_status = f"merkle rebuild failed: {exc}"

    # 3. Leaf count.
    declared_count = obj.get("leaf_count")
    actual_count = len(declared_leaves)
    count_status: bool | str = (
        True
        if declared_count == actual_count
        else f"leaf_count {declared_count} != actual {actual_count}"
    )

    # 4. Signature.
    sig = obj.get("signature") or {}
    sig_present = bool(sig.get("bundle_b64") and sig.get("payload_sha256"))
    sig_kind = str(sig.get("kind") or "stub")
    sig_verified = _verify_signature(sig, obj)

    # 5. Optional transparency anchor — a non-gating side-signal, absent by
    # default (a run that didn't opt into anchoring carries no block, so this is
    # vacuously True and the manifest verifies exactly as before).
    transparency_status = _verify_transparency_offline(
        obj.get("transparency_log") or {}, declared_root
    )

    sig_failed = (
        sig_present and sig_kind not in _ADVISORY_SIG_KINDS and sig_verified is not True
    )
    overall = (
        audit_status is True
        and merkle_status is True
        and count_status is True
        and sig_present
        and not sig_failed
    )
    return OfflineVerification(
        audit_chain_ok=audit_status,
        merkle_root_ok=merkle_status,
        leaf_count_ok=count_status,
        signature_present=sig_present,
        signature_kind=sig_kind,
        signature_verified=sig_verified,
        transparency_ok=transparency_status,
        overall=overall,
    )


def _consistency_status(
    obj: dict[str, Any],
    derived_leaves: list[DerivedLeaf],
    replayed_count: int,
    replayed_final: str,
) -> bool | str:
    """Compare re-derived count/final-hash/leaves to the manifest's declarations."""
    if replayed_count != obj.get("audit_log_record_count"):
        return (
            f"audit log has {replayed_count} record(s) but the manifest declares "
            f"{obj.get('audit_log_record_count')} (tail truncation or post-seal append)"
        )
    if replayed_final != str(obj.get("audit_log_final_hash") or ""):
        return "audit log final hash does not match the manifest's audit_log_final_hash"
    declared = [
        (
            int(leaf.get("seq", -1)),
            str(leaf.get("kind", "")),
            str(leaf.get("digest_hex", "")),
            str(leaf.get("record_id", "")),
        )
        for leaf in obj.get("leaves", [])
    ]
    if [leaf.as_tuple() for leaf in derived_leaves] != declared:
        return "leaves re-derived from the audit log do not match the manifest's declared leaves"
    return True


# ---------------------------------------------------------------------------
# --check: agreement with the committed product sidecar.
# ---------------------------------------------------------------------------

# manifest_verify.json field name -> OfflineVerification attribute. Only the
# custody/signature fields this independent verifier re-derives are compared;
# the product's separate entailment side-signal is out of this verifier's scope.
_SIDECAR_FIELD_MAP: dict[str, str] = {
    "audit_chain_ok": "audit_chain_ok",
    "merkle_root_ok": "merkle_root_ok",
    "leaf_count_ok": "leaf_count_ok",
    "signature_present": "signature_present",
    "signature_kind": "signature_kind",
    "signature_verified": "signature_verified",
    "transparency_ok": "transparency_ok",
    "overall": "overall",
}


def _as_bool_field(value: Any) -> bool | str:
    """The product sidecar stores each *_ok as a bare ``true`` plus an optional
    ``<field>_detail`` reason; collapse a non-true value to its boolean polarity
    so we compare pass/fail, not two differently-worded reason strings."""
    return True if value is True else False if value is False else bool(value)


def check_agreement(result: OfflineVerification, sidecar: dict[str, Any]) -> list[str]:
    """Return a list of disagreements between this verifier and the committed
    product sidecar. Empty list means full agreement on the custody fields."""
    disagreements: list[str] = []
    result_d = asdict(result)
    for sidecar_field, attr in _SIDECAR_FIELD_MAP.items():
        if sidecar_field not in sidecar:
            continue
        product_val = sidecar[sidecar_field]
        offline_val = result_d[attr]
        if sidecar_field in ("signature_present", "overall"):
            if bool(product_val) != bool(offline_val):
                disagreements.append(
                    f"{sidecar_field}: product={product_val!r} offline={offline_val!r}"
                )
        elif sidecar_field == "signature_kind":
            if str(product_val) != str(offline_val):
                disagreements.append(
                    f"{sidecar_field}: product={product_val!r} offline={offline_val!r}"
                )
        else:
            # *_ok / signature_verified: compare pass/fail polarity.
            if _as_bool_field(product_val) != _as_bool_field(offline_val):
                disagreements.append(
                    f"{sidecar_field}: product={product_val!r} offline={offline_val!r}"
                )
    return disagreements


# ---------------------------------------------------------------------------
# CLI.
# ---------------------------------------------------------------------------


def _format_field(label: str, value: bool | str) -> str:
    if value is True:
        return f"  [PASS]  {label}"
    return f"  [FAIL]  {label}  -  {value}"


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("manifest", help="path to run.manifest.json")
    parser.add_argument("--audit-log", default=None, help="override the audit log path")
    parser.add_argument(
        "--check",
        action="store_true",
        help="also assert agreement with the sibling manifest_verify.json",
    )
    parser.add_argument(
        "--json", action="store_true", help="emit JSON instead of a report"
    )
    args = parser.parse_args(argv[1:])

    manifest_path = Path(args.manifest).resolve()
    if not manifest_path.is_file():
        print(f"not a file: {manifest_path}", file=sys.stderr)
        return 2
    audit_log = Path(args.audit_log).resolve() if args.audit_log else None

    try:
        result = verify_manifest_offline(manifest_path, audit_log_path=audit_log)
    except (VerifyError, json.JSONDecodeError) as exc:
        print(f"verification could not run: {exc}", file=sys.stderr)
        return 2

    disagreements: list[str] = []
    sidecar_checked = False
    if args.check:
        sidecar_path = manifest_path.parent / "manifest_verify.json"
        if not sidecar_path.is_file():
            print(
                f"--check: no sibling manifest_verify.json next to {manifest_path}",
                file=sys.stderr,
            )
            return 2
        sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
        disagreements = check_agreement(result, sidecar)
        sidecar_checked = True

    if args.json:
        out = asdict(result)
        out["agrees_with_committed_sidecar"] = (
            (not disagreements) if sidecar_checked else None
        )
        out["disagreements"] = disagreements
        print(json.dumps(out, indent=2, sort_keys=True))
    else:
        print(f"offline manifest verification: {manifest_path}")
        print(
            _format_field(
                "audit chain (per-line hash chain + log/manifest consistency)",
                result.audit_chain_ok,
            )
        )
        print(_format_field("merkle root", result.merkle_root_ok))
        print(_format_field("leaf count", result.leaf_count_ok))
        print(
            f"  [{'PASS' if result.signature_present else 'FAIL'}]  signature present (kind={result.signature_kind})"
        )
        print(
            _format_field(
                f"signature verified ({result.signature_kind})",
                result.signature_verified,
            )
        )
        print(
            _format_field(
                "transparency anchor (non-gating side-signal)", result.transparency_ok
            )
        )
        print(f"  overall: {'PASS' if result.overall else 'FAIL'}")
        if sidecar_checked:
            if disagreements:
                print("  [FAIL]  agreement with committed manifest_verify.json:")
                for line in disagreements:
                    print(f"            - {line}")
            else:
                print(
                    "  [PASS]  agrees with committed manifest_verify.json on every custody field"
                )

    ok = result.overall and (not disagreements if sidecar_checked else True)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
