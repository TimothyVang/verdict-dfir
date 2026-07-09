"""Opt-in Sigstore Rekor transparency-log anchoring of the audit Merkle root.

This module publishes the run's audit-chain Merkle root to a public
transparency log so a third party can later prove *when* the sealed root
existed, independent of our servers. It is a strictly ADDITIVE custody
side-signal:

  * **Absent by default.** Anchoring only happens when the operator opts in
    with ``FINDEVIL_REKOR_ENABLE`` *and* the caller sets the per-call
    ``anchor_transparency`` flag. With the flag unset the manifest is
    byte-identical to today: no network is touched and no ``transparency_log``
    block is written.
  * **Never part of the signed body.** The block is attached *after* the
    manifest is signed and is excluded from the signed bytes (see
    ``manifest._to_json_safe`` / ``_verify_ed25519_signature``), so adding it
    cannot invalidate an existing Ed25519 signature.
  * **Non-gating.** ``verify_anchor`` reports a side-signal (``transparency_ok``)
    that never flips a manifest's ``overall`` custody verdict.

What leaves the host when anchoring fires is the bare 32-byte SHA-256 Merkle
root (a hash of hashes) — **no evidence text**, so the egress risk is low.
It is still gated opt-in per the project's fail-closed egress policy: a hash of
the sealed chain is metadata about the investigation, and publishing it is the
operator's decision, not a default.

Rekor submission is keyless (Fulcio/Rekor), so it needs an OIDC identity token
(``$SIGSTORE_ID_TOKEN``) and network at anchoring time. When Rekor is
unreachable (or no token is present) and ``allow_tsa_fallback`` is set, the root
digest is instead timestamped with an RFC-3161 Trusted Timestamp Authority via
``openssl ts``. On total failure the function returns an honest ``kind="none"``
block and NEVER raises into the run.
"""

from __future__ import annotations

import base64
import hashlib
import os
import subprocess  # only invokes the local `openssl` binary with fixed args, no shell
import tempfile
import urllib.request
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Constants.
# ---------------------------------------------------------------------------

_REKOR_ENABLE_ENV = "FINDEVIL_REKOR_ENABLE"
_ID_TOKEN_ENV = "SIGSTORE_ID_TOKEN"

_SUBJECT_NAME = "audit-merkle-root"
_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
_PREDICATE_TYPE = "https://verdict.dev/attestations/audit-merkle-root/v1"

# Public production Rekor + a public RFC-3161 TSA for the offline-time fallback.
_DEFAULT_REKOR_URL = "https://rekor.sigstore.dev"
_DEFAULT_TSA_URL = "https://freetsa.org/tsr"

_OPENSSL_TIMEOUT_S = 30


class RekorAnchorDisabledError(RuntimeError):
    """Transparency anchoring was requested but ``FINDEVIL_REKOR_ENABLE`` is unset.

    Fail-closed sibling of :class:`agentloop.factory.EvidenceEgressError`: a
    network action (Rekor/TSA submission) must not fire unless the operator has
    explicitly opted in.
    """


# ---------------------------------------------------------------------------
# Opt-in gate.
# ---------------------------------------------------------------------------


def rekor_enabled() -> bool:
    """True iff the operator opted into transparency anchoring via the env flag.

    Default (unset/empty/``0``/``false``/``no``/``off``) is OFF: no anchoring,
    no network.
    """
    val = os.environ.get(_REKOR_ENABLE_ENV, "").strip().lower()
    return val not in ("", "0", "false", "no", "off")


def require_rekor_enabled() -> None:
    """Raise :class:`RekorAnchorDisabledError` unless the env opt-in is set."""
    if not rekor_enabled():
        raise RekorAnchorDisabledError(
            "transparency anchoring requested but disabled; set "
            f"{_REKOR_ENABLE_ENV}=1 to opt in (publishes the bare SHA-256 Merkle "
            "root to a public transparency log — no evidence text)"
        )


# ---------------------------------------------------------------------------
# Anchor.
# ---------------------------------------------------------------------------


def anchor_merkle_root(
    merkle_root_hex: str,
    *,
    rekor_url: str | None = None,
    allow_tsa_fallback: bool = True,
) -> dict[str, Any] | None:
    """Anchor ``merkle_root_hex`` in a transparency log and return the block.

    Builds an in-toto DSSE Statement whose subject is the Merkle root, submits
    it to Rekor keylessly, and returns the structured ``transparency_log`` block.
    On Rekor failure (and ``allow_tsa_fallback``) it degrades to an RFC-3161
    ``openssl ts`` timestamp over the root digest. On total failure it returns a
    ``kind="none"`` block recording the reason — it NEVER raises into the run.

    This function assumes the opt-in gate already passed; callers wanting the
    fail-closed behaviour call :func:`require_rekor_enabled` first.
    """
    if not _is_sha256_hex(merkle_root_hex):
        return _none_block(
            merkle_root_hex,
            "merkle_root_hex is not a 64-char SHA-256 hex string; nothing to anchor",
        )

    effective_rekor_url = rekor_url or _DEFAULT_REKOR_URL
    try:
        entry, body_b64 = _submit_to_rekor(merkle_root_hex)
        return _rekor_block(merkle_root_hex, entry, body_b64, effective_rekor_url)
    except Exception as rekor_exc:  # degrade on ANY Rekor failure — never raise into the run
        rekor_reason = f"rekor anchoring failed: {rekor_exc}"
        if not allow_tsa_fallback:
            return _none_block(merkle_root_hex, rekor_reason)
        try:
            return _tsa_block(merkle_root_hex, _DEFAULT_TSA_URL, rekor_reason)
        except Exception as tsa_exc:  # the fallback must also never raise
            return _none_block(merkle_root_hex, f"{rekor_reason}; tsa fallback failed: {tsa_exc}")


def verify_anchor(block: dict[str, Any], merkle_root_hex: str) -> bool | str:
    """Offline-verify a ``transparency_log`` block against ``merkle_root_hex``.

    Pure/offline — contacts no network. Confirms the block's subject digest
    equals the manifest's Merkle root, then verifies the transparency evidence:
    a Rekor inclusion proof is re-derived from its embedded body/hashes/root
    (sigstore's own RFC-6962 verifier), and an RFC-3161 token is checked with
    ``openssl ts``. Returns ``True`` or an honest reason string. Never raises.
    """
    if not isinstance(block, dict):
        return "transparency_log block is not an object"
    subject = _subject_digest(block)
    if subject != merkle_root_hex:
        return (
            f"transparency subject digest {subject!r} != manifest merkle root "
            f"{merkle_root_hex!r}"
        )
    kind = block.get("kind")
    if kind == "none":
        return str(block.get("fallback_reason") or "root was not anchored")
    if kind == "rekor":
        return _verify_rekor_block(block)
    if kind == "rfc3161":
        return _verify_tsa_block(block, merkle_root_hex)
    return f"unknown transparency kind {kind!r}"


# ---------------------------------------------------------------------------
# Rekor path.
# ---------------------------------------------------------------------------


def _submit_to_rekor(merkle_root_hex: str) -> tuple[Any, str]:
    """Keyless-sign a DSSE Statement over the root and submit it to Rekor.

    Returns ``(log_entry, body_b64)``. Requires ``$SIGSTORE_ID_TOKEN`` and
    network — raises on any missing prerequisite so the caller can degrade.
    Isolated as a single function so tests can monkeypatch it without touching
    the live log.
    """
    from sigstore.oidc import IdentityToken  # type: ignore[import-not-found]
    from sigstore.sign import SigningContext  # type: ignore[import-not-found]

    token = os.environ.get(_ID_TOKEN_ENV)
    if not token:
        raise RuntimeError(
            f"no OIDC identity token in ${_ID_TOKEN_ENV}; keyless Rekor signing "
            "needs one (acquire via Sigstore's OIDC flow)"
        )

    statement = _build_statement(merkle_root_hex)
    ctx = SigningContext.production()
    identity = IdentityToken(token)
    with ctx.signer(identity) as signer:
        bundle = signer.sign_dsse(statement)
    entry = bundle.log_entry
    return entry, str(entry.body)


def _build_statement(merkle_root_hex: str) -> Any:
    """Build the in-toto DSSE Statement whose subject is the Merkle root."""
    from sigstore.dsse import StatementBuilder, Subject  # type: ignore[import-not-found]

    return StatementBuilder(
        subjects=[Subject(name=_SUBJECT_NAME, digest={"sha256": merkle_root_hex})],
        predicate_type=_PREDICATE_TYPE,
        predicate={
            "tool": "verdict-dfir",
            "note": "audit-chain Merkle root transparency anchor",
        },
    ).build()


def _rekor_block(merkle_root_hex: str, entry: Any, body_b64: str, rekor_url: str) -> dict[str, Any]:
    proof = entry.inclusion_proof
    return {
        "kind": "rekor",
        "anchored": True,
        "subject": {"merkle_root_sha256": merkle_root_hex},
        "statement_type": _STATEMENT_TYPE,
        "predicate_type": _PREDICATE_TYPE,
        "rekor": {
            "url": rekor_url,
            "log_id": entry.log_id,
            "log_index": entry.log_index,
            "integrated_time": entry.integrated_time,
            "entry_uuid": entry.uuid,
            # The canonical Rekor entry body — needed to recompute the RFC-6962
            # leaf hash during OFFLINE inclusion-proof verification.
            "body": body_b64,
            "inclusion_proof": {
                "checkpoint": _checkpoint_str(proof.checkpoint),
                "hashes": list(proof.hashes),
                "log_index": proof.log_index,
                "root_hash": proof.root_hash,
                "tree_size": proof.tree_size,
            },
        },
        "tsa": None,
        "fallback_reason": None,
    }


def _verify_rekor_block(block: dict[str, Any]) -> bool | str:
    rekor = block.get("rekor") or {}
    proof = rekor.get("inclusion_proof") or {}
    body = rekor.get("body")
    if not body:
        return "rekor block missing entry body; cannot verify inclusion proof offline"
    try:
        from sigstore.models import (  # type: ignore[import-not-found]
            LogEntry,
            LogInclusionProof,
            verify_merkle_inclusion,
        )

        inclusion = LogInclusionProof(
            checkpoint=str(proof.get("checkpoint") or ""),
            hashes=[str(h) for h in (proof.get("hashes") or [])],
            log_index=int(proof.get("log_index") or 0),
            root_hash=str(proof.get("root_hash") or ""),
            tree_size=int(proof.get("tree_size") or 0),
        )
        entry = LogEntry(
            uuid=(str(rekor["entry_uuid"]) if rekor.get("entry_uuid") else None),
            body=str(body),
            integrated_time=int(rekor.get("integrated_time") or 0),
            log_id=str(rekor.get("log_id") or ""),
            log_index=int(rekor.get("log_index") or proof.get("log_index") or 0),
            inclusion_proof=inclusion,
            inclusion_promise=None,
        )
        verify_merkle_inclusion(entry)
    except Exception as exc:  # honest reason, never a crash
        return f"rekor inclusion proof did not verify offline: {exc}"
    return True


# ---------------------------------------------------------------------------
# RFC-3161 TSA fallback (offline-time trust when Rekor is unreachable).
# ---------------------------------------------------------------------------


def _tsa_block(merkle_root_hex: str, tsa_url: str, fallback_reason: str) -> dict[str, Any]:
    """Countersign the root digest with an RFC-3161 timestamp via ``openssl ts``.

    Isolated so tests can monkeypatch :func:`_rfc3161_timestamp` (mock openssl /
    the TSA) or let it raise cleanly when ``openssl`` is absent.
    """
    tsr_b64 = _rfc3161_timestamp(merkle_root_hex, tsa_url)
    tsr_bytes = base64.b64decode(tsr_b64)
    return {
        "kind": "rfc3161",
        "anchored": True,
        "subject": {"merkle_root_sha256": merkle_root_hex},
        "statement_type": _STATEMENT_TYPE,
        "predicate_type": _PREDICATE_TYPE,
        "rekor": None,
        "tsa": {
            "kind": "rfc3161",
            "tsa_url": tsa_url,
            "tsr_b64": tsr_b64,
            # SHA-256 over the DER RFC-3161 token — a stable identifier for the
            # returned timestamp. Full issuing-CA-chain extraction is not done
            # here (the chain is not bundled), so this is a token fingerprint.
            "cert_chain_sha256": hashlib.sha256(tsr_bytes).hexdigest(),
        },
        "fallback_reason": fallback_reason,
    }


def _rfc3161_timestamp(merkle_root_hex: str, tsa_url: str) -> str:
    """Return a base64 RFC-3161 timestamp token over the root digest.

    Builds an ``openssl ts`` query over the SHA-256 imprint (the Merkle root is
    already a SHA-256 digest) and POSTs it to the TSA. Requires ``openssl`` +
    network; raises otherwise so the caller degrades to a ``none`` block.
    """
    if not _openssl_available():
        raise RuntimeError("openssl not found on PATH; cannot build an RFC-3161 token")
    with tempfile.TemporaryDirectory() as td:
        tsq = Path(td) / "request.tsq"
        _run_openssl(
            [
                "ts",
                "-query",
                "-digest",
                merkle_root_hex,
                "-sha256",
                "-cert",
                "-out",
                str(tsq),
            ]
        )
        tsr_bytes = _post_timestamp(tsa_url, tsq.read_bytes())
    return base64.b64encode(tsr_bytes).decode("ascii")


def _verify_tsa_block(block: dict[str, Any], merkle_root_hex: str) -> bool | str:
    """Offline-verify an RFC-3161 token: parse it and match the imprint digest.

    Uses ``openssl ts -reply`` to decode the stored token and confirm its hashed
    message imprint equals the Merkle root. Full TSA-signature verification needs
    the issuing CA chain (not bundled) — a documented residual — so this is a
    structural imprint check, honestly reported.
    """
    tsa = block.get("tsa") or {}
    tsr_b64 = tsa.get("tsr_b64")
    if not tsr_b64:
        return "rfc3161 block missing tsr_b64; nothing to verify"
    if not _openssl_available():
        return "rfc3161 timestamp present but openssl is unavailable to verify it offline"
    try:
        tsr_bytes = base64.b64decode(str(tsr_b64))
    except Exception as exc:
        return f"rfc3161 tsr_b64 is not valid base64: {exc}"
    try:
        with tempfile.TemporaryDirectory() as td:
            tsr = Path(td) / "response.tsr"
            tsr.write_bytes(tsr_bytes)
            text = _run_openssl(["ts", "-reply", "-in", str(tsr), "-text"])
    except Exception as exc:
        return f"rfc3161 token did not parse under openssl: {exc}"
    imprint = merkle_root_hex.lower()
    normalized = text.lower().replace(":", "").replace(" ", "").replace("\n", "")
    if imprint not in normalized:
        return (
            "rfc3161 token message imprint does not match the Merkle root "
            "(timestamp is over a different digest)"
        )
    return True


def _post_timestamp(tsa_url: str, request_bytes: bytes) -> bytes:
    # Fixed https TSA URL + RFC-3161 content type; only fires on the opt-in path.
    req = urllib.request.Request(
        tsa_url,
        data=request_bytes,
        headers={"Content-Type": "application/timestamp-query"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=_OPENSSL_TIMEOUT_S) as resp:
        return resp.read()


def _openssl_available() -> bool:
    try:
        # Fixed argv (no shell); `openssl` is a trusted local binary.
        subprocess.run(
            ["openssl", "version"],
            capture_output=True,
            check=True,
            timeout=_OPENSSL_TIMEOUT_S,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return True


def _run_openssl(args: list[str]) -> str:
    # Fixed argv (no shell); `openssl` is a trusted local binary.
    proc = subprocess.run(
        ["openssl", *args],
        capture_output=True,
        check=True,
        timeout=_OPENSSL_TIMEOUT_S,
    )
    return proc.stdout.decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------


def _none_block(merkle_root_hex: str, reason: str) -> dict[str, Any]:
    return {
        "kind": "none",
        "anchored": False,
        "subject": {"merkle_root_sha256": merkle_root_hex},
        "statement_type": _STATEMENT_TYPE,
        "predicate_type": _PREDICATE_TYPE,
        "rekor": None,
        "tsa": None,
        "fallback_reason": reason,
    }


def _subject_digest(block: dict[str, Any]) -> str | None:
    subject = block.get("subject")
    if not isinstance(subject, dict):
        return None
    val = subject.get("merkle_root_sha256")
    return str(val) if val is not None else None


def _checkpoint_str(checkpoint: Any) -> str:
    """Best-effort string form of a LogInclusionProof checkpoint (str or model)."""
    if checkpoint is None:
        return ""
    if isinstance(checkpoint, str):
        return checkpoint
    for attr in ("signed_note", "note"):
        inner = getattr(checkpoint, attr, None)
        if isinstance(inner, str):
            return inner
    return str(checkpoint)


def _is_sha256_hex(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        bytes.fromhex(value)
    except ValueError:
        return False
    return True


__all__ = [
    "RekorAnchorDisabledError",
    "anchor_merkle_root",
    "rekor_enabled",
    "require_rekor_enabled",
    "verify_anchor",
]
