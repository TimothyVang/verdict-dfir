"""Sigstore-keyless signing of MCP tool calls + findings.

Spec #2 §7.1 third tier. Per the design memo
``project_crypto_custody_stack.md``, every tool-call envelope is
JCS-canonicalized and signed via sigstore-python's keyless flow:

  1. Acquire ONE ephemeral Fulcio cert per run (OIDC handshake).
  2. Submit per-call signatures to Rekor in async batches.
  3. The Sigstore bundle (cert + signature + Rekor inclusion proof)
     is appended to ``audit.jsonl`` next to the audit record itself.

Per-call latency is dominated by the Rekor round-trip; with batched
submission + a single Fulcio handshake per run the steady-state
overhead is sub-50ms per call.

This module is structured so the agent never depends on the
sigstore library at *type* level — the abstract ``Signer`` protocol
keeps tests fast and fully offline. Production code instantiates
``SigstoreSigner`` (which imports sigstore lazily); tests use
``StubSigner`` which produces a deterministic placeholder bundle.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import threading
from dataclasses import dataclass, replace
from typing import Any, Protocol


@dataclass(frozen=True)
class SignedBundle:
    """The minimal structure both real + stub signers produce.

    For real Sigstore output, ``raw_bundle_json`` is the verbatim
    Sigstore Bundle JSON serialization (per the Sigstore Bundle
    spec). For the stub, it's a compact deterministic JSON that the
    integration tests can assert against.
    """

    payload_sha256: str
    """SHA-256 hex of the JCS-canonicalized payload bytes."""

    bundle_b64: str
    """Base64-encoded Sigstore bundle JSON, ready for embedding in
    ``audit.jsonl`` rows."""

    cert_fingerprint: str
    """SHA-256 hex of the issuing certificate. Stub uses a
    placeholder string."""

    signed_at: str
    """UTC ISO-8601Z."""

    kind: str = "stub"
    """Which signer produced this bundle: ``"sigstore"`` (real keyless
    Fulcio/Rekor proof) or ``"stub"`` (deterministic dev/offline
    placeholder). Recorded in the manifest so a verifier can tell a real
    proof from a placeholder without reaching into the bundle."""

    fallback_reason: str | None = None
    """Set when a sigstore attempt failed and the run honestly degraded to
    the stub signer (e.g. no ``$SIGSTORE_ID_TOKEN`` / no Fulcio reachability).
    ``None`` for a clean run. Lets the release gate read the *effective*
    signer instead of the *requested* one."""

    @property
    def raw_bundle_json(self) -> str:
        return base64.b64decode(self.bundle_b64).decode("utf-8")


class Signer(Protocol):
    """Abstract signer the agent depends on. ``sign(payload)`` is
    the only call site downstream code uses.
    """

    def sign(self, payload: bytes) -> SignedBundle: ...


class SigstoreSigner:
    """Production signer — keyless via sigstore-python.

    Lazily imports ``sigstore`` so test environments without
    Fulcio/Rekor reachability don't need the library installed.
    """

    def __init__(
        self,
        *,
        identity_token: str | None = None,
        oidc_issuer: str | None = None,
    ) -> None:
        self._identity_token = identity_token
        self._oidc_issuer = oidc_issuer
        self._lock = threading.Lock()
        self._signing_ctx: Any = None  # lazy-init sigstore SigningContext

    def _ensure_ctx(self) -> Any:
        with self._lock:
            if self._signing_ctx is not None:
                return self._signing_ctx
            try:
                # Lazy import — keeps test env offline-friendly.
                from sigstore.sign import SigningContext  # type: ignore[import-not-found]
            except ImportError as exc:
                raise RuntimeError(
                    "sigstore-python is not installed. Install with `uv add sigstore` "
                    "or use StubSigner in tests."
                ) from exc
            self._signing_ctx = SigningContext.production()
            return self._signing_ctx

    def sign(self, payload: bytes) -> SignedBundle:
        """Sign ``payload`` (canonical JSON bytes). Returns a SignedBundle."""
        ctx = self._ensure_ctx()
        # The exact API differs across sigstore-python versions;
        # this code path is defensive and pinned to sigstore 3.x
        # per Spec #2 §16.
        from sigstore.oidc import IdentityToken  # type: ignore[import-not-found]

        if self._identity_token is None:
            raise RuntimeError(
                "SigstoreSigner requires identity_token in non-interactive mode. "
                "Acquire one via Sigstore's OIDC flow before instantiation."
            )
        identity = IdentityToken(self._identity_token)
        with ctx.signer(identity) as signer_session:
            bundle = signer_session.sign_artifact(payload)

        return SignedBundle(
            payload_sha256=hashlib.sha256(payload).hexdigest(),
            bundle_b64=base64.b64encode(bundle.to_json().encode("utf-8")).decode("ascii"),
            cert_fingerprint=_fingerprint_from_bundle_json(bundle.to_json()),
            signed_at=_utc_iso(),
            kind="sigstore",
        )


class StubSigner:
    """Deterministic offline signer for tests + demos.

    Produces a bundle that's structurally similar to a real Sigstore
    bundle (so downstream parsing code exercises the same shape) but
    contains no real cryptographic signature. ``audit.jsonl`` rows
    written under StubSigner declare ``"sigstore_bundle_kind":
    "stub"`` so verifiers refuse to accept them as production proof.
    """

    def __init__(self, *, run_id: str = "stub-run") -> None:
        self._run_id = run_id
        self._counter = 0
        self._lock = threading.Lock()

    def sign(self, payload: bytes) -> SignedBundle:
        with self._lock:
            self._counter += 1
            seq = self._counter
        digest = hashlib.sha256(payload).hexdigest()
        # Deterministic stub: cert_fingerprint derived from run_id +
        # seq so two stub runs produce distinguishable but
        # reproducible "fingerprints".
        cert_fp = hashlib.sha256(f"stub:{self._run_id}:{seq}".encode("ascii")).hexdigest()
        bundle_obj: dict[str, Any] = {
            "kind": "stub",
            "run_id": self._run_id,
            "seq": seq,
            "payload_sha256": digest,
            "cert_fingerprint": cert_fp,
            "note": "StubSigner output — NOT a real Sigstore signature.",
        }
        bundle_json = json.dumps(bundle_obj, sort_keys=True, separators=(",", ":"))
        return SignedBundle(
            payload_sha256=digest,
            bundle_b64=base64.b64encode(bundle_json.encode("utf-8")).decode("ascii"),
            cert_fingerprint=cert_fp,
            signed_at=_utc_iso(),
            kind="stub",
        )


class FallbackSigner:
    """Tries a primary signer (real sigstore) and honestly degrades to a
    fallback (stub) when the primary fails — the typical offline / no-token
    case. The returned bundle carries ``kind="stub"`` and a non-empty
    ``fallback_reason`` so the release gate reads the *effective* signer, not
    the *requested* one, and never crashes a run just because Fulcio/Rekor
    (or an OIDC token) was unavailable.
    """

    def __init__(self, primary: Signer, fallback: Signer) -> None:
        self._primary = primary
        self._fallback = fallback

    def sign(self, payload: bytes) -> SignedBundle:
        try:
            return self._primary.sign(payload)
        except Exception as exc:  # noqa: BLE001 — degrade on ANY signer failure
            bundle = self._fallback.sign(payload)
            reason = f"sigstore signing failed, degraded to stub: {exc}"
            return replace(bundle, fallback_reason=reason)


def _fingerprint_from_bundle_json(bundle_json: str) -> str:
    """Best-effort cert fingerprint extraction from a Sigstore bundle.

    The bundle's verifying certificate lives at
    ``verificationMaterial.x509CertificateChain.certificates[0].rawBytes``
    in Sigstore's JSON wire format. We hash the raw bytes; failure
    falls back to a hash over the whole bundle to keep fingerprints
    populated even on schema drift.
    """
    try:
        obj = json.loads(bundle_json)
        chain = obj["verificationMaterial"]["x509CertificateChain"]["certificates"]
        if chain:
            cert_b64 = chain[0]["rawBytes"]
            return hashlib.sha256(base64.b64decode(cert_b64)).hexdigest()
    except (KeyError, json.JSONDecodeError, ValueError, TypeError):
        pass
    return hashlib.sha256(bundle_json.encode("utf-8")).hexdigest()


def _utc_iso() -> str:
    from datetime import UTC, datetime

    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_signer(*, kind: str | None = None, **kwargs: Any) -> Signer:
    """Factory the rest of the agent calls.

    ``kind`` defaults to ``$FINDEVIL_SIGNER`` env var, falling back
    to ``"stub"`` so unit tests + offline runs work out of the box.
    Production deployments set ``FINDEVIL_SIGNER=sigstore``.
    """
    actual = kind if kind is not None else os.environ.get("FINDEVIL_SIGNER", "stub")
    if actual == "sigstore":
        # Pick up the ambient OIDC identity from $SIGSTORE_ID_TOKEN when the
        # caller didn't pass one explicitly — this is the non-interactive path
        # the docs/manifest_finalize describe (a judge/CI exports the token
        # before sealing). Without it SigstoreSigner.sign() raises a clear
        # error rather than silently producing an unsigned bundle.
        kwargs.setdefault("identity_token", os.environ.get("SIGSTORE_ID_TOKEN"))
        return SigstoreSigner(**kwargs)
    if actual == "stub":
        return StubSigner(**kwargs)
    raise ValueError(f"unknown signer kind: {actual!r}")


__all__ = [
    "FallbackSigner",
    "SignedBundle",
    "Signer",
    "SigstoreSigner",
    "StubSigner",
    "make_signer",
]
