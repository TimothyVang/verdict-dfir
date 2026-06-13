"""Manifest signer implementations.

The custody stack signs the canonicalized run manifest after the
hash-chained audit log and Merkle root are built. The default signer is
``LocalEd25519Signer``: a real local keypair whose signature verifies
offline from data embedded in ``run.manifest.json``. ``SigstoreSigner`` is
the customer-release identity/transparency tier when an OIDC token and
network access are available. ``StubSigner`` is explicit test/demo fallback
only and never cryptographic proof.

This module is structured so the agent never depends on the sigstore
library at import time — the abstract ``Signer`` protocol keeps tests fast
and fully offline, and Sigstore imports lazily only when requested.
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
    """The minimal structure all signers produce.

    For Sigstore output, ``raw_bundle_json`` is the verbatim Sigstore Bundle
    JSON serialization. For Ed25519, it is a compact JSON object containing
    the public key and signature. For the stub, it is deterministic placeholder
    JSON that integration tests can assert against.
    """

    payload_sha256: str
    """SHA-256 hex of the JCS-canonicalized payload bytes."""

    bundle_b64: str
    """Base64-encoded signer bundle JSON, ready for embedding in the
    manifest."""

    cert_fingerprint: str
    """SHA-256 hex of the Sigstore certificate or Ed25519 public key. Stub
    uses a placeholder string."""

    signed_at: str
    """UTC ISO-8601Z."""

    kind: str = "stub"
    """Which signer produced this bundle: ``"ed25519"`` (offline-verifiable
    local signature), ``"sigstore"`` (keyless Fulcio/Rekor proof), or
    ``"stub"`` (deterministic dev/offline placeholder). Recorded in the
    manifest so a verifier can tell a real proof from a placeholder without
    reaching into the bundle."""

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
    written under StubSigner declare ``kind="stub"`` in the manifest
    signature bundle so verifiers refuse to accept them as production proof.
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


class LocalEd25519Signer:
    """Real local-keypair signer — the offline default tier.

    Signs the canonical payload bytes with an Ed25519 private key kept at a
    stable local path (``~/.findevil/signing.key`` unless overridden via
    ``FINDEVIL_SIGNING_KEY`` or the ``key_path`` argument). The key is
    auto-generated on first use (dir 0o700, file 0o600). The bundle embeds the
    public key, so ``manifest_verify`` can cryptographically verify the
    signature OFFLINE — unlike the stub (a placeholder, never proof) and
    unlike sigstore (which adds identity + a transparency log but needs an
    OIDC token and network at signing time).

    This proves *integrity and local key continuity*, not *identity*: the
    customer-release gate still requires sigstore.
    """

    def __init__(self, key_path: os.PathLike[str] | str | None = None) -> None:
        from pathlib import Path

        self._key_path = Path(key_path) if key_path is not None else _default_key_path()
        self._lock = threading.Lock()
        self._private_key: Any = None  # lazy Ed25519PrivateKey

    def _ensure_key(self) -> Any:
        with self._lock:
            if self._private_key is not None:
                return self._private_key
            # Lazy import — cryptography ships as a sigstore dependency, but
            # keep module import time free of it for offline-light callers.
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            from cryptography.hazmat.primitives.serialization import (
                Encoding,
                NoEncryption,
                PrivateFormat,
                load_pem_private_key,
            )

            if self._key_path.exists():
                self._private_key = load_pem_private_key(self._key_path.read_bytes(), password=None)
            else:
                key = Ed25519PrivateKey.generate()
                self._key_path.parent.mkdir(parents=True, exist_ok=True)
                os.chmod(self._key_path.parent, 0o700)
                pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
                # Write owner-only: create with 0o600 before the bytes land.
                fd = os.open(self._key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "wb") as fh:
                    fh.write(pem)
                self._private_key = key
            return self._private_key

    def sign(self, payload: bytes) -> SignedBundle:
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
        )

        key = self._ensure_key()
        digest = hashlib.sha256(payload).hexdigest()
        signature = key.sign(payload)
        public_raw = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        cert_fp = hashlib.sha256(public_raw).hexdigest()
        bundle_obj: dict[str, Any] = {
            "kind": "ed25519",
            "public_key_b64": base64.b64encode(public_raw).decode("ascii"),
            "signature_b64": base64.b64encode(signature).decode("ascii"),
            "payload_sha256": digest,
            "cert_fingerprint": cert_fp,
        }
        bundle_json = json.dumps(bundle_obj, sort_keys=True, separators=(",", ":"))
        return SignedBundle(
            payload_sha256=digest,
            bundle_b64=base64.b64encode(bundle_json.encode("utf-8")).decode("ascii"),
            cert_fingerprint=cert_fp,
            signed_at=_utc_iso(),
            kind="ed25519",
        )


def _default_key_path() -> Any:
    from pathlib import Path

    env = os.environ.get("FINDEVIL_SIGNING_KEY")
    if env:
        return Path(env)
    return Path.home() / ".findevil" / "signing.key"


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
        except Exception as exc:  # degrade on ANY primary-signer failure
            bundle = self._fallback.sign(payload)
            reason = f"primary signer failed, degraded to {bundle.kind}: {exc}"
            if bundle.fallback_reason:  # nested fallback — keep the inner story
                reason = f"{reason} (after: {bundle.fallback_reason})"
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

    ``kind`` defaults to ``$FINDEVIL_SIGNER`` env var, falling back to
    ``"ed25519"`` — a REAL local signature that verifies offline — so every
    run is cryptographically signed out of the box. ``"stub"`` (a placeholder,
    never proof) is explicit opt-in only. Production deployments set
    ``FINDEVIL_SIGNER=sigstore`` for identity + transparency-log tier.
    """
    actual = kind if kind is not None else os.environ.get("FINDEVIL_SIGNER", "ed25519")
    if actual == "sigstore":
        # Pick up the ambient OIDC identity from $SIGSTORE_ID_TOKEN when the
        # caller didn't pass one explicitly — this is the non-interactive path
        # the docs/manifest_finalize describe (a judge/CI exports the token
        # before sealing). Without it SigstoreSigner.sign() raises a clear
        # error rather than silently producing an unsigned bundle.
        kwargs.setdefault("identity_token", os.environ.get("SIGSTORE_ID_TOKEN"))
        return SigstoreSigner(**kwargs)
    if actual == "ed25519":
        return LocalEd25519Signer(**kwargs)
    if actual == "stub":
        return StubSigner(**kwargs)
    raise ValueError(f"unknown signer kind: {actual!r}")


__all__ = [
    "FallbackSigner",
    "LocalEd25519Signer",
    "SignedBundle",
    "Signer",
    "SigstoreSigner",
    "StubSigner",
    "make_signer",
]
