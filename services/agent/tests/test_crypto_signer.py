"""Tests for findevil_agent.crypto.signer.

We never call sigstore.sign in these tests — the StubSigner path
exercises the bundle shape + integration with audit_log without
network. SigstoreSigner is unit-tested only for its lazy-import
guard since the real signing path requires Fulcio/Rekor.
"""

from __future__ import annotations

import base64
import json

import pytest

from findevil_agent.crypto.signer import (
    FallbackSigner,
    SignedBundle,
    SigstoreSigner,
    StubSigner,
    make_signer,
)


class TestSignerKind:
    def test_stub_bundle_kind_is_stub(self) -> None:
        b = StubSigner(run_id="k1").sign(b"x")
        assert b.kind == "stub"
        assert b.fallback_reason is None


class _BoomSigner:
    """A signer whose sign() always raises — stands in for an unreachable
    Fulcio/Rekor (no $SIGSTORE_ID_TOKEN, no network)."""

    def sign(self, payload: bytes) -> SignedBundle:
        raise RuntimeError("fulcio unreachable")


class TestFallbackSigner:
    def test_falls_back_to_stub_and_records_reason(self) -> None:
        signer = FallbackSigner(_BoomSigner(), StubSigner(run_id="fb"))
        b = signer.sign(b'{"a":1}')
        assert b.kind == "stub"
        assert b.fallback_reason
        assert "fulcio unreachable" in b.fallback_reason

    def test_primary_success_passes_through_unchanged(self) -> None:
        primary = StubSigner(run_id="primary")  # stand-in success path
        signer = FallbackSigner(primary, StubSigner(run_id="never"))
        b = signer.sign(b"x")
        assert b.fallback_reason is None


class TestStubSigner:
    def test_sign_produces_bundle(self) -> None:
        s = StubSigner(run_id="r1")
        b = s.sign(b'{"foo":1}')
        assert isinstance(b, SignedBundle)
        # SHA-256 hex is 64 chars.
        assert len(b.payload_sha256) == 64
        assert len(b.cert_fingerprint) == 64
        # Base64 round-trips to JSON bundle.
        bundle_obj = json.loads(b.raw_bundle_json)
        assert bundle_obj["kind"] == "stub"
        assert bundle_obj["run_id"] == "r1"
        assert bundle_obj["seq"] == 1

    def test_seq_increments(self) -> None:
        s = StubSigner(run_id="r2")
        b1 = s.sign(b"a")
        b2 = s.sign(b"b")
        b3 = s.sign(b"a")  # same payload, different seq
        assert b1.cert_fingerprint != b2.cert_fingerprint
        assert b1.cert_fingerprint != b3.cert_fingerprint
        # payload_sha256 is deterministic across reuses.
        assert b1.payload_sha256 == b3.payload_sha256

    def test_two_runs_with_same_run_id_seq_diverges(self) -> None:
        # Different StubSigner instances start fresh — seq doesn't
        # cross instances. This documents that StubSigner is
        # per-run, not per-process.
        s1 = StubSigner(run_id="rx")
        s2 = StubSigner(run_id="rx")
        b1 = s1.sign(b"x")
        b2 = s2.sign(b"x")
        # cert_fingerprint depends only on (run_id, seq). Both
        # should be seq=1, so identical fingerprints.
        assert b1.cert_fingerprint == b2.cert_fingerprint

    def test_bundle_b64_decodes(self) -> None:
        s = StubSigner(run_id="r3")
        b = s.sign(b"data")
        decoded = base64.b64decode(b.bundle_b64).decode("utf-8")
        assert "stub" in decoded


class TestSignedBundleRawProperty:
    def test_raw_bundle_json_round_trip(self) -> None:
        b = SignedBundle(
            payload_sha256="a" * 64,
            bundle_b64=base64.b64encode(b'{"x":1}').decode("ascii"),
            cert_fingerprint="b" * 64,
            signed_at="2026-04-24T00:00:00Z",
        )
        assert b.raw_bundle_json == '{"x":1}'


class TestMakeSigner:
    def test_default_is_stub(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("FINDEVIL_SIGNER", raising=False)
        s = make_signer()
        assert isinstance(s, StubSigner)

    def test_explicit_stub(self) -> None:
        s = make_signer(kind="stub")
        assert isinstance(s, StubSigner)

    def test_explicit_sigstore_returns_real(self) -> None:
        s = make_signer(kind="sigstore")
        assert isinstance(s, SigstoreSigner)

    def test_unknown_kind_raises(self) -> None:
        with pytest.raises(ValueError):
            make_signer(kind="bogus")

    def test_env_override_resolves(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("FINDEVIL_SIGNER", "sigstore")
        s = make_signer()
        assert isinstance(s, SigstoreSigner)

    def test_sigstore_picks_up_ambient_id_token(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SIGSTORE_ID_TOKEN", "ambient-oidc-token")
        s = make_signer(kind="sigstore")
        assert isinstance(s, SigstoreSigner)
        assert s._identity_token == "ambient-oidc-token"

    def test_explicit_token_overrides_ambient(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SIGSTORE_ID_TOKEN", "ambient")
        s = make_signer(kind="sigstore", identity_token="explicit")
        assert isinstance(s, SigstoreSigner)
        assert s._identity_token == "explicit"


class TestSigstoreSignerLazyImport:
    def test_sign_without_sigstore_installed_raises(self) -> None:
        # We can't fully test the production sigstore path without
        # a live Fulcio/Rekor, but we can assert the lazy-import
        # guard works: calling sign() without a token surfaces a
        # helpful error before any network call would happen.
        s = SigstoreSigner(identity_token=None)
        with pytest.raises(RuntimeError) as exc:
            s.sign(b"x")
        msg = str(exc.value)
        assert "sigstore-python is not installed" in msg or "identity_token" in msg
