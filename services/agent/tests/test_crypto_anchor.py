"""Tests for findevil_agent.crypto.anchor — opt-in Rekor transparency anchoring.

Never contacts the live Rekor log or a TSA: ``_submit_to_rekor`` and
``_rfc3161_timestamp`` are monkeypatched so the anchoring logic (block shape,
fallback ladder, offline verification) is exercised fully offline. Offline
verification uses a GENUINE minimal single-leaf RFC-6962 inclusion proof, so
``verify_anchor`` runs the real sigstore verifier — not a stub.
"""

from __future__ import annotations

import base64
import hashlib
from types import SimpleNamespace

import pytest

from findevil_agent.crypto import anchor

_ROOT = "ab" * 32  # a valid 64-char SHA-256 hex string


def _statement_body(merkle_root_hex: str) -> bytes:
    """Canonical DSSE in-toto Statement bytes for the given root."""
    return anchor._build_statement(merkle_root_hex)._contents


def _single_leaf_root(body: bytes) -> str:
    """RFC-6962 leaf hash of ``body`` = the Merkle root of a size-1 tree."""
    return hashlib.sha256(b"\x00" + body).hexdigest()


def _fake_entry(merkle_root_hex: str):
    """A fake Rekor ``LogEntry`` whose single-leaf inclusion proof genuinely
    verifies offline. Returns ``(entry, body_b64)`` like ``_submit_to_rekor``."""
    body = _statement_body(merkle_root_hex)
    body_b64 = base64.b64encode(body).decode("ascii")
    root_hex = _single_leaf_root(body)
    proof = SimpleNamespace(
        checkpoint="rekor.sigstore.dev - 000\n1\n<root>\n",
        hashes=[],
        log_index=0,
        root_hash=root_hex,
        tree_size=1,
    )
    entry = SimpleNamespace(
        uuid="deadbeefcafef00d",
        body=body_b64,
        integrated_time=1_700_000_000,
        log_id="c0ffee",
        log_index=0,
        inclusion_proof=proof,
    )
    return entry, body_b64


class TestOptInGate:
    def test_disabled_by_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("FINDEVIL_REKOR_ENABLE", raising=False)
        assert anchor.rekor_enabled() is False
        with pytest.raises(anchor.RekorAnchorDisabledError):
            anchor.require_rekor_enabled()

    @pytest.mark.parametrize("val", ["", "0", "false", "no", "off"])
    def test_falsey_values_stay_disabled(self, monkeypatch: pytest.MonkeyPatch, val: str) -> None:
        monkeypatch.setenv("FINDEVIL_REKOR_ENABLE", val)
        assert anchor.rekor_enabled() is False

    @pytest.mark.parametrize("val", ["1", "true", "yes", "on"])
    def test_truthy_values_enable(self, monkeypatch: pytest.MonkeyPatch, val: str) -> None:
        monkeypatch.setenv("FINDEVIL_REKOR_ENABLE", val)
        assert anchor.rekor_enabled() is True
        anchor.require_rekor_enabled()  # must not raise


class TestAnchorMerkleRoot:
    def test_rekor_block_shape(self, monkeypatch: pytest.MonkeyPatch) -> None:
        entry, body_b64 = _fake_entry(_ROOT)
        monkeypatch.setattr(anchor, "_submit_to_rekor", lambda root: (entry, body_b64))

        block = anchor.anchor_merkle_root(_ROOT)

        assert block is not None
        assert block["kind"] == "rekor"
        assert block["anchored"] is True
        assert block["subject"]["merkle_root_sha256"] == _ROOT
        assert block["statement_type"] == "https://in-toto.io/Statement/v1"
        assert block["predicate_type"].endswith("/audit-merkle-root/v1")
        rekor = block["rekor"]
        assert rekor["entry_uuid"] == "deadbeefcafef00d"
        assert rekor["log_index"] == 0
        assert rekor["body"] == body_b64
        ip = rekor["inclusion_proof"]
        assert ip["tree_size"] == 1
        assert ip["root_hash"] == _single_leaf_root(_statement_body(_ROOT))
        assert block["tsa"] is None
        assert block["fallback_reason"] is None

    def test_invalid_root_returns_none_block(self) -> None:
        block = anchor.anchor_merkle_root("not-a-sha256")
        assert block is not None
        assert block["kind"] == "none"
        assert block["anchored"] is False
        assert "not a 64-char SHA-256" in block["fallback_reason"]

    def test_tsa_fallback_on_rekor_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _boom(root: str):
            raise RuntimeError("fulcio/rekor unreachable")

        canned_tsr = base64.b64encode(b"fake-rfc3161-token").decode("ascii")
        monkeypatch.setattr(anchor, "_submit_to_rekor", _boom)
        monkeypatch.setattr(anchor, "_rfc3161_timestamp", lambda root, tsa_url: canned_tsr)

        block = anchor.anchor_merkle_root(_ROOT)

        assert block is not None
        assert block["kind"] == "rfc3161"
        assert block["anchored"] is True
        assert block["rekor"] is None
        assert block["tsa"]["tsr_b64"] == canned_tsr
        assert block["tsa"]["kind"] == "rfc3161"
        assert "rekor anchoring failed" in block["fallback_reason"]

    def test_no_tsa_fallback_when_disabled(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _boom(root: str):
            raise RuntimeError("rekor down")

        monkeypatch.setattr(anchor, "_submit_to_rekor", _boom)
        block = anchor.anchor_merkle_root(_ROOT, allow_tsa_fallback=False)

        assert block is not None
        assert block["kind"] == "none"
        assert block["anchored"] is False
        assert "rekor down" in block["fallback_reason"]

    def test_total_failure_returns_none_block_never_raises(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def _boom_rekor(root: str):
            raise RuntimeError("rekor down")

        def _boom_tsa(root: str, tsa_url: str):
            raise RuntimeError("openssl missing")

        monkeypatch.setattr(anchor, "_submit_to_rekor", _boom_rekor)
        monkeypatch.setattr(anchor, "_rfc3161_timestamp", _boom_tsa)

        block = anchor.anchor_merkle_root(_ROOT)

        assert block is not None
        assert block["kind"] == "none"
        assert block["anchored"] is False
        assert "rekor down" in block["fallback_reason"]
        assert "tsa fallback failed" in block["fallback_reason"]


class TestVerifyAnchor:
    def _good_block(self, monkeypatch: pytest.MonkeyPatch, root: str = _ROOT) -> dict:
        entry, body_b64 = _fake_entry(root)
        monkeypatch.setattr(anchor, "_submit_to_rekor", lambda r: (entry, body_b64))
        block = anchor.anchor_merkle_root(root)
        assert block is not None
        return block

    def test_accepts_good_rekor_block(self, monkeypatch: pytest.MonkeyPatch) -> None:
        block = self._good_block(monkeypatch)
        # Real sigstore RFC-6962 inclusion verification over the embedded body.
        assert anchor.verify_anchor(block, _ROOT) is True

    def test_rejects_subject_root_mismatch(self, monkeypatch: pytest.MonkeyPatch) -> None:
        block = self._good_block(monkeypatch)
        result = anchor.verify_anchor(block, "ff" * 32)
        assert result is not True
        assert "subject digest" in str(result)

    def test_rejects_corrupted_inclusion_proof(self, monkeypatch: pytest.MonkeyPatch) -> None:
        block = self._good_block(monkeypatch)
        # Flip the declared root_hash so the inclusion proof no longer chains.
        block["rekor"]["inclusion_proof"]["root_hash"] = "ff" * 32
        result = anchor.verify_anchor(block, _ROOT)
        assert result is not True
        assert "inclusion proof did not verify" in str(result)

    def test_rejects_missing_body(self, monkeypatch: pytest.MonkeyPatch) -> None:
        block = self._good_block(monkeypatch)
        block["rekor"]["body"] = None
        result = anchor.verify_anchor(block, _ROOT)
        assert result is not True
        assert "missing entry body" in str(result)

    def test_none_kind_block_reports_reason(self) -> None:
        block = anchor.anchor_merkle_root("not-a-sha256")
        assert block is not None
        # subject digest for a none block is the (invalid) root string itself.
        result = anchor.verify_anchor(block, "not-a-sha256")
        assert result is not True
        assert "not a 64-char SHA-256" in str(result)
