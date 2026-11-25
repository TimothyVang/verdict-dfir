"""Tests for findevil_agent.crypto.manifest — the M2 integration layer."""

from __future__ import annotations

import json
from pathlib import Path

from findevil_agent.crypto.audit_log import AuditLog
from findevil_agent.crypto.manifest import (
    MANIFEST_VERSION,
    ManifestLeaf,
    build_manifest,
    verify_manifest,
    write_manifest,
)
from findevil_agent.crypto.signer import StubSigner


def _seed_log(path: Path) -> AuditLog:
    log = AuditLog(path)
    log.append("tool_call_start", {"tool_call_id": "tc-1", "tool": "evtx_query"})
    log.append(
        "tool_call_output",
        {"tool_call_id": "tc-1", "output_hash": "a" * 64, "row_count": 42},
    )
    log.append("agent_message", {"role": "supervisor", "content": "investigating"})
    log.append("tool_call_start", {"tool_call_id": "tc-2", "tool": "mft_timeline"})
    log.append(
        "tool_call_output",
        {"tool_call_id": "tc-2", "output_hash": "b" * 64, "row_count": 12},
    )
    log.append(
        "finding_approved",
        {"finding_id": "f-1", "tool_call_id": "tc-1", "confidence": "CONFIRMED"},
    )
    log.append(
        "finding_approved",
        {"finding_id": "f-2", "tool_call_id": "tc-2", "confidence": "INFERRED"},
    )
    return log


class TestBuildManifest:
    def test_full_round_trip(self, tmp_path: Path) -> None:
        log = _seed_log(tmp_path / "audit.jsonl")
        signer = StubSigner(run_id="rt-1")

        manifest = build_manifest(
            case_id="case-001",
            run_id="rt-1",
            started_at="2026-04-24T00:00:00Z",
            audit_log=log,
            signer=signer,
            extra={"image_path": "/tmp/case.e01", "model": "claude-sonnet"},
        )

        # Manifest shape.
        assert manifest.version == MANIFEST_VERSION
        assert manifest.case_id == "case-001"
        assert manifest.run_id == "rt-1"
        assert manifest.audit_log_record_count == 7
        assert len(manifest.leaves) == 4  # 2 tool_call_outputs + 2 findings
        assert all(isinstance(leaf, ManifestLeaf) for leaf in manifest.leaves)
        # Tool-output leaves use the declared output_hash.
        tool_leaves = [leaf for leaf in manifest.leaves if leaf.kind == "tool_call_output"]
        assert len(tool_leaves) == 2
        assert tool_leaves[0].digest_hex == "a" * 64
        assert tool_leaves[1].digest_hex == "b" * 64
        # Finding leaves digest the canonicalized record.
        finding_leaves = [leaf for leaf in manifest.leaves if leaf.kind == "finding"]
        assert len(finding_leaves) == 2
        for leaf in finding_leaves:
            assert len(leaf.digest_hex) == 64
        # Signature attached.
        assert manifest.signature["bundle_b64"]
        assert len(manifest.signature["payload_sha256"]) == 64
        # Extra preserved.
        assert manifest.extra["model"] == "claude-sonnet"

    def test_zero_findings_zero_outputs_yields_empty_tree(self, tmp_path: Path) -> None:
        log = AuditLog(tmp_path / "audit.jsonl")
        log.append("agent_message", {"role": "supervisor", "content": "starting"})
        log.append("plan_proposed", {"plan_steps": ["s1"]})

        manifest = build_manifest(
            case_id="case-002",
            run_id="empty-1",
            started_at="2026-04-24T00:00:00Z",
            audit_log=log,
            signer=StubSigner(run_id="empty-1"),
        )
        assert manifest.leaf_count == 0
        # Empty Merkle root is 64 zeros.
        assert manifest.merkle_root_hex == "00" * 32

    def test_memory_kinds_never_become_leaves(self, tmp_path: Path) -> None:
        # G3 regression guard (the "memory is never evidence" invariant):
        # memory_recall / memory_remember records are hash-chained process
        # provenance but must NEVER be Merkle evidence leaves. If anyone later
        # adds these kinds to build_manifest's leaf selection, this fails loudly.
        log = AuditLog(tmp_path / "audit.jsonl")
        log.append("tool_call_output", {"tool_call_id": "tc-1", "output_hash": "a" * 64})
        log.append(
            "finding_approved",
            {"finding_id": "f-1", "tool_call_id": "tc-1", "confidence": "CONFIRMED"},
        )
        log.append(
            "memory_recall",
            {
                "query": "T1014",
                "kind": None,
                "hit_count": 1,
                "hits": [{"case_id": "c-prev", "ts": "2026-01-01T00:00:00Z", "confidence": 0.8}],
            },
        )
        log.append(
            "memory_remember",
            {
                "case_id": "c-1",
                "kind": "finding_summary",
                "key": "T1014",
                "sha256": "sha256:" + "b" * 64,
            },
        )

        manifest = build_manifest(
            case_id="c-1",
            run_id="r-1",
            started_at="2026-01-01T00:00:00Z",
            audit_log=log,
            signer=StubSigner(run_id="r-1"),
        )
        # Only the tool_call_output + the finding become leaves.
        assert manifest.leaf_count == 2
        assert {leaf.kind for leaf in manifest.leaves} == {"tool_call_output", "finding"}
        assert all(
            leaf.kind not in ("memory_recall", "memory_remember") for leaf in manifest.leaves
        )

    def test_audit_log_final_hash_links_last_record(self, tmp_path: Path) -> None:
        log = _seed_log(tmp_path / "audit.jsonl")
        manifest = build_manifest(
            case_id="case-003",
            run_id="hash-1",
            started_at="2026-04-24T00:00:00Z",
            audit_log=log,
            signer=StubSigner(run_id="hash-1"),
        )
        # The final hash should be 64 hex chars.
        assert len(manifest.audit_log_final_hash) == 64

    def test_extra_metadata_preserved_through_write(self, tmp_path: Path) -> None:
        log = _seed_log(tmp_path / "audit.jsonl")
        manifest = build_manifest(
            case_id="case-004",
            run_id="extra-1",
            started_at="2026-04-24T00:00:00Z",
            audit_log=log,
            signer=StubSigner(run_id="extra-1"),
            extra={"image_hash": "deadbeef" * 8, "model": "claude-opus"},
        )
        path = write_manifest(manifest, tmp_path / "run.manifest.json")
        loaded = json.loads(path.read_text(encoding="utf-8"))
        assert loaded["extra"]["image_hash"] == "deadbeef" * 8
        assert loaded["extra"]["model"] == "claude-opus"


class TestWriteManifest:
    def test_writes_pretty_json(self, tmp_path: Path) -> None:
        log = _seed_log(tmp_path / "audit.jsonl")
        manifest = build_manifest(
            case_id="case-005",
            run_id="write-1",
            started_at="2026-04-24T00:00:00Z",
            audit_log=log,
            signer=StubSigner(run_id="write-1"),
        )
        path = write_manifest(manifest, tmp_path / "run.manifest.json")
        text = path.read_text(encoding="utf-8")
        # Pretty JSON has indented braces/brackets.
        assert "  " in text  # 2-space indent
        loaded = json.loads(text)
        assert loaded["version"] == MANIFEST_VERSION

    def test_creates_parent_dirs(self, tmp_path: Path) -> None:
        log = _seed_log(tmp_path / "audit.jsonl")
        manifest = build_manifest(
            case_id="case-006",
            run_id="parent-1",
            started_at="2026-04-24T00:00:00Z",
            audit_log=log,
            signer=StubSigner(run_id="parent-1"),
        )
        nested = tmp_path / "a" / "b" / "c" / "run.manifest.json"
        write_manifest(manifest, nested)
        assert nested.is_file()


class TestVerifyManifest:
    def test_clean_manifest_verifies(self, tmp_path: Path) -> None:
        log = _seed_log(tmp_path / "audit.jsonl")
        manifest = build_manifest(
            case_id="case-100",
            run_id="ver-1",
            started_at="2026-04-24T00:00:00Z",
            audit_log=log,
            signer=StubSigner(run_id="ver-1"),
        )
        path = write_manifest(manifest, tmp_path / "run.manifest.json")
        result = verify_manifest(path)
        assert result.audit_chain_ok is True, result.audit_chain_ok
        assert result.merkle_root_ok is True, result.merkle_root_ok
        assert result.leaf_count_ok is True
        assert result.signature_present is True
        assert result.overall is True

    def test_copied_case_dir_verifies_via_manifest_sibling(self, tmp_path: Path) -> None:
        # A judge copies a case dir to another machine: the embedded absolute
        # audit_log_path 404s there. verify_manifest must fall back to the
        # audit log sitting NEXT TO the manifest before giving up.
        orig = tmp_path / "orig"
        orig.mkdir()
        log = _seed_log(orig / "audit.jsonl")
        manifest = build_manifest(
            case_id="case-copy",
            run_id="ver-copy",
            started_at="2026-04-24T00:00:00Z",
            audit_log=log,
            signer=StubSigner(run_id="ver-copy"),
        )
        write_manifest(manifest, orig / "run.manifest.json")

        copy = tmp_path / "copy"
        copy.mkdir()
        (copy / "audit.jsonl").write_bytes((orig / "audit.jsonl").read_bytes())
        (copy / "run.manifest.json").write_bytes((orig / "run.manifest.json").read_bytes())
        # Simulate the other machine: the original path no longer exists.
        (orig / "audit.jsonl").unlink()
        (orig / "run.manifest.json").unlink()
        orig.rmdir()

        result = verify_manifest(copy / "run.manifest.json")
        assert result.audit_chain_ok is True, result.audit_chain_ok
        assert result.overall is True

    def test_explicit_audit_log_path_still_wins(self, tmp_path: Path) -> None:
        # The override must take precedence over both the sibling and the
        # embedded path.
        log = _seed_log(tmp_path / "audit.jsonl")
        manifest = build_manifest(
            case_id="case-ovr",
            run_id="ver-ovr",
            started_at="2026-04-24T00:00:00Z",
            audit_log=log,
            signer=StubSigner(run_id="ver-ovr"),
        )
        path = write_manifest(manifest, tmp_path / "run.manifest.json")
        elsewhere = tmp_path / "elsewhere.jsonl"
        elsewhere.write_bytes((tmp_path / "audit.jsonl").read_bytes())
        (tmp_path / "audit.jsonl").unlink()

        result = verify_manifest(path, audit_log_path=elsewhere)
        assert result.audit_chain_ok is True, result.audit_chain_ok
        assert result.overall is True

    def test_ed25519_manifest_verifies_cryptographically_offline(self, tmp_path: Path) -> None:
        from findevil_agent.crypto.signer import LocalEd25519Signer

        log = _seed_log(tmp_path / "audit.jsonl")
        manifest = build_manifest(
            case_id="case-ed",
            run_id="ver-ed",
            started_at="2026-04-24T00:00:00Z",
            audit_log=log,
            signer=LocalEd25519Signer(key_path=tmp_path / "signing.key"),
        )
        path = write_manifest(manifest, tmp_path / "run.manifest.json")
        assert manifest.signature["kind"] == "ed25519"

        result = verify_manifest(path)
        assert result.overall is True
        assert result.signature_kind == "ed25519"
        # The real claim: a genuine offline cryptographic verification.
        assert result.signature_verified is True

    def test_ed25519_tampered_body_fails_signature_verification(self, tmp_path: Path) -> None:
        from findevil_agent.crypto.signer import LocalEd25519Signer

        log = _seed_log(tmp_path / "audit.jsonl")
        manifest = build_manifest(
            case_id="case-ed2",
            run_id="ver-ed2",
            started_at="2026-04-24T00:00:00Z",
            audit_log=log,
            signer=LocalEd25519Signer(key_path=tmp_path / "signing.key"),
        )
        path = write_manifest(manifest, tmp_path / "run.manifest.json")
        obj = json.loads(path.read_text(encoding="utf-8"))
        obj["case_id"] = "case-FORGED"
        path.write_text(json.dumps(obj), encoding="utf-8")

        result = verify_manifest(path)
        # Body no longer matches the signed bytes: honest reason string, not True.
        assert result.signature_verified is not True
        assert "ed25519" in str(result.signature_verified)
        # A present ed25519 signature that fails verification must fail overall —
        # a forged/corrupted signature cannot pass (chain+merkle+count still OK here).
        assert result.audit_chain_ok is True
        assert result.merkle_root_ok is True
        assert result.overall is False

    def test_ed25519_tampered_bundle_fails_signature_verification(self, tmp_path: Path) -> None:
        import base64 as _b64

        from findevil_agent.crypto.signer import LocalEd25519Signer

        log = _seed_log(tmp_path / "audit.jsonl")
        manifest = build_manifest(
            case_id="case-ed3",
            run_id="ver-ed3",
            started_at="2026-04-24T00:00:00Z",
            audit_log=log,
            signer=LocalEd25519Signer(key_path=tmp_path / "signing.key"),
        )
        path = write_manifest(manifest, tmp_path / "run.manifest.json")
        obj = json.loads(path.read_text(encoding="utf-8"))
        bundle = json.loads(_b64.b64decode(obj["signature"]["bundle_b64"]))
        sig = bytearray(_b64.b64decode(bundle["signature_b64"]))
        sig[0] ^= 0xFF  # flip one bit of the signature
        bundle["signature_b64"] = _b64.b64encode(bytes(sig)).decode("ascii")
        obj["signature"]["bundle_b64"] = _b64.b64encode(
            json.dumps(bundle, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).decode("ascii")
        path.write_text(json.dumps(obj), encoding="utf-8")

        result = verify_manifest(path)
        assert result.signature_verified is not True
        assert "ed25519" in str(result.signature_verified)
        # A flipped signature bit must fail overall, not just the side-signal.
        assert result.overall is False

    def test_records_signer_kind_and_honest_verification(self, tmp_path: Path) -> None:
        log = _seed_log(tmp_path / "audit.jsonl")
        manifest = build_manifest(
            case_id="case-kind",
            run_id="ver-kind",
            started_at="2026-04-24T00:00:00Z",
            audit_log=log,
            signer=StubSigner(run_id="ver-kind"),
        )
        path = write_manifest(manifest, tmp_path / "run.manifest.json")
        # The signer kind is recorded in the manifest signature block.
        assert manifest.signature["kind"] == "stub"

        result = verify_manifest(path)
        # A run still verifies overall (chain + merkle + presence) ...
        assert result.overall is True
        # ... but the new honest field never claims a stub is cryptographic proof.
        assert result.signature_kind == "stub"
        assert result.signature_verified is not True
        assert "not cryptographic proof" in str(result.signature_verified)

    def test_fallback_reason_recorded_in_manifest(self, tmp_path: Path) -> None:
        from findevil_agent.crypto.signer import FallbackSigner

        class _Boom:
            def sign(self, payload: bytes):  # type: ignore[no-untyped-def]
                raise RuntimeError("no token")

        log = _seed_log(tmp_path / "audit.jsonl")
        manifest = build_manifest(
            case_id="case-fb",
            run_id="ver-fb",
            started_at="2026-04-24T00:00:00Z",
            audit_log=log,
            signer=FallbackSigner(_Boom(), StubSigner(run_id="ver-fb")),
        )
        assert manifest.signature["kind"] == "stub"
        assert "no token" in manifest.signature["fallback_reason"]

    def test_tampered_merkle_root_caught(self, tmp_path: Path) -> None:
        log = _seed_log(tmp_path / "audit.jsonl")
        manifest = build_manifest(
            case_id="case-101",
            run_id="ver-2",
            started_at="2026-04-24T00:00:00Z",
            audit_log=log,
            signer=StubSigner(run_id="ver-2"),
        )
        path = write_manifest(manifest, tmp_path / "run.manifest.json")
        # Tamper with the on-disk root.
        loaded = json.loads(path.read_text(encoding="utf-8"))
        loaded["merkle_root_hex"] = "ff" * 32
        path.write_text(json.dumps(loaded, indent=2), encoding="utf-8")

        result = verify_manifest(path)
        assert result.merkle_root_ok is not True
        assert "ff" in str(result.merkle_root_ok)
        assert result.overall is False

    def test_tampered_leaf_caught(self, tmp_path: Path) -> None:
        log = _seed_log(tmp_path / "audit.jsonl")
        manifest = build_manifest(
            case_id="case-102",
            run_id="ver-3",
            started_at="2026-04-24T00:00:00Z",
            audit_log=log,
            signer=StubSigner(run_id="ver-3"),
        )
        path = write_manifest(manifest, tmp_path / "run.manifest.json")
        loaded = json.loads(path.read_text(encoding="utf-8"))
        # Flip a bit in a leaf digest.
        loaded["leaves"][0]["digest_hex"] = "f" + loaded["leaves"][0]["digest_hex"][1:]
        path.write_text(json.dumps(loaded, indent=2), encoding="utf-8")

        result = verify_manifest(path)
        assert result.merkle_root_ok is not True
        assert result.overall is False

    def test_audit_log_break_caught(self, tmp_path: Path) -> None:
        log = _seed_log(tmp_path / "audit.jsonl")
        manifest = build_manifest(
            case_id="case-103",
            run_id="ver-4",
            started_at="2026-04-24T00:00:00Z",
            audit_log=log,
            signer=StubSigner(run_id="ver-4"),
        )
        path = write_manifest(manifest, tmp_path / "run.manifest.json")

        # Tamper with the audit log itself.
        manifest_obj = json.loads(path.read_text(encoding="utf-8"))
        log_path = path.parent / manifest_obj["audit_log_path"]
        lines = log_path.read_bytes().splitlines()
        first = json.loads(lines[0])
        first["payload"]["tool"] = "MUTATED"
        from findevil_agent.crypto.audit_log import canonicalize_json

        lines[0] = canonicalize_json(first)
        log_path.write_bytes(b"\n".join(lines) + b"\n")

        result = verify_manifest(path)
        assert result.audit_chain_ok is not True
        assert result.overall is False

    def test_leaf_count_mismatch_caught(self, tmp_path: Path) -> None:
        log = _seed_log(tmp_path / "audit.jsonl")
        manifest = build_manifest(
            case_id="case-104",
            run_id="ver-5",
            started_at="2026-04-24T00:00:00Z",
            audit_log=log,
            signer=StubSigner(run_id="ver-5"),
        )
        path = write_manifest(manifest, tmp_path / "run.manifest.json")
        loaded = json.loads(path.read_text(encoding="utf-8"))
        loaded["leaf_count"] = 99  # lie
        path.write_text(json.dumps(loaded, indent=2), encoding="utf-8")

        result = verify_manifest(path)
        assert result.leaf_count_ok is not True
        assert result.overall is False

    def test_missing_audit_log_file_caught(self, tmp_path: Path) -> None:
        log = _seed_log(tmp_path / "audit.jsonl")
        manifest = build_manifest(
            case_id="case-105",
            run_id="ver-6",
            started_at="2026-04-24T00:00:00Z",
            audit_log=log,
            signer=StubSigner(run_id="ver-6"),
        )
        path = write_manifest(manifest, tmp_path / "run.manifest.json")
        # Delete the audit log.
        manifest_obj = json.loads(path.read_text(encoding="utf-8"))
        (path.parent / manifest_obj["audit_log_path"]).unlink()

        result = verify_manifest(path)
        assert result.audit_chain_ok is not True
        assert result.overall is False


class TestTamperEvidence:
    """The manifest must catch log-vs-manifest divergence, not just internal
    chain breaks: a tail-truncated audit log still replays prefix-cleanly,
    and an internally-consistent forged leaf set still rebuilds its own root.
    Both must fail against the sealed manifest."""

    def _sealed(self, tmp_path: Path) -> Path:
        log = _seed_log(tmp_path / "audit.jsonl")
        manifest = build_manifest(
            case_id="case-tamper",
            run_id="tamper-1",
            started_at="2026-04-24T00:00:00Z",
            audit_log=log,
            signer=StubSigner(run_id="tamper-1"),
        )
        return write_manifest(manifest, tmp_path / "run.manifest.json")

    def test_tail_truncation_fails_verification(self, tmp_path: Path) -> None:
        path = self._sealed(tmp_path)
        audit = tmp_path / "audit.jsonl"
        lines = audit.read_text(encoding="utf-8").splitlines(keepends=True)
        audit.write_text("".join(lines[:-1]), encoding="utf-8")

        result = verify_manifest(path)
        assert result.audit_chain_ok is not True
        assert result.overall is False

    def test_rerooted_leaf_forgery_fails_verification(self, tmp_path: Path) -> None:
        # An attacker drops a leaf from the manifest and recomputes the root
        # and leaf_count so the manifest stays internally consistent. The
        # leaves re-derived from the actual audit log must catch it.
        from findevil_agent.crypto.merkle import MerkleTree

        path = self._sealed(tmp_path)
        obj = json.loads(path.read_text(encoding="utf-8"))
        forged_leaves = obj["leaves"][:-1]
        tree = MerkleTree()
        for leaf in forged_leaves:
            tree.append(bytes.fromhex(leaf["digest_hex"]))
        obj["leaves"] = forged_leaves
        obj["leaf_count"] = len(forged_leaves)
        obj["merkle_root_hex"] = tree.root_hex()
        path.write_text(json.dumps(obj, indent=2, sort_keys=True), encoding="utf-8")

        result = verify_manifest(path)
        assert result.overall is False

    def test_clean_run_still_passes_consistency_checks(self, tmp_path: Path) -> None:
        result = verify_manifest(self._sealed(tmp_path))
        assert result.audit_chain_ok is True, result.audit_chain_ok
        assert result.overall is True


class TestCitationGate:
    """Sealing is the last code-enforced citation gate: a run containing a
    finding_approved record that does not cite a tool_call_id recorded
    earlier in the chain must refuse to finalize (CLAUDE.md invariant —
    every Finding cites a tool_call_id), independent of prompt discipline."""

    def _log_with(self, tmp_path: Path, finding_payload: dict) -> AuditLog:
        log = AuditLog(tmp_path / "audit.jsonl")
        log.append("tool_call_start", {"tool_call_id": "tc-1", "tool": "evtx_query"})
        log.append("tool_call_output", {"tool_call_id": "tc-1", "output_hash": "a" * 64})
        log.append("finding_approved", finding_payload)
        return log

    def _seal(self, log: AuditLog) -> None:
        build_manifest(
            case_id="case-gate",
            run_id="gate-1",
            started_at="2026-04-24T00:00:00Z",
            audit_log=log,
            signer=StubSigner(run_id="gate-1"),
        )

    def test_seal_refuses_finding_without_citation(self, tmp_path: Path) -> None:
        import pytest

        from findevil_agent.crypto.manifest import UncitedFindingError

        log = self._log_with(tmp_path, {"finding_id": "f-uncited"})
        with pytest.raises(UncitedFindingError, match="f-uncited"):
            self._seal(log)

    def test_seal_refuses_citation_missing_from_chain(self, tmp_path: Path) -> None:
        import pytest

        from findevil_agent.crypto.manifest import UncitedFindingError

        log = self._log_with(tmp_path, {"finding_id": "f-ghost", "tool_call_id": "tc-ghost"})
        with pytest.raises(UncitedFindingError, match="f-ghost"):
            self._seal(log)

    def test_seal_accepts_cited_finding(self, tmp_path: Path) -> None:
        log = self._log_with(tmp_path, {"finding_id": "f-ok", "tool_call_id": "tc-1"})
        self._seal(log)  # must not raise


class TestEntailmentReVerification:
    """manifest_verify re-runs the entailment matcher over the sealed slices
    offline (no tool re-run). entailment_ok is a separate honest signal — it
    does NOT gate overall, exactly like signature_verified."""

    @staticmethod
    def _replay_record(*, sealed_actual: str) -> dict:
        return {
            "finding_id": "f-1",
            "replay_artifact": {
                "tool_call_id": "tc-1",
                "drift_class": "exact_match",
                "entailment": {
                    "passed": True,
                    "matched": [
                        {
                            "path": "run_count",
                            "expected": "8",
                            "actual": sealed_actual,
                            "match": "int",
                        }
                    ],
                    "failures": [],
                },
            },
        }

    def _verify(self, tmp_path: Path, sealed_actual: str):
        log = _seed_log(tmp_path / "audit.jsonl")
        log.append("replay", self._replay_record(sealed_actual=sealed_actual))
        manifest = build_manifest(
            case_id="case-ent",
            run_id="ent-1",
            started_at="2026-04-24T00:00:00Z",
            audit_log=log,
            signer=StubSigner(run_id="ent-1"),
        )
        path = write_manifest(manifest, tmp_path / "run.manifest.json")
        return verify_manifest(path)

    def test_clean_sealed_slice_reports_entailment_ok(self, tmp_path: Path) -> None:
        result = self._verify(tmp_path, sealed_actual="8")  # matches expected "8"
        assert result.entailment_ok is True
        assert result.overall is True

    def test_inconsistent_sealed_slice_is_caught_without_gating_overall(
        self, tmp_path: Path
    ) -> None:
        # The sealed evidence value no longer satisfies the assertion (8 != 9).
        # This only fails if the wiring actually FINDS and re-checks the slice.
        result = self._verify(tmp_path, sealed_actual="9")
        assert result.entailment_ok is not True
        assert "entailment re-check failed" in str(result.entailment_ok)
        # entailment_ok is a separate signal; chain/merkle/signature still pass.
        assert result.overall is True
