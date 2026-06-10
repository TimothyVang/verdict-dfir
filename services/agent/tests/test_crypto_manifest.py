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
        log_path = Path(json.loads(path.read_text(encoding="utf-8"))["audit_log_path"])
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
        Path(json.loads(path.read_text(encoding="utf-8"))["audit_log_path"]).unlink()

        result = verify_manifest(path)
        assert result.audit_chain_ok is not True
        assert result.overall is False
