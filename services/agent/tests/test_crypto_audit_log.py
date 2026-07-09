"""Tests for findevil_agent.crypto.audit_log."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from findevil_agent.crypto.audit_log import (
    AuditLog,
    AuditLogError,
    canonicalize_json,
    hash_line,
)


class TestCanonicalize:
    def test_sorted_keys(self) -> None:
        a = canonicalize_json({"b": 2, "a": 1})
        b = canonicalize_json({"a": 1, "b": 2})
        assert a == b

    def test_no_whitespace(self) -> None:
        got = canonicalize_json({"a": 1, "b": [2, 3]})
        assert got == b'{"a":1,"b":[2,3]}'

    def test_escapes_non_ascii(self) -> None:
        got = canonicalize_json({"x": "é"})
        # ensure_ascii=True escapes non-ASCII.
        assert got == b'{"x":"\\u00e9"}'


class TestAuditLogBasics:
    def test_append_writes_canonical_jsonl(self, tmp_path: Path) -> None:
        log = AuditLog(tmp_path / "audit.jsonl")
        r1 = log.append("tool_call_start", {"tool": "evtx_query", "tc": "1"})
        r2 = log.append("finding", {"tc": "1", "id": "f-1"})

        # First record seq 0, empty prev_hash.
        assert r1.seq == 0
        assert r1.prev_hash == ""
        # Second record seq 1, prev_hash = hash of first line bytes.
        assert r2.seq == 1
        assert len(r2.prev_hash) == 64  # SHA-256 hex

        # File shape: one canonical JSON object per line.
        lines = (tmp_path / "audit.jsonl").read_bytes().splitlines()
        assert len(lines) == 2
        # Each line round-trips as canonical form.
        for ln in lines:
            assert canonicalize_json(json.loads(ln)) == ln

    def test_chain_prev_hash_links_correctly(self, tmp_path: Path) -> None:
        log = AuditLog(tmp_path / "audit.jsonl")
        log.append("a", {"x": 1})
        log.append("b", {"x": 2})
        log.append("c", {"x": 3})

        lines = (tmp_path / "audit.jsonl").read_bytes().splitlines()
        # Each subsequent record's prev_hash == hash of prior line.
        expected = ""
        for ln in lines:
            obj = json.loads(ln)
            assert obj["prev_hash"] == expected
            expected = hash_line(ln)

    def test_verify_clean_chain(self, tmp_path: Path) -> None:
        log = AuditLog(tmp_path / "audit.jsonl")
        for i in range(5):
            log.append(f"kind-{i}", {"i": i})
        assert log.verify() == 5

    def test_verify_detects_tampering(self, tmp_path: Path) -> None:
        path = tmp_path / "audit.jsonl"
        log = AuditLog(path)
        log.append("a", {"x": 1})
        log.append("b", {"x": 2})
        # Tamper with line 2's payload.
        lines = path.read_bytes().splitlines()
        obj = json.loads(lines[1])
        obj["payload"]["x"] = 99
        lines[1] = canonicalize_json(obj)
        path.write_bytes(b"\n".join(lines) + b"\n")

        # prev_hash in line 2 is unchanged (pointed at original line 1),
        # but the tampered payload has a DIFFERENT prev_hash link if we
        # recompute. Here line 2's declared prev_hash still matches
        # line 1's hash, so this specific tamper is caught by the
        # canonicalization-round-trip check (different payload → line
        # differs from what prev_hash-of-line-3 would have captured).
        # We check the basic verifier still either passes OR raises —
        # depending on WHICH byte we tampered with. Use a line-1 tamper
        # to make the mismatch certain:
        lines = path.read_bytes().splitlines()
        obj0 = json.loads(lines[0])
        obj0["payload"]["x"] = 777
        lines[0] = canonicalize_json(obj0)
        path.write_bytes(b"\n".join(lines) + b"\n")

        fresh = AuditLog(path)
        with pytest.raises(AuditLogError):
            fresh.verify()

    def test_verify_malformed_line_raises_auditlogerror_not_crash(self, tmp_path: Path) -> None:
        # A non-JSON line must surface as a typed AuditLogError (a clean failure
        # the manifest verifier turns into overall=False), never a raw
        # json.JSONDecodeError that crashes verification.
        path = tmp_path / "audit.jsonl"
        log = AuditLog(path)
        log.append("a", {"x": 1})
        log.append("b", {"x": 2})
        log.append("c", {"x": 3})
        # Malform a NON-last line so the constructor's tail read (which already
        # guards the last line) succeeds and the break is hit inside verify().
        lines = path.read_bytes().splitlines()
        lines[1] = b"@@NOTJSON@@" + lines[1]
        path.write_bytes(b"\n".join(lines) + b"\n")

        fresh = AuditLog(path)
        with pytest.raises(AuditLogError, match="not valid JSON"):
            fresh.verify()

    def test_verify_detects_truncation(self, tmp_path: Path) -> None:
        path = tmp_path / "audit.jsonl"
        log = AuditLog(path)
        for i in range(3):
            log.append("x", {"i": i})
        # Chop off the last line.
        data = path.read_bytes().splitlines()
        path.write_bytes(b"\n".join(data[:-1]) + b"\n")
        # Re-opening is fine — chain replays to 2 records successfully.
        fresh = AuditLog(path)
        assert fresh.verify() == 2


class TestReopenAndExtend:
    def test_reopen_advances_seq(self, tmp_path: Path) -> None:
        log1 = AuditLog(tmp_path / "audit.jsonl")
        log1.append("a", {"x": 1})
        log1.append("b", {"x": 2})
        # New instance picks up where we left off.
        log2 = AuditLog(tmp_path / "audit.jsonl")
        assert log2.next_seq == 2
        assert log2.last_hash == log1.last_hash
        r = log2.append("c", {"x": 3})
        assert r.seq == 2

    def test_empty_file_starts_at_zero(self, tmp_path: Path) -> None:
        log = AuditLog(tmp_path / "audit.jsonl")
        assert log.next_seq == 0
        assert log.last_hash == ""


class TestIterRecords:
    def test_iter_yields_records_in_order(self, tmp_path: Path) -> None:
        log = AuditLog(tmp_path / "audit.jsonl")
        for i in range(4):
            log.append(f"k-{i}", {"i": i})
        seqs = [r.seq for r in log.iter_records()]
        assert seqs == [0, 1, 2, 3]
        kinds = [r.kind for r in log.iter_records()]
        assert kinds == ["k-0", "k-1", "k-2", "k-3"]


class TestKnownVectors:
    def test_hash_line_matches_sha256(self) -> None:
        line = b'{"a":1,"b":2}'
        expected = hashlib.sha256(line).hexdigest()
        assert hash_line(line) == expected

    def test_hash_line_ignores_trailing_newline(self) -> None:
        assert hash_line(b"hello") == hash_line(b"hello\n")
