"""Hash-chained append-only JSONL audit log.

Spec #2 §7.1 + invariant: every line embeds ``prev_hash`` linking to
the SHA-256 of the preceding line. Rewriting history breaks the
chain; the M2 crypto stack detects the break on verify.

Canonicalization uses RFC 8785 (JSON Canonicalization Scheme) so
the same record hashes identically across platforms — required for
``verify_manifest`` (in ``findevil_agent.crypto.manifest``, also
exposed via the ``manifest_verify`` MCP tool) to reproduce the
chain offline. See ``docs/cryptographic-attestation.md`` for the
third-party verification recipe.

Design goals:

1. **Pure stdlib.** No sigstore, no network. Signing is a separate
   layer that reads this log as input.
2. **Crash-safe.** Every ``append`` fsyncs. If the writer crashes
   mid-line, the next writer detects a torn tail via hash mismatch
   and refuses to extend.
3. **Deterministic.** Given the same sequence of logical records,
   two writers produce byte-identical output files — important for
   reproducible CI runs and courtroom replay.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:  # POSIX
    import fcntl
except ImportError:  # pragma: no cover - Windows
    fcntl = None  # type: ignore[assignment]
    import msvcrt


def _lock_exclusive(f: Any) -> None:
    """Blocking exclusive lock over the whole audit log.

    A bare ``import fcntl`` at module scope makes this module unimportable on
    Windows, and cross-platform.yml runs the Python suite on windows-latest, so
    conftest's import of AuditLog would fail at collection.
    """
    if fcntl is not None:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        return
    # msvcrt locks a byte range from the current offset; byte 0 is the
    # conventional whole-file sentinel. LK_LOCK gives up after ~10 retries, so
    # loop to preserve the blocking contract the POSIX path provides.
    f.seek(0)
    while True:
        try:
            msvcrt.locking(f.fileno(), msvcrt.LK_LOCK, 1)
            return
        except OSError:
            time.sleep(0.1)


def _unlock(f: Any) -> None:
    if fcntl is not None:
        fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        return
    f.seek(0)
    msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)


# ---------------------------------------------------------------------------
# Canonicalization — RFC 8785 JCS, approximated.
#
# Full JCS is complex; we implement the subset that matters for our
# payloads (sorted keys, no whitespace, UTF-8, numbers in IEEE-754
# shortest form). The Python ``json`` module with ``sort_keys=True``
# + ``(',', ':')`` separators produces canonical output for all
# JSON shapes our events use. Numbers are integer or float; floats
# we emit via the repr path which matches IEEE-754 shortest.
# ---------------------------------------------------------------------------

_CANONICAL_SEPARATORS = (",", ":")


def canonicalize_json(obj: Any) -> bytes:
    """Return the RFC-8785-compatible canonical bytes for ``obj``.

    ``sort_keys=True`` + tightest separators + UTF-8 + escape
    non-ASCII to ``\\uXXXX``. Two logically-equal Python dicts
    produce byte-identical output regardless of key-insertion order.
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=_CANONICAL_SEPARATORS,
        ensure_ascii=True,
    ).encode("ascii")


def hash_line(line: bytes) -> str:
    """SHA-256 of a full JSONL line (without the trailing newline)."""
    h = hashlib.sha256()
    h.update(line.rstrip(b"\n"))
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Record shape.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AuditRecord:
    """One line of the audit log before hashing.

    ``seq`` is 0-based and monotonic. ``prev_hash`` is the SHA-256
    of the preceding line (empty string for the first record). The
    ``payload`` dict is the domain-specific event body — tool calls,
    findings, contradictions, etc.
    """

    seq: int
    ts: str  # UTC ISO-8601Z
    kind: str
    prev_hash: str
    payload: dict[str, Any]

    def to_canonical_dict(self) -> dict[str, Any]:
        """Dict shape written to disk. Field order matters for audit readability
        but doesn't affect hashing — JCS canonicalization sorts anyway.
        """
        return {
            "seq": self.seq,
            "ts": self.ts,
            "kind": self.kind,
            "prev_hash": self.prev_hash,
            "payload": self.payload,
        }


# ---------------------------------------------------------------------------
# AuditLog — the writer + reader.
# ---------------------------------------------------------------------------


class AuditLogError(RuntimeError):
    """Raised when the chain invariant is violated."""


class AuditLog:
    """Append-only hash-chained JSONL log.

    Usage:
        log = AuditLog(Path("~/.findevil/cases/<id>/audit.jsonl"))
        log.append("tool_call_start", {"tool": "evtx_query", ...})
        log.append("finding", {"tool_call_id": "tc-1", ...})
        log.verify()  # replays chain; raises AuditLogError on break
    """

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        self._next_seq = 0
        self._last_hash = ""
        self._load_tail()

    # ------------------------------------------------------------------
    # Construction-time tail load.
    # ------------------------------------------------------------------

    def _load_tail(self) -> None:
        """Populate ``_next_seq`` + ``_last_hash`` from any existing file."""
        if not self.path.is_file():
            return
        with self.path.open("rb") as f:
            self._scan_tail(f)

    def _scan_tail(self, f: Any) -> None:
        """Derive ``_next_seq`` + ``_last_hash`` from an open binary file handle.

        Scans from the start of ``f`` and sets the writer's cached tail state
        from the last non-empty record. Shared by construction-time
        ``_load_tail`` and the locked re-read in ``append`` so the same
        validation applies to both paths.
        """
        f.seek(0)
        last_line: bytes | None = None
        count = 0
        for raw in f:
            raw = raw.rstrip(b"\n")
            if not raw:
                continue
            last_line = raw
            count += 1
        if last_line is None:
            self._next_seq = 0
            self._last_hash = ""
            return
        try:
            obj = json.loads(last_line)
        except json.JSONDecodeError as exc:
            raise AuditLogError(
                f"audit log {self.path}: last line is not valid JSON: {exc}"
            ) from exc
        if not isinstance(obj, dict) or "seq" not in obj:
            raise AuditLogError(f"audit log {self.path}: last line is not an audit record")
        self._next_seq = int(obj["seq"]) + 1
        self._last_hash = hash_line(last_line)
        if count != self._next_seq:
            raise AuditLogError(
                f"audit log {self.path}: seq-count mismatch "
                f"(file has {count} lines but last seq is {obj['seq']})"
            )

    # ------------------------------------------------------------------
    # Writer.
    # ------------------------------------------------------------------

    def append(self, kind: str, payload: dict[str, Any], *, ts: str | None = None) -> AuditRecord:
        """Append one record. Safe for concurrent multi-writer sharing. fsyncs
        before returning.

        Multiple writers routinely share one ``audit.jsonl`` — every
        audit-writing MCP tool constructs a fresh ``AuditLog`` per call, so the
        per-instance :class:`threading.Lock` alone gives no cross-instance or
        cross-process protection. To keep the hash chain intact under
        concurrency we hold an OS-level exclusive lock (``fcntl.flock``) across
        the whole read-tail-then-append critical section, and re-derive the tail
        *under* that lock — a lock without the re-read would still splice a stale
        ``prev_hash``/``seq`` and brick the chain. The lock is blocking, so
        contending writers queue and each appends in turn; failure to acquire it
        propagates and fails the append closed rather than writing unlocked.
        """
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a+b") as f:
                _lock_exclusive(f)
                try:
                    # Re-derive the true tail under the lock: another writer may
                    # have appended since this instance was constructed, so the
                    # cached _next_seq/_last_hash can be stale.
                    self._scan_tail(f)
                    record = AuditRecord(
                        seq=self._next_seq,
                        ts=ts or _utc_iso(),
                        kind=kind,
                        prev_hash=self._last_hash,
                        payload=payload,
                    )
                    line = canonicalize_json(record.to_canonical_dict())
                    # Required to legally switch the shared handle from reading
                    # (the tail scan) to writing.
                    f.seek(0, os.SEEK_END)
                    f.write(line + b"\n")
                    f.flush()
                    os.fsync(f.fileno())
                    self._last_hash = hash_line(line)
                    self._next_seq += 1
                    return record
                finally:
                    _unlock(f)

    # ------------------------------------------------------------------
    # Reader / verifier.
    # ------------------------------------------------------------------

    def iter_records(self) -> Iterable[AuditRecord]:
        """Yield each record in order, without verifying."""
        if not self.path.is_file():
            return
        with self.path.open("rb") as f:
            for raw in f:
                raw = raw.rstrip(b"\n")
                if not raw:
                    continue
                try:
                    obj = json.loads(raw)
                except json.JSONDecodeError as exc:
                    raise AuditLogError(f"line is not valid JSON: {exc}") from exc
                yield AuditRecord(
                    seq=int(obj["seq"]),
                    ts=str(obj["ts"]),
                    kind=str(obj["kind"]),
                    prev_hash=str(obj["prev_hash"]),
                    payload=obj.get("payload") or {},
                )

    def verify(self) -> int:
        """Replay the chain. Returns the record count. Raises on break.

        Checks:
          * seq is monotonic starting at 0
          * each record's prev_hash equals SHA-256 of the previous
            line's exact bytes
          * canonicalization round-trip matches the on-disk line
        """
        if not self.path.is_file():
            return 0
        count = 0
        prev_hash = ""
        with self.path.open("rb") as f:
            for raw in f:
                raw = raw.rstrip(b"\n")
                if not raw:
                    continue
                try:
                    obj = json.loads(raw)
                except json.JSONDecodeError as exc:
                    raise AuditLogError(f"seq {count}: line is not valid JSON: {exc}") from exc
                if not isinstance(obj, dict):
                    raise AuditLogError(f"seq {count}: not a JSON object")
                seq = obj.get("seq")
                if seq != count:
                    raise AuditLogError(f"seq {count}: expected seq={count}, got seq={seq}")
                declared = obj.get("prev_hash")
                if declared != prev_hash:
                    raise AuditLogError(
                        f"seq {count}: prev_hash break (declared={declared!r}, expected={prev_hash!r})"
                    )
                # Canonicalization round-trip — catches byte-level
                # tampering within a line even if prev_hash still
                # links up.
                canonical = canonicalize_json(obj)
                if canonical != raw:
                    raise AuditLogError(f"seq {count}: line is not in canonical form")
                prev_hash = hash_line(raw)
                count += 1
        return count

    # ------------------------------------------------------------------
    # Public inspection.
    # ------------------------------------------------------------------

    @property
    def next_seq(self) -> int:
        return self._next_seq

    @property
    def last_hash(self) -> str:
        return self._last_hash


def _utc_iso() -> str:
    from datetime import UTC, datetime

    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
