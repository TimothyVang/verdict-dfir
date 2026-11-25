"""Round-trip + FTS5 ranking tests for MemoryStore."""

from collections.abc import Iterator
from pathlib import Path

import pytest

from findevil_agent.memory.store import MemoryStore


@pytest.fixture
def store(tmp_path: Path) -> Iterator[MemoryStore]:
    s = MemoryStore(tmp_path / "memory.sqlite")
    try:
        yield s
    finally:
        s.close()


def test_remember_then_recall_exact_hash(store: MemoryStore) -> None:
    store.remember(
        case_id="case-001",
        kind="hash",
        key="malicious.exe",
        value="abc123def456",
        sha256="sha256:abc123def456" + "0" * 50,
    )
    hits = store.recall("malicious.exe")
    assert len(hits) == 1
    assert hits[0].case_id == "case-001"
    assert hits[0].kind == "hash"
    assert hits[0].confidence > 0.0


def test_recall_ranks_by_bm25_then_decay(store: MemoryStore) -> None:
    store.remember(
        case_id="case-old",
        kind="ttp",
        key="T1059.001",
        value="powershell encoded command",
        sha256="sha256:" + "1" * 64,
        ts="2025-01-01T00:00:00Z",
    )
    store.remember(
        case_id="case-new",
        kind="ttp",
        key="T1059.001",
        value="powershell encoded command",
        sha256="sha256:" + "2" * 64,
        ts="2026-04-01T00:00:00Z",
    )
    hits = store.recall("powershell")
    assert len(hits) == 2
    assert hits[0].case_id == "case-new"
    assert hits[0].confidence > hits[1].confidence


def test_recall_filters_by_kind(store: MemoryStore) -> None:
    store.remember(
        case_id="c1", kind="ioc", key="evil.com", value="evil.com", sha256="sha256:" + "a" * 64
    )
    store.remember(
        case_id="c2", kind="hash", key="evil.com", value="evil.com", sha256="sha256:" + "b" * 64
    )
    hits = store.recall("evil.com", kind="ioc")
    assert len(hits) == 1
    assert hits[0].kind == "ioc"
