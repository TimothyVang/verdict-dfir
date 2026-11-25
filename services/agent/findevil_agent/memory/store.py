"""Cross-case memory store backed by SQLite FTS5.

Schema and confidence formula: see Amendment A3 §2.4. Designed for
single-machine, single-thread callers; the underlying
sqlite3.Connection raises ProgrammingError if shared across threads
(`check_same_thread=True` is the Python default and we keep it).
Cross-process writers to the same file serialize on the default
sqlite3 file lock.
"""

from __future__ import annotations

import math
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

_HALF_LIFE_DAYS = 90.0


@dataclass(frozen=True)
class RecallHit:
    case_id: str
    kind: str
    key: str
    value: str
    sha256: str
    ts: str
    confidence: float


class MemoryStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(path))
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.executescript(
            """
            CREATE VIRTUAL TABLE IF NOT EXISTS memories USING fts5(
                case_id UNINDEXED,
                kind,
                key,
                value,
                sha256 UNINDEXED,
                ts UNINDEXED,
                tokenize='porter unicode61'
            );
            CREATE TABLE IF NOT EXISTS meta (
                case_id TEXT PRIMARY KEY,
                case_path TEXT,
                first_seen_ts TEXT,
                last_updated_ts TEXT
            );
            """
        )
        self._conn.commit()

    def remember(
        self,
        *,
        case_id: str,
        kind: str,
        key: str,
        value: str,
        sha256: str,
        ts: str | None = None,
        case_path: str | None = None,
    ) -> None:
        now = ts or datetime.now(tz=UTC).isoformat().replace("+00:00", "Z")
        self._conn.execute(
            "INSERT INTO memories(case_id, kind, key, value, sha256, ts) VALUES (?, ?, ?, ?, ?, ?)",
            (case_id, kind, key, value, sha256, now),
        )
        self._conn.execute(
            "INSERT INTO meta(case_id, case_path, first_seen_ts, last_updated_ts) "
            "VALUES (?, ?, ?, ?) "
            "ON CONFLICT(case_id) DO UPDATE SET last_updated_ts=excluded.last_updated_ts, "
            "case_path=COALESCE(excluded.case_path, meta.case_path)",
            (case_id, case_path, now, now),
        )
        self._conn.commit()

    def recall(
        self,
        query: str,
        *,
        kind: str | None = None,
        limit: int = 10,
    ) -> list[RecallHit]:
        # FTS5 requires special characters (., @, -, etc.) to be phrase-quoted.
        fts_query = '"' + query.replace('"', '""') + '"'
        sql = (
            "SELECT case_id, kind, key, value, sha256, ts, "
            "       bm25(memories) AS score "
            "FROM memories "
            "WHERE memories MATCH ? "
        )
        params: list = [fts_query]
        if kind is not None:
            sql += "AND kind = ? "
            params.append(kind)
        # Fetch all candidates (up to limit) ordered by BM25 only; final sort
        # by combined confidence (relevance * decay) is done in Python below.
        sql += "ORDER BY score LIMIT ?"
        params.append(limit)

        now = datetime.now(tz=UTC)
        out: list[RecallHit] = []
        for row in self._conn.execute(sql, params):
            row_ts = datetime.fromisoformat(row["ts"].replace("Z", "+00:00"))
            days_old = max(0.0, (now - row_ts).total_seconds() / 86400.0)
            decay = math.exp(-days_old / _HALF_LIFE_DAYS)
            # bm25 returns negative scores in sqlite (lower = better);
            # invert so confidence rises with relevance.
            relevance = 1.0 / (1.0 + abs(row["score"]))
            out.append(
                RecallHit(
                    case_id=row["case_id"],
                    kind=row["kind"],
                    key=row["key"],
                    value=row["value"],
                    sha256=row["sha256"],
                    ts=row["ts"],
                    confidence=relevance * decay,
                )
            )
        # Re-rank by combined confidence descending so decay breaks BM25 ties.
        out.sort(key=lambda h: h.confidence, reverse=True)
        return out

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> MemoryStore:
        return self

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        self.close()
