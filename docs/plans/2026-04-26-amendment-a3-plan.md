# Amendment A3 Implementation Plan — Agent-Army Bridge + Cross-Case Memory + NES.css Dashboard

> **Status: RETIRED (Phases 1-4 + role-state dashboard SHIPPED, pixel-art/chrome polish PARKED).** The three Python MCP tools (`memory_remember`, `memory_recall`, `pool_handoff`) shipped in `services/agent_mcp/findevil_agent_mcp/tools/`. The FTS5 memory store shipped in `services/agent/findevil_agent/memory/store.py`. The `apps/web/` dashboard shipped with SSE audit-tail at `/api/audit`, role-state sprite containers, `/debug` raw viewer, and Codex cockpit routes; SSE was chosen over WebSocket. The pixel-art sprite swap and AuditBeadString/HashChainBadge/FindingChip chrome are parked, gated on a Claude Design prototyping pass. **Do not execute this as a TDD plan; live code and CLAUDE.md state win.**

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement Amendment A3 — three new Python MCP tools (`memory_remember`, `memory_recall`, `pool_handoff`) inside `services/agent_mcp/`, plus a NES.css live dashboard at `apps/web/` reading the audit JSONL hash chain over WebSocket.

**Architecture:** Three additive layers on top of A2. Python work follows the established `services/agent_mcp/findevil_agent_mcp/tools/_base.py::ToolSpec` pattern with Pydantic Input/Output models + async handlers. Dashboard is Next.js 15 + Tailwind v4 + NES.css. Memory store is local SQLite FTS5 at `~/.local/state/findevil/memory.sqlite` (or `%LOCALAPPDATA%\findevil\memory.sqlite` on Windows).

**Tech Stack:** Python 3.11 + uv + pytest + pydantic 2.x + sqlite3 (stdlib, FTS5 enabled) + the existing `mcp` Anthropic SDK; Next.js 15 + React 19 + Tailwind v4 + nes.css 2.3.x + chokidar (file watching) + ws (WebSocket server) + pydantic-to-typescript (event-type codegen).

**Spec:** `docs/specs/2026-04-26-amendment-a3-agent-army-and-dashboard.md`.

---

## File Structure

**Python (Phases 1-3) — fully specified TDD below:**

```
services/agent/findevil_agent/
├── memory/                                # NEW
│   ├── __init__.py
│   └── store.py                           # MemoryStore (sqlite + FTS5)
└── acp/                                   # NEW
    ├── __init__.py
    └── handoff.py                         # IBM-ACP envelope + writer

services/agent/tests/
├── test_memory_store.py                   # NEW
└── test_acp_handoff.py                    # NEW

services/agent_mcp/findevil_agent_mcp/tools/
├── memory_remember.py                     # NEW
├── memory_recall.py                       # NEW
└── pool_handoff.py                        # NEW

services/agent_mcp/findevil_agent_mcp/server.py     # MODIFY: register 3 new SPECs

services/agent_mcp/tests/
├── test_memory_tools.py                   # NEW
└── test_acp_tools.py                      # NEW
```

**Dashboard (Phases 4-6) — design-then-build, scaffold here, components TBD by Claude Design pass:**

```
apps/web/                                  # NEW directory tree (un-defers A2 §2.1)
├── package.json
├── next.config.ts
├── tsconfig.json
├── tailwind.config.ts
├── app/
│   ├── layout.tsx
│   ├── globals.css                        # NES.css import
│   ├── page.tsx                           # 5 sprites + audit bead string
│   └── api/audit/route.ts                 # WebSocket upgrade
├── components/
│   ├── sprites/PoolASprite.tsx
│   ├── sprites/PoolBSprite.tsx
│   ├── sprites/VerifierSprite.tsx
│   ├── sprites/JudgeSprite.tsx
│   ├── sprites/CorrelatorSprite.tsx
│   ├── AuditBeadString.tsx
│   ├── FindingChip.tsx
│   └── HashChainBadge.tsx
├── lib/
│   ├── audit-tail.ts                      # chokidar watcher → WebSocket
│   └── audit-types.ts                     # generated from findevil_agent.events
└── public/sprites/
    └── (PNG sprite sheets — exported from Claude Design pass)
```

---

# Phase 1 — Memory Store (`findevil_agent.memory`)

### Task 1.1: MemoryStore module + failing test for round-trip remember/recall

**Files:**
- Create: `services/agent/findevil_agent/memory/__init__.py`
- Create: `services/agent/findevil_agent/memory/store.py`
- Create: `services/agent/tests/test_memory_store.py`

- [ ] **Step 1: Write the failing test**

```python
# services/agent/tests/test_memory_store.py
"""Round-trip + FTS5 ranking tests for MemoryStore."""

from pathlib import Path

import pytest

from findevil_agent.memory.store import MemoryStore


@pytest.fixture
def store(tmp_path: Path) -> MemoryStore:
    return MemoryStore(tmp_path / "memory.sqlite")


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
    # Two memories matching 'powershell'; the older one should rank lower.
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
    store.remember(case_id="c1", kind="ioc", key="evil.com", value="evil.com",
                   sha256="sha256:" + "a" * 64)
    store.remember(case_id="c2", kind="hash", key="evil.com", value="evil.com",
                   sha256="sha256:" + "b" * 64)
    hits = store.recall("evil.com", kind="ioc")
    assert len(hits) == 1
    assert hits[0].kind == "ioc"
```

- [ ] **Step 2: Run test to confirm RED**

```bash
uv run --directory services/agent pytest tests/test_memory_store.py -v
```

Expected: ImportError (MemoryStore module does not exist).

- [ ] **Step 3: Implement `MemoryStore`**

```python
# services/agent/findevil_agent/memory/__init__.py
"""SQLite FTS5-backed cross-case memory layer (Hermes pattern, A3 §2.4)."""

from findevil_agent.memory.store import MemoryStore, RecallHit

__all__ = ["MemoryStore", "RecallHit"]
```

```python
# services/agent/findevil_agent/memory/store.py
"""Cross-case memory store backed by SQLite FTS5.

Schema and confidence formula: see Amendment A3 §2.4. Designed for
single-machine investigations; concurrent writers serialize on the
default sqlite3 file lock.
"""

from __future__ import annotations

import math
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

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
        ts: Optional[str] = None,
        case_path: Optional[str] = None,
    ) -> None:
        now = ts or datetime.now(tz=timezone.utc).isoformat().replace("+00:00", "Z")
        self._conn.execute(
            "INSERT INTO memories(case_id, kind, key, value, sha256, ts) "
            "VALUES (?, ?, ?, ?, ?, ?)",
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
        kind: Optional[str] = None,
        limit: int = 10,
    ) -> list[RecallHit]:
        # FTS5 requires special characters (., @, -, etc.) to be phrase-quoted —
        # raw "evil.com" or "T1059.001" otherwise triggers
        # `sqlite3.OperationalError: fts5: syntax error near "."`.
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
        # Fetch up to `limit` ordered by raw BM25 only; final sort by combined
        # confidence (relevance * decay) is done in Python below so decay can
        # break BM25 ties (which `ORDER BY` would otherwise return in
        # insertion order).
        sql += "ORDER BY score LIMIT ?"
        params.append(limit)

        now = datetime.now(tz=timezone.utc)
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
```

- [ ] **Step 4: Run tests to confirm GREEN**

```bash
uv run --directory services/agent pytest tests/test_memory_store.py -v
```

Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add services/agent/findevil_agent/memory/ services/agent/tests/test_memory_store.py
git commit -m "feat(memory): add SQLite FTS5 cross-case memory store (A3 §2.4)"
```

---

### Task 1.2: `memory_remember` MCP tool

**Files:**
- Create: `services/agent_mcp/findevil_agent_mcp/tools/memory_remember.py`
- Create: `services/agent_mcp/tests/test_memory_tools.py`

- [ ] **Step 1: Write the failing test**

```python
# services/agent_mcp/tests/test_memory_tools.py
"""Tests for memory_remember + memory_recall MCP tools (A3 §2.2)."""

from pathlib import Path

import pytest

from findevil_agent_mcp.tools.memory_remember import (
    SPEC as REMEMBER_SPEC,
    MemoryRememberInput,
)


@pytest.mark.asyncio
async def test_memory_remember_writes_row(tmp_path: Path) -> None:
    db = tmp_path / "memory.sqlite"
    inp = MemoryRememberInput(
        store_path=str(db),
        case_id="case-001",
        kind="hash",
        key="evil.exe",
        value="evil.exe sha=abc",
        sha256="sha256:" + "a" * 64,
    )
    out = await REMEMBER_SPEC.handler(inp)
    assert out.case_id == "case-001"
    assert out.kind == "hash"
    assert db.exists()
```

- [ ] **Step 2: Run test to confirm RED**

```bash
uv run --directory services/agent_mcp pytest tests/test_memory_tools.py::test_memory_remember_writes_row -v
```

Expected: ImportError on `memory_remember`.

- [ ] **Step 3: Implement the tool (mirrors `audit_append.py` pattern)**

```python
# services/agent_mcp/findevil_agent_mcp/tools/memory_remember.py
"""``memory_remember`` tool — Hermes-pattern cross-case memory write (A3 §2.2)."""

from __future__ import annotations

from pathlib import Path

from findevil_agent.memory.store import MemoryStore
from pydantic import BaseModel, ConfigDict, Field

from findevil_agent_mcp.tools._base import ToolSpec


class MemoryRememberInput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    store_path: str = Field(..., description="Absolute path to memory.sqlite. Created if missing.")
    case_id: str = Field(..., min_length=1)
    kind: str = Field(..., description="One of: 'ioc', 'hash', 'ttp', 'hostname', 'finding_summary'.")
    key: str = Field(..., min_length=1)
    value: str = Field(..., min_length=1)
    sha256: str = Field(..., pattern=r"^sha256:[0-9a-f]{64}$")
    ts: str | None = Field(default=None, description="UTC ISO-8601Z; defaults to now().")
    case_path: str | None = Field(default=None)


class MemoryRememberOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: str
    kind: str
    key: str
    sha256: str


async def _handle(inp: BaseModel) -> MemoryRememberOutput:
    assert isinstance(inp, MemoryRememberInput)
    store = MemoryStore(Path(inp.store_path))
    try:
        store.remember(
            case_id=inp.case_id,
            kind=inp.kind,
            key=inp.key,
            value=inp.value,
            sha256=inp.sha256,
            ts=inp.ts,
            case_path=inp.case_path,
        )
    finally:
        store.close()
    return MemoryRememberOutput(case_id=inp.case_id, kind=inp.kind, key=inp.key, sha256=inp.sha256)


SPEC = ToolSpec(
    name="memory_remember",
    description=(
        "Write a (case_id, kind, key, value, sha256) row to the cross-case FTS5 memory store "
        "so that future investigations can recall this observation. Call when you encounter a "
        "noteworthy IOC, hash, TTP, hostname, or finding summary you'd want a future case to "
        "see. Hermes-pattern (A3 §2.2). The store_path argument is the absolute path to "
        "memory.sqlite — typically ~/.local/state/findevil/memory.sqlite or "
        "%LOCALAPPDATA%\\findevil\\memory.sqlite on Windows. Returns an echo of the key fields. "
        "On error: check the store_path parent directory is writable."
    ),
    input_model=MemoryRememberInput,
    output_model=MemoryRememberOutput,
    handler=_handle,
)

__all__ = ["MemoryRememberInput", "MemoryRememberOutput", "SPEC"]
```

- [ ] **Step 4: Run tests GREEN**

```bash
uv run --directory services/agent_mcp pytest tests/test_memory_tools.py::test_memory_remember_writes_row -v
```

Expected: 1 passed.

- [ ] **Step 5: Commit**

```bash
git add services/agent_mcp/findevil_agent_mcp/tools/memory_remember.py services/agent_mcp/tests/test_memory_tools.py
git commit -m "feat(agent_mcp): add memory_remember tool (A3 §2.2)"
```

---

### Task 1.3: `memory_recall` MCP tool

**Files:**
- Create: `services/agent_mcp/findevil_agent_mcp/tools/memory_recall.py`
- Modify: `services/agent_mcp/tests/test_memory_tools.py` (extend)

- [ ] **Step 1: Add failing test for recall round-trip via the tool**

```python
# Append to services/agent_mcp/tests/test_memory_tools.py
from findevil_agent_mcp.tools.memory_recall import (
    SPEC as RECALL_SPEC,
    MemoryRecallInput,
)


@pytest.mark.asyncio
async def test_memory_recall_returns_remembered_row(tmp_path: Path) -> None:
    db = tmp_path / "memory.sqlite"
    # Seed via the remember tool.
    await REMEMBER_SPEC.handler(
        MemoryRememberInput(
            store_path=str(db),
            case_id="case-recall-1",
            kind="ioc",
            key="badguy.example",
            value="badguy.example c2 domain",
            sha256="sha256:" + "f" * 64,
        )
    )
    # Recall.
    out = await RECALL_SPEC.handler(
        MemoryRecallInput(store_path=str(db), query="badguy", limit=5)
    )
    assert len(out.hits) == 1
    assert out.hits[0].case_id == "case-recall-1"
    assert out.hits[0].confidence > 0.0
```

- [ ] **Step 2: Run RED**

```bash
uv run --directory services/agent_mcp pytest tests/test_memory_tools.py::test_memory_recall_returns_remembered_row -v
```

Expected: ImportError on `memory_recall`.

- [ ] **Step 3: Implement**

```python
# services/agent_mcp/findevil_agent_mcp/tools/memory_recall.py
"""``memory_recall`` tool — Hermes-pattern cross-case memory query (A3 §2.2)."""

from __future__ import annotations

from pathlib import Path

from findevil_agent.memory.store import MemoryStore, RecallHit
from pydantic import BaseModel, ConfigDict, Field

from findevil_agent_mcp.tools._base import ToolSpec


class MemoryRecallInput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    store_path: str = Field(..., description="Absolute path to memory.sqlite.")
    query: str = Field(..., min_length=1, description="FTS5 query string.")
    kind: str | None = Field(default=None, description="Optional filter: 'ioc'|'hash'|'ttp'|'hostname'|'finding_summary'.")
    limit: int = Field(default=10, ge=1, le=100)


class RecallHitOut(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: str
    kind: str
    key: str
    value: str
    sha256: str
    ts: str
    confidence: float


class MemoryRecallOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    hits: list[RecallHitOut]


async def _handle(inp: BaseModel) -> MemoryRecallOutput:
    assert isinstance(inp, MemoryRecallInput)
    store = MemoryStore(Path(inp.store_path))
    try:
        rows = store.recall(inp.query, kind=inp.kind, limit=inp.limit)
    finally:
        store.close()
    return MemoryRecallOutput(
        hits=[
            RecallHitOut(
                case_id=r.case_id,
                kind=r.kind,
                key=r.key,
                value=r.value,
                sha256=r.sha256,
                ts=r.ts,
                confidence=r.confidence,
            )
            for r in rows
        ]
    )


SPEC = ToolSpec(
    name="memory_recall",
    description=(
        "Query the cross-case FTS5 memory store for prior-case observations matching a search. "
        "Use this BEFORE proposing a finding to check whether you've seen this IOC/hash/TTP "
        "in a previous investigation — reduces re-investigation hallucination on patterns you "
        "already know. Hermes-pattern (A3 §2.2). Hits are returned ordered by "
        "BM25 relevance × 90-day exponential decay. The kind argument optionally filters to "
        "one of: 'ioc', 'hash', 'ttp', 'hostname', 'finding_summary'. Empty hits list means "
        "no prior cases matched — that's a useful signal too."
    ),
    input_model=MemoryRecallInput,
    output_model=MemoryRecallOutput,
    handler=_handle,
)

__all__ = ["MemoryRecallInput", "MemoryRecallOutput", "RecallHitOut", "SPEC"]
```

- [ ] **Step 4: Run GREEN**

```bash
uv run --directory services/agent_mcp pytest tests/test_memory_tools.py -v
```

Expected: 2 passed (both memory tests).

- [ ] **Step 5: Commit**

```bash
git add services/agent_mcp/findevil_agent_mcp/tools/memory_recall.py services/agent_mcp/tests/test_memory_tools.py
git commit -m "feat(agent_mcp): add memory_recall tool (A3 §2.2)"
```

---

# Phase 2 — IBM-ACP Pool Handoff (`findevil_agent.acp`)

### Task 2.1: ACP envelope + handoff function with audit-log writer

**Files:**
- Create: `services/agent/findevil_agent/acp/__init__.py`
- Create: `services/agent/findevil_agent/acp/handoff.py`
- Create: `services/agent/tests/test_acp_handoff.py`

- [ ] **Step 1: Write the failing test**

```python
# services/agent/tests/test_acp_handoff.py
"""IBM-ACP envelope + audit-log writer tests (A3 §2.3)."""

import json
from pathlib import Path

from findevil_agent.acp.handoff import ACPMessage, handoff
from findevil_agent.crypto.audit_log import AuditLog


def test_handoff_writes_acp_handoff_kind_to_audit_log(tmp_path: Path) -> None:
    audit = tmp_path / "audit.jsonl"
    log = AuditLog(audit)

    msg = handoff(
        log=log,
        from_role="pool_a",
        to_role="pool_b",
        payload={"finding_id": "f-001", "summary": "persistence via Run key"},
    )

    assert msg.acp_version == "1.0"
    assert msg.from_role == "pool_a"
    assert msg.to_role == "pool_b"
    assert msg.correlation_id  # non-empty UUID

    # The audit log got one entry, kind=acp_handoff.
    lines = audit.read_text().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["kind"] == "acp_handoff"
    assert record["payload"]["from_role"] == "pool_a"
    assert record["payload"]["to_role"] == "pool_b"


def test_acp_message_envelope_shape() -> None:
    msg = ACPMessage(
        from_role="pool_a",
        to_role="judge",
        payload={"x": 1},
    )
    dumped = msg.model_dump()
    assert set(dumped.keys()) == {"acp_version", "from_role", "to_role", "correlation_id", "payload", "ts"}
    assert dumped["acp_version"] == "1.0"
```

- [ ] **Step 2: RED**

```bash
uv run --directory services/agent pytest tests/test_acp_handoff.py -v
```

Expected: ImportError.

- [ ] **Step 3: Implement**

```python
# services/agent/findevil_agent/acp/__init__.py
"""IBM Agent Communication Protocol envelope + handoff writer (A3 §2.3)."""

from findevil_agent.acp.handoff import ACPMessage, handoff

__all__ = ["ACPMessage", "handoff"]
```

```python
# services/agent/findevil_agent/acp/handoff.py
"""IBM-ACP envelope + audit-log-backed handoff (A3 §2.3).

Records agent-to-agent messages as kind="acp_handoff" lines in the
case's hash-chained audit JSONL. Network transport is deliberately
out of scope; future networked-ACP can add an HTTP transport behind
the same `handoff()` signature.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Literal

from findevil_agent.crypto.audit_log import AuditLog
from pydantic import BaseModel, ConfigDict, Field

Role = Literal["pool_a", "pool_b", "verifier", "judge", "correlator", "supervisor"]


class ACPMessage(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    acp_version: str = Field(default="1.0")
    from_role: Role
    to_role: Role
    correlation_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    payload: dict[str, Any]
    ts: str = Field(
        default_factory=lambda: datetime.now(tz=timezone.utc).isoformat().replace("+00:00", "Z")
    )


def handoff(
    *,
    log: AuditLog,
    from_role: Role,
    to_role: Role,
    payload: dict[str, Any],
    correlation_id: str | None = None,
) -> ACPMessage:
    msg = ACPMessage(
        from_role=from_role,
        to_role=to_role,
        payload=payload,
        **({"correlation_id": correlation_id} if correlation_id else {}),
    )
    log.append("acp_handoff", msg.model_dump(), ts=msg.ts)
    return msg
```

- [ ] **Step 4: GREEN**

```bash
uv run --directory services/agent pytest tests/test_acp_handoff.py -v
```

Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
git add services/agent/findevil_agent/acp/ services/agent/tests/test_acp_handoff.py
git commit -m "feat(acp): add IBM-ACP envelope + audit-log-backed handoff (A3 §2.3)"
```

---

### Task 2.2: `pool_handoff` MCP tool

**Files:**
- Create: `services/agent_mcp/findevil_agent_mcp/tools/pool_handoff.py`
- Create: `services/agent_mcp/tests/test_acp_tools.py`

- [ ] **Step 1: Write the failing test**

```python
# services/agent_mcp/tests/test_acp_tools.py
"""Tests for pool_handoff MCP tool (A3 §2.3)."""

import json
from pathlib import Path

import pytest

from findevil_agent_mcp.tools.pool_handoff import SPEC, PoolHandoffInput


@pytest.mark.asyncio
async def test_pool_handoff_appends_acp_line(tmp_path: Path) -> None:
    audit = tmp_path / "audit.jsonl"
    out = await SPEC.handler(
        PoolHandoffInput(
            audit_path=str(audit),
            from_role="pool_a",
            to_role="judge",
            payload={"finding_id": "f-42"},
        )
    )
    assert out.acp_version == "1.0"
    assert out.from_role == "pool_a"
    assert out.to_role == "judge"

    record = json.loads(audit.read_text().splitlines()[0])
    assert record["kind"] == "acp_handoff"
```

- [ ] **Step 2: RED**

```bash
uv run --directory services/agent_mcp pytest tests/test_acp_tools.py -v
```

Expected: ImportError.

- [ ] **Step 3: Implement**

```python
# services/agent_mcp/findevil_agent_mcp/tools/pool_handoff.py
"""``pool_handoff`` tool — IBM-ACP agent-to-agent handoff (A3 §2.3)."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from findevil_agent.acp.handoff import handoff
from findevil_agent.crypto.audit_log import AuditLog
from pydantic import BaseModel, ConfigDict, Field

from findevil_agent_mcp.tools._base import ToolSpec

Role = Literal["pool_a", "pool_b", "verifier", "judge", "correlator", "supervisor"]


class PoolHandoffInput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    audit_path: str = Field(..., description="Absolute path to the case's audit.jsonl.")
    from_role: Role
    to_role: Role
    payload: dict[str, Any]
    correlation_id: str | None = Field(default=None)


class PoolHandoffOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    acp_version: str
    from_role: Role
    to_role: Role
    correlation_id: str
    ts: str


async def _handle(inp: BaseModel) -> PoolHandoffOutput:
    assert isinstance(inp, PoolHandoffInput)
    log = AuditLog(Path(inp.audit_path))
    msg = handoff(
        log=log,
        from_role=inp.from_role,
        to_role=inp.to_role,
        payload=inp.payload,
        correlation_id=inp.correlation_id,
    )
    return PoolHandoffOutput(
        acp_version=msg.acp_version,
        from_role=msg.from_role,
        to_role=msg.to_role,
        correlation_id=msg.correlation_id,
        ts=msg.ts,
    )


SPEC = ToolSpec(
    name="pool_handoff",
    description=(
        "Send an IBM-ACP-shaped agent-to-agent message between roles "
        "(pool_a → pool_b, verifier → judge, etc.) and record it as a kind='acp_handoff' "
        "line in the case audit JSONL. Use when one pool/role needs to formally hand "
        "structured findings or context to another, distinct from natural-language "
        "supervisor messaging. The correlation_id lets downstream roles thread replies. "
        "Returns the envelope echo so the caller can record the correlation_id for "
        "later replies."
    ),
    input_model=PoolHandoffInput,
    output_model=PoolHandoffOutput,
    handler=_handle,
)

__all__ = ["PoolHandoffInput", "PoolHandoffOutput", "SPEC"]
```

- [ ] **Step 4: GREEN**

```bash
uv run --directory services/agent_mcp pytest tests/test_acp_tools.py -v
```

Expected: 1 passed.

- [ ] **Step 5: Commit**

```bash
git add services/agent_mcp/findevil_agent_mcp/tools/pool_handoff.py services/agent_mcp/tests/test_acp_tools.py
git commit -m "feat(agent_mcp): add pool_handoff IBM-ACP tool (A3 §2.3)"
```

---

# Phase 3 — Server Registration

### Task 3.1: Register the three new SPECs in the MCP server

**Files (corrected against actual codebase shape):**
- Modify: `services/agent_mcp/findevil_agent_mcp/tools/__init__.py` — the registration point is here, NOT in `server.py`. Auto-discovery iterates a `_MODULES: tuple[str, ...]`; adding a module name imports it and picks up its `SPEC`.
- Modify: `services/agent_mcp/tests/test_registry.py` — extend tool-count assertion + extend `EXPECTED_TOOL_NAMES` set.
- Modify: `services/agent_mcp/tests/test_server_boot.py` — bump `test_returns_*_specs` count assertion + rename method honestly.
- Modify: `services/agent_mcp/tests/test_stdio_smoke.py` — extend the in-test list of expected tool names with the 3 new entries.

> **Spec/code divergence (committed in run history)**: an earlier draft of this plan said to edit `server.py`; the actual server iterates `tools/__init__.py::all_specs()` dynamically and needs no edits. The earlier draft also named only `test_registry.py` as a test edit, but two more test files pin the count + the tool list and need updating. Match the names below — don't grep for `TOOL_SPECS` in `server.py`.

- [ ] **Step 1: Update the failing count assertions**

In `services/agent_mcp/tests/test_registry.py` (around line 30) and `services/agent_mcp/tests/test_server_boot.py` (around line 24), change the count from `== 10` to `== 13` AND rename the test method to match (e.g., `test_all_specs_returns_thirteen_tools`, `test_returns_thirteen_specs`). A method named `test_returns_ten_specs` that asserts 13 is dishonest — readers and CI logs lie.

In `services/agent_mcp/tests/test_registry.py`, also extend the `EXPECTED_TOOL_NAMES` set (look for the literal set near the top of the file) with `"memory_remember"`, `"memory_recall"`, `"pool_handoff"`.

In `services/agent_mcp/tests/test_stdio_smoke.py`, find the ordered list of tool names asserted by the `tools/list` smoke and extend it with the 3 new names in the same order they appear in `_MODULES`.

- [ ] **Step 2: Run RED**

```bash
uv run --directory services/agent_mcp pytest tests/ -v
```

Expected: 3 failures (count assertions + the names-list / set assertions).

- [ ] **Step 3: Wire SPECs into the registry**

Open `services/agent_mcp/findevil_agent_mcp/tools/__init__.py`. Find the `_MODULES` tuple. Append `"memory_remember"`, `"memory_recall"`, `"pool_handoff"` (alphabetical or grouped — match the existing convention, which groups crypto/ACH first and the A3 additions last).

Do **not** edit `server.py` — it iterates `all_specs()` dynamically and picks up the new modules automatically.

- [ ] **Step 4: GREEN**

```bash
uv run --directory services/agent_mcp pytest tests/ -v
```

Expected: all 44 tests pass, including the now-13 tool-count assertion and the extended name list.

- [ ] **Step 5: Smoke-test stdio boot (already covered above)**

The stdio smoke test in `test_stdio_smoke.py` already runs as part of the full suite; no separate invocation needed unless you want to single it out.

- [ ] **Step 6: Commit**

```bash
git add services/agent_mcp/findevil_agent_mcp/tools/__init__.py services/agent_mcp/tests/test_registry.py services/agent_mcp/tests/test_server_boot.py services/agent_mcp/tests/test_stdio_smoke.py
git commit -m "feat(agent_mcp): register memory_* + pool_handoff (13 tools total) (A3 §2.2)"
```

---

# Phase 4 — Dashboard scaffold (`apps/web/`)

> **Gate before starting Phase 4**: open Anthropic Claude Design (<https://www.anthropic.com/news/claude-design-anthropic-labs>), prototype the 5-sprite layout against the audit JSONL schema (`services/agent/findevil_agent/events.py` for the `AgentEvent` union; `services/agent/findevil_agent/crypto/audit_log.py` for the on-disk line shape). Export the agreed sprite PNGs to `apps/web/public/sprites/` before writing the React components. Phases 4-6 below intentionally do not include hand-fabricated component test cases — write them after the design pass when the actual visual contract exists.

### Task 4.1: Next.js + Tailwind v4 + NES.css scaffold

- [ ] Create `apps/web/package.json` with deps: `next@15`, `react@19`, `react-dom@19`, `tailwindcss@4`, `nes.css@~2.3`, `chokidar@~4`, `ws@~8`, `zod@~3`. Dev deps: `typescript@~5`, `@types/node`, `@types/react`, `@types/ws`.
- [ ] Create `apps/web/next.config.ts`, `apps/web/tsconfig.json` (strict), `apps/web/tailwind.config.ts`.
- [ ] Create `apps/web/app/layout.tsx`, `apps/web/app/globals.css` with `@import "nes.css/css/nes.min.css";`.
- [ ] Create a placeholder `apps/web/app/page.tsx` rendering `<div className="nes-container with-title">Find Evil! Dashboard</div>`.
- [ ] Run `pnpm install --frozen-lockfile && pnpm --filter @findevil/web build && pnpm --filter @findevil/web dev`. Verify `localhost:3000` renders the placeholder.
- [ ] Commit `chore(web): scaffold Next.js + NES.css per A3 §2.2`.

### Task 4.2: WebSocket route + audit-log tail

- [ ] Create `apps/web/lib/audit-tail.ts` — chokidar watcher on a `case=` query param path, parses each new JSONL line, emits typed events.
- [ ] Create `apps/web/app/api/audit/route.ts` — Next.js route handler doing the WS upgrade and pushing tail events to the client.
- [ ] Write a failing integration test (Playwright or Vitest + supertest equivalent) that: starts the dev server, opens a WS to `/api/audit?case=<tmp>`, appends a line to `<tmp>/audit.jsonl`, expects the WS message within 500ms.
- [ ] Implement to GREEN.
- [ ] Commit `feat(web): WebSocket tail of audit JSONL (A3 §2.2)`.

### Task 4.3: pydantic-to-typescript codegen for audit event types

- [ ] Add a `pnpm --filter @findevil/web codegen:audit-types` script that invokes `pydantic-to-typescript` against `findevil_agent.events` → `apps/web/lib/audit-types.ts`.
- [ ] Document this script in `services/agent/README.md` (run after touching `events.py`).
- [ ] Commit `chore(web): pydantic-to-typescript codegen for audit event types`.

---

# Phase 5 — Sprite components

> **Prerequisite**: Phase 4 dev server runs + design pass complete + sprite PNGs in `apps/web/public/sprites/`.

### Task 5.1-5.5: Five sprite components

For each role (Pool A, Pool B, Verifier, Judge, Correlator):

- [ ] Create `apps/web/components/sprites/<Role>Sprite.tsx`. Component takes `state: 'idle' | 'working' | 'waiting' | 'verdict'` and renders the correct sprite frame.
- [ ] Write a Vitest snapshot test that renders each state and asserts the correct image src.
- [ ] Commit `feat(web): <role> pixel-art sprite component (A3 §2.2)`.

### Task 5.6: Wire sprites to live audit events

- [ ] Create `apps/web/lib/sprite-state.ts` — derives per-role state from the WS event stream (e.g., `tool_call_start` for `pool_a` → state='working'; `finding_approved` → state='verdict' for 1500ms then back to idle).
- [ ] Create `apps/web/app/page.tsx` proper — subscribes to the WS, renders all 5 sprites with their derived states.
- [ ] Manual verification: start the agent, run a smoke investigation, watch sprites animate.
- [ ] Commit `feat(web): wire sprites to live audit-log state derivation`.

---

# Phase 6 — AuditBeadString + supporting chrome

### Task 6.1: AuditBeadString component

- [ ] Create `apps/web/components/AuditBeadString.tsx`. One bead per `audit_append` event, color-coded by `kind` (NES.css palette).
- [ ] Hover bead → tooltip showing `seq`, `kind`, `prev_hash[:8]`, `line_hash[:8]`.

### Task 6.2: HashChainBadge component

- [ ] Create `apps/web/components/HashChainBadge.tsx`. Calls a `/api/verify-chain?case=` endpoint that runs the existing `audit_verify` MCP tool. Renders green/red.
- [ ] Add the `/api/verify-chain/route.ts` endpoint that subprocesses the Python MCP server's `audit_verify` tool.

### Task 6.3: FindingChip component

- [ ] Create `apps/web/components/FindingChip.tsx`. Renders `[CONFIRMED · tool_name · sha256:abc...]` styled per NES.css.
- [ ] Snapshot test for each confidence level (CONFIRMED / INFERRED / HYPOTHESIS).

### Task 6.4: End-to-end verification

- [ ] Run `bash scripts/find-evil-auto goldens/synthetic-benign/` in one terminal; `pnpm --filter @findevil/web dev` in another. Open `http://localhost:3000?case=<absolute case dir>`.
- [ ] Confirm all A3 §4 acceptance criteria: 13 MCP tools listed, dashboard renders, beads appear in real time, hash-chain badge green, sprites animate correctly.

### Task 6.5: Final commit

- [ ] Commit `feat(web): A3 dashboard end-to-end (sprites + audit beads + chain badge)`.

---

# Acceptance verification (recap A3 §4)

After all phases complete, run from repo root:

```bash
# Python tests
uv run --directory services/agent pytest tests/test_memory_store.py tests/test_acp_handoff.py -v
uv run --directory services/agent_mcp pytest tests/ -v

# .gitignore fix verified
git check-ignore git-hub-references/openclaw/README.md
# Expected output: git-hub-references/openclaw/README.md

# No-regression: existing 40 tests still green
uv run --directory services/agent_mcp pytest tests/ --co -q | wc -l
# Expected: ≥ 40 + new memory + new acp tests

# No openclaw/hermes/pixel imports leaked into shipping code
git grep -nE '(openclaw|hermes_agent|pixel_agents)' -- services/ apps/web/ agent-config/ \
  || echo "OK — no leaks"
# Expected: "OK — no leaks"

# Web e2e (manual)
pnpm --filter @findevil/web build
pnpm --filter @findevil/web dev
# Open http://localhost:3000?case=<absolute case dir>; verify all 5 sprites render
```

---

# Rollback (recap A3 §5)

The three additions revert independently — see A3 §5 for per-component instructions. Total full-A3 rollback: ~1 hour. The `.gitignore` fix should stay regardless.
