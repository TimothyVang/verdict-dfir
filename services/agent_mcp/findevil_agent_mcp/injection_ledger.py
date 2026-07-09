"""Injection-alert ledger — a counts-only sidecar of neutralization events.

The Python half of the injection-alert sidecar (mirrored by
``services/mcp/src/injection_ledger.rs``). When the MCP-output->LLM sanitizer
(:mod:`findevil_agent_mcp.sanitize`) neutralizes attacker-controlled evidence
text at the boundary, the per-pattern counts are already computed. This module
appends one JSONL record per neutralization event to a sidecar ledger so an
operator -- and the ``judge_findings`` escalation hook -- can see WHICH tool
outputs carried injection attempts.

Custody boundary (why this is safe to add):

  * SIDECAR, never the hash-chained ``audit.jsonl`` and never a Merkle leaf.
    Nothing here feeds ``verify_finding``, the signed manifest, or
    ``manifest_verify``; the audit chain still attests exactly the sanitized
    bytes the model saw.
  * COUNTS ONLY -- never the neutralized payload -- mirroring the existing
    "only counts are logged" rule in :mod:`findevil_agent_mcp.sanitize`, so the
    ledger itself cannot re-leak the injection attempt. The optional
    ``output_sha256`` is a digest of the *already-sanitized* output (the same
    value the audit chain records), not the payload, and is the correlation key
    an orchestrator uses to map a neutralization back to a ``tool_call_id``.
  * BEST-EFFORT -- a ledger I/O failure must never break a tool call or alter
    the sealed output, so :func:`record_neutralization` swallows write errors.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any

LEDGER_FILENAME = "injection_alerts.jsonl"
RECORD_KIND = "injection_neutralized"


def _now_iso() -> str:
    """UTC ISO-8601 with a trailing ``Z`` (CLAUDE.md timestamp rule)."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def resolve_ledger_path() -> Path | None:
    """Resolve the sidecar ledger path, or ``None`` when no contained home exists.

    Order:

      1. ``FINDEVIL_INJECTION_LEDGER`` -- explicit ledger-file override.
      2. ``FINDEVIL_HOME`` -- a ``injection_alerts.jsonl`` sibling of the case
         store (where the contained runtime state already lives).

    There is deliberately **no** ``$HOME`` fallback: a stray neutralization must
    never write outside a contained run (CLAUDE.md containment). ``None`` means
    "nowhere safe to write" and the caller no-ops.
    """
    override = os.environ.get("FINDEVIL_INJECTION_LEDGER")
    if override:
        return Path(override)
    home = os.environ.get("FINDEVIL_HOME")
    if home:
        return Path(home) / LEDGER_FILENAME
    return None


def build_record(
    counts: Mapping[str, int],
    *,
    tool: str | None = None,
    tool_call_id: str | None = None,
    output_sha256: str | None = None,
    ts: str | None = None,
) -> dict[str, Any]:
    """Build one counts-only ledger record (pure; no I/O).

    ``counts`` maps each neutralized pattern id (a role-token id or
    ``invisible_unicode``) to how many times it fired -- exactly the tally
    :func:`findevil_agent_mcp.sanitize.sanitize_value` returns. The payload is
    never included.
    """
    patterns = {str(k): int(v) for k, v in counts.items()}
    return {
        "ts": ts or _now_iso(),
        "kind": RECORD_KIND,
        "tool": tool,
        "tool_call_id": tool_call_id,
        "output_sha256": output_sha256,
        "patterns": patterns,
        "total": sum(patterns.values()),
    }


def record_neutralization(
    counts: Mapping[str, int],
    *,
    tool: str | None = None,
    tool_call_id: str | None = None,
    output_text: str | None = None,
    ledger_path: Path | None = None,
) -> Path | None:
    """Append one neutralization event to the sidecar ledger (best-effort).

    No-ops (returns ``None``) when ``counts`` is empty or no contained ledger
    path resolves. When ``output_text`` is supplied, its SHA-256 is recorded as
    the correlation key (a digest of the already-sanitized output, not the
    payload). Write failures are swallowed so the tool path is never broken.

    Returns the ledger path on a successful append, else ``None``.
    """
    if not counts or sum(int(v) for v in counts.values()) == 0:
        return None
    path = ledger_path or resolve_ledger_path()
    if path is None:
        return None
    output_sha256 = (
        sha256(output_text.encode("utf-8")).hexdigest() if output_text is not None else None
    )
    record = build_record(
        counts,
        tool=tool,
        tool_call_id=tool_call_id,
        output_sha256=output_sha256,
    )
    line = json.dumps(record, sort_keys=True, separators=(",", ":"))
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
    except OSError:
        # Best-effort sidecar: a ledger write must never break a tool call.
        return None
    return path


__all__ = [
    "LEDGER_FILENAME",
    "RECORD_KIND",
    "build_record",
    "record_neutralization",
    "resolve_ledger_path",
]
