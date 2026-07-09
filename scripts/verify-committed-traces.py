#!/usr/bin/env python3
"""verify-committed-traces — offline integrity check for the committed audit traces.

A judge can run this with NOTHING but a Python 3 interpreter — no MCP server, no
venv, no network, no API key — to re-prove that the audit traces committed under
docs/release-evidence/ are internally consistent and have not been edited since
they were sealed.

Two committed trace shapes are recognised, each verified against its sidecar
``*-summary.json``:

1. Hash-chained excerpt (e.g. natural-self-correction-trace.jsonl). Every record
   carries ``seq``, ``ts``, and ``prev_hash``. We re-canonicalize each line
   (RFC-8785-compatible, identical to findevil_agent.crypto.audit_log), confirm
   the byte-for-byte canonical form, confirm ``seq`` is contiguous, and replay the
   ``prev_hash`` chain within the contiguous window (record N's prev_hash equals
   the SHA-256 of record N-1's raw canonical line). We also confirm the file's
   SHA-256 matches the summary's ``excerpt_sha256``. Any edit changes the canonical
   bytes, breaks the chain, and changes the file digest.

2. Flat structured trace (e.g. evtx-security-log-clear-trace.jsonl). Records carry
   ``seq`` and per-tool ``output_hash`` values but no prev_hash. We confirm ``seq``
   is contiguous from 0, the record count matches ``committed_trace.record_count``,
   and the summary's ``spot_check`` mapping resolves: the spot-checked
   ``tool_output_seq`` record exists, names ``tool_name``, and carries the exact
   ``tool_output_sha256``. We also confirm the ``case_open`` output hash equals the
   summary's evidence SHA-256 when both are present.

Usage:
    scripts/verify-committed-traces.py [evidence-dir]

    [evidence-dir]  directory holding the committed *-trace*.jsonl + *-summary.json
                    files (default: docs/release-evidence/).

Exit code 0 iff every discovered trace verifies; non-zero otherwise.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent
DEFAULT_EVIDENCE_DIR = REPO / "docs" / "release-evidence"
_CANONICAL_SEPARATORS = (",", ":")


def _canonicalize(obj: Any) -> bytes:
    """RFC-8785-compatible canonical bytes — identical to audit_log.canonicalize_json."""
    return json.dumps(
        obj, sort_keys=True, separators=_CANONICAL_SEPARATORS, ensure_ascii=True
    ).encode("ascii")


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class TraceError(RuntimeError):
    """A committed trace is malformed or its integrity check failed."""


def _load_jsonl(path: Path) -> list[tuple[bytes, dict[str, Any]]]:
    """Return (raw_line_bytes, parsed_record) pairs, skipping blank lines."""
    records: list[tuple[bytes, dict[str, Any]]] = []
    with path.open("rb") as handle:
        for index, raw in enumerate(handle):
            raw = raw.rstrip(b"\n")
            if not raw:
                continue
            try:
                obj = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise TraceError(
                    f"{path.name}: line {index}: invalid JSON: {exc}"
                ) from exc
            if not isinstance(obj, dict):
                raise TraceError(f"{path.name}: line {index}: not a JSON object")
            records.append((raw, obj))
    if not records:
        raise TraceError(f"{path.name}: no records")
    return records


def _verify_chained_trace(trace: Path, summary: dict[str, Any]) -> str:
    """Re-canonicalize, replay the prev_hash window, and match excerpt_sha256."""
    records = _load_jsonl(trace)
    prev_raw: bytes | None = None
    seq_prev: int | None = None
    for raw, obj in records:
        seq = obj.get("seq")
        if not isinstance(seq, int):
            raise TraceError(f"{trace.name}: record missing integer seq")
        if seq_prev is not None and seq != seq_prev + 1:
            raise TraceError(f"{trace.name}: seq not contiguous ({seq_prev} -> {seq})")
        if _canonicalize(obj) != raw:
            raise TraceError(
                f"{trace.name}: seq {seq}: line is not in canonical form (tampered)"
            )
        if prev_raw is not None:
            expected = _sha256_bytes(prev_raw)
            if obj.get("prev_hash") != expected:
                raise TraceError(
                    f"{trace.name}: seq {seq}: prev_hash break "
                    f"(declared={obj.get('prev_hash')!r}, expected={expected!r})"
                )
        prev_raw = raw
        seq_prev = seq

    declared = summary.get("excerpt_sha256")
    if not isinstance(declared, str):
        raise TraceError(f"{trace.name}: summary has no excerpt_sha256 to anchor")
    actual = _sha256_bytes(trace.read_bytes())
    if actual != declared:
        raise TraceError(
            f"{trace.name}: file SHA-256 {actual} != summary excerpt_sha256 {declared}"
        )
    return (
        f"hash-chained: {len(records)} records, seq contiguous, every line canonical, "
        f"prev_hash chain intact, excerpt_sha256 matches"
    )


def _verify_flat_trace(trace: Path, summary: dict[str, Any]) -> str:
    """Confirm seq contiguity, record count, and the summary spot-check mapping."""
    records = _load_jsonl(trace)
    by_seq: dict[int, dict[str, Any]] = {}
    for index, (_raw, obj) in enumerate(records):
        seq = obj.get("seq")
        if seq != index:
            raise TraceError(f"{trace.name}: expected seq={index}, got {seq!r}")
        by_seq[seq] = obj

    committed = summary.get("committed_trace") or {}
    declared_count = committed.get("record_count")
    if isinstance(declared_count, int) and declared_count != len(records):
        raise TraceError(
            f"{trace.name}: record_count {len(records)} != summary {declared_count}"
        )

    spot = summary.get("spot_check") or {}
    out_seq = spot.get("tool_output_seq")
    if not isinstance(out_seq, int):
        raise TraceError(f"{trace.name}: summary has no spot_check.tool_output_seq")
    output_record = by_seq.get(out_seq)
    if output_record is None:
        raise TraceError(f"{trace.name}: spot_check tool_output_seq {out_seq} missing")

    expected_tool = spot.get("tool_name")
    if expected_tool and output_record.get("tool") != expected_tool:
        raise TraceError(
            f"{trace.name}: spot_check seq {out_seq} tool "
            f"{output_record.get('tool')!r} != summary {expected_tool!r}"
        )

    expected_hash = spot.get("tool_output_sha256")
    if not isinstance(expected_hash, str):
        raise TraceError(f"{trace.name}: summary has no spot_check.tool_output_sha256")
    if output_record.get("output_hash") != expected_hash:
        raise TraceError(
            f"{trace.name}: spot_check seq {out_seq} output_hash "
            f"{output_record.get('output_hash')!r} != summary {expected_hash!r}"
        )

    evidence = summary.get("evidence") or {}
    evidence_sha = evidence.get("sha256")
    if isinstance(evidence_sha, str):
        case_open_outputs = [
            obj
            for _raw, obj in records
            if obj.get("tool") == "case_open" and obj.get("kind") == "tool_call_output"
        ]
        for obj in case_open_outputs:
            if obj.get("output_hash") != evidence_sha:
                raise TraceError(
                    f"{trace.name}: case_open output_hash "
                    f"{obj.get('output_hash')!r} != summary evidence.sha256 {evidence_sha!r}"
                )

    return (
        f"flat structured: {len(records)} records, seq contiguous from 0, "
        f"spot-check finding->tool_call hash matches, evidence hash matches"
    )


def _is_chained(records: list[tuple[bytes, dict[str, Any]]]) -> bool:
    """A trace is treated as hash-chained iff its first record carries prev_hash."""
    return "prev_hash" in records[0][1]


def _summary_for(trace: Path) -> Path | None:
    """Resolve the sidecar summary JSON for a committed trace, if present."""
    stem = trace.name[: -len(".jsonl")]
    candidates = [
        trace.with_name(f"{stem}-summary.json"),
        trace.with_name(f"{stem.replace('-trace', '')}-summary.json"),
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def _load_summary(path: Path) -> dict[str, Any]:
    obj = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(obj, dict):
        raise TraceError(f"{path.name}: summary is not a JSON object")
    return obj


def verify_dir(evidence_dir: Path) -> int:
    traces = sorted(evidence_dir.glob("*-trace*.jsonl"))
    if not traces:
        print(
            f"no committed *-trace*.jsonl traces under {evidence_dir}", file=sys.stderr
        )
        return 1

    failures = 0
    for trace in traces:
        summary_path = _summary_for(trace)
        if summary_path is None:
            print(f"  [FAIL]  {trace.name}  -  no sidecar summary JSON found")
            failures += 1
            continue
        try:
            summary = _load_summary(summary_path)
            records = _load_jsonl(trace)
            if _is_chained(records):
                detail = _verify_chained_trace(trace, summary)
            else:
                detail = _verify_flat_trace(trace, summary)
        except TraceError as exc:
            print(f"  [FAIL]  {trace.name}  -  {exc}")
            failures += 1
            continue
        print(f"  [PASS]  {trace.name}  -  {detail}")

    if failures:
        print(f"committed-trace verification: {failures} of {len(traces)} FAILED")
        return 1
    print(f"committed-trace verification: all {len(traces)} traces verified")
    return 0


def main(argv: list[str]) -> int:
    evidence_dir = Path(argv[1]).resolve() if len(argv) > 1 else DEFAULT_EVIDENCE_DIR
    if not evidence_dir.is_dir():
        print(f"not a directory: {evidence_dir}", file=sys.stderr)
        return 2
    return verify_dir(evidence_dir)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
