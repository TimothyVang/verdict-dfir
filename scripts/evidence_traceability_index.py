#!/usr/bin/env python3
"""evidence_traceability_index — deterministic, no-LLM evidence traceability index.

Given a completed run output directory (e.g. ``tmp/auto-runs/<case-id>``), this
module emits a join table that links, for every Finding in ``verdict.json``:

    claim (description) -> asserted entities/values
                        -> finding_id
                        -> each cited tool_call_id
                        -> the exact audit.jsonl line number + output_sha256

It is **read-only** over ``verdict.json`` and ``audit.jsonl``: no model, no
network, no MCP server, no mutation. It is a pure presentation / forensic-
navigation aid — per CLAUDE.md, indexes and visuals never create Findings,
satisfy citations, or upgrade confidence. The custody spine (verify_finding, the
audit chain, the signed manifest) is untouched; this only *navigates* it.

A citation is marked RESOLVED when its tool_call_id maps to a ``tool_call_output``
record whose audit line is intact (in canonical form with an unbroken prev_hash
chain). Any broken link — a missing tool_call_output, or a cited line that has
been tampered so its hash chain no longer holds — surfaces the citation, and the
owning Finding, as UNRESOLVED.

Usage:
    python -m scripts.evidence_traceability_index <run-dir> [--json]

    <run-dir>   a directory holding verdict.json and audit.jsonl
    --json      print only the machine-readable JSON index (default prints a
                human-readable table followed by nothing else)

Exit code 0 iff every Finding resolves to an intact citation chain; 1 otherwise
(missing inputs, malformed JSON, or any UNRESOLVED Finding).
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

SCHEMA = "verdict.evidence-traceability-index/v1"

_CANONICAL_SEPARATORS = (",", ":")

# Finding fields that name a concrete entity/value worth surfacing in the join.
# Kept as a fixed allow-list so the index is deterministic and evidence-agnostic
# (it reports whatever the finding actually parsed; it hard-codes no image value).
_ENTITY_FIELDS = (
    "host",
    "artifact_path",
    "artifact_offset",
    "event_id",
    "event_type",
    "mitre_technique",
)


def _canonicalize(obj: Any) -> bytes:
    """RFC-8785-compatible canonical bytes — matches audit_log.canonicalize_json."""
    return json.dumps(
        obj, sort_keys=True, separators=_CANONICAL_SEPARATORS, ensure_ascii=True
    ).encode("ascii")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class IndexError_(RuntimeError):
    """A run directory is missing inputs or holds malformed JSON."""


def _load_verdict(path: Path) -> dict[str, Any]:
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise IndexError_(f"unable to read {path.name}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise IndexError_(f"{path.name} is not valid JSON: {exc}") from exc
    if not isinstance(obj, dict):
        raise IndexError_(f"{path.name} is not a JSON object")
    return obj


def _load_audit(audit_path: Path) -> tuple[list[dict[str, Any]], int | None]:
    """Parse audit.jsonl and verify the hash chain.

    Returns ``(records, first_break_seq)``. Each record gains a synthetic
    ``_line`` (1-based file line number) and ``_chain_ok`` flag. ``_chain_ok`` is
    True only while the canonical form matches the stored bytes and prev_hash
    links to the previous line; once the chain breaks, every later record is
    marked not-ok (its provenance can no longer be trusted offline).
    ``first_break_seq`` is the seq of the first broken record, or None if intact.
    """
    if not audit_path.is_file():
        raise IndexError_(f"no audit.jsonl in {audit_path.parent}")
    records: list[dict[str, Any]] = []
    prev_hash = ""
    expected_seq = 0
    chain_intact = True
    first_break: int | None = None
    line_no = 0
    with audit_path.open("rb") as handle:
        for raw in handle:
            line_no += 1
            raw = raw.rstrip(b"\n")
            if not raw:
                continue
            try:
                obj = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise IndexError_(f"line {line_no}: invalid JSON: {exc}") from exc
            if not isinstance(obj, dict):
                raise IndexError_(f"line {line_no}: not a JSON object")
            ok = (
                chain_intact
                and obj.get("seq") == expected_seq
                and obj.get("prev_hash") == prev_hash
                and _canonicalize(obj) == raw
            )
            if not ok and chain_intact:
                chain_intact = False
                seq = obj.get("seq")
                first_break = seq if isinstance(seq, int) else expected_seq
            obj["_line"] = line_no
            obj["_chain_ok"] = ok
            records.append(obj)
            prev_hash = _sha256(raw)
            expected_seq += 1
    return records, first_break


def _index_tool_outputs(records: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Map tool_call_id -> the tool_call_output record's join fields.

    Last write wins on a duplicate tool_call_id (the latest recorded output). The
    tool name is read from the tool_call_output payload when present, else from the
    matching tool_call_start (real audit logs record the name on the start record).
    """
    start_tools: dict[str, str] = {}
    for record in records:
        if record.get("kind") != "tool_call_start":
            continue
        payload = record.get("payload", {})
        tcid = payload.get("tool_call_id")
        if tcid and payload.get("tool"):
            start_tools[str(tcid)] = str(payload["tool"])

    index: dict[str, dict[str, Any]] = {}
    for record in records:
        if record.get("kind") != "tool_call_output":
            continue
        payload = record.get("payload", {})
        tcid = payload.get("tool_call_id")
        if not tcid:
            continue
        index[str(tcid)] = {
            "audit_line": record.get("_line"),
            "seq": record.get("seq"),
            "tool": payload.get("tool") or start_tools.get(str(tcid)),
            "output_sha256": payload.get("output_hash"),
            "chain_ok": bool(record.get("_chain_ok")),
        }
    return index


def _finding_citations(finding: dict[str, Any]) -> list[str]:
    """Sorted, de-duplicated tool_call_ids a finding cites (primary + derived)."""
    cited: set[str] = set()
    primary = finding.get("tool_call_id")
    if primary:
        cited.add(str(primary))
    derived = finding.get("derived_from")
    if isinstance(derived, list):
        for tcid in derived:
            if tcid:
                cited.add(str(tcid))
    return sorted(cited)


def _finding_entities(finding: dict[str, Any]) -> dict[str, Any]:
    """The asserted entities/values the finding names, from the fixed allow-list."""
    return {
        field: finding[field]
        for field in _ENTITY_FIELDS
        if finding.get(field) not in (None, "", [])
    }


def _resolve_citation(tcid: str, outputs: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Resolve one tool_call_id against the audit tool_call_output index."""
    hit = outputs.get(tcid)
    if hit is None:
        return {
            "tool_call_id": tcid,
            "status": "UNRESOLVED",
            "reason": "no tool_call_output in audit.jsonl",
            "audit_line": None,
            "seq": None,
            "tool": None,
            "output_sha256": None,
        }
    if not hit["chain_ok"]:
        return {
            "tool_call_id": tcid,
            "status": "UNRESOLVED",
            "reason": "audit line failed hash-chain verification (tampered)",
            "audit_line": hit["audit_line"],
            "seq": hit["seq"],
            "tool": hit["tool"],
            "output_sha256": hit["output_sha256"],
        }
    return {
        "tool_call_id": tcid,
        "status": "RESOLVED",
        "reason": None,
        "audit_line": hit["audit_line"],
        "seq": hit["seq"],
        "tool": hit["tool"],
        "output_sha256": hit["output_sha256"],
    }


def build_index(run_dir: Path) -> dict[str, Any]:
    """Build the deterministic traceability index for a run directory."""
    verdict = _load_verdict(run_dir / "verdict.json")
    records, first_break = _load_audit(run_dir / "audit.jsonl")
    outputs = _index_tool_outputs(records)

    findings_out: list[dict[str, Any]] = []
    resolved = 0
    for finding in verdict.get("findings") or []:
        fid = str(finding.get("finding_id") or finding.get("id") or "?")
        citations = [
            _resolve_citation(tcid, outputs) for tcid in _finding_citations(finding)
        ]
        # A finding with no citations cannot be traced; a single broken citation
        # taints the whole finding.
        status = (
            "RESOLVED"
            if citations and all(c["status"] == "RESOLVED" for c in citations)
            else "UNRESOLVED"
        )
        if status == "RESOLVED":
            resolved += 1
        desc = finding.get("description") or ""
        findings_out.append(
            {
                "finding_id": fid,
                "confidence": finding.get("confidence"),
                "mitre_technique": finding.get("mitre_technique"),
                "claim": desc,
                "entities": _finding_entities(finding),
                "citations": citations,
                "status": status,
            }
        )

    total = len(findings_out)
    return {
        "schema": SCHEMA,
        "run_dir": run_dir.name,
        "case_id": verdict.get("case_id"),
        "verdict": verdict.get("verdict"),
        "audit_chain": {
            "records": len(records),
            "intact": first_break is None,
            "first_break_seq": first_break,
        },
        "summary": {
            "findings": total,
            "resolved": resolved,
            "unresolved": total - resolved,
        },
        "findings": findings_out,
    }


def _render_table(index: dict[str, Any]) -> str:
    """Human-readable rendering of the join table."""
    lines: list[str] = []
    lines.append(f"EVIDENCE TRACEABILITY INDEX -- {index['run_dir']}")
    chain = index["audit_chain"]
    chain_state = (
        f"OK ({chain['records']} records)"
        if chain["intact"]
        else f"BROKEN at seq {chain['first_break_seq']} ({chain['records']} records)"
    )
    summary = index["summary"]
    lines.append(
        f"verdict: {index.get('verdict')}  |  audit chain: {chain_state}  |  "
        f"findings: {summary['resolved']}/{summary['findings']} resolved"
    )
    for finding in index["findings"]:
        lines.append("")
        lines.append(
            f"[{finding['status']}] {finding['finding_id']}  "
            f"({finding.get('confidence') or '?'})  "
            f"{finding.get('mitre_technique') or '-'}"
        )
        claim = finding["claim"].replace("\n", " ")
        if len(claim) > 100:
            claim = claim[:97] + "..."
        lines.append(f"  claim: {claim}")
        if finding["entities"]:
            for key in sorted(finding["entities"]):
                lines.append(f"  entity {key}: {finding['entities'][key]}")
        if not finding["citations"]:
            lines.append("  citation: (none) -- finding is not traceable")
        for cit in finding["citations"]:
            if cit["status"] == "RESOLVED":
                sha = (cit["output_sha256"] or "")[:16]
                lines.append(
                    f"  citation {cit['tool_call_id']} -> audit line {cit['audit_line']} "
                    f"(seq {cit['seq']}, tool {cit['tool']}, output_sha256 {sha}...)"
                )
            else:
                lines.append(
                    f"  citation {cit['tool_call_id']} -> UNRESOLVED: {cit['reason']}"
                )
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    args = [a for a in argv[1:] if a != "--json"]
    want_json = "--json" in argv[1:]
    if len(args) != 1:
        sys.stderr.write(__doc__ or "")
        return 2
    run_dir = Path(args[0])
    try:
        index = build_index(run_dir)
    except IndexError_ as exc:
        if want_json:
            print(
                json.dumps(
                    {"schema": SCHEMA, "error": str(exc)}, indent=2, sort_keys=True
                )
            )
        else:
            print(f"TRACEABILITY INDEX ERROR: {exc}")
        return 1

    if want_json:
        print(json.dumps(index, indent=2, sort_keys=True))
    else:
        print(_render_table(index))

    return 0 if index["summary"]["unresolved"] == 0 and index["findings"] else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
