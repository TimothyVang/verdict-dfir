"""Pure recall/remember glue between the orchestrator and Hermes memory.

These helpers are deliberately I/O-free (no MCP, no store, no network) so the
recall-before-draft / remember-after-confirmed wiring is unit-testable apart
from the 334 KB ``find_evil_auto.py`` orchestrator. They also pin the "memory
is never evidence" invariant at the data-shape layer:

- ``attach_prior_observations`` returns a NEW finding dict and never touches the
  finding's ``tool_call_id`` (G1) — recall context never substitutes for the
  required evidence citation.
- ``hits_to_prior_observations`` emits only ``{case_id, ts, confidence}`` (G2) —
  no ``value`` / ``sha256`` / ``tool_call_id`` that could masquerade as
  current-case evidence.
- ``confirmed_findings_for_remember`` keeps only CONFIRMED findings (G5).
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

# IOC-shaped tokens worth a cross-case recall lookup. Conservative on purpose:
# sha256 hashes, IPv4 literals, and common executable/script filenames.
_IOC_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b[a-fA-F0-9]{64}\b"),
    re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    re.compile(r"\b[\w-]+\.(?:exe|dll|sys|ps1|bat|scr|vbs)\b", re.IGNORECASE),
)


def recall_terms_for_finding(finding: dict[str, Any]) -> list[str]:
    """Distinctive terms to query cross-case memory with before drafting.

    Pulls the MITRE technique and any IOC-shaped tokens from the description,
    de-duplicated with order preserved. Empty list = nothing worth recalling.
    """
    terms: list[str] = []
    technique = finding.get("mitre_technique")
    if isinstance(technique, str) and technique:
        terms.append(technique)
    description = finding.get("description")
    if isinstance(description, str):
        for pattern in _IOC_PATTERNS:
            terms.extend(match.group(0) for match in pattern.finditer(description))

    seen: set[str] = set()
    ordered: list[str] = []
    for term in terms:
        if term not in seen:
            seen.add(term)
            ordered.append(term)
    return ordered


def hits_to_prior_observations(hits: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Project recall hits down to NON-evidentiary context (G2).

    Only ``case_id``, ``ts``, and ``confidence`` survive; the evidence-bearing
    fields (``value``, ``sha256``, ``key``, ``kind``) are dropped so a recall
    hit can never be mistaken for current-case evidence.
    """
    return [
        {"case_id": hit["case_id"], "ts": hit["ts"], "confidence": hit["confidence"]}
        for hit in hits
    ]


def attach_prior_observations(
    finding: dict[str, Any], hits: list[dict[str, Any]]
) -> dict[str, Any]:
    """Return a NEW finding carrying recall context (G1).

    Immutable: the input finding is never mutated, and its ``tool_call_id`` (the
    real evidence citation) is preserved untouched. The attached
    ``prior_observations`` is context only.
    """
    return {**finding, "prior_observations": hits_to_prior_observations(hits)}


def confirmed_findings_for_remember(
    merged: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Keep only CONFIRMED findings — the only ones worth seeding future cases (G5)."""
    return [f for f in merged if f.get("confidence") == "CONFIRMED"]


def remember_payload_for_finding(finding: dict[str, Any]) -> dict[str, Any] | None:
    """Build a ``memory_remember`` payload for a CONFIRMED finding, else None.

    Returns ``{kind, key, value, sha256}`` (case_id is supplied by the caller).
    The key is the MITRE technique when present, else the finding id. The sha256
    is computed over a canonical ``key\\ndescription`` preimage so the same
    finding is stable across runs.
    """
    if finding.get("confidence") != "CONFIRMED":
        return None
    description = finding.get("description") or ""
    key = finding.get("mitre_technique") or finding.get("finding_id") or ""
    if not key or not description:
        return None
    preimage = f"{key}\n{description}".encode()
    digest = hashlib.sha256(preimage).hexdigest()
    return {
        "kind": "finding_summary",
        "key": str(key),
        "value": str(description),
        "sha256": f"sha256:{digest}",
    }


__all__ = [
    "attach_prior_observations",
    "confirmed_findings_for_remember",
    "hits_to_prior_observations",
    "recall_terms_for_finding",
    "remember_payload_for_finding",
]
