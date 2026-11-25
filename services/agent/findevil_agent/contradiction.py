"""Contradiction-detection node — fires BEFORE the judge.

Spec #2 §8.3 + ``project_adversarial_agents_pattern.md``. The M4
moat: when Pool A (persistence-biased) and Pool B (exfil-biased)
disagree about the same artifact, the user sees the disagreement
*before* the judge tries to reconcile. Most submissions hide
contradictions inside a consensus output; we surface them.

Detection rules (in order of severity):

1. **Direct artifact contradiction.** Two findings cite the same
   ``tool_call_id`` but with confidence labels at opposite ends of
   the hierarchy (e.g. one CONFIRMED, the other HYPOTHESIS).
2. **MITRE technique conflict.** Same artifact_path, same
   tool_call_id, but different mitre_technique values.
3. **Pool disagreement on artifact_path.** Both pools touched the
   same ``artifact_path`` but produced findings with different
   ``description`` themes (heuristic: token-overlap < 30%).

The detector is pure: deterministic given the same inputs, no LLM.
The Python agent runs it inline as a LangGraph node before the
judge fires; emitted ``ContradictionFound`` events go straight to
the SSE bus and the audit log.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

from findevil_agent.events import ContradictionFound, Finding

_CONFIDENCE_RANK = {"CONFIRMED": 2, "INFERRED": 1, "HYPOTHESIS": 0}


@dataclass(frozen=True)
class ContradictionPair:
    """A detected contradiction before it becomes an event."""

    pool_a_finding: Finding
    pool_b_finding: Finding
    reason: str


def detect_contradictions(
    pool_a: Iterable[Finding],
    pool_b: Iterable[Finding],
) -> list[ContradictionPair]:
    """Pairwise scan of the two pool outputs.

    The cost is O(|A| * |B|); both pools cap at ~50 findings per
    Spec #2 design budget so this stays well under a millisecond
    in practice.
    """
    a_list = [f for f in pool_a if (f.pool_origin or "A") == "A"]
    b_list = [f for f in pool_b if (f.pool_origin or "B") == "B"]
    contradictions: list[ContradictionPair] = []

    for a in a_list:
        for b in b_list:
            reason = _classify_pair(a, b)
            if reason is not None:
                contradictions.append(
                    ContradictionPair(pool_a_finding=a, pool_b_finding=b, reason=reason)
                )
    return contradictions


def _classify_pair(a: Finding, b: Finding) -> str | None:
    """Decide whether ``a`` and ``b`` contradict. Returns a reason
    string when they do, ``None`` otherwise.
    """
    # Rule 1: same tool_call_id, opposite confidence ends.
    if (
        a.tool_call_id
        and a.tool_call_id == b.tool_call_id
        and _is_confidence_extreme(a.confidence, b.confidence)
    ):
        return (
            f"same tool_call_id={a.tool_call_id} cited with "
            f"{a.confidence} (Pool A) vs {b.confidence} (Pool B)"
        )

    # Rule 2: same artifact + same tool_call_id, different MITRE.
    if (
        a.tool_call_id
        and a.tool_call_id == b.tool_call_id
        and a.artifact_path == b.artifact_path
        and a.mitre_technique
        and b.mitre_technique
        and a.mitre_technique != b.mitre_technique
    ):
        return (
            f"same artifact {a.artifact_path!r}, different MITRE technique "
            f"({a.mitre_technique} vs {b.mitre_technique})"
        )

    # Rule 3: same artifact_path, low token overlap → pool disagreement.
    if (
        a.artifact_path
        and a.artifact_path == b.artifact_path
        and _token_overlap(a.description, b.description) < 0.30
    ):
        return f"both pools cite artifact {a.artifact_path!r} but description token-overlap < 30%"

    return None


def _is_confidence_extreme(c_a: str, c_b: str) -> bool:
    """True if the two confidence labels are at opposite ends of the
    CONFIRMED → INFERRED → HYPOTHESIS hierarchy.

    CONFIRMED vs HYPOTHESIS counts; CONFIRMED vs INFERRED does not
    (one tier apart isn't a contradiction — it's a calibration
    difference and the judge handles it).
    """
    rank_a = _CONFIDENCE_RANK.get(c_a, 1)
    rank_b = _CONFIDENCE_RANK.get(c_b, 1)
    return abs(rank_a - rank_b) >= 2


_WORD_RE = re.compile(r"[a-z0-9_]+")


def _token_overlap(a: str, b: str) -> float:
    """Jaccard token overlap on lowercased word-ish tokens."""
    tokens_a = set(_WORD_RE.findall(a.lower()))
    tokens_b = set(_WORD_RE.findall(b.lower()))
    if not tokens_a and not tokens_b:
        return 1.0  # both empty = perfectly agree (trivially)
    if not tokens_a or not tokens_b:
        return 0.0
    return len(tokens_a & tokens_b) / len(tokens_a | tokens_b)


def to_events(
    contradictions: list[ContradictionPair],
    *,
    case_id: str,
    resolution_required: bool,
) -> list[ContradictionFound]:
    """Project ``ContradictionPair`` objects into wire-format events.

    ``resolution_required`` is True for interactive runs (the user
    must Trust A / Trust B / Flag in the UI before the judge fires)
    and False for ``--unattended`` runs (all auto-pass to the judge
    with the contradiction logged but not gated on user input).
    """
    out: list[ContradictionFound] = []
    for i, pair in enumerate(contradictions, start=1):
        a = pair.pool_a_finding
        b = pair.pool_b_finding
        conflicting_ids: list[str] = []
        if a.tool_call_id:
            conflicting_ids.append(a.tool_call_id)
        if b.tool_call_id and b.tool_call_id != a.tool_call_id:
            conflicting_ids.append(b.tool_call_id)
        out.append(
            ContradictionFound(
                case_id=case_id,
                contradiction_id=f"ctr-{i:04d}",
                pool_a_claim=_summarize(a),
                pool_b_claim=_summarize(b),
                conflicting_tool_call_ids=conflicting_ids,
                resolution_required=resolution_required,
            )
        )
    return out


def _summarize(finding: Finding) -> str:
    """One-line claim summary for the UI's Trust A/B picker."""
    parts = [f"[{finding.confidence}]"]
    if finding.mitre_technique:
        parts.append(finding.mitre_technique)
    parts.append(finding.description[:200])
    return " ".join(parts)


__all__ = [
    "ContradictionPair",
    "detect_contradictions",
    "to_events",
]
