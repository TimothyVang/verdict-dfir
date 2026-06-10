"""Cross-artifact correlator — enforces ``SOUL.md`` rules.

Spec #2 §8.1 (Correlate stage) + ``agent-config/SOUL.md`` invariant
"Execution claims need ≥2 artifact classes." This module is the
last gate before the verdict is assembled — it walks the merged
finding list and downgrades any "execution"-flavored claim whose
own description doesn't carry corroboration from a second
execution-artifact source (prefetch + registry pair, or EDR-tier
telemetry). Corroboration must appear in the Finding itself; other
findings elsewhere in the run do NOT corroborate it (the report-QA
gate, which sees timeline event linkage, is the layer that can join
same-binary/same-time findings across classes).

It also enforces the Amcache caveat (per
``agent-config/MEMORY.md``): ``Amcache LastModified`` is
catalog-registration time, NOT execution. A Finding that cites
Amcache as its only execution evidence is downgraded.

Pure logic — no LLM calls, no I/O. Deterministic given the same
inputs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from findevil_agent.events import Finding
from findevil_agent.execution_claim import is_execution_claim

# Amcache-only execution evidence — the SOUL.md / MEMORY.md
# explicit caveat: Amcache LastModified is registration, not run.
_AMCACHE_RE = re.compile(r"\bamcache\b", re.IGNORECASE)
_PREFETCH_RE = re.compile(r"\bprefetch\b", re.IGNORECASE)
_SHIMCACHE_RE = re.compile(r"\b(?:shimcache|appcompatcache)\b", re.IGNORECASE)
# UserAssist (HKCU\...\Explorer\UserAssist) is a per-user GUI-execution record
# from a different subsystem than the OS prefetcher, so Prefetch + UserAssist is
# an independent two-artifact-class execution corroboration (peer of Amcache /
# ShimCache).
_USERASSIST_RE = re.compile(r"\buserassist\b", re.IGNORECASE)
_EDR_RE = re.compile(r"\b(?:sysmon|edr|carbon[\s-]?black|crowdstrike)\b", re.IGNORECASE)


@dataclass(frozen=True)
class CorrelationOutcome:
    """Per-finding decision the correlator made."""

    finding_id: str
    action: str  # "kept" | "downgraded" | "rejected"
    reason: str


def correlate(
    findings: list[Finding],
) -> tuple[list[Finding], list[CorrelationOutcome]]:
    """Walk findings and apply SOUL.md cross-artifact rules.

    Returns a tuple of (refined_findings, outcomes). ``outcomes`` is
    one entry per input Finding describing what the correlator did.
    """
    refined: list[Finding] = []
    outcomes: list[CorrelationOutcome] = []

    for f in findings:
        if not _is_execution_claim(f):
            refined.append(f)
            outcomes.append(
                CorrelationOutcome(
                    finding_id=f.finding_id, action="kept", reason="non-execution claim"
                )
            )
            continue

        # Execution claim — apply cross-artifact rule.
        # Strong corroboration: prefetch paired with a second execution registry
        # artifact (Amcache / ShimCache / UserAssist) OR EDR-tier (Sysmon /
        # Carbon Black / CrowdStrike) telemetry mentioned in this Finding's
        # description.
        own_text = f.description.lower()
        has_strong_corroboration = (
            _PREFETCH_RE.search(own_text)
            and (
                _AMCACHE_RE.search(own_text)
                or _SHIMCACHE_RE.search(own_text)
                or _USERASSIST_RE.search(own_text)
            )
        ) or _EDR_RE.search(own_text) is not None

        # Weak: only Amcache cited.
        amcache_only = (
            _AMCACHE_RE.search(own_text)
            and not _PREFETCH_RE.search(own_text)
            and not _SHIMCACHE_RE.search(own_text)
            and not _EDR_RE.search(own_text)
        )

        if amcache_only:
            refined.append(_downgrade(f))
            outcomes.append(
                CorrelationOutcome(
                    finding_id=f.finding_id,
                    action="downgraded",
                    reason="Amcache LastModified is catalog-registration, not execution",
                )
            )
        elif has_strong_corroboration:
            refined.append(f)
            outcomes.append(
                CorrelationOutcome(
                    finding_id=f.finding_id,
                    action="kept",
                    reason="execution corroborated in-finding by prefetch+registry pair or EDR telemetry",
                )
            )
        else:
            refined.append(_downgrade(f))
            outcomes.append(
                CorrelationOutcome(
                    finding_id=f.finding_id,
                    action="downgraded",
                    reason="execution claim from a single artifact class without prefetch/EDR corroboration",
                )
            )

    return refined, outcomes


# ---------------------------------------------------------------------------
# Internals.
# ---------------------------------------------------------------------------


def _is_execution_claim(f: Finding) -> bool:
    # Single source of truth shared with the engine's report-QA gate so the two
    # never disagree on what counts as an execution claim. See execution_claim.py.
    return is_execution_claim(f.description, f.mitre_technique)


def _downgrade(f: Finding) -> Finding:
    ladder = {"CONFIRMED": "INFERRED", "INFERRED": "HYPOTHESIS", "HYPOTHESIS": "HYPOTHESIS"}
    new_label = ladder.get(f.confidence, f.confidence)
    if new_label == f.confidence:
        return f
    return f.model_copy(update={"confidence": new_label})


__all__ = ["CorrelationOutcome", "correlate"]
