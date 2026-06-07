"""Cross-artifact correlator — enforces ``SOUL.md`` rules.

Spec #2 §8.1 (Correlate stage) + ``agent-config/SOUL.md`` invariant
"Execution claims need ≥2 artifact classes." This module is the
last gate before the verdict is assembled — it walks the merged
finding list and downgrades any "execution"-flavored claim that
doesn't have corroboration from at least two distinct artifact
classes (disk + log + memory).

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
from findevil_agent.judge import _classify_artifact

# Token sets that mark a Finding as making an execution claim.
# Anchored at word boundaries so "execute_shell" mentions inside
# narrative blocks don't accidentally trigger.
_EXECUTION_TOKENS = (
    r"\bexecut(?:ed|ion|ing)\b",
    r"\bran\b",
    r"\binvok(?:ed|ation|ing)\b",
    r"\blaunch(?:ed|ing)\b",
    r"\bspawn(?:ed|ing)\b",
    r"\bstarted\b",
)
_EXECUTION_RE = re.compile("|".join(_EXECUTION_TOKENS), re.IGNORECASE)

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
    # Index artifact classes the run touched, for cross-checks.
    classes_in_run: set[str] = {c for f in findings if (c := _classify_artifact(f)) is not None}

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
        own_class = _classify_artifact(f)
        has_other_class = bool(classes_in_run - ({own_class} if own_class else set()))

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
        elif has_strong_corroboration or has_other_class:
            refined.append(f)
            outcomes.append(
                CorrelationOutcome(
                    finding_id=f.finding_id,
                    action="kept",
                    reason="execution claim corroborated by ≥2 artifact classes or EDR/prefetch+cache",
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
    if _EXECUTION_RE.search(f.description):
        return True
    # Common MITRE techniques classed as execution evidence.
    return bool(
        f.mitre_technique
        and f.mitre_technique.startswith(
            ("T1059", "T1106", "T1129", "T1203", "T1543", "T1547", "T1053")
        )
    )


def _downgrade(f: Finding) -> Finding:
    ladder = {"CONFIRMED": "INFERRED", "INFERRED": "HYPOTHESIS", "HYPOTHESIS": "HYPOTHESIS"}
    new_label = ladder.get(f.confidence, f.confidence)
    if new_label == f.confidence:
        return f
    return f.model_copy(update={"confidence": new_label})


__all__ = ["CorrelationOutcome", "correlate"]
