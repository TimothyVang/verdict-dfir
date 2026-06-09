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
from collections.abc import Mapping
from dataclasses import dataclass

from findevil_agent.events import Finding
from findevil_agent.execution_claim import is_execution_claim, is_execution_corroborated
from findevil_agent.judge import _classify_artifact

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
    *,
    tool_classes: Mapping[str, str] | None = None,
) -> tuple[list[Finding], list[CorrelationOutcome]]:
    """Walk findings and apply SOUL.md cross-artifact rules.

    Returns a tuple of (refined_findings, outcomes). ``outcomes`` is
    one entry per input Finding describing what the correlator did.

    When ``tool_classes`` (a ``tool_call_id -> artifact_class`` map, e.g. built
    from ``find_evil_auto.TOOL_ARTIFACT_CLASSES``) is supplied, an execution
    claim's corroboration is derived from the STRUCTURED classes of the tools it
    cites (``tool_call_id`` + ``derived_from``) — the same basis the report-QA
    gate uses — instead of description-prose regex. Without it (or with an empty
    map) the correlator falls back to the legacy prose heuristic.
    """
    # Index artifact classes the run touched, for the legacy prose cross-check.
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

        # Preferred: structural corroboration from the tools this finding cites,
        # not its prose. A single-artifact claim can no longer ride on an unrelated
        # finding's class elsewhere in the run.
        if tool_classes:
            cited = {f.tool_call_id, *(f.derived_from or [])}
            classes = {tool_classes[t] for t in cited if t and t in tool_classes}
            classes.discard("custody")  # case_open custody is not execution evidence
            if is_execution_corroborated(classes):
                refined.append(f)
                outcomes.append(
                    CorrelationOutcome(
                        finding_id=f.finding_id,
                        action="kept",
                        reason=f"execution claim corroborated by cited artifact classes {sorted(classes)}",
                    )
                )
            else:
                refined.append(_downgrade(f))
                outcomes.append(
                    CorrelationOutcome(
                        finding_id=f.finding_id,
                        action="downgraded",
                        reason=(
                            f"execution claim cites artifact class(es) {sorted(classes)}; "
                            "SOUL.md needs ≥2 non-weak classes from the cited tools"
                        ),
                    )
                )
            continue

        # Legacy fallback — prose-based cross-artifact rule.
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
