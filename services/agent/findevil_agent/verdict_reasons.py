"""Typed reason-codes for an INDETERMINATE/ABSTAIN verdict.

When VERDICT cannot commit to ``SUSPICIOUS`` or scoped ``NO_EVIL`` it
returns a non-committal verdict word. The word alone does not say *why*
the run abstained. This module adds a small, typed vocabulary of
reason-codes plus a pure, deterministic derivation so the reason can be
attached to the ``RunVerdict`` event and rendered downstream.

The surface is **additive and custody-neutral**: it never changes the
verdict WORD, the audit chain, the manifest, or any committed scoring
math. It only annotates an already-decided non-committal verdict.

The derivation is pure — deterministic given the same inputs, no LLM, no
I/O — so it can be unit-tested one reason-code at a time and reproduced
offline.
"""

from __future__ import annotations

from enum import StrEnum

# The two-artifact-class gate (see CLAUDE.md): an execution/exfiltration
# story needs corroboration across >= 2 artifact classes. Below that, the
# coverage is insufficient to commit either way.
MIN_ARTIFACT_CLASSES = 2


class IndeterminateReason(StrEnum):
    """Why a verdict abstained from committing.

    A ``StrEnum`` so members serialize as plain JSON strings on the SSE
    wire and compare equal to their string value (matches
    ``config.CredentialMode``).
    """

    CONTRADICTION = "CONTRADICTION"
    """A cross-pool / cross-finding conflict the run could not reconcile."""

    INSUFFICIENT_COVERAGE = "INSUFFICIENT_COVERAGE"
    """Too few artifact classes examined, or only HYPOTHESIS leads."""

    DEGRADED_MODE = "DEGRADED_MODE"
    """A tool or parse path failed, so coverage is partial."""

    REFUTED = "REFUTED"
    """One or more findings were categorically refuted/falsified (e.g. via
    ``falsify_finding`` / categorical-impossibility), leaving the Case without a
    committable story. The refutation itself is not an abstain, but recording it
    explains the non-committal verdict rather than silently dropping the claim."""


# Canonical ordering for a deterministic, reproducible output. Most
# severe / decision-blocking first. REFUTED is appended last so adding it
# leaves the prior three reasons' relative order unchanged.
_CANONICAL_ORDER: tuple[IndeterminateReason, ...] = (
    IndeterminateReason.CONTRADICTION,
    IndeterminateReason.INSUFFICIENT_COVERAGE,
    IndeterminateReason.DEGRADED_MODE,
    IndeterminateReason.REFUTED,
)


def derive_indeterminate_reasons(
    *,
    contradiction_count: int = 0,
    artifact_class_count: int = 0,
    leads_only: bool = False,
    tool_failure_count: int = 0,
    refuted_count: int = 0,
    min_artifact_classes: int = MIN_ARTIFACT_CLASSES,
) -> tuple[IndeterminateReason, ...]:
    """Derive the reason-codes for a non-committal verdict.

    Pure and deterministic — the same inputs always yield the same
    ordered tuple in :data:`_CANONICAL_ORDER`.

    Args:
        contradiction_count: Unresolved cross-pool / cross-finding
            conflicts. ``> 0`` raises ``CONTRADICTION``.
        artifact_class_count: Distinct artifact classes actually
            examined. Below ``min_artifact_classes`` raises
            ``INSUFFICIENT_COVERAGE``.
        leads_only: ``True`` when every finding is a HYPOTHESIS lead
            (nothing corroborated). Raises ``INSUFFICIENT_COVERAGE``.
        tool_failure_count: Tool/parse failures recorded this run.
            ``> 0`` raises ``DEGRADED_MODE``.
        refuted_count: Findings categorically refuted/falsified this run
            (e.g. via ``falsify_finding``). ``> 0`` raises ``REFUTED``.
            Defaults to 0 so existing callers are unaffected.
        min_artifact_classes: The coverage gate (default
            :data:`MIN_ARTIFACT_CLASSES`).

    Returns:
        The triggered reason-codes in canonical order; empty when none
        apply.
    """
    triggered: set[IndeterminateReason] = set()

    if contradiction_count > 0:
        triggered.add(IndeterminateReason.CONTRADICTION)
    if artifact_class_count < min_artifact_classes or leads_only:
        triggered.add(IndeterminateReason.INSUFFICIENT_COVERAGE)
    if tool_failure_count > 0:
        triggered.add(IndeterminateReason.DEGRADED_MODE)
    if refuted_count > 0:
        triggered.add(IndeterminateReason.REFUTED)

    return tuple(reason for reason in _CANONICAL_ORDER if reason in triggered)
