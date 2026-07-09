"""Cross-host correlation hygiene (fleet stage).

Focused submodule of :mod:`findevil_agent.correlator`. The fleet pipeline
summarizes many per-host Cases. When it joins hosts by a shared binary hash or a
shared network pivot, two background-noise traps make unrelated hosts look
"linked":

  1. Operating-system / vendor-baseline binaries (Microsoft-signed and the
     like) share the SAME hash on every host by design — that is expected,
     not a campaign signal. They are excluded from auto actor-linkage and from
     the shared-binary grouping (which is renamed "shared binaries (review)" —
     a lead for an analyst, never a conclusion).
  2. "Too-common" network pivots — bulk/budget registrars, CDNs/reverse
     proxies (Cloudflare, CloudFront, ...), and free/automated TLS issuers
     (Let's Encrypt, ZeroSSL) — are shared by millions of unrelated domains, so
     a shared registrar/CDN/CA between two hosts cannot, by itself, establish a
     cross-host link.

A cross-host campaign lead is emitted ONLY when at least one DISCRIMINATING
pivot exists (a non-OS-signed shared binary or a network pivot not on the
too-common denylist). Otherwise the result is downgraded to host-side
co-occurrence. Either way the strongest tier is HYPOTHESIS and ``attribution``
is ALWAYS False — host artifacts never establish actor identity (SOUL.md /
CLAUDE.md no-attribution guardrail).

Pure logic, deterministic, custody-neutral: the fleet correlation report is a
derivative summary, never the signed per-host manifest.
"""

from __future__ import annotations

from dataclasses import dataclass

# Code-signing subjects that mark a binary as OS / trusted-vendor baseline. The
# same hash on N hosts is expected, so it is never a discriminating pivot.
# General signatures, not image-specific values (evidence-agnostic).
_OS_SIGNER_SUBSTRINGS: tuple[str, ...] = (
    "microsoft",  # "Microsoft Corporation", "Microsoft Windows Publisher", ...
    "windows",
)

# Network pivots too common to discriminate one campaign from internet noise.
# Curated general DFIR denylist keyed on the indicator's org/value — never on any
# single image's data (evidence-agnostic).
_TOO_COMMON_PIVOTS: tuple[str, ...] = (
    # CDN / reverse-proxy / cloud infra
    "cloudflare",
    "cloudfront",
    "akamai",
    "fastly",
    "amazonaws",
    "azureedge",
    "googleusercontent",
    # Free / automated TLS issuers
    "let's encrypt",
    "lets encrypt",
    "letsencrypt",
    "isrg",
    "zerossl",
    # Bulk / budget domain registrars
    "godaddy",
    "namecheap",
    "namesilo",
    "porkbun",
    "tucows",
    "enom",
    "dynadot",
    "publicdomainregistry",
    "hostinger",
    # Free dynamic-DNS providers
    "no-ip",
    "duckdns",
    "dyndns",
)


@dataclass(frozen=True)
class SharedArtifact:
    """An artifact (binary hash or network pivot) observed across fleet hosts.

    ``kind`` is ``"binary"`` (``value`` is the SHA-256; ``signer`` is the
    code-signing subject if known) or ``"network_pivot"`` (``value`` is the
    domain / registrar / CDN org / CA, ``signer`` unused).
    """

    kind: str
    value: str
    hosts: tuple[str, ...]
    signer: str | None = None


@dataclass(frozen=True)
class CrossHostOutcome:
    """Per-shared-artifact cross-host decision.

    ``decision`` is one of ``"shared_binaries_review"`` (non-OS shared binary,
    grouped for analyst review), ``"campaign_lead"`` (a discriminating network
    pivot — a HYPOTHESIS-tier campaign lead), or ``"suppressed"`` (OS-signed
    binary or too-common pivot that cannot link hosts on its own).

    ``attribution`` is ALWAYS False — the no-attribution guardrail forbids
    asserting actor identity from host artifacts.
    """

    kind: str
    value: str
    hosts: tuple[str, ...]
    decision: str
    reason: str
    epistemic_label: str  # "HYPOTHESIS" for leads/groupings; "" when suppressed
    attribution: bool = False


@dataclass(frozen=True)
class CrossHostCorrelation:
    """Aggregate cross-host hygiene result for a fleet.

    ``actor_link`` is the campaign-lead gate: True only when a discriminating
    pivot exists. ``co_occurrence`` is True when hosts share artifacts but none
    discriminate (the downgraded, host-side-only outcome). ``attribution`` is the
    fleet-level invariant — ALWAYS False.
    """

    outcomes: tuple[CrossHostOutcome, ...]
    actor_link: bool
    co_occurrence: bool
    attribution: bool = False


def is_os_signed(signer: str | None) -> bool:
    """True when a code-signing subject marks the binary as OS / vendor baseline."""
    if not signer:
        return False
    low = signer.lower()
    return any(sub in low for sub in _OS_SIGNER_SUBSTRINGS)


def is_too_common_pivot(value: str) -> bool:
    """True when a network pivot is too common to discriminate a campaign."""
    low = (value or "").lower()
    return any(sub in low for sub in _TOO_COMMON_PIVOTS)


def is_discriminating(artifact: SharedArtifact) -> bool:
    """True when this shared artifact can, alone, support a cross-host campaign
    LEAD (never attribution). OS-signed binaries and too-common network pivots
    are not discriminating; an artifact seen on fewer than 2 hosts never is."""
    if len({h for h in artifact.hosts}) < 2:
        return False
    if artifact.kind == "binary":
        return not is_os_signed(artifact.signer)
    if artifact.kind == "network_pivot":
        return not is_too_common_pivot(artifact.value)
    return False


def _classify(artifact: SharedArtifact) -> CrossHostOutcome:
    hosts = tuple(artifact.hosts)
    if artifact.kind == "binary":
        if is_os_signed(artifact.signer):
            return CrossHostOutcome(
                kind=artifact.kind,
                value=artifact.value,
                hosts=hosts,
                decision="suppressed",
                reason="OS / Microsoft-signed baseline binary — shared hash is expected, excluded from actor-linkage",
                epistemic_label="",
            )
        return CrossHostOutcome(
            kind=artifact.kind,
            value=artifact.value,
            hosts=hosts,
            decision="shared_binaries_review",
            reason="non-OS binary shared across hosts — grouped as 'shared binaries (review)', a lead not a conclusion",
            epistemic_label="HYPOTHESIS",
        )
    if artifact.kind == "network_pivot":
        if is_too_common_pivot(artifact.value):
            return CrossHostOutcome(
                kind=artifact.kind,
                value=artifact.value,
                hosts=hosts,
                decision="suppressed",
                reason="too-common pivot (bulk registrar / CDN / free-TLS issuer) cannot establish a cross-host link alone",
                epistemic_label="",
            )
        return CrossHostOutcome(
            kind=artifact.kind,
            value=artifact.value,
            hosts=hosts,
            decision="campaign_lead",
            reason="discriminating network pivot shared across hosts — HYPOTHESIS-tier campaign lead, never attribution",
            epistemic_label="HYPOTHESIS",
        )
    return CrossHostOutcome(
        kind=artifact.kind,
        value=artifact.value,
        hosts=hosts,
        decision="suppressed",
        reason=f"unknown shared-artifact kind {artifact.kind!r}",
        epistemic_label="",
    )


def correlate_cross_host(
    shared: list[SharedArtifact],
) -> CrossHostCorrelation:
    """Apply cross-host hygiene to fleet shared artifacts.

    Only artifacts spanning >=2 distinct hosts are considered. Emits a
    cross-host campaign lead (``actor_link=True``) ONLY when a discriminating
    pivot exists; otherwise downgrades to host-side co-occurrence. Never
    attribution. Deterministic given the same input (outcomes preserve input
    order)."""
    multi_host = [a for a in shared if len({h for h in a.hosts}) >= 2]
    outcomes = tuple(_classify(a) for a in multi_host)
    actor_link = any(is_discriminating(a) for a in multi_host)
    co_occurrence = bool(multi_host) and not actor_link
    return CrossHostCorrelation(
        outcomes=outcomes,
        actor_link=actor_link,
        co_occurrence=co_occurrence,
    )
