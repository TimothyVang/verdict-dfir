"""Deterministic categorical-impossibility falsifiers — read-only scorer side.

Most VERDICT gates *corroborate* a finding (entailment, ≥2 artifact classes,
counter-hypothesis). This module does the inverse: it REFUTES a finding when it
asserts something physically or logically impossible for the evidence at hand.
A categorical impossibility is not a confidence downgrade — it is a hard
contradiction with the laws the evidence must obey.

Two falsifiers:

1. **Temporal physics.** An artifact event cannot post-date the moment the
   evidence was acquired: nothing was written to the image after the capture
   completed. A finding asserting an event timestamp strictly AFTER the
   capture/acquisition time is impossible (clock skew, fabricated leads, or a
   misparse — all worth surfacing rather than scoring).

2. **Platform consistency.** An OS-exclusive artifact claim cannot be true on an
   image of a different platform — a Windows registry/NTFS claim on a Linux/ext
   image, or a Linux ``/etc/crontab`` claim on a Windows image, is categorically
   impossible.

This is **custody-neutral**. It never mutates the audit chain, the manifest, the
finding, or any committed scoring math. It is a pure function of (finding,
context) that returns typed :class:`Falsification` records; callers decide what
to do with them (surface in the report, flag for the verifier). Deterministic,
pure stdlib + the event model, no LLM, no I/O.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum

from findevil_agent.events import Finding


class RefutationReason(str, Enum):
    """Typed reason a finding was categorically refuted or flagged."""

    TEMPORAL_PHYSICS = "temporal_physics"
    PLATFORM_CONSISTENCY = "platform_consistency"
    # Chronological / internal-consistency pre-gates (Item #15). The first is a
    # hard ordering impossibility; the latter two are LINTS surfaced as leads.
    CHRONOLOGY_EXECUTION_BEFORE_CREATION = "chronology_execution_before_creation"
    PRESENCE_NOT_EXECUTION = "presence_not_execution"
    DUAL_SEVERITY_SAME_EVIDENCE = "dual_severity_same_evidence"


@dataclass(frozen=True)
class Falsification:
    """A single categorical-impossibility refutation of a finding.

    ``impossible_values`` carries the concrete values that collide (e.g. the
    asserted timestamp vs the capture time, or the claimed vs image platform) so
    a reader can verify the impossibility without re-deriving it.
    """

    finding_id: str
    reason: RefutationReason
    message: str
    impossible_values: dict[str, str] = field(default_factory=dict)


# --------------------------------------------------------------------------- #
# Temporal physics
# --------------------------------------------------------------------------- #

# ISO-8601: date, optional time, optional fractional seconds, optional zone.
# Anchored on the date so a bare run-count or offset never parses as a time.
_ISO_RE = re.compile(
    r"\b\d{4}-\d{2}-\d{2}" r"(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?\s*(?:Z|[+-]\d{2}:?\d{2})?)?\b"
)


def _parse_iso(value: str) -> datetime | None:
    """Parse an ISO-8601 string to an aware UTC datetime, or None.

    A naive timestamp (no zone) is treated as UTC — VERDICT's timestamp
    contract is UTC ISO-8601 (CLAUDE.md), so an unzoned evidence time is UTC.
    """
    text = value.strip()
    if not text:
        return None
    normalized = text.replace("Z", "+00:00") if text.endswith("Z") else text
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _candidate_timestamps(finding: Finding) -> list[tuple[str, datetime]]:
    """Every well-formed ISO-8601 timestamp the finding asserts.

    Sources: ``asserted_values`` (the structured values the verifier
    re-extracts) and the description prose. Returns (raw_text, parsed) pairs
    for the parseable ones; unparseable matches are dropped.
    """
    raw: list[str] = []
    for value in finding.asserted_values:
        raw.append(value.expected)
    raw.extend(_ISO_RE.findall(finding.description or ""))

    out: list[tuple[str, datetime]] = []
    for text in raw:
        for match in _ISO_RE.findall(text):
            parsed = _parse_iso(match)
            if parsed is not None:
                out.append((match, parsed))
    return out


def falsify_temporal_physics(
    finding: Finding,
    *,
    capture_time: str | None,
) -> list[Falsification]:
    """Refute the finding if it asserts an event strictly after capture.

    ``capture_time`` is the evidence acquisition time (UTC ISO-8601). When it is
    None or unparseable the check is a no-op — we never invent a bound. At most
    one refutation is returned, carrying the worst (latest) impossible timestamp.
    """
    if capture_time is None:
        return []
    capture = _parse_iso(capture_time)
    if capture is None:
        return []

    impossible = [(raw, ts) for raw, ts in _candidate_timestamps(finding) if ts > capture]
    if not impossible:
        return []

    worst_raw, _ = max(impossible, key=lambda pair: pair[1])
    return [
        Falsification(
            finding_id=finding.finding_id,
            reason=RefutationReason.TEMPORAL_PHYSICS,
            message=(
                f"asserted event time {worst_raw} is after evidence capture time "
                f"{capture_time}; an artifact cannot post-date acquisition"
            ),
            impossible_values={
                "asserted_time": worst_raw,
                "capture_time": capture_time,
            },
        )
    ]


# --------------------------------------------------------------------------- #
# Platform consistency
# --------------------------------------------------------------------------- #

# OS-exclusive signatures, keyed to a normalized platform. These are general
# DFIR artifact/path patterns (not image-specific values): a registry hive ref,
# an NTFS structure, a Windows event-log artifact => Windows; a Unix system path
# or Linux-only log/filesystem => Linux; an Apple-specific structure => macOS.
_PLATFORM_SIGNATURES: dict[str, tuple[re.Pattern[str], ...]] = {
    "windows": (
        re.compile(r"\bHK(?:LM|CU|CR|U|EY_[A-Z_]+)\b"),
        re.compile(r"\bregistry\s+(?:run\s+key|hive)\b", re.IGNORECASE),
        re.compile(r"\bNTFS\b|\b\$MFT\b|\bUsnJrnl\b"),
        re.compile(r"\b(?:Prefetch|Amcache|ShimCache|EVTX)\b", re.IGNORECASE),
        re.compile(r"\\(?:SOFTWARE|SYSTEM|Windows\\System32)\b", re.IGNORECASE),
        re.compile(r"\bC:\\"),
    ),
    "linux": (
        re.compile(r"\bext[2-4]\b"),
        re.compile(r"/etc/(?:crontab|passwd|shadow|cron\.d)\b"),
        re.compile(r"/var/log/(?:syslog|auth\.log|secure)\b"),
        re.compile(r"\bsystemd\b|\bjournald\b|\.bash_history\b"),
    ),
    "macos": (
        re.compile(r"\bAPFS\b|\bHFS\+"),
        re.compile(r"\.plist\b|\bLaunchAgents\b|\bLaunchDaemons\b"),
        re.compile(r"\.DS_Store\b"),
    ),
}


def _normalize_platform(platform: str | None) -> str | None:
    """Map free-form platform/OS strings to windows/linux/macos, else None."""
    if not platform:
        return None
    token = platform.strip().lower()
    if token in {"windows", "win", "nt", "ntfs"}:
        return "windows"
    if token in {"linux", "ext", "ext4", "ext3", "ext2", "unix"}:
        return "linux"
    if token in {"macos", "mac", "osx", "darwin", "apfs", "hfs"}:
        return "macos"
    return None


def _claimed_platforms(finding: Finding) -> set[str]:
    """Platforms whose OS-exclusive signatures appear in the finding text."""
    text = " ".join(
        part
        for part in (
            finding.description or "",
            finding.artifact_path or "",
            finding.artifact_offset or "",
        )
        if part
    )
    return {
        platform
        for platform, patterns in _PLATFORM_SIGNATURES.items()
        if any(pattern.search(text) for pattern in patterns)
    }


def falsify_platform_consistency(
    finding: Finding,
    *,
    platform: str | None,
) -> list[Falsification]:
    """Refute the finding if it makes an OS-exclusive claim foreign to the image.

    ``platform`` is the image platform (e.g. "windows", "linux", an ext/NTFS
    filesystem hint). When it is unknown/unrecognized the check is a no-op — we
    never refute against an unestablished platform. One refutation per foreign
    platform claimed, deterministically ordered.
    """
    image_platform = _normalize_platform(platform)
    if image_platform is None:
        return []

    foreign = sorted(p for p in _claimed_platforms(finding) if p != image_platform)
    return [
        Falsification(
            finding_id=finding.finding_id,
            reason=RefutationReason.PLATFORM_CONSISTENCY,
            message=(
                f"finding makes a {claimed}-exclusive artifact claim, but the image "
                f"platform is {image_platform}; the artifact cannot exist there"
            ),
            impossible_values={
                "claimed_platform": claimed,
                "image_platform": image_platform,
            },
        )
        for claimed in foreign
    ]


def falsify_finding(
    finding: Finding,
    *,
    capture_time: str | None = None,
    platform: str | None = None,
) -> list[Falsification]:
    """Run every categorical-impossibility falsifier and aggregate refutations.

    Pure and order-stable: temporal-physics refutations first, then
    platform-consistency. Returns an empty list for a finding that violates no
    categorical law given the supplied context.

    NOTE: the Item #15 chronological/consistency LINTS are intentionally NOT
    folded in here. ``falsify_finding``'s output count feeds the engine's REFUTED
    verdict path, so the lints stay in :func:`lint_findings` (custody-neutral)
    until a caller opts to consume them.
    """
    refutations: list[Falsification] = []
    refutations.extend(falsify_temporal_physics(finding, capture_time=capture_time))
    refutations.extend(falsify_platform_consistency(finding, platform=platform))
    return refutations


# --------------------------------------------------------------------------- #
# Chronological-impossibility / internal-consistency pre-gates (Item #15)
#
# Additive lints surfaced as the same typed Falsification record. Three checks:
#   1. execution-before-creation — a hard ordering impossibility (a binary cannot
#      run before it is created).
#   2. presence-only-vs-execution — a LINT/LEAD: a finding claims execution but its
#      evidence shows only presence/registration (presence is not execution).
#   3. same-evidence-dual-severity — a LINT/LEAD: identical evidence asserted at two
#      different confidence tiers.
#
# Pure ordering/keyword math; no I/O, no LLM. Deterministic. Kept off the
# ``falsify_finding`` REFUTED path (see note above) so this is custody-neutral.
# --------------------------------------------------------------------------- #

# Context keywords that tag a nearby timestamp as a CREATION/birth time.
_CREATION_CTX_RE = re.compile(
    r"\b(?:created|create|creation|birth|installed|install|first seen|written|"
    r"write time|standard information|si created|mft created)\b"
)
# Context keywords that tag a nearby timestamp as an EXECUTION/run time.
_EXECUTION_CTX_RE = re.compile(
    r"\b(?:ran|run|runs|executed|execute|execution|launched|launch|started|"
    r"last run|first executed|last executed|run time|prefetch)\b"
)


def _role_of_context(window: str) -> str | None:
    """Classify a context window as 'creation', 'execution', or None.

    Punctuation/underscores collapse to spaces so a dotted/underscored
    asserted-value path (``rows[0].last_run_time``) classifies like prose.
    Ambiguous (both roles) or empty (neither) windows return None.
    """
    norm = re.sub(r"[^a-z0-9]+", " ", window.lower())
    has_creation = bool(_CREATION_CTX_RE.search(norm))
    has_execution = bool(_EXECUTION_CTX_RE.search(norm))
    if has_creation and not has_execution:
        return "creation"
    if has_execution and not has_creation:
        return "execution"
    return None


def _keyword_positions(text: str) -> list[tuple[int, int, str]]:
    """``(start, end, role)`` for each creation/execution keyword in ``text``.

    Normalization replaces every non-alphanumeric char with a single space, which
    is LENGTH-PRESERVING so the match spans line up with the original text — the
    nearest-keyword distance below depends on that alignment.
    """
    norm = re.sub(r"[^a-z0-9]", " ", text.lower())
    out: list[tuple[int, int, str]] = []
    for match in _CREATION_CTX_RE.finditer(norm):
        out.append((match.start(), match.end(), "creation"))
    for match in _EXECUTION_CTX_RE.finditer(norm):
        out.append((match.start(), match.end(), "execution"))
    return out


def _nearest_role(keywords: list[tuple[int, int, str]], start: int, end: int) -> str | None:
    """Role of the keyword nearest the timestamp span ``(start, end)``.

    Distance is the GAP between the keyword span and the timestamp span (not a
    center-to-center distance — a long timestamp would skew that toward whichever
    keyword follows it). Edge-gap distance lets two adjacent timestamps
    ("created at <ts1> ... ran at <ts2>") each bind to their own nearest keyword.
    A tie between a creation and an execution keyword is ambiguous -> None.
    """
    best_role: str | None = None
    best_dist: int | None = None
    for k_start, k_end, role in keywords:
        if k_end <= start:
            dist = start - k_end
        elif k_start >= end:
            dist = k_start - end
        else:
            dist = 0  # keyword overlaps the timestamp span
        if best_dist is None or dist < best_dist:
            best_dist, best_role = dist, role
        elif dist == best_dist and role != best_role:
            best_role = None
    return best_role


def _role_tagged_timestamps(finding: Finding) -> dict[str, list[tuple[str, datetime]]]:
    """Timestamps in the finding tagged 'creation' / 'execution'.

    Description prose is classified by the nearest creation/execution keyword to
    each ISO match; asserted_values by the role keywords in their dotted ``path``.
    Ambiguous or role-less timestamps are dropped (conservatism).
    """
    tagged: dict[str, list[tuple[str, datetime]]] = {"creation": [], "execution": []}

    description = finding.description or ""
    keywords = _keyword_positions(description)
    for match in _ISO_RE.finditer(description):
        parsed = _parse_iso(match.group(0))
        if parsed is None:
            continue
        start, end = match.span()
        role = _nearest_role(keywords, start, end)
        if role is not None:
            tagged[role].append((match.group(0), parsed))

    for value in finding.asserted_values:
        role = _role_of_context(value.path)
        if role is None:
            continue
        for raw in _ISO_RE.findall(value.expected):
            parsed = _parse_iso(raw)
            if parsed is not None:
                tagged[role].append((raw, parsed))

    return tagged


def lint_execution_before_creation(finding: Finding) -> list[Falsification]:
    """Refute a finding that asserts a binary ran before it was created.

    A categorical ordering impossibility: an execution timestamp strictly earlier
    than the artifact's earliest asserted creation time. No-op unless the finding
    asserts BOTH a creation-tagged and an execution-tagged timestamp. At most one
    refutation, carrying the worst (earliest) offending execution time.
    """
    tagged = _role_tagged_timestamps(finding)
    creations = tagged["creation"]
    executions = tagged["execution"]
    if not creations or not executions:
        return []
    creation_raw, creation_ts = min(creations, key=lambda pair: pair[1])
    offending = [(raw, ts) for raw, ts in executions if ts < creation_ts]
    if not offending:
        return []
    exec_raw, _ = min(offending, key=lambda pair: pair[1])
    return [
        Falsification(
            finding_id=finding.finding_id,
            reason=RefutationReason.CHRONOLOGY_EXECUTION_BEFORE_CREATION,
            message=(
                f"asserted execution time {exec_raw} precedes the artifact's creation time "
                f"{creation_raw}; a binary cannot run before it exists"
            ),
            impossible_values={
                "execution_time": exec_raw,
                "creation_time": creation_raw,
            },
        )
    ]


# An execution CLAIM verb (the finding says the thing executed/ran).
_EXECUTION_CLAIM_RE = re.compile(
    r"\b(?:executed|execute|execution|ran|runs|was run|launched|invoked)\b",
    re.IGNORECASE,
)
# MITRE execution-tactic families — an execution claim by technique.
_EXECUTION_MITRE_RE = re.compile(r"\bT1(?:059|106|129|203|204|569|047|053)\b", re.IGNORECASE)
# Genuine execution CORROBORATION (a run trace, not just the verb).
_EXECUTION_TRACE_RE = re.compile(
    r"\brun count\b|\bran \d+ times?\b|\b4688\b|\bprocess creation\b"
    r"|\bprocess (?:started|launched|spawned)\b|\blast run\b|\brun time\b"
    r"|\bcommand[ -]?line\b|\bpslist\b|\bpsscan\b|\bpid\b",
    re.IGNORECASE,
)
# Presence-/registration-only artifact signals (NOT execution).
_PRESENCE_ONLY_RE = re.compile(
    r"\bamcache\b|\bshim ?cache\b|\bappcompat(?:cache)?\b"
    r"|\blisted in\b|\bpresent (?:in|on)\b|\bexists? (?:in|on)\b"
    r"|\bon disk\b|\bfile system entry\b|\b\$mft\b|\bmft\b|\bfile exists\b",
    re.IGNORECASE,
)


def lint_presence_only_vs_execution(finding: Finding) -> list[Falsification]:
    """Lint a finding that claims execution while its evidence shows only presence.

    Presence/registration (Amcache, ShimCache, an MFT/file entry) proves the file
    EXISTED, not that it RAN (the MEMORY.md trap). When a finding asserts execution
    but carries a presence-only artifact signal and NO genuine run trace, surface a
    LEAD (not a hard refutation) to corroborate with a process/run artifact.
    """
    text = " ".join(
        part for part in (finding.description or "", finding.mitre_technique or "") if part
    )
    claims_execution = bool(_EXECUTION_CLAIM_RE.search(text) or _EXECUTION_MITRE_RE.search(text))
    if not claims_execution:
        return []
    if _EXECUTION_TRACE_RE.search(text):
        return []  # a real run trace is present — not an over-claim
    if not _PRESENCE_ONLY_RE.search(text):
        return []  # no presence-only artifact to flag against
    return [
        Falsification(
            finding_id=finding.finding_id,
            reason=RefutationReason.PRESENCE_NOT_EXECUTION,
            message=(
                "finding claims execution but its cited evidence shows only presence/"
                "registration (e.g. Amcache/ShimCache/MFT); presence is not execution — "
                "corroborate with a run/process trace (LEAD)"
            ),
            impossible_values={"claim": "execution", "evidence": "presence_only"},
        )
    ]


def _asserted_signature(finding: Finding) -> tuple[tuple[str, str, str, int], ...]:
    """Order-stable signature of a finding's structured asserted values."""
    return tuple(
        sorted(
            (av.path, av.expected, av.match, av.count if av.count is not None else -1)
            for av in finding.asserted_values
        )
    )


_HYP_PREFIX_RE = re.compile(r"^\s*hypothesis:\s*", re.IGNORECASE)


def _normalized_claim(finding: Finding) -> str:
    """Lowercased, prefix-stripped, whitespace-collapsed claim text.

    Drops the auto-applied ``hypothesis:`` prefix so a HYPOTHESIS finding and an
    otherwise-identical INFERRED/CONFIRMED twin share one claim signature.
    """
    text = _HYP_PREFIX_RE.sub("", finding.description or "").strip().lower()
    return re.sub(r"\s+", " ", text)


def _evidence_signature(
    finding: Finding,
) -> tuple[str, str, str, tuple[tuple[str, str, str, int], ...], str]:
    """Strong 'same evidence' key: citation + artifact + MITRE + values + claim."""
    return (
        finding.tool_call_id or "",
        finding.artifact_path or "",
        finding.mitre_technique or "",
        _asserted_signature(finding),
        _normalized_claim(finding),
    )


def lint_same_evidence_dual_severity(findings: Iterable[Finding]) -> list[Falsification]:
    """Lint identical evidence asserted at two different confidence tiers.

    Groups findings by a strong evidence signature (tool_call_id + artifact_path +
    MITRE + asserted-value signature + normalized claim text). A group holding two
    or more DISTINCT confidence labels is an internal inconsistency — the same
    evidence cannot justify two severities. One LEAD per participating finding, in
    input order, so callers can reconcile.
    """
    found = list(findings)
    groups: dict[
        tuple[str, str, str, tuple[tuple[str, str, str, int], ...], str], list[Finding]
    ] = {}
    for f in found:
        groups.setdefault(_evidence_signature(f), []).append(f)

    flagged: set[str] = set()
    for members in groups.values():
        if len(members) >= 2 and len({m.confidence for m in members}) >= 2:
            flagged.update(m.finding_id for m in members)

    out: list[Falsification] = []
    for f in found:
        if f.finding_id not in flagged:
            continue
        peers = sorted({m.confidence for m in groups[_evidence_signature(f)]})
        out.append(
            Falsification(
                finding_id=f.finding_id,
                reason=RefutationReason.DUAL_SEVERITY_SAME_EVIDENCE,
                message=(
                    f"the same evidence (tool_call_id={f.tool_call_id or ''!r}, "
                    f"artifact={f.artifact_path!r}) is cited at multiple confidence tiers "
                    f"({', '.join(peers)}); identical evidence cannot support two severities — "
                    f"reconcile (LEAD)"
                ),
                impossible_values={
                    "tool_call_id": f.tool_call_id or "",
                    "confidences": ", ".join(peers),
                },
            )
        )
    return out


def lint_findings(findings: Iterable[Finding]) -> list[Falsification]:
    """Run every chronological/consistency LINT over a finding set.

    Additive sibling to :func:`falsify_finding` — deliberately NOT folded into it
    (whose count feeds the engine's REFUTED verdict path), so the lints stay
    custody-neutral until a caller opts to consume them. Per-finding lints first
    (input order), then the cross-finding dual-severity lint. Deterministic.
    """
    found = list(findings)
    out: list[Falsification] = []
    for f in found:
        out.extend(lint_execution_before_creation(f))
        out.extend(lint_presence_only_vs_execution(f))
    out.extend(lint_same_evidence_dual_severity(found))
    return out


__all__ = [
    "Falsification",
    "RefutationReason",
    "falsify_finding",
    "falsify_platform_consistency",
    "falsify_temporal_physics",
    "lint_execution_before_creation",
    "lint_findings",
    "lint_presence_only_vs_execution",
    "lint_same_evidence_dual_severity",
]
