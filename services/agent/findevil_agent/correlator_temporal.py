"""Temporal-coupling check for execution-timing claims (deterministic, downgrade-only).

Focused submodule of :mod:`findevil_agent.correlator`. An execution claim that
pins a specific *time* ("X ran at 03:04") is only as strong as the timeline
sources behind that time. Two failure modes make such a claim shaky, and both
are pure timestamp math:

  1. **Source disagreement.** When two or more genuine execution-time sources
     (Prefetch last-run, UserAssist last-executed, Sysmon/EDR or 4688
     process-creation) are cited for the SAME run but disagree beyond a tolerance,
     the asserted single execution time is not corroborated — it is contradicted.
     The claim is DEMOTED one tier.
  2. **Catalog time mistaken for run time.** ``$STANDARD_INFORMATION`` ($SI) MAC
     times, ShimCache/AppCompatCache entries, and Amcache ``LastModified`` are
     catalog / registration / standard-information timestamps — NOT "when it ran"
     (per ``agent-config/MEMORY.md``). A timing claim whose ONLY timestamp comes
     from one of those excluded sources is DEMOTED: the "when it ran" rests on a
     timestamp that does not record execution.

The check is deterministic, downgrade-only (it never raises a tier and never
clears a finding), evidence-agnostic (it keys on general artifact/source names
and timestamp shapes, never image-specific literals), and opt-in via
``FIND_EVIL_REQUIRE_TEMPORAL_COUPLING=1`` so live behavior is unchanged until the
rollout flips it on. It is custody-neutral: no audit-chain / manifest / scoring
edits.

Pure logic — no LLM calls, no I/O. Deterministic given the same inputs.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from datetime import datetime

from findevil_agent.events import Finding
from findevil_agent.execution_claim import is_execution_claim

# Two execution-time sources for the same run should land within minutes of each
# other (Prefetch granularity, event-log clock skew). A spread beyond this is a
# real disagreement, not jitter. Named constant, deterministic.
_EXECUTION_TIME_TOLERANCE_SECONDS = 300

# How far (chars) from a timestamp a source keyword may sit and still attribute
# that timestamp to the source. Deterministic proximity window.
_SOURCE_WINDOW = 64

_SECONDS_PER_DAY = 86400
_EPOCH = datetime(1970, 1, 1)  # naive reference for ISO->seconds (UTC-assumed)

# Genuine execution-time sources: a timestamp attributed to one of these records
# WHEN a binary ran. General DFIR signatures, never image-specific literals.
_EXECUTION_SOURCE_RE = re.compile(
    r"\b(?:prefetch|last\s*run|last\s*execut\w*|userassist|sysmon|edr|"
    r"4688|process\s*creation|process\s*create)\b",
    re.IGNORECASE,
)

# Catalog / registration / $SI sources: a timestamp attributed to one of these is
# NOT execution time and must not count as "when it ran".
_EXCLUDED_SOURCE_RE = re.compile(
    r"\b(?:amcache|shimcache|appcompatcache|\$si|\$?standard[\s_]*information|"
    r"catalog\w*|registration)\b",
    re.IGNORECASE,
)

# "LastModified"-style markers always demote a timestamp to non-execution,
# regardless of any nearby source (a Prefetch file's $SI modified time is still
# not the run time).
_LASTMOD_RE = re.compile(
    r"\blast[\s-]*modified\b|\blastmodified\b|\bmodif\w*\s*time\b|\bmtime\b",
    re.IGNORECASE,
)

# Full date+time (ISO-8601-ish; optional seconds/fraction/Z). Matched first so a
# time-only pass does not double-count the HH:MM inside an ISO stamp.
_ISO_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}[ t]\d{2}:\d{2}(?::\d{2})?(?:\.\d+)?z?",
    re.IGNORECASE,
)
# Bare clock time (HH:MM[:SS]).
_TIME_RE = re.compile(r"\b\d{1,2}:\d{2}(?::\d{2})?\b")


@dataclass(frozen=True)
class TemporalCouplingDecision:
    """Outcome of the execution-timing temporal-coupling check.

    ``state`` is one of ``"not_timing_claim"`` (not an execution claim, or no
    timestamp / no attributable execution time), ``"ok"`` (execution-time sources
    agree, or only one), ``"demote_source_disagreement"`` (>=2 execution-time
    sources disagree beyond tolerance), or ``"demote_only_catalog_time"`` (the
    only asserted timestamp(s) are $SI / ShimCache / Amcache-LastModified catalog
    times). ``demote`` is True for the two ``demote_*`` states only. The decision
    NEVER raises a tier and NEVER clears a finding.
    """

    finding_id: str
    state: str
    reason: str
    demote: bool
    execution_times: tuple[str, ...] = ()
    excluded_times: tuple[str, ...] = ()


def temporal_coupling_gate_active() -> bool:
    """Opt-in, default-OFF (custody-neutral, downgrade-only)."""
    return os.environ.get("FIND_EVIL_REQUIRE_TEMPORAL_COUPLING") == "1"


def _extract_timestamps(text: str) -> list[tuple[int, int, str, str]]:
    """Non-overlapping (start, end, kind, raw) timestamps; ISO first, then bare time.

    ``kind`` is ``"dt"`` for full date+time, ``"tod"`` for a bare clock time.
    """
    spans: list[tuple[int, int, str, str]] = []
    taken: list[tuple[int, int]] = []
    for m in _ISO_RE.finditer(text):
        spans.append((m.start(), m.end(), "dt", m.group()))
        taken.append((m.start(), m.end()))
    for m in _TIME_RE.finditer(text):
        if any(s <= m.start() < e for s, e in taken):
            continue
        spans.append((m.start(), m.end(), "tod", m.group()))
    spans.sort(key=lambda s: s[0])
    return spans


def _nearest_distance(rx: re.Pattern[str], text: str, pos: int) -> int | None:
    """Minimum char distance from ``pos`` to any match of ``rx`` within the window."""
    best: int | None = None
    for m in rx.finditer(text):
        d = min(abs(m.start() - pos), abs(m.end() - pos))
        if d <= _SOURCE_WINDOW and (best is None or d < best):
            best = d
    return best


def _classify_source(text: str, start: int, end: int) -> str:
    """Attribute a timestamp to ``"execution"`` / ``"excluded"`` / ``"unknown"``."""
    mid = (start + end) // 2
    if _nearest_distance(_LASTMOD_RE, text, mid) is not None:
        return "excluded"
    excl = _nearest_distance(_EXCLUDED_SOURCE_RE, text, mid)
    execu = _nearest_distance(_EXECUTION_SOURCE_RE, text, mid)
    if excl is None and execu is None:
        return "unknown"
    if execu is None:
        return "excluded"
    if excl is None:
        return "execution"
    # Tie -> excluded (conservative: do not credit a contested timestamp as run time).
    return "excluded" if excl <= execu else "execution"


def _parse_iso(raw: str) -> float | None:
    s = raw.strip().upper().replace(" ", "T")
    if s.endswith("Z"):
        s = s[:-1]
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    return (dt.replace(tzinfo=None) - _EPOCH).total_seconds()


def _parse_tod(raw: str) -> float | None:
    parts = raw.strip().split(":")
    try:
        nums = [int(p) for p in parts]
    except ValueError:
        return None
    h = nums[0]
    m = nums[1] if len(nums) > 1 else 0
    s = nums[2] if len(nums) > 2 else 0
    if not (0 <= h < 24 and 0 <= m < 60 and 0 <= s < 60):
        return None
    return float(h * 3600 + m * 60 + s)


def _spread_exceeds(seconds: list[float], kind: str) -> bool:
    if len(seconds) < 2:
        return False
    spread = max(seconds) - min(seconds)
    if kind == "tod":
        spread = min(spread, _SECONDS_PER_DAY - spread)  # clock wrap-around
    return spread > _EXECUTION_TIME_TOLERANCE_SECONDS


def evaluate_temporal_coupling(finding: Finding) -> TemporalCouplingDecision:
    """Decide whether an execution-timing claim should be temporally demoted.

    Deterministic and downgrade-only. Returns ``not_timing_claim`` for anything
    that is not an execution claim with at least one attributable timestamp.
    """
    fid = finding.finding_id
    if not is_execution_claim(finding.description, finding.mitre_technique):
        return TemporalCouplingDecision(fid, "not_timing_claim", "not an execution claim", False)

    text = finding.description.lower()
    stamps = _extract_timestamps(text)
    if not stamps:
        return TemporalCouplingDecision(
            fid, "not_timing_claim", "execution claim asserts no timestamp", False
        )

    exec_dt: list[float] = []
    exec_tod: list[float] = []
    exec_raw: list[str] = []
    excluded_raw: list[str] = []
    for start, end, kind, raw in stamps:
        src = _classify_source(text, start, end)
        if src == "excluded":
            excluded_raw.append(raw)
            continue
        if src == "execution":
            exec_raw.append(raw)
            secs = _parse_iso(raw) if kind == "dt" else _parse_tod(raw)
            if secs is not None:
                (exec_dt if kind == "dt" else exec_tod).append(secs)
        # "unknown" timestamps are neither credited nor penalized (conservative).

    if not exec_raw and excluded_raw:
        return TemporalCouplingDecision(
            fid,
            "demote_only_catalog_time",
            (
                "execution-timing claim rests only on catalog/registration "
                "timestamps ($SI / ShimCache / Amcache LastModified), which record "
                "cataloging/registration, not when the binary ran"
            ),
            True,
            execution_times=(),
            excluded_times=tuple(excluded_raw),
        )

    if _spread_exceeds(exec_dt, "dt") or _spread_exceeds(exec_tod, "tod"):
        return TemporalCouplingDecision(
            fid,
            "demote_source_disagreement",
            (
                "cited execution-time sources disagree beyond "
                f"{_EXECUTION_TIME_TOLERANCE_SECONDS}s on when the binary ran; the "
                "single asserted execution time is not corroborated"
            ),
            True,
            execution_times=tuple(exec_raw),
            excluded_times=tuple(excluded_raw),
        )

    return TemporalCouplingDecision(
        fid,
        "ok",
        "execution-time sources agree (or a single execution-time source)",
        False,
        execution_times=tuple(exec_raw),
        excluded_times=tuple(excluded_raw),
    )
