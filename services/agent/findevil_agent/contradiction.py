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
4. **Cross-citation same-entity contradiction.** Two findings name the
   same entity (normalized binary name / file path / hash mentioned in
   *both* descriptions) yet make mutually exclusive claims about it —
   presence-vs-absence (``X ran/present`` vs ``X absent/not found``) or
   mutually exclusive timestamps for that entity — *even when their
   ``tool_call_id`` / ``artifact_path`` citations are disjoint*. Rules
   1-3 all key on a shared citation, so this conservative entity-keyed
   rule catches contradictions that route around them. It requires a
   clear same-entity match to avoid false contradictions.

The detector is pure: deterministic given the same inputs, no LLM.
The Python agent runs it inline as a LangGraph node before the
judge fires; emitted ``ContradictionFound`` events go straight to
the SSE bus and the audit log.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum

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

    # Rule 4: same entity, mutually exclusive claims — even across disjoint
    # citations (Rules 1-3 all require a shared tool_call_id / artifact_path).
    entity_reason = _entity_contradiction(a, b)
    if entity_reason is not None:
        return entity_reason

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


# --- Rule 4 helpers: cross-citation, same-entity contradiction --------------

# Curated executable / script / library extensions. General DFIR signatures —
# never image-specific. A binary named X.exe in one description and X.exe in
# another is the same entity even if cited through different tool calls.
_ENTITY_EXTS = (
    "exe",
    "dll",
    "sys",
    "scr",
    "com",
    "bat",
    "cmd",
    "ps1",
    "vbs",
    "js",
    "jar",
    "msi",
    "lnk",
    "bin",
    "elf",
    "so",
    "sh",
    "py",
)

# Filenames with a known executable/script extension. The character class
# excludes path separators, so a full path collapses to its basename match
# (``C:\\Windows\\evil.exe`` -> ``evil.exe``). Non-capturing group keeps
# ``findall`` returning the full match.
_ENTITY_FILE_RE = re.compile(
    r"[A-Za-z0-9_.\-]+\.(?:" + "|".join(_ENTITY_EXTS) + r")\b",
    re.IGNORECASE,
)

# MD5 (32) / SHA-1 (40) / SHA-256 (64) hex digests — strong entity identifiers.
_ENTITY_HASH_RE = re.compile(
    r"\b[a-f0-9]{64}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{32}\b",
    re.IGNORECASE,
)

# UTC ISO-8601 timestamps with a trailing Z (the project timestamp contract).
_TIMESTAMP_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z\b")

# Presence assertions about an entity.
_PRESENCE_RE = re.compile(
    r"\b(?:present|exists?|existed|ran|run|executed|execution|launched|"
    r"observed|detected|found|seen|recorded|logged|loaded)\b",
    re.IGNORECASE,
)

# Absence assertions. Matched (and stripped) BEFORE presence so a negated verb
# such as ``not found`` does not also register as presence via ``found``.
_ABSENCE_RE = re.compile(
    r"\b(?:absent|missing)\b"
    r"|\bnot\s+(?:found|present|observed|detected|seen|recorded|run|executed|loaded)\b"
    r"|\bno\s+(?:evidence|trace|record|sign|indication)\b"
    r"|\bnever\s+(?:ran|run|executed|loaded)\b"
    r"|\bdid\s+not\s+(?:run|execute|load)\b",
    re.IGNORECASE,
)


def _extract_entities(text: str) -> set[str]:
    """Strong entity identifiers named in ``text``: hashes and known-extension
    binary/file basenames, all lowercased for stable comparison.
    """
    entities: set[str] = set()
    for match in _ENTITY_HASH_RE.findall(text):
        entities.add(match.lower())
    for match in _ENTITY_FILE_RE.findall(text):
        entities.add(match.lower())
    return entities


def _presence_polarity(text: str) -> str | None:
    """Classify ``text`` as ``"present"``, ``"absent"``, or ``None``.

    Conservative: a description that signals BOTH presence and absence (or
    neither) is ambiguous and returns ``None`` so it never anchors a
    contradiction.
    """
    has_absence = bool(_ABSENCE_RE.search(text))
    # Drop absence phrases (incl. their negated verb) before scoring presence,
    # so "X not found" does not also read as presence via "found".
    stripped = _ABSENCE_RE.sub(" ", text)
    has_presence = bool(_PRESENCE_RE.search(stripped))
    if has_absence and not has_presence:
        return "absent"
    if has_presence and not has_absence:
        return "present"
    return None


def _extract_timestamps(text: str) -> set[str]:
    """All UTC ISO-8601 ``...Z`` timestamps named in ``text``."""
    return set(_TIMESTAMP_RE.findall(text))


def _entity_contradiction(a: Finding, b: Finding) -> str | None:
    """Flag a contradiction when ``a`` and ``b`` name the same entity but make
    mutually exclusive claims — presence-vs-absence or disjoint timestamps —
    regardless of whether their citations overlap. Returns ``None`` unless a
    clear same-entity match is present (the conservatism anchor).
    """
    shared = _extract_entities(a.description) & _extract_entities(b.description)
    if not shared:
        return None
    entity = sorted(shared)[0]

    pol_a = _presence_polarity(a.description)
    pol_b = _presence_polarity(b.description)
    if {pol_a, pol_b} == {"present", "absent"}:
        present_pool = "A" if pol_a == "present" else "B"
        absent_pool = "B" if present_pool == "A" else "A"
        return (
            f"same entity {entity!r}: Pool {present_pool} asserts it present/ran "
            f"while Pool {absent_pool} asserts it absent/not found "
            f"(disjoint citations)"
        )

    ts_a = _extract_timestamps(a.description)
    ts_b = _extract_timestamps(b.description)
    if ts_a and ts_b and ts_a.isdisjoint(ts_b):
        return (
            f"same entity {entity!r}: mutually exclusive timestamps "
            f"({sorted(ts_a)} vs {sorted(ts_b)})"
        )

    return None


# --- Cross-source anti-forensics: the "something is missing" family ----------
#
# Rules 1-4 above detect two findings that CONTRADICT each other. This family is
# the inverse: one finding asserts an artifact is PRESENT, but the corroborating
# artifact that should ride alongside it is ABSENT from the whole finding set. An
# absence is never proof of anti-forensics (it may just be a collection gap), so
# every detector here fires as a HYPOTHESIS-tier LEAD — never a conclusion — and
# rides the same ContradictionFound resolution path (Trust present / Trust absent
# / Flag) so the analyst adjudicates it before the judge merges.
#
# All signatures are GENERAL DFIR patterns (event IDs, artifact nouns, MITRE
# techniques) — never image-specific values.


class AntiForensicsPattern(str, Enum):
    """Named cross-source 'something is missing' anti-forensics leads."""

    HIDDEN_SERVICE = "HIDDEN_SERVICE"
    NETWORK_WITHOUT_PROCESS = "NETWORK_WITHOUT_PROCESS"
    INVISIBLE_CONNECTION = "INVISIBLE_CONNECTION"
    LOG_WIPE = "LOG_WIPE"
    PREFETCH_WITHOUT = "PREFETCH_WITHOUT"


@dataclass(frozen=True)
class AntiForensicsLead:
    """A single 'present X but missing corroborating Y' lead (HYPOTHESIS-tier)."""

    pattern: AntiForensicsPattern
    anchor_finding: Finding
    reason: str
    missing: str


# A service was installed / created (T1543.003). EID 7045 is the canonical
# install event; the worded forms and the Services registry path generalize it.
_SERVICE_RE = re.compile(
    r"\b7045\b"
    r"|\bservice\s+(?:was\s+)?(?:installed|created|registered)\b"
    r"|\bnew\s+service\b"
    r"|\bservice\s+creation\b"
    r"|\bServiceDll\b"
    r"|\bImagePath\b"
    r"|\\CurrentControlSet\\Services\\",
    re.IGNORECASE,
)

# A process-listing / process-evidence finding (pslist/psscan/EID 4688/Sysmon 1).
_PROCESS_RE = re.compile(
    r"\bprocess(?:es)?\b"
    r"|\bpslist\b|\bpsscan\b|\bpsxview\b"
    r"|\bpid\b|\bprocess\s+id\b"
    r"|\b4688\b"
    r"|\bimage\s+name\b"
    r"|\bparent\s+process\b|\bchild\s+process\b"
    r"|\brunning\s+process\b",
    re.IGNORECASE,
)

# A network-connection finding (netstat/sysmon network/Zeek/pcap-derived).
_NETWORK_RE = re.compile(
    r"\bconnections?\b"
    r"|\bnetstat\b|\bnetconn\b"
    r"|\bestablished\b|\blistening\b"
    r"|\bremote\s+(?:address|ip|host|port)\b"
    r"|\boutbound\b|\binbound\b"
    r"|\bsockets?\b"
    r"|\bsysmon\s+network\b"
    r"|\bc2\b|\bcommand[\s-]and[\s-]control\b"
    r"|\bport\s+\d+\b"
    r"|\b(?:tcp|udp)\b",
    re.IGNORECASE,
)

# Explicit 'this connection has no owner' signal — the invisible/unlinked socket
# tell (DKOM/rootkit hiding, T1014/T1055), keyed on the finding's own prose.
_NO_OWNER_RE = re.compile(
    r"\bno\s+(?:owning|associated|owner)\s+process\b"
    r"|\bprocess\s+not\s+found\b"
    r"|\bwithout\s+(?:an?\s+)?(?:owning\s+)?process\b"
    r"|\borphan(?:ed)?\s+(?:socket|connection)\b"
    r"|\bunlinked\b"
    r"|\bhidden\s+process\b"
    r"|\bno\s+pid\b"
    r"|\bunknown\s+(?:owner|owning\s+process)\b",
    re.IGNORECASE,
)

# Log-clearing signal (T1070.001) — Security EID 1102 plus the worded clears.
_LOG_CLEAR_RE = re.compile(
    r"\b1102\b"
    r"|\blogs?\s+(?:were\s+|was\s+)?cleared\b"
    r"|\bcleared\s+the\s+(?:security|event|audit|system)\s+log\b"
    r"|\b(?:audit|event|security|system)\s+log\s+(?:was\s+)?cleared\b"
    r"|\bwevtutil\s+cl\b"
    r"|\bClear-EventLog\b",
    re.IGNORECASE,
)

# A timeline-gap finding — corroborates a wipe ('cleared + gap').
_TIME_GAP_RE = re.compile(
    r"\btime(?:line)?\s+gap\b"
    r"|\bgap\s+in\s+(?:the\s+)?(?:logs?|timeline|events?)\b"
    r"|\bno\s+events?\s+(?:between|for|during)\b"
    r"|\bmissing\s+(?:events?|log\s+entries|records?)\b"
    r"|\blog\s+discontinuity\b"
    r"|\bunexplained\s+gap\b",
    re.IGNORECASE,
)

# Execution-artifact finding (prefetch/Amcache/ShimCache) — presence/registration.
_EXEC_ARTIFACT_RE = re.compile(
    r"\bprefetch\b|\.pf\b"
    r"|\bamcache\b"
    r"|\bshim\s?cache\b|\bappcompat(?:cache)?\b"
    r"|\brecentfilecache\b",
    re.IGNORECASE,
)

# A corroborating execution TRACE in a different class (process create / 4688).
_EXEC_TRACE_RE = re.compile(
    r"\b4688\b"
    r"|\bprocess\s+creation\b"
    r"|\bprocess\s+(?:started|launched|spawned|executed)\b"
    r"|\bcommand[\s-]?line\b"
    r"|\bpslist\b|\bpsscan\b"
    r"|\bsecurity\.evtx\b",
    re.IGNORECASE,
)


def _finding_text(finding: Finding) -> str:
    """Concatenated searchable text for signature scanning (no I/O)."""
    return " ".join(
        part
        for part in (
            finding.description or "",
            finding.artifact_path or "",
            finding.artifact_offset or "",
            finding.mitre_technique or "",
        )
        if part
    )


def detect_antiforensics(findings: Iterable[Finding]) -> list[AntiForensicsLead]:
    """Scan the COMBINED finding set for 'present X, missing Y' anti-forensics.

    Pure and deterministic. Every lead is HYPOTHESIS-tier — an absence is a lead
    to corroborate, never a conclusion. Leads are emitted in a fixed pattern
    order, and within each pattern in finding order; ``(pattern, finding_id)`` is
    deduped so one anchor never yields the same lead twice.
    """
    found = list(findings)
    texts = {id(f): _finding_text(f) for f in found}
    entities = {id(f): _extract_entities(texts[id(f)]) for f in found}

    process_findings = [f for f in found if _PROCESS_RE.search(texts[id(f)])]
    exec_trace_findings = [
        f for f in found if _EXEC_TRACE_RE.search(texts[id(f)]) or _PROCESS_RE.search(texts[id(f)])
    ]
    has_time_gap = any(_TIME_GAP_RE.search(texts[id(f)]) for f in found)

    leads: list[AntiForensicsLead] = []
    seen: set[tuple[str, str]] = set()

    def _add(pattern: AntiForensicsPattern, anchor: Finding, reason: str, missing: str) -> None:
        key = (pattern.value, anchor.finding_id)
        if key in seen:
            return
        seen.add(key)
        leads.append(
            AntiForensicsLead(
                pattern=pattern, anchor_finding=anchor, reason=reason, missing=missing
            )
        )

    def _uncorroborated(anchor: Finding, corroborators: list[Finding]) -> str | None:
        """First entity of ``anchor`` that no corroborator shares, else None.

        Returns None when the anchor names no strong entity (conservatism anchor)
        or when some other finding corroborates one of its entities.
        """
        ents = entities[id(anchor)]
        if not ents:
            return None
        for other in corroborators:
            if other.finding_id != anchor.finding_id and ents & entities[id(other)]:
                return None
        return sorted(ents)[0]

    # HIDDEN_SERVICE — a service names a binary, a process listing exists, but no
    # process finding shows a matching process for it.
    if process_findings:
        for f in found:
            if not _SERVICE_RE.search(texts[id(f)]):
                continue
            entity = _uncorroborated(f, process_findings)
            if entity is not None:
                _add(
                    AntiForensicsPattern.HIDDEN_SERVICE,
                    f,
                    f"service references {entity!r} but no process finding shows a matching "
                    f"running process (possible hidden service T1543.003, or the process was "
                    f"not captured) — LEAD",
                    f"owning process for service binary {entity!r}",
                )

    # NETWORK_WITHOUT_PROCESS — a connection is attributed to a binary, a process
    # listing exists, but no process finding owns it.
    if process_findings:
        for f in found:
            if not _NETWORK_RE.search(texts[id(f)]):
                continue
            entity = _uncorroborated(f, process_findings)
            if entity is not None:
                _add(
                    AntiForensicsPattern.NETWORK_WITHOUT_PROCESS,
                    f,
                    f"network connection attributed to {entity!r} has no corroborating "
                    f"owning-process finding (possible unlinked/hidden owner T1055/T1090, or "
                    f"the process was not captured) — LEAD",
                    f"owning process for connection {entity!r}",
                )

    # INVISIBLE_CONNECTION — a connection finding whose own prose says it has no
    # owner (orphan/unlinked socket): the classic DKOM/rootkit tell.
    for f in found:
        text = texts[id(f)]
        if _NETWORK_RE.search(text) and _NO_OWNER_RE.search(text):
            _add(
                AntiForensicsPattern.INVISIBLE_CONNECTION,
                f,
                "network connection finding explicitly lacks an owning process (invisible / "
                "unlinked socket — DKOM/rootkit tell T1014/T1055); treat as a LEAD until the "
                "owner is recovered",
                "owning process structure for the connection",
            )

    # LOG_WIPE — a log-clear signal means records in that window are MISSING, so a
    # downstream 'absence' may be anti-forensic rather than clean.
    for f in found:
        if _LOG_CLEAR_RE.search(texts[id(f)]):
            gap = " (a timeline-gap finding co-occurs)" if has_time_gap else ""
            _add(
                AntiForensicsPattern.LOG_WIPE,
                f,
                "log-clearing signal (e.g. Security EID 1102 / explicit clear) means records "
                "in the affected window are MISSING; downstream 'absence' may be anti-forensic "
                "(T1070.001), not clean" + gap + " — LEAD",
                "log records destroyed by the clear",
            )

    # PREFETCH_WITHOUT — an execution artifact (prefetch/Amcache/ShimCache) names a
    # binary, but no second-class execution trace corroborates that it ran.
    for f in found:
        if not _EXEC_ARTIFACT_RE.search(texts[id(f)]):
            continue
        entity = _uncorroborated(f, exec_trace_findings)
        if entity is not None:
            _add(
                AntiForensicsPattern.PREFETCH_WITHOUT,
                f,
                f"execution artifact (prefetch/Amcache/ShimCache) for {entity!r} has no "
                f"corroborating execution trace in a 2nd artifact class; execution stays a LEAD "
                f"until corroborated (>=2-artifact-class rule)",
                f"corroborating execution trace for {entity!r}",
            )

    return leads


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


def antiforensics_to_events(
    leads: list[AntiForensicsLead],
    *,
    case_id: str,
    resolution_required: bool,
) -> list[ContradictionFound]:
    """Project anti-forensics leads onto the ContradictionFound resolution path.

    Each lead becomes a ``ContradictionFound`` whose A-claim is the PRESENT
    artifact and whose B-claim is the MISSING corroboration, explicitly labelled
    HYPOTHESIS so it is never read as a conclusion. IDs use the ``afl-`` prefix so
    they never collide with :func:`to_events`' ``ctr-`` contradiction IDs.
    """
    out: list[ContradictionFound] = []
    for i, lead in enumerate(leads, start=1):
        anchor = lead.anchor_finding
        conflicting_ids = [anchor.tool_call_id] if anchor.tool_call_id else []
        out.append(
            ContradictionFound(
                case_id=case_id,
                contradiction_id=f"afl-{i:04d}",
                pool_a_claim=f"PRESENT: {_summarize(anchor)}",
                pool_b_claim=(
                    f"MISSING (anti-forensics lead / HYPOTHESIS, {lead.pattern.value}): "
                    f"{lead.missing} is absent — {lead.reason}; corroborate before concluding "
                    f"(may also be a collection gap)"
                ),
                conflicting_tool_call_ids=conflicting_ids,
                resolution_required=resolution_required,
            )
        )
    return out


__all__ = [
    "AntiForensicsLead",
    "AntiForensicsPattern",
    "ContradictionPair",
    "antiforensics_to_events",
    "detect_antiforensics",
    "detect_contradictions",
    "to_events",
]
