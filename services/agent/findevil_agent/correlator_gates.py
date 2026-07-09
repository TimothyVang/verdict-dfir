"""Per-technique corroboration gate family + confidence-ceiling table.

Focused submodule of :mod:`findevil_agent.correlator` (kept under the ECC
800-line guideline). It holds the deterministic, downgrade-only machinery the
facade orchestrates:

* the named, severity-tagged per-technique corroboration gates (EXECUTION,
  LATERAL_MOVEMENT, PRIVILEGE_ESCALATION, PERSISTENCE, CREDENTIAL_ACCESS,
  DEFENSE_EVASION, COMMAND_AND_CONTROL), each mapping a MITRE tactic onto the
  independent artifact-class pair(s) it requires in the Finding's own text, and
* the per-claim-type confidence CEILING table (a hard MAXIMUM tier keyed by
  claim type / evidence composition).

Both families are deterministic and only ever LOWER a tier; they never edit the
audit chain / manifest and never raise a label. ``CorrelationOutcome`` and
``_downgrade`` live here (the lowest layer that constructs/uses them) and are
re-exported by the :mod:`findevil_agent.correlator` facade so the public import
surface is unchanged.

Pure logic — no LLM calls, no I/O. Deterministic given the same inputs.
"""

from __future__ import annotations

import os
import re
from collections.abc import Callable
from dataclasses import dataclass

from findevil_agent.events import Finding

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

# Confidence ladder ordering (high -> low). Used to cap a tier without raising it.
_TIER_ORDER: dict[str, int] = {"HYPOTHESIS": 0, "INFERRED": 1, "CONFIRMED": 2}

# Lateral-movement signature (text or MITRE T1021 Remote Services family). RDP,
# psexec/psexesvc, wmiexec, pass-the-hash and "remote service" are the common
# tells; the destination authentication is what actually proves movement.
_LATERAL_RE = re.compile(
    r"\b(?:lateral\s*movement|pass[-\s]?the[-\s]?hash|psexe(?:c|svc)|wmiexec|rdp|"
    r"remote\s+service)\b",
    re.IGNORECASE,
)
_LATERAL_TECHNIQUE_RE = re.compile(r"\bT1021\b", re.IGNORECASE)
# Windows network (Type 3) / RemoteInteractive-RDP (Type 10) logon — the
# destination-side evidence that a remote authentication actually landed. Without
# it, a source-side process-create of psexec/wmiexec is not lateral-movement proof.
_LATERAL_LOGON_RE = re.compile(
    r"\blogon\s*type\s*(?:3|10)\b|\btype\s*(?:3|10)\s*logon\b", re.IGNORECASE
)

# LSASS named together with a memory/handle-access cue: a process holding a handle
# into LSASS is access, not a completed credential dump.
_LSASS_ACCESS_RE = re.compile(
    r"(?=.*\blsass\b)"
    r"(?=.*\b(?:handle|memory\s?access|process\s?memory|"
    r"read\s?process\s?memory|open\s?process|access(?:ed|ing)?\s+lsass)\b)",
    re.IGNORECASE | re.DOTALL,
)
# A real dump artifact or a 4624/4688 log corroboration lifts the LSASS cap.
_LSASS_DUMP_RE = re.compile(
    r"\.dmp\b|\bminidump\b|\bprocdump\b|\bcomsvcs\b|\bmemory\s?dump\b|"
    r"\bcredential\s?dump\w*|\bntds\.dit\b|\b4624\b|\b4688\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class CorrelationOutcome:
    """Per-finding decision the correlator made.

    ``gate`` / ``severity`` / ``required_pairs`` / ``missing_classes`` are
    populated when a per-technique corroboration gate fired (they stay at their
    neutral defaults for findings no gate matched), giving each WARNING an
    auditable, structured record of which independent artifact-class pair the
    claim needed and which class was absent.

    ``benign_hold`` / ``benign_clearance_state`` / ``benign_hold_reason`` are
    populated by the opt-in benign-exoneration library (see
    :func:`findevil_agent.correlator_benign.evaluate_benign_clearance`) when a
    benign clearance of the finding was REFUSED. A HOLD never changes ``action``
    or the finding's confidence — it is a downgrade/HOLD-only annotation that
    records the malicious reading was kept rather than auto-cleared.
    """

    finding_id: str
    action: str  # "kept" | "downgraded" | "rejected"
    reason: str
    gate: str | None = None  # e.g. "EXECUTION" | "LATERAL_MOVEMENT" | None
    severity: str | None = None  # gate severity tag, e.g. "high" | "medium"
    # Human-readable independent pairs the gate accepts, e.g. ("network+process",
    # "logon"). Any ONE of these satisfies the gate.
    required_pairs: tuple[str, ...] = ()
    # Artifact classes that, if added, would satisfy the closest pair. Empty when
    # the gate held (or no gate fired).
    missing_classes: tuple[str, ...] = ()
    # Benign-exoneration HOLD annotation (opt-in, default-OFF). True when a benign
    # clearance was refused; ``benign_clearance_state`` names the curated reason
    # category ("hold_non_clearable" | "hold_legit_tool_mimic" |
    # "hold_no_verbatim_evidence"); ``benign_hold_reason`` carries the detail.
    benign_hold: bool = False
    benign_clearance_state: str | None = None
    benign_hold_reason: str | None = None
    # Temporal-coupling annotation (opt-in, default-OFF). Names the curated state
    # when the execution-timing check fired ("demote_source_disagreement" |
    # "demote_only_catalog_time"); None when the check did not fire or did not
    # demote. Downgrade-only (see correlator_temporal.evaluate_temporal_coupling).
    temporal_state: str | None = None
    # Counter-evidence FP-suppressor annotation (opt-in, default-OFF). ``fp_suppressor``
    # names which suppressor fired ("known_good_hash" | "system_path_legit" |
    # "process_baseline"); ``fp_reason`` carries the detail. Downgrade/HOLD/NOTE-only
    # (see correlator_suppressors.evaluate_fp_suppressors).
    fp_suppressor: str | None = None
    fp_reason: str | None = None


@dataclass(frozen=True)
class _Ceiling:
    """One entry of the confidence-CEILING table."""

    claim_type: str
    max_tier: str  # hard maximum confidence tier this composition can reach
    reason: str
    # (description_lower, mitre_technique) -> True when this ceiling applies.
    applies: Callable[[str, str | None], bool]


def _is_lateral_claim(text: str, mitre: str | None) -> bool:
    if _LATERAL_RE.search(text):
        return True
    return bool(mitre and _LATERAL_TECHNIQUE_RE.search(mitre))


def _is_lsass_access_only(text: str) -> bool:
    # LSASS handle/memory access without a dump artifact or 4624/4688 log: access,
    # not a completed credential dump.
    return bool(_LSASS_ACCESS_RE.search(text)) and not _LSASS_DUMP_RE.search(text)


# Table is checked top-to-bottom; the most restrictive applicable ceiling wins
# (deterministic — all ceilings only lower).
_CEILING_TABLE: tuple[_Ceiling, ...] = (
    _Ceiling(
        claim_type="lateral-movement",
        max_tier="INFERRED",
        reason=(
            "lateral-movement claim without destination Logon Type 3/10 evidence "
            "cannot exceed INFERRED (source-side process-create is not remote-auth proof)"
        ),
        applies=lambda text, mitre: (
            _is_lateral_claim(text, mitre) and not _LATERAL_LOGON_RE.search(text)
        ),
    ),
    _Ceiling(
        claim_type="credential-access",
        max_tier="INFERRED",
        reason=(
            "ceiling lsass-memory-access-only: a process holding a handle into LSASS "
            "is access, not a completed credential dump — cannot exceed INFERRED "
            "without a dump artifact or 4624/4688 corroboration"
        ),
        applies=lambda text, mitre: _is_lsass_access_only(text),
    ),
)


# ---------------------------------------------------------------------------
# Per-technique corroboration gate family (deterministic, downgrade-only).
#
# Generalizes the single execution gate into a family of named, severity-tagged
# gates (EXECUTION, LATERAL_MOVEMENT, PRIVILEGE_ESCALATION, PERSISTENCE). Each
# maps a MITRE tactic onto the independent artifact-class pairs it requires,
# evaluated against the Finding's OWN text via a shared independence table
# (``_GATE_CLASS_PATTERNS``). It is custody-neutral and never raises confidence.
#
# This table is DISTINCT from ``_CLASS_PATTERNS`` in the facade: that one feeds
# the evidence-type weighting (``classify_evidence_type``) and must stay stable;
# this richer one (adds process/logon/registry/service/token/execution classes)
# feeds only the gate family's ``_present_classes``.
# ---------------------------------------------------------------------------

_GATE_CLASS_PATTERNS: dict[str, re.Pattern[str]] = {
    "prefetch": _PREFETCH_RE,
    "amcache": _AMCACHE_RE,
    "shimcache": _SHIMCACHE_RE,
    "userassist": _USERASSIST_RE,
    "edr": _EDR_RE,
    # Generic "the thing actually ran" class — prefetch/amcache/shimcache/
    # userassist OR an execution verb / 4688 process-creation record. Used by the
    # PERSISTENCE gate's "registry/service + execution" pair.
    "execution": re.compile(
        r"\b(?:prefetch|amcache|shimcache|appcompatcache|userassist|4688"
        r"|process creation|execut(?:ed|ion|ing)|ran|launched|spawned)\b",
        re.IGNORECASE,
    ),
    "network": re.compile(
        r"\b(?:network|netflow|pcap|packet|dns|c2|beacon|smb|443"
        r"|connection|zeek|suricata|nfdump|admin\$|remote share)\b",
        re.IGNORECASE,
    ),
    "process": re.compile(
        r"\b(?:process creation|4688|pslist|psscan|psxview|processguid"
        r"|parent process|child process|process tree)\b",
        re.IGNORECASE,
    ),
    "logon": re.compile(
        r"\b(?:logon type|type 3|type 10|4624|4625|interactive logon"
        r"|network logon|remote logon|rdp logon)\b",
        re.IGNORECASE,
    ),
    "registry": re.compile(
        r"\b(?:registry|run key|runonce|hklm|hkcu|hkey|autostart|ifeo)\b",
        re.IGNORECASE,
    ),
    "service": re.compile(
        r"\b(?:7045|imagepath|sc create|service creation|new service)\b",
        re.IGNORECASE,
    ),
    "token": re.compile(
        r"\b(?:token|privilege|se[a-z]+privilege|integrity level" r"|impersonat\w*|elevat\w*)\b",
        re.IGNORECASE,
    ),
    "eventlog": re.compile(
        r"\b(?:event ?log|evtx|event id|eid \d|4\d{3}|hayabusa|sigma)\b",
        re.IGNORECASE,
    ),
    # Process-memory / volatile-evidence class (LSASS handles, dumps, malfind).
    # Used by the CREDENTIAL_ACCESS and DEFENSE_EVASION gates; no existing gate
    # references it, so adding it does not change prior gate behavior.
    "memory": re.compile(
        r"\b(?:memory|volatility|malfind|handle|lsass|minidump|dump)\b",
        re.IGNORECASE,
    ),
}

# A "slot" is a tuple of acceptable class names (any-of). An "alternative" is a
# tuple of slots that ALL must be satisfied. A gate holds when ANY alternative
# is fully satisfied.
_Slot = tuple[str, ...]
_Alternative = tuple[_Slot, ...]


@dataclass(frozen=True)
class CorroborationGate:
    """A named, severity-tagged per-technique corroboration gate."""

    name: str
    severity: str
    mitre_prefixes: tuple[str, ...]
    text_re: re.Pattern[str]  # tactic detection when no MITRE id is present
    alternatives: tuple[_Alternative, ...]


# EXECUTION mirrors the shipped rule exactly: prefetch + a second registry-class
# execution artifact, OR EDR telemetry. Detection still routes through the shared
# is_execution_claim predicate (in the facade); the alternatives drive only the
# record.
_EXECUTION_GATE = CorroborationGate(
    name="EXECUTION",
    severity="high",
    mitre_prefixes=(),  # detection via is_execution_claim, not a prefix list
    text_re=re.compile(r"(?!)"),  # never matches — execution detection is special-cased
    alternatives=(
        (("prefetch",), ("amcache", "shimcache", "userassist")),
        (("edr",),),
    ),
)

# Other tactic gates. T1543/T1547/T1053 are intentionally absent here — they are
# EXECUTION-prefix techniques handled by the execution gate first, so a scheduled
# task / autostart finding keeps its existing (execution) treatment.
_TACTIC_GATES: tuple[CorroborationGate, ...] = (
    CorroborationGate(
        name="LATERAL_MOVEMENT",
        severity="high",
        mitre_prefixes=("T1021", "T1210", "T1534", "T1550", "T1563", "T1570"),
        text_re=re.compile(
            r"\b(?:lateral movement|psexec|wmiexec|pass[- ]the[- ]hash"
            r"|pass[- ]the[- ]ticket)\b",
            re.IGNORECASE,
        ),
        # network+process, OR a remote logon-type record.
        alternatives=(
            (("network",), ("process",)),
            (("logon",),),
        ),
    ),
    CorroborationGate(
        name="PRIVILEGE_ESCALATION",
        severity="high",
        mitre_prefixes=("T1055", "T1068", "T1078", "T1134", "T1484", "T1548"),
        text_re=re.compile(
            r"\b(?:privilege escalation|priv[- ]?esc|token manipulation|uac bypass)\b",
            re.IGNORECASE,
        ),
        # token/process + an event-log corroboration.
        alternatives=((("token", "process"), ("eventlog",)),),
    ),
    CorroborationGate(
        name="PERSISTENCE",
        severity="medium",
        mitre_prefixes=(
            "T1037",
            "T1098",
            "T1136",
            "T1137",
            "T1197",
            "T1505",
            "T1546",
            "T1556",
            "T1574",
        ),
        text_re=re.compile(
            r"\b(?:persistence|persist\w*|run key|runonce|autostart"
            r"|logon script|wmi event subscription)\b",
            re.IGNORECASE,
        ),
        # registry/service + execution evidence the mechanism actually ran.
        alternatives=((("registry", "service"), ("execution",)),),
    ),
    CorroborationGate(
        name="CREDENTIAL_ACCESS",
        severity="high",
        # T1003 OS Credential Dumping, T1110 Brute Force, T1555 Credentials from
        # Password Stores, T1056 Input Capture, T1212 Exploitation for Cred Access.
        mitre_prefixes=("T1003", "T1110", "T1555", "T1056", "T1212"),
        text_re=re.compile(
            r"\b(?:lsass|credential\s?dump\w*|sekurlsa|mimikatz|secretsdump|"
            r"ntds\.dit|sam\s?hive|dcsync|kerberoast\w*|brute[\s-]?force|"
            r"password\s?spray\w*)\b",
            re.IGNORECASE,
        ),
        # A credential-access claim needs a process/memory class AND an
        # event-log/token class.
        alternatives=((("process", "memory"), ("eventlog", "token")),),
    ),
    CorroborationGate(
        name="DEFENSE_EVASION",
        severity="high",
        # T1070 Indicator Removal, T1112 Modify Registry, T1027 Obfuscated Files,
        # T1218 System Binary Proxy Execution, T1562 Impair Defenses.
        mitre_prefixes=("T1070", "T1112", "T1027", "T1218", "T1562"),
        text_re=re.compile(
            r"\b(?:event\s?log\s?clear\w*|log\s?clear\w*|1102|wevtutil\s?cl|"
            r"clear-?eventlog|timestomp\w*|amsi\s?bypass|"
            r"disab\w*\s+(?:defender|antivirus|av)|defender\s?disab\w*)\b",
            re.IGNORECASE,
        ),
        # A log-clearing / tamper claim needs the event-log class AND a second,
        # non-event-log artifact class.
        alternatives=((("eventlog",), ("process", "network", "memory", "token", "registry")),),
    ),
    CorroborationGate(
        name="COMMAND_AND_CONTROL",
        severity="high",
        # T1071 Application Layer Protocol, T1090 Proxy, T1095 Non-App Layer,
        # T1102 Web Service, T1572 Protocol Tunneling, T1219 Remote Access SW.
        mitre_prefixes=("T1071", "T1090", "T1095", "T1102", "T1572", "T1219"),
        text_re=re.compile(
            r"\b(?:c2|c&c|command\s?and\s?control|beacon\w*|cobalt\s?strike|"
            r"reverse\s?shell|dns\s?tunnel\w*|web\s?shell|webshell)\b",
            re.IGNORECASE,
        ),
        # A C2 claim needs the network class AND the process class.
        alternatives=((("network",), ("process",)),),
    ),
)


# ---------------------------------------------------------------------------
# Gate evaluation.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Adversarial free-text hardening (deterministic, downgrade-only).
#
# Class detection keys on the Finding's prose. Attacker-controlled evidence text
# can be echoed into a description as a QUOTED excerpt (a filename, a registry
# value, a log line) — and a quoted excerpt that names an artifact class
# ("...registry value reads 'corroborated by Sysmon EDR and prefetch'...") would
# otherwise manufacture an artifact-class signal the corroboration gate then
# treats as independent evidence. Class attribution must rest on the analyst's
# OWN (unquoted) wording, not on a string the attacker chose. This strips quoted
# spans before class detection. It can only REMOVE a spoofed class, never add one
# (downgrade-only), and is opt-in via FIND_EVIL_NEUTRALIZE_QUOTED_CLASSES=1 so
# live recall is unchanged until the rollout flips it on.
#
# Note: this does NOT (and cannot) make the correlator manufacture confidence —
# the correlator is downgrade-only, so even un-neutralized spoof prose can at
# most stop a downgrade; it can never UPGRADE a finding above its engine-set tier
# (that tier is anchored by the default-on fact-fidelity gate + verifier, not by
# prose). This guard closes the residual "kept-not-downgraded via quoted echo"
# vector.
# ---------------------------------------------------------------------------

_QUOTED_SPAN_RE = re.compile(r"\"[^\"]*\"|'[^']*'")


def _neutralize_quoted_classes_active() -> bool:
    # Opt-in, default-OFF (custody-neutral, downgrade-only). Mirrors the other
    # correlator gate flags.
    return os.environ.get("FIND_EVIL_NEUTRALIZE_QUOTED_CLASSES") == "1"


def strip_quoted_spans(text: str) -> str:
    """Remove double/single-quoted excerpts (attacker-controllable evidence echoes).

    Deterministic and idempotent: quoted spans are replaced with a single space so
    surrounding tokens stay word-separated. Used before artifact-class detection so
    a class named only inside a quoted excerpt cannot spoof corroboration.
    """
    return _QUOTED_SPAN_RE.sub(" ", text)


def _present_classes(text: str) -> frozenset[str]:
    """Artifact classes whose regex matches the (already-lowercased) text.

    When ``FIND_EVIL_NEUTRALIZE_QUOTED_CLASSES`` is on, quoted excerpts are
    stripped first so an attacker-echoed class name inside a quote cannot
    manufacture a corroboration signal (downgrade-only).
    """
    if _neutralize_quoted_classes_active():
        text = strip_quoted_spans(text)
    return frozenset(name for name, rx in _GATE_CLASS_PATTERNS.items() if rx.search(text))


def _describe_alternatives(alternatives: tuple[_Alternative, ...]) -> tuple[str, ...]:
    """Human-readable pairs the gate accepts, e.g. ("network+process", "logon")."""
    return tuple("+".join("|".join(slot) for slot in alt) for alt in alternatives)


def _evaluate(
    present: frozenset[str], alternatives: tuple[_Alternative, ...]
) -> tuple[bool, tuple[str, ...]]:
    """Return (satisfied, missing_classes).

    A gate holds when ANY alternative has every slot satisfied. When none holds,
    ``missing_classes`` describes the unsatisfied slots of the CLOSEST (fewest
    missing) alternative — deterministic: ties break toward the earlier-listed
    alternative.
    """
    best_missing: list[_Slot] | None = None
    for alt in alternatives:
        missing = [slot for slot in alt if not any(c in present for c in slot)]
        if not missing:
            return True, ()
        if best_missing is None or len(missing) < len(best_missing):
            best_missing = missing
    return False, tuple("|".join(slot) for slot in (best_missing or ()))


def _apply_execution_gate_with_benign(f: Finding) -> tuple[Finding, CorrelationOutcome]:
    # P0-5 benign-explanation gate (opt-in via
    # FIND_EVIL_REQUIRE_COUNTER_HYPOTHESIS_FINDING; default-OFF) runs before the
    # corroboration rule: an execution/intent claim that recorded NO benign
    # alternative it ruled out (counter_hypothesis) is the "too clean" tell and is
    # downgraded one tier regardless of corroboration. The schema validator rejects
    # such a finding at construction when the same flag is on; this covers findings
    # that reached the correlator via the MCP wire (raw dict) and bypassed Pydantic.
    if _benign_gate_active() and not (f.counter_hypothesis or "").strip():
        return _downgrade(f), CorrelationOutcome(
            finding_id=f.finding_id,
            action="downgraded",
            reason="execution/intent claim missing benign-explanation (counter_hypothesis)",
            gate=_EXECUTION_GATE.name,
            severity=_EXECUTION_GATE.severity,
        )
    return _apply_execution_gate(f)


def _apply_execution_gate(f: Finding) -> tuple[Finding, CorrelationOutcome]:
    own_text = f.description.lower()
    present = _present_classes(own_text)
    required = _describe_alternatives(_EXECUTION_GATE.alternatives)
    satisfied, missing = _evaluate(present, _EXECUTION_GATE.alternatives)

    if satisfied:
        return f, CorrelationOutcome(
            finding_id=f.finding_id,
            action="kept",
            reason="execution corroborated in-finding by prefetch+registry pair or EDR telemetry",
            gate=_EXECUTION_GATE.name,
            severity=_EXECUTION_GATE.severity,
            required_pairs=required,
        )

    # Unmet — preserve the original Amcache-vs-generic reason wording.
    amcache_only = (
        _AMCACHE_RE.search(own_text)
        and not _PREFETCH_RE.search(own_text)
        and not _SHIMCACHE_RE.search(own_text)
        and not _EDR_RE.search(own_text)
    )
    reason = (
        "Amcache LastModified is catalog-registration, not execution"
        if amcache_only
        else "execution claim from a single artifact class without prefetch/EDR corroboration"
    )
    return _downgrade(f), CorrelationOutcome(
        finding_id=f.finding_id,
        action="downgraded",
        reason=reason,
        gate=_EXECUTION_GATE.name,
        severity=_EXECUTION_GATE.severity,
        required_pairs=required,
        missing_classes=missing,
    )


def _select_tactic_gate(f: Finding, *, mitre_only: bool) -> CorroborationGate | None:
    """First non-execution gate whose MITRE prefix (and, unless ``mitre_only``,
    tactic prose) matches."""
    own_text = f.description.lower()
    mitre = f.mitre_technique or ""
    for gate in _TACTIC_GATES:
        if mitre and mitre.startswith(gate.mitre_prefixes):
            return gate
        if not mitre_only and gate.text_re.search(own_text):
            return gate
    return None


def _apply_tactic_gate(f: Finding, gate: CorroborationGate) -> tuple[Finding, CorrelationOutcome]:
    present = _present_classes(f.description.lower())
    required = _describe_alternatives(gate.alternatives)
    satisfied, missing = _evaluate(present, gate.alternatives)

    if satisfied:
        return f, CorrelationOutcome(
            finding_id=f.finding_id,
            action="kept",
            reason=f"{gate.name} corroborated in-finding by an independent class pair",
            gate=gate.name,
            severity=gate.severity,
            required_pairs=required,
        )
    return _downgrade(f), CorrelationOutcome(
        finding_id=f.finding_id,
        action="downgraded",
        reason=(
            f"{gate.name} claim from a single artifact class; "
            f"missing independent class(es): {', '.join(missing)}"
        ),
        gate=gate.name,
        severity=gate.severity,
        required_pairs=required,
        missing_classes=missing,
    )


def apply_confidence_ceiling(f: Finding) -> tuple[Finding, str | None]:
    """Cap a finding to its per-claim-type confidence ceiling.

    Returns ``(finding, reason)``. ``reason`` is non-None only when a ceiling
    actually LOWERED the tier; otherwise the original finding is returned with
    ``None``. The ceiling never raises a tier (deterministic anti-overclaim).
    """
    text = f.description.lower()
    applicable = [c for c in _CEILING_TABLE if c.applies(text, f.mitre_technique)]
    if not applicable:
        return f, None
    # Most restrictive applicable ceiling wins.
    strictest = min(applicable, key=lambda c: _TIER_ORDER[c.max_tier])
    capped = _cap_to_tier(f.confidence, strictest.max_tier)
    if capped == f.confidence:
        return f, None
    return f.model_copy(update={"confidence": capped}), strictest.reason


def _active_ceiling_reason(f: Finding) -> str | None:
    """The strictest applicable confidence-ceiling reason for ``f``, regardless of
    whether it would change the tier.

    Used so the ceiling's claim-type explanation (e.g. a lateral-movement claim
    needs destination Logon Type 3/10) stays the authoritative reason on a
    downgraded finding even when a corroboration gate had already lowered it to the
    ceiling tier with a less-specific missing-class reason.
    """
    text = f.description.lower()
    applicable = [c for c in _CEILING_TABLE if c.applies(text, f.mitre_technique)]
    if not applicable:
        return None
    return min(applicable, key=lambda c: _TIER_ORDER[c.max_tier]).reason


def _benign_gate_active() -> bool:
    # Shares the finding-level flag with events.py::_require_counter_hypothesis and
    # the verifier preflight, so stage 5b flips schema + verifier + correlator
    # together. (The judge-collapse discipline uses a separate flag,
    # FIND_EVIL_REQUIRE_COUNTER_HYPOTHESIS — intentionally distinct.)
    return os.environ.get("FIND_EVIL_REQUIRE_COUNTER_HYPOTHESIS_FINDING") == "1"


def _cap_to_tier(confidence: str, max_tier: str) -> str:
    if _TIER_ORDER.get(confidence, 0) <= _TIER_ORDER[max_tier]:
        return confidence  # already at or below the ceiling — never raised
    return max_tier


def _downgrade(f: Finding) -> Finding:
    ladder = {"CONFIRMED": "INFERRED", "INFERRED": "HYPOTHESIS", "HYPOTHESIS": "HYPOTHESIS"}
    new_label = ladder.get(f.confidence, f.confidence)
    if new_label == f.confidence:
        return f
    return f.model_copy(update={"confidence": new_label})
