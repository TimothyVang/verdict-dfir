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

The execution gate is one member of a **family of named,
severity-tagged per-technique corroboration gates** (EXECUTION,
LATERAL_MOVEMENT, PRIVILEGE_ESCALATION, PERSISTENCE,
CREDENTIAL_ACCESS, DEFENSE_EVASION, COMMAND_AND_CONTROL). Each maps a
MITRE tactic onto the independent artifact-class pair(s) it requires
in the Finding's own text and emits a structured record
(``gate``/``severity``/``required_pairs``/``missing_classes``). The
family is deterministic and downgrade-only, and composes with the
per-claim-type confidence CEILING (the stricter constraint wins;
both only ever lower a tier).

The complementary EXONERATION direction is guarded by a curated
benign-clearance library (see
:func:`findevil_agent.correlator_benign.evaluate_benign_clearance`):
a benign clearance of a finding must be evidence-bound and never
softens a non-clearable signature (credential-dumping, log-clearing,
backup-destruction, defense-impairment) or a legit-tool / vendor-signed
demotion. It is HOLD-only — it never clears or raises a finding — and
opt-in via ``FIND_EVIL_REQUIRE_BENIGN_EVIDENCE`` (default-OFF).

This module is the PUBLIC FACADE: the gate family and ceiling table
live in :mod:`findevil_agent.correlator_gates`, the benign-clearance
library in :mod:`findevil_agent.correlator_benign`, and the cross-host
hygiene in :mod:`findevil_agent.correlator_crosshost`. They are all
re-exported here so ``from findevil_agent.correlator import X`` keeps
working unchanged.

Pure logic — no LLM calls, no I/O. Deterministic given the same
inputs.
"""

from __future__ import annotations

import os
import re
from dataclasses import replace

from findevil_agent.correlator_benign import (
    BenignClearanceDecision,
    evaluate_benign_clearance,
)
from findevil_agent.correlator_crosshost import (
    CrossHostCorrelation,
    CrossHostOutcome,
    SharedArtifact,
    correlate_cross_host,
    is_discriminating,
    is_os_signed,
    is_too_common_pivot,
)
from findevil_agent.correlator_gates import (
    _AMCACHE_RE,
    _EDR_RE,
    _LATERAL_RE,
    _PREFETCH_RE,
    _SHIMCACHE_RE,
    _USERASSIST_RE,
    CorrelationOutcome,
    CorroborationGate,
    _active_ceiling_reason,
    _apply_execution_gate_with_benign,
    _apply_tactic_gate,
    _downgrade,
    _neutralize_quoted_classes_active,
    _select_tactic_gate,
    apply_confidence_ceiling,
    strip_quoted_spans,
)
from findevil_agent.correlator_pid_check import (
    MemoryProcess,
    build_cross_artifact_findings,
    cross_artifact_pid_check,
)
from findevil_agent.correlator_suppressors import (
    FpSuppressionDecision,
    evaluate_fp_suppressors,
    fp_suppressors_active,
)
from findevil_agent.correlator_temporal import (
    TemporalCouplingDecision,
    evaluate_temporal_coupling,
    temporal_coupling_gate_active,
)
from findevil_agent.events import Finding
from findevil_agent.execution_claim import is_execution_claim

# ---------------------------------------------------------------------------
# Evidence-type-weighted confidence scoring (custody-neutral).
#
# This is a SCORING ANNOTATION the correlator computes AFTER the ≥2-artifact-class
# gate. It does not change the gate, never edits the audit chain / manifest, and
# never upgrades a Finding's confidence label — it only derives a deterministic
# verdict-level ``confidence_score`` plus a human-readable ``score_basis`` string.
# ---------------------------------------------------------------------------

# Deterministic base confidence per evidence tier.
#   DIRECT        — first-party process-execution telemetry (EDR / Sysmon).
#   CORROBORATED  — ≥2 independent artifact classes agree within the finding.
#   CIRCUMSTANTIAL— a single artifact class supports the claim.
#   INFERRED      — lead-tier (HYPOTHESIS label, or no class signal at all).
_EVIDENCE_TYPE_WEIGHT: dict[str, float] = {
    "DIRECT": 0.90,
    "CORROBORATED": 0.80,
    "CIRCUMSTANTIAL": 0.50,
    "INFERRED": 0.30,
}

# Named, additive corroboration bonus: when ≥2 findings independently reference
# lateral-movement evidence, the campaign reading is stronger than any single
# finding. Additive and capped at 1.0; it never lowers the ≥2-artifact-class gate.
_LATERAL_MOVEMENT_BONUS = 0.05

# Independent artifact-class signals used to weight an individual finding. Kept
# deliberately non-overlapping (no generic "registry" key) so a single Amcache
# mention counts once, not twice. The shared execution-class regexes come from
# correlator_gates; this dict is DISTINCT from the gate family's
# ``_GATE_CLASS_PATTERNS`` (see that module).
_CLASS_PATTERNS: dict[str, re.Pattern[str]] = {
    "prefetch": _PREFETCH_RE,
    "amcache": _AMCACHE_RE,
    "shimcache": _SHIMCACHE_RE,
    "userassist": _USERASSIST_RE,
    "edr": _EDR_RE,
    "eventlog": re.compile(
        r"\b(?:evtx|event\s*log|eid\s*\d+|\d{4}\s+log|security\.evtx)\b", re.IGNORECASE
    ),
    "mft": re.compile(r"\b(?:\$mft|mft|usnjrnl|\$j)\b", re.IGNORECASE),
    "memory": re.compile(r"\b(?:malfind|pslist|psscan|psxview|memory\s*image)\b", re.IGNORECASE),
    "network": re.compile(r"\b(?:pcap|netflow|zeek|suricata|beacon|c2)\b", re.IGNORECASE),
}


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
        # Precedence:
        #   1. A tactic gate matched by its OWN MITRE prefix wins — those prefixes
        #      (T1021/T1134/T1546/…) are disjoint from the execution prefixes, so
        #      this never reroutes a finding the execution gate handled before, and
        #      it lets a persistence/lateral claim that legitimately cites execution
        #      evidence be judged against its tactic's pair rather than as raw
        #      execution.
        #   2. Otherwise EXECUTION keeps its exact shipped decision logic (benign
        #      gate + prefetch/EDR corroboration), so trust-root-collapse is intact.
        #   3. Otherwise a tactic gate matched by prose.
        #   4. Otherwise the non-execution pass-through.
        gate = _select_tactic_gate(f, mitre_only=True)
        if gate is not None:
            refined_f, outcome = _apply_tactic_gate(f, gate)
        elif _is_execution_claim(f):
            refined_f, outcome = _apply_execution_gate_with_benign(f)
        else:
            gate = _select_tactic_gate(f, mitre_only=False)
            if gate is None:
                refined_f, outcome = (
                    f,
                    CorrelationOutcome(
                        finding_id=f.finding_id, action="kept", reason="non-execution claim"
                    ),
                )
            else:
                refined_f, outcome = _apply_tactic_gate(f, gate)
        refined.append(refined_f)
        outcomes.append(outcome)

    # Post-pass: apply the per-claim-type confidence CEILING and the opt-in
    # why_not_higher gate. Both can only LOWER a tier, so order vs. the gates
    # above does not matter for correctness — the most restrictive wins.
    return _apply_post_gates(refined, outcomes)


def classify_evidence_type(finding: Finding) -> str:
    """Map a single finding to its evidence tier (DIRECT / CORROBORATED /
    CIRCUMSTANTIAL / INFERRED).

    The finding's own confidence label is the ceiling — scoring annotates, it
    never upgrades: a HYPOTHESIS lead is always INFERRED-tier, and an INFERRED
    finding caps at CIRCUMSTANTIAL no matter how many classes its text names.
    """
    if finding.confidence == "HYPOTHESIS":
        return "INFERRED"

    text = finding.description.lower()
    # Adversarial-prose hardening (opt-in, downgrade-only): a class named only
    # inside a quoted (attacker-controllable) excerpt must not inflate the
    # evidence tier. See correlator_gates.strip_quoted_spans.
    if _neutralize_quoted_classes_active():
        text = strip_quoted_spans(text)
    classes = {name for name, rx in _CLASS_PATTERNS.items() if rx.search(text)}

    if finding.confidence == "INFERRED":
        return "CIRCUMSTANTIAL" if classes else "INFERRED"

    # CONFIRMED-tier finding: first-party telemetry is direct evidence; two or
    # more independent classes corroborate; a single class is circumstantial.
    if "edr" in classes:
        return "DIRECT"
    if len(classes) >= 2:
        return "CORROBORATED"
    return "CIRCUMSTANTIAL"


def score_verdict(findings: list[Finding]) -> tuple[float, str]:
    """Derive a deterministic verdict ``confidence_score`` and human-readable
    ``score_basis`` from the (already correlated) finding set.

    The strongest finding anchors the base weight; named, additive bonuses are
    then applied and spelled out in ``score_basis`` (e.g.
    ``"base 0.90 direct (f-2) +0.05 lateral-movement corroboration = 0.95"``).
    Pure, deterministic, and custody-neutral.
    """
    if not findings:
        return 0.0, "no findings — base 0.00 = 0.00"

    typed = [(f, classify_evidence_type(f)) for f in findings]
    strongest_f, strongest_type = max(typed, key=lambda pair: _EVIDENCE_TYPE_WEIGHT[pair[1]])
    base = _EVIDENCE_TYPE_WEIGHT[strongest_type]
    components = [f"base {base:.2f} {strongest_type.lower()} ({strongest_f.finding_id})"]
    score = base

    lateral = [f for f, _ in typed if _LATERAL_RE.search(f.description)]
    if len(lateral) >= 2:
        score = min(1.0, score + _LATERAL_MOVEMENT_BONUS)
        components.append(f"+{_LATERAL_MOVEMENT_BONUS:.2f} lateral-movement corroboration")

    score = round(score, 4)
    basis = " ".join(components) + f" = {score:.2f}"
    return score, basis


# ---------------------------------------------------------------------------
# Post-gate orchestration internals.
# ---------------------------------------------------------------------------


def _why_not_higher_gate_active() -> bool:
    # Opt-in, default-OFF (custody-neutral). Mirrors the benign-gate flag style.
    return os.environ.get("FIND_EVIL_REQUIRE_WHY_NOT_HIGHER") == "1"


def _benign_evidence_gate_active() -> bool:
    # Opt-in, default-OFF (custody-neutral). Distinct from the incrimination
    # benign gate (FIND_EVIL_REQUIRE_COUNTER_HYPOTHESIS_FINDING): this one guards
    # the EXONERATION direction via the curated benign-clearance library.
    return os.environ.get("FIND_EVIL_REQUIRE_BENIGN_EVIDENCE") == "1"


def _apply_post_gates(
    refined: list[Finding],
    outcomes: list[CorrelationOutcome],
) -> tuple[list[Finding], list[CorrelationOutcome]]:
    gate_on = _why_not_higher_gate_active()
    benign_evidence_on = _benign_evidence_gate_active()
    temporal_on = temporal_coupling_gate_active()
    fp_on = fp_suppressors_active()
    out_findings: list[Finding] = []
    out_outcomes: list[CorrelationOutcome] = []
    for f, outcome in zip(refined, outcomes, strict=True):
        capped, reason = apply_confidence_ceiling(f)
        if reason is not None:
            # Ceiling lowered the tier — adopt its reason but keep the structured
            # gate record (gate/severity/required_pairs/missing_classes).
            f = capped
            outcome = replace(outcome, action="downgraded", reason=reason)
        else:
            # The ceiling condition can hold without a tier change (a gate already
            # downgraded the finding to/below the ceiling). When it does, the
            # ceiling's reason is the authoritative anti-overclaim explanation for
            # this claim type, so it supersedes the gate's missing-class reason.
            ceiling_reason = _active_ceiling_reason(f)
            if ceiling_reason is not None and outcome.action == "downgraded":
                outcome = replace(outcome, reason=ceiling_reason)
        # why_not_higher gate (opt-in): an INFERRED finding that records no
        # rationale for stopping below CONFIRMED is downgraded one tier.
        if gate_on and f.confidence == "INFERRED" and not (f.why_not_higher or "").strip():
            f = _downgrade(f)
            outcome = replace(
                outcome,
                action="downgraded",
                reason="INFERRED finding declares no why_not_higher rationale",
            )
        # Temporal-coupling check (opt-in): an execution-timing claim whose cited
        # timeline sources disagree, or whose "when it ran" rests only on a
        # catalog/registration ($SI/ShimCache/Amcache LastModified) timestamp, is
        # downgraded one tier. Pure timestamp math, downgrade-only.
        if temporal_on:
            temporal_decision = evaluate_temporal_coupling(f)
            if temporal_decision.demote:
                f = _downgrade(f)
                outcome = replace(
                    outcome,
                    action="downgraded",
                    reason=temporal_decision.reason,
                    temporal_state=temporal_decision.state,
                )
        # Counter-evidence FP suppressors (opt-in): demote when a boring
        # explanation fits (known-good hash, legitimate system-path instance) or
        # NOTE a high-base-rate baseline process. Downgrade/HOLD/NOTE-only.
        if fp_on:
            fp = evaluate_fp_suppressors(f)
            if fp.action == "demote":
                f = _downgrade(f)
                outcome = replace(
                    outcome,
                    action="downgraded",
                    reason=fp.reason,
                    fp_suppressor=fp.suppressor,
                    fp_reason=fp.reason,
                )
            elif fp.action == "note":
                outcome = replace(outcome, fp_suppressor=fp.suppressor, fp_reason=fp.reason)
        # Benign-exoneration HOLD annotation (opt-in). Records when a benign
        # clearance was refused; never changes the finding's confidence or the
        # gate ``action`` (HOLD-only — the malicious reading is kept, not cleared).
        if benign_evidence_on:
            decision = evaluate_benign_clearance(f)
            if decision.benign_hold:
                outcome = replace(
                    outcome,
                    benign_hold=True,
                    benign_clearance_state=decision.state,
                    benign_hold_reason=decision.reason,
                )
        out_findings.append(f)
        out_outcomes.append(outcome)
    return out_findings, out_outcomes


def _is_execution_claim(f: Finding) -> bool:
    # Single source of truth shared with the engine's report-QA gate so the two
    # never disagree on what counts as an execution claim. See execution_claim.py.
    return is_execution_claim(f.description, f.mitre_technique)


__all__ = [
    "BenignClearanceDecision",
    "CorrelationOutcome",
    "CorroborationGate",
    "CrossHostCorrelation",
    "CrossHostOutcome",
    "FpSuppressionDecision",
    "MemoryProcess",
    "SharedArtifact",
    "TemporalCouplingDecision",
    "apply_confidence_ceiling",
    "build_cross_artifact_findings",
    "classify_evidence_type",
    "correlate",
    "correlate_cross_host",
    "cross_artifact_pid_check",
    "evaluate_benign_clearance",
    "evaluate_fp_suppressors",
    "evaluate_temporal_coupling",
    "is_discriminating",
    "is_os_signed",
    "is_too_common_pivot",
    "score_verdict",
    "strip_quoted_spans",
]
