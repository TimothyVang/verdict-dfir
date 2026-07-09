"""Tests for findevil_agent.correlator."""

from __future__ import annotations

import pytest

from findevil_agent.correlator import (
    BenignClearanceDecision,
    SharedArtifact,
    apply_confidence_ceiling,
    classify_evidence_type,
    correlate,
    correlate_cross_host,
    evaluate_benign_clearance,
    evaluate_fp_suppressors,
    evaluate_temporal_coupling,
    is_discriminating,
    is_os_signed,
    is_too_common_pivot,
    score_verdict,
)
from findevil_agent.events import Finding


def _f(
    finding_id: str,
    description: str,
    *,
    confidence: str = "CONFIRMED",
    artifact_path: str = "Security.evtx",
    mitre: str | None = None,
    counter_hypothesis: str | None = None,
    construct: bool = False,
    why_not_higher: str | None = None,
) -> Finding:
    fields = dict(
        case_id="c",
        finding_id=finding_id,
        tool_call_id="tc-1",
        artifact_path=artifact_path,
        confidence=confidence,
        description=description,
        mitre_technique=mitre,
        counter_hypothesis=counter_hypothesis,
        why_not_higher=why_not_higher,
    )
    # construct=True bypasses validators to simulate a finding that reached the
    # correlator via the MCP wire (raw dict) rather than the Pydantic constructor —
    # the path the correlator's own benign-gate exists to cover when the schema
    # gate (which rejects at construction) is active.
    return Finding.model_construct(**fields) if construct else Finding(**fields)


class TestNonExecutionFindings:
    def test_passes_through_unchanged(self) -> None:
        f = _f("f-1", "Scheduled task created in Windows namespace")
        refined, outcomes = correlate([f])
        assert refined[0].confidence == "CONFIRMED"
        assert outcomes[0].action == "kept"
        assert "non-execution" in outcomes[0].reason


class TestAmcacheOnly:
    def test_amcache_only_execution_downgrades(self) -> None:
        f = _f(
            "f-1",
            "Amcache shows attacker.exe was executed at 02:11",
            confidence="CONFIRMED",
        )
        refined, outcomes = correlate([f])
        assert refined[0].confidence == "INFERRED"
        assert outcomes[0].action == "downgraded"
        assert "Amcache" in outcomes[0].reason

    def test_amcache_plus_prefetch_kept(self) -> None:
        f = _f(
            "f-1",
            "Prefetch + Amcache corroborate execution of attacker.exe",
            confidence="CONFIRMED",
        )
        refined, outcomes = correlate([f])
        assert refined[0].confidence == "CONFIRMED"
        assert outcomes[0].action == "kept"

    def test_edr_telemetry_kept(self) -> None:
        f = _f(
            "f-1",
            "Sysmon EID 1 records execution of attacker.exe ProcessGuid abc",
            artifact_path="sysmon.evtx",
            confidence="CONFIRMED",
        )
        refined, outcomes = correlate([f])
        assert refined[0].confidence == "CONFIRMED"
        assert outcomes[0].action == "kept"


class TestCrossArtifactRule:
    def test_disk_only_execution_claim_downgraded(self) -> None:
        # Single artifact class, no EDR/prefetch corroboration.
        f = _f(
            "f-1",
            "MFT shows attacker.exe was executed",
            artifact_path="C:\\$MFT",
            confidence="CONFIRMED",
        )
        refined, outcomes = correlate([f])
        assert refined[0].confidence == "INFERRED"
        assert "single artifact class" in outcomes[0].reason

    def test_unrelated_run_classes_do_not_corroborate(self) -> None:
        # Option-1 regression: another finding touching a different artifact
        # class elsewhere in the run must NOT corroborate this finding's
        # execution claim — corroboration has to appear in the Finding itself.
        exec_claim = _f(
            "f-1",
            "MFT shows attacker.exe was executed",
            artifact_path="C:\\$MFT",
            confidence="CONFIRMED",
        )
        unrelated = _f(
            "f-2",
            "Scheduled task created in Windows namespace",
            artifact_path="memory.raw",
            confidence="CONFIRMED",
        )
        refined, outcomes = correlate([exec_claim, unrelated])
        by_id = {o.finding_id: o for o in outcomes}
        assert by_id["f-1"].action == "downgraded"
        assert "single artifact class" in by_id["f-1"].reason
        assert refined[0].confidence == "INFERRED"
        # The unrelated non-execution finding passes through untouched.
        assert by_id["f-2"].action == "kept"

    def test_disk_plus_log_separate_findings_each_downgraded(self) -> None:
        # Two single-class execution claims do not corroborate each other
        # run-wide; each must carry its own ≥2-class evidence. The report-QA
        # gate (which sees timeline event linkage) is the layer that can
        # legitimately join same-binary/same-time findings across classes.
        f1 = _f(
            "f-1",
            "MFT shows attacker.exe was executed",
            artifact_path="C:\\$MFT",
            confidence="CONFIRMED",
        )
        f2 = _f(
            "f-2",
            "EVTX 4688 logs attacker.exe execution at same time",
            artifact_path="Security.evtx",
            confidence="CONFIRMED",
        )
        refined, outcomes = correlate([f1, f2])
        assert all(o.action == "downgraded" for o in outcomes)
        assert all(f.confidence == "INFERRED" for f in refined)


class TestMitreTechniqueTrigger:
    def test_t1053_alone_triggers_execution_check(self) -> None:
        f = _f(
            "f-1",
            "Scheduled task SvcHelper exists in registry",
            mitre="T1053.005",
            confidence="CONFIRMED",
        )
        refined, _outcomes = correlate([f])
        # Single artifact class + no EDR/prefetch cross-corroboration → downgrade.
        assert refined[0].confidence == "INFERRED"

    def test_t1059_with_strong_corroboration_kept(self) -> None:
        f = _f(
            "f-1",
            "PowerShell -enc command launched via Sysmon EID 1",
            mitre="T1059.001",
            artifact_path="sysmon.evtx",
            confidence="CONFIRMED",
        )
        refined, _outcomes = correlate([f])
        assert refined[0].confidence == "CONFIRMED"


class TestEpistemicLadder:
    def test_inferred_downgrades_to_hypothesis(self) -> None:
        f = _f(
            "f-1",
            "Amcache only — execution claim",
            confidence="INFERRED",
        )
        refined, _ = correlate([f])
        assert refined[0].confidence == "HYPOTHESIS"

    def test_hypothesis_stays_hypothesis(self) -> None:
        f = _f(
            "f-1",
            "Amcache only — execution claim",
            confidence="HYPOTHESIS",
        )
        refined, _ = correlate([f])
        assert refined[0].confidence == "HYPOTHESIS"


_GATE = "FIND_EVIL_REQUIRE_COUNTER_HYPOTHESIS_FINDING"
# A strong-corroboration execution claim (prefetch + registry pair) — normally KEPT
# by the corroboration rule, so any downgrade here is the benign-gate's doing.
_STRONG_EXEC = "Prefetch + Amcache corroborate execution of attacker.exe"


class TestBenignGate:
    """P0-5: an execution/intent claim that recorded no benign explanation it ruled
    out (counter_hypothesis) is downgraded one tier. Opt-in via
    FIND_EVIL_REQUIRE_COUNTER_HYPOTHESIS_FINDING — default-OFF, so it is inert on
    live runs until the emitters are taught to populate the field (stage 5b)."""

    def test_default_off_keeps_execution_without_counter_hypothesis(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv(_GATE, raising=False)
        f = _f("f-1", _STRONG_EXEC, confidence="CONFIRMED")
        refined, outcomes = correlate([f])
        # Gate dormant: strong corroboration keeps it CONFIRMED.
        assert refined[0].confidence == "CONFIRMED"
        assert outcomes[0].action == "kept"

    def test_on_downgrades_execution_missing_counter_hypothesis(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(_GATE, "1")
        # Wire-arriving finding (schema gate bypassed) — the correlator's own gate
        # must still catch the missing benign explanation.
        f = _f("f-1", _STRONG_EXEC, confidence="CONFIRMED", construct=True)
        refined, outcomes = correlate([f])
        assert refined[0].confidence == "INFERRED"
        assert outcomes[0].action == "downgraded"
        assert "counter_hypothesis" in outcomes[0].reason

    def test_on_keeps_execution_with_counter_hypothesis(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(_GATE, "1")
        f = _f(
            "f-1",
            _STRONG_EXEC,
            confidence="CONFIRMED",
            counter_hypothesis="benign: could be a vendor updater, but path is user-writable temp",
        )
        refined, outcomes = correlate([f])
        assert refined[0].confidence == "CONFIRMED"
        assert outcomes[0].action == "kept"

    def test_on_keeps_non_execution_without_counter_hypothesis(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Gate scope is execution/intent only — a non-execution CONFIRMED finding
        # without a counter_hypothesis is untouched.
        monkeypatch.setenv(_GATE, "1")
        f = _f(
            "f-1",
            "Scheduled task created in Windows namespace",
            confidence="CONFIRMED",
            construct=True,
        )
        refined, outcomes = correlate([f])
        assert refined[0].confidence == "CONFIRMED"
        assert outcomes[0].action == "kept"


class TestEvidenceTypeWeighting:
    """Rank-4 evidence-type-weighted confidence scoring + human-readable
    score_basis. Custody-neutral: this is the correlator's scoring annotation,
    it never touches verify_finding / the audit chain, and it never upgrades a
    finding's confidence label."""

    def test_two_corroborating_classes_is_corroborated(self) -> None:
        f = _f("f-1", "Prefetch + Amcache corroborate execution of attacker.exe")
        assert classify_evidence_type(f) == "CORROBORATED"
        score, basis = score_verdict([f])
        assert score == 0.80
        assert "corroborated" in basis
        assert "0.80" in basis

    def test_single_class_is_circumstantial_no_upgrade(self) -> None:
        # A single artifact class supports the claim — circumstantial weighting,
        # no auto-upgrade to a stronger tier.
        f = _f(
            "f-1",
            "MFT shows attacker.exe was present on disk",
            artifact_path="C:\\$MFT",
        )
        assert classify_evidence_type(f) == "CIRCUMSTANTIAL"
        score, basis = score_verdict([f])
        assert score == 0.50
        assert "circumstantial" in basis

    def test_edr_telemetry_is_direct(self) -> None:
        f = _f(
            "f-1",
            "Sysmon EID 1 records execution of attacker.exe ProcessGuid abc",
            artifact_path="sysmon.evtx",
        )
        assert classify_evidence_type(f) == "DIRECT"
        score, _ = score_verdict([f])
        assert score == 0.90

    def test_hypothesis_label_caps_at_inferred_weight(self) -> None:
        f = _f(
            "f-1",
            "Prefetch + Amcache hint at execution of attacker.exe",
            confidence="HYPOTHESIS",
        )
        assert classify_evidence_type(f) == "INFERRED"
        score, _ = score_verdict([f])
        assert score == 0.30

    def test_inferred_label_caps_at_circumstantial(self) -> None:
        # Scoring annotates; it must never upgrade an INFERRED-labelled finding
        # to a DIRECT/CORROBORATED weight just because the text names classes.
        f = _f(
            "f-1",
            "Prefetch + Amcache suggest execution of attacker.exe",
            confidence="INFERRED",
        )
        assert classify_evidence_type(f) == "CIRCUMSTANTIAL"
        score, _ = score_verdict([f])
        assert score == 0.50

    def test_strongest_finding_anchors_the_base(self) -> None:
        weak = _f("f-1", "MFT shows attacker.exe was present", artifact_path="C:\\$MFT")
        strong = _f(
            "f-2",
            "Sysmon EID 1 records execution of attacker.exe",
            artifact_path="sysmon.evtx",
        )
        score, basis = score_verdict([weak, strong])
        # DIRECT (0.90) from the Sysmon finding anchors the verdict score.
        assert score == 0.90
        assert "f-2" in basis

    def test_lateral_movement_corroboration_bonus(self) -> None:
        f1 = _f(
            "f-1",
            "Sysmon EID 1 records execution of psexesvc.exe (lateral movement)",
            artifact_path="sysmon.evtx",
        )
        f2 = _f(
            "f-2",
            "RDP lateral movement to host2 logged in Security.evtx EID 4624",
            artifact_path="Security.evtx",
        )
        score, basis = score_verdict([f1, f2])
        # base DIRECT 0.90 + 0.05 lateral-movement corroboration.
        assert score == 0.95
        assert "lateral-movement corroboration" in basis

    def test_empty_finding_set_scores_zero(self) -> None:
        score, basis = score_verdict([])
        assert score == 0.0
        assert "0.00" in basis

    def test_score_basis_snapshot(self) -> None:
        f = _f("f-1", "Prefetch + Amcache corroborate execution of attacker.exe")
        _, basis = score_verdict([f])
        assert basis == "base 0.80 corroborated (f-1) = 0.80"


class TestConfidenceCeiling:
    """Per-claim-type confidence-CEILING table (deterministic anti-overclaim).

    A lateral-movement claim that does not cite a network/RemoteInteractive logon
    (Windows Logon Type 3 or 10) on the destination cannot exceed INFERRED, no
    matter how strong its in-finding execution corroboration is. A process-create
    of psexec/wmiexec on the SOURCE host is not proof the remote authentication
    succeeded. The ceiling can only LOWER a tier, never raise it.
    """

    def test_lateral_movement_without_logon_type_capped(self) -> None:
        # EDR (Sysmon) corroboration would otherwise KEEP this at CONFIRMED via
        # the >=2-artifact-class gate, but no Logon Type 3/10 on the target →
        # ceiling caps at INFERRED.
        f = _f(
            "f-1",
            "Sysmon EID 1 records psexec lateral movement to HOST-2",
            artifact_path="sysmon.evtx",
            confidence="CONFIRMED",
        )
        refined, outcomes = correlate([f])
        assert refined[0].confidence == "INFERRED"
        assert outcomes[0].action == "downgraded"
        assert "logon type" in outcomes[0].reason.lower()

    def test_lateral_movement_with_logon_type_3_left_untouched(self) -> None:
        # Network logon (Type 3) on the target present + EDR corroboration → the
        # ceiling condition is met, finding is left at CONFIRMED.
        f = _f(
            "f-1",
            "Sysmon EID 1 plus Logon Type 3 network logon corroborate "
            "psexec lateral movement to HOST-2",
            artifact_path="sysmon.evtx",
            confidence="CONFIRMED",
        )
        refined, outcomes = correlate([f])
        assert refined[0].confidence == "CONFIRMED"
        assert outcomes[0].action == "kept"

    def test_lateral_movement_with_logon_type_10_left_untouched(self) -> None:
        f = _f(
            "f-1",
            "Sysmon EID 1 plus Logon Type 10 RemoteInteractive logon corroborate "
            "RDP lateral movement to HOST-2",
            artifact_path="sysmon.evtx",
            confidence="CONFIRMED",
        )
        refined, _outcomes = correlate([f])
        assert refined[0].confidence == "CONFIRMED"

    def test_ceiling_never_upgrades_hypothesis(self) -> None:
        # A HYPOTHESIS lateral-movement lead with no logon evidence must stay
        # HYPOTHESIS — the ceiling only lowers, never raises.
        f = _f(
            "f-1",
            "wmiexec lateral movement to HOST-2 suspected",
            confidence="HYPOTHESIS",
        )
        refined, _outcomes = correlate([f])
        assert refined[0].confidence == "HYPOTHESIS"

    def test_ceiling_leaves_inferred_lateral_at_inferred(self) -> None:
        f = _f(
            "f-1",
            "wmiexec lateral movement to HOST-2 suspected",
            confidence="INFERRED",
        )
        capped, reason = apply_confidence_ceiling(f)
        assert capped.confidence == "INFERRED"
        assert reason is None

    def test_non_lateral_finding_not_capped(self) -> None:
        # A plain execution finding (no lateral signature) is untouched by the
        # ceiling table — the EDR corroboration keeps it CONFIRMED.
        f = _f(
            "f-1",
            "Sysmon EID 1 records execution of attacker.exe ProcessGuid abc",
            artifact_path="sysmon.evtx",
            confidence="CONFIRMED",
        )
        capped, reason = apply_confidence_ceiling(f)
        assert capped.confidence == "CONFIRMED"
        assert reason is None

    def test_deterministic_same_input_same_tier(self) -> None:
        f = _f(
            "f-1",
            "Sysmon EID 1 records psexec lateral movement to HOST-2",
            artifact_path="sysmon.evtx",
            confidence="CONFIRMED",
        )
        first, _ = correlate([f])
        second, _ = correlate([f])
        assert first[0].confidence == second[0].confidence == "INFERRED"


class TestWhyNotHigherGate:
    """Opt-in gate: every INFERRED finding must record a ``why_not_higher``
    rationale. Default-OFF (custody-neutral); enabled with
    FIND_EVIL_REQUIRE_WHY_NOT_HIGHER=1.
    """

    def test_gate_off_by_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("FIND_EVIL_REQUIRE_WHY_NOT_HIGHER", raising=False)
        f = _f("f-1", "Some inferred lead", confidence="INFERRED")
        refined, outcomes = correlate([f])
        # Non-execution INFERRED finding passes through untouched.
        assert refined[0].confidence == "INFERRED"
        assert outcomes[0].action == "kept"

    def test_gate_downgrades_inferred_missing_rationale(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FIND_EVIL_REQUIRE_WHY_NOT_HIGHER", "1")
        f = _f("f-1", "Some inferred lead", confidence="INFERRED")
        refined, outcomes = correlate([f])
        assert refined[0].confidence == "HYPOTHESIS"
        assert outcomes[0].action == "downgraded"
        assert "why_not_higher" in outcomes[0].reason

    def test_gate_keeps_inferred_with_rationale(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("FIND_EVIL_REQUIRE_WHY_NOT_HIGHER", "1")
        f = _f(
            "f-1",
            "Some inferred lead",
            confidence="INFERRED",
            why_not_higher="single artifact class; no second corroborating source",
        )
        refined, outcomes = correlate([f])
        assert refined[0].confidence == "INFERRED"
        assert outcomes[0].action == "kept"


class TestExecutionGateRecord:
    def test_kept_execution_emits_gate_record(self) -> None:
        f = _f(
            "f-1",
            "Prefetch + Amcache corroborate execution of attacker.exe",
            confidence="CONFIRMED",
        )
        _refined, outcomes = correlate([f])
        o = outcomes[0]
        assert o.gate == "EXECUTION"
        assert o.severity == "high"
        assert o.required_pairs  # non-empty
        assert o.missing_classes == ()

    def test_downgraded_execution_records_missing_classes(self) -> None:
        f = _f("f-1", "MFT shows attacker.exe was executed", artifact_path="C:\\$MFT")
        _refined, outcomes = correlate([f])
        o = outcomes[0]
        assert o.gate == "EXECUTION"
        assert o.action == "downgraded"
        assert o.missing_classes  # records what was missing


class TestLateralMovementGate:
    def test_single_class_downgrades_with_missing(self) -> None:
        # Only a network class present — missing the independent process pair.
        f = _f(
            "f-1",
            "Lateral movement: SMB network connection to 10.0.0.5 admin$ share",
            mitre="T1021.002",
            confidence="CONFIRMED",
        )
        refined, outcomes = correlate([f])
        o = outcomes[0]
        assert o.gate == "LATERAL_MOVEMENT"
        assert o.action == "downgraded"
        assert refined[0].confidence == "INFERRED"
        assert o.missing_classes  # records the absent class
        assert any("process" in m for m in o.missing_classes)

    def test_independent_pair_holds(self) -> None:
        # network+process satisfies the LATERAL_MOVEMENT *gate* (missing_classes
        # empty), but the rank-4 confidence ceiling then caps it to INFERRED: a
        # lateral claim needs destination Logon Type 3/10, which this finding lacks
        # (source-side process-create is not remote-auth proof). The gate and the
        # ceiling compose to the stricter, more honest result.
        f = _f(
            "f-1",
            "Lateral movement: SMB network connection plus 4688 process creation of psexesvc",
            mitre="T1021.002",
            confidence="CONFIRMED",
        )
        refined, outcomes = correlate([f])
        o = outcomes[0]
        assert o.gate == "LATERAL_MOVEMENT"
        assert o.missing_classes == ()  # the gate itself was satisfied
        assert o.action == "downgraded"  # ceiling capped it
        assert refined[0].confidence == "INFERRED"
        assert "logon type" in o.reason.lower()

    def test_logon_type_alone_holds(self) -> None:
        f = _f(
            "f-1",
            "Lateral movement via remote logon type 3 (4624) from another host",
            mitre="T1021.001",
            confidence="CONFIRMED",
        )
        refined, outcomes = correlate([f])
        assert outcomes[0].gate == "LATERAL_MOVEMENT"
        assert outcomes[0].action == "kept"
        assert refined[0].confidence == "CONFIRMED"


class TestPersistenceGate:
    def test_missing_execution_class_downgrades(self) -> None:
        f = _f(
            "f-1",
            "Persistence: malicious Run key registry value installed under HKLM",
            mitre="T1546.001",
            confidence="CONFIRMED",
        )
        refined, outcomes = correlate([f])
        o = outcomes[0]
        assert o.gate == "PERSISTENCE"
        assert o.severity == "medium"
        assert o.action == "downgraded"
        assert refined[0].confidence == "INFERRED"
        assert any("execution" in m for m in o.missing_classes)

    def test_registry_plus_execution_holds(self) -> None:
        f = _f(
            "f-1",
            "Persistence: Run key registry value plus prefetch shows the payload executed",
            mitre="T1546.001",
            confidence="CONFIRMED",
        )
        refined, outcomes = correlate([f])
        assert outcomes[0].gate == "PERSISTENCE"
        assert outcomes[0].action == "kept"
        assert refined[0].confidence == "CONFIRMED"


class TestPrivilegeEscalationGate:
    def test_missing_eventlog_downgrades(self) -> None:
        f = _f(
            "f-1",
            "Privilege escalation: token manipulation granting SeDebugPrivilege",
            mitre="T1134.001",
            confidence="CONFIRMED",
        )
        refined, outcomes = correlate([f])
        o = outcomes[0]
        assert o.gate == "PRIVILEGE_ESCALATION"
        assert o.severity == "high"
        assert o.action == "downgraded"
        assert refined[0].confidence == "INFERRED"
        assert o.missing_classes

    def test_token_plus_eventlog_holds(self) -> None:
        f = _f(
            "f-1",
            "Privilege escalation: token manipulation, 4672 special privileges logged in Security.evtx",
            mitre="T1134.001",
            confidence="CONFIRMED",
        )
        refined, outcomes = correlate([f])
        assert outcomes[0].gate == "PRIVILEGE_ESCALATION"
        assert outcomes[0].action == "kept"
        assert refined[0].confidence == "CONFIRMED"


class TestGateNeutralForUnmatchedFindings:
    def test_plain_finding_has_no_gate(self) -> None:
        f = _f("f-1", "Scheduled task created in Windows namespace")
        _refined, outcomes = correlate([f])
        assert outcomes[0].gate is None
        assert outcomes[0].action == "kept"


class TestCrossHostHygiene:
    """Rank-7 cross-host correlation hygiene. Custody-neutral: the fleet
    correlation summary is derivative, never the signed per-host manifest, so
    none of this touches verify_finding / the audit chain / scoring math."""

    @staticmethod
    def _by_value(corr):
        return {o.value: o for o in corr.outcomes}

    def test_microsoft_signed_only_produces_no_actor_link(self) -> None:
        # Two hosts sharing only a Microsoft-signed baseline binary: expected,
        # not a campaign signal -> no actor link, binary suppressed from linkage.
        art = SharedArtifact(
            kind="binary",
            value="a" * 64,
            hosts=("HOST-A", "HOST-B"),
            signer="Microsoft Windows Publisher",
        )
        corr = correlate_cross_host([art])
        assert corr.actor_link is False
        assert corr.attribution is False
        out = self._by_value(corr)[art.value]
        assert out.decision == "suppressed"
        assert is_os_signed(art.signer) is True
        assert is_discriminating(art) is False

    def test_unique_implant_hash_groups_for_review_without_attribution(self) -> None:
        # Two hosts sharing a unique unsigned implant hash: a 'shared binaries
        # (review)' grouping (HYPOTHESIS lead) but NEVER attribution.
        art = SharedArtifact(
            kind="binary",
            value="b" * 64,
            hosts=("HOST-A", "HOST-B"),
            signer=None,
        )
        corr = correlate_cross_host([art])
        out = self._by_value(corr)[art.value]
        assert out.decision == "shared_binaries_review"
        assert out.epistemic_label == "HYPOTHESIS"
        assert out.attribution is False
        assert corr.attribution is False

    def test_cloudflare_only_overlap_is_suppressed(self) -> None:
        # A shared CDN/reverse-proxy pivot cannot establish a cross-host link.
        art = SharedArtifact(
            kind="network_pivot",
            value="cdn.cloudflare.net",
            hosts=("HOST-A", "HOST-B"),
        )
        corr = correlate_cross_host([art])
        assert corr.actor_link is False
        assert corr.co_occurrence is True
        out = self._by_value(corr)[art.value]
        assert out.decision == "suppressed"
        assert is_too_common_pivot(art.value) is True

    def test_letsencrypt_and_registrar_pivots_are_too_common(self) -> None:
        assert is_too_common_pivot("Let's Encrypt") is True
        assert is_too_common_pivot("R3 / letsencrypt.org") is True
        assert is_too_common_pivot("GoDaddy.com, LLC") is True
        assert is_too_common_pivot("evil-c2-7f3a.example") is False

    def test_discriminating_pivot_emits_campaign_lead_never_attribution(self) -> None:
        art = SharedArtifact(
            kind="network_pivot",
            value="update-7f3a.duck-typed-c2.example",
            hosts=("HOST-A", "HOST-B"),
        )
        corr = correlate_cross_host([art])
        assert corr.actor_link is True
        assert corr.co_occurrence is False
        assert corr.attribution is False
        out = self._by_value(corr)[art.value]
        assert out.decision == "campaign_lead"
        assert out.epistemic_label == "HYPOTHESIS"
        assert out.attribution is False

    def test_single_host_artifact_is_ignored(self) -> None:
        art = SharedArtifact(kind="binary", value="c" * 64, hosts=("HOST-A",), signer=None)
        corr = correlate_cross_host([art])
        assert corr.outcomes == ()
        assert corr.actor_link is False
        assert corr.co_occurrence is False
        assert is_discriminating(art) is False

    def test_common_pivot_does_not_gate_a_discriminating_binary(self) -> None:
        # Mixed input: a too-common pivot is suppressed but a co-present unsigned
        # shared binary still discriminates -> actor link allowed, no attribution.
        common = SharedArtifact(
            kind="network_pivot", value="cloudflare.com", hosts=("HOST-A", "HOST-B")
        )
        implant = SharedArtifact(
            kind="binary", value="d" * 64, hosts=("HOST-A", "HOST-B"), signer=None
        )
        corr = correlate_cross_host([common, implant])
        assert corr.actor_link is True
        assert corr.co_occurrence is False
        assert corr.attribution is False
        by_value = self._by_value(corr)
        assert by_value["cloudflare.com"].decision == "suppressed"
        assert by_value["d" * 64].decision == "shared_binaries_review"

    def test_attribution_invariant_holds_for_every_outcome(self) -> None:
        arts = [
            SharedArtifact("binary", "e" * 64, ("H1", "H2"), "Microsoft Corporation"),
            SharedArtifact("binary", "f" * 64, ("H1", "H2"), None),
            SharedArtifact("network_pivot", "cloudflare.com", ("H1", "H2")),
            SharedArtifact("network_pivot", "rare-c2.example", ("H1", "H2")),
        ]
        corr = correlate_cross_host(arts)
        assert corr.attribution is False
        assert all(o.attribution is False for o in corr.outcomes)

    def test_outcomes_preserve_input_order_deterministically(self) -> None:
        arts = [
            SharedArtifact("network_pivot", "rare-c2.example", ("H1", "H2")),
            SharedArtifact("binary", "1" * 64, ("H1", "H2"), None),
            SharedArtifact("network_pivot", "cloudflare.com", ("H1", "H2")),
        ]
        corr1 = correlate_cross_host(arts)
        corr2 = correlate_cross_host(arts)
        assert [o.value for o in corr1.outcomes] == [a.value for a in arts]
        assert corr1 == corr2


class TestCredentialAccessGate:
    """CREDENTIAL_ACCESS needs a process/memory class + an event-log/token class."""

    def test_uncorroborated_credential_access_downgraded(self) -> None:
        # Brute-force logon (no process/memory and no event-log/token class).
        f = _f(
            "f-1",
            "Repeated brute-force logon attempts against the administrator account",
            mitre="T1110.001",
            confidence="CONFIRMED",
        )
        refined, outcomes = correlate([f])
        assert refined[0].confidence == "INFERRED"
        assert outcomes[0].action == "downgraded"
        assert outcomes[0].gate == "CREDENTIAL_ACCESS"

    def test_corroborated_credential_access_kept(self) -> None:
        # Process class (4688) + event-log class (4625/4624/Security.evtx).
        f = _f(
            "f-1",
            "Brute-force logon burst (4625 failures then a 4624 success) "
            "corroborated by Security.evtx and a Sysmon process 4688 record",
            mitre="T1110.001",
            confidence="CONFIRMED",
        )
        refined, outcomes = correlate([f])
        assert refined[0].confidence == "CONFIRMED"
        assert outcomes[0].action == "kept"
        assert outcomes[0].gate == "CREDENTIAL_ACCESS"


class TestDefenseEvasionGate:
    """DEFENSE_EVASION (e.g. EID 1102 log clear) needs eventlog + a second class."""

    def test_uncorroborated_log_clear_downgraded(self) -> None:
        f = _f(
            "f-1",
            "Security event log was cleared (EID 1102)",
            mitre="T1070.001",
            confidence="CONFIRMED",
        )
        refined, outcomes = correlate([f])
        assert refined[0].confidence == "INFERRED"
        assert outcomes[0].action == "downgraded"
        assert outcomes[0].gate == "DEFENSE_EVASION"

    def test_corroborated_log_clear_kept(self) -> None:
        f = _f(
            "f-1",
            "Security event log cleared (EID 1102) alongside a Sysmon process "
            "4688 event for the clearing utility",
            mitre="T1070.001",
            confidence="CONFIRMED",
        )
        refined, outcomes = correlate([f])
        assert refined[0].confidence == "CONFIRMED"
        assert outcomes[0].action == "kept"
        assert outcomes[0].gate == "DEFENSE_EVASION"


class TestCommandAndControlGate:
    """COMMAND_AND_CONTROL needs a network class + a process class."""

    def test_uncorroborated_c2_downgraded(self) -> None:
        f = _f(
            "f-1",
            "Periodic beaconing to an external host over HTTPS consistent with C2",
            mitre="T1071.001",
            confidence="CONFIRMED",
        )
        refined, outcomes = correlate([f])
        assert refined[0].confidence == "INFERRED"
        assert outcomes[0].action == "downgraded"
        assert outcomes[0].gate == "COMMAND_AND_CONTROL"

    def test_corroborated_c2_kept(self) -> None:
        # network (beacon/c2/connection) + process (4688 process creation).
        f = _f(
            "f-1",
            "Beaconing C2 over HTTPS from svchost.exe; a Sysmon 4688 process "
            "creation record and the network connection event tie the flow to "
            "that process",
            mitre="T1071.001",
            confidence="CONFIRMED",
        )
        refined, outcomes = correlate([f])
        assert refined[0].confidence == "CONFIRMED"
        assert outcomes[0].action == "kept"
        assert outcomes[0].gate == "COMMAND_AND_CONTROL"


class TestLsassCeiling:
    """LSASS memory-access-only claims cannot exceed INFERRED without a dump
    artifact or a 4624/4688 corroboration — a deterministic anti-overclaim cap."""

    def test_memory_access_only_capped_at_inferred(self) -> None:
        f = _f(
            "f-1",
            "Process opened a handle to lsass memory",
            mitre="T1003.001",
            confidence="CONFIRMED",
        )
        refined, outcomes = correlate([f])
        assert refined[0].confidence == "INFERRED"
        assert outcomes[0].action == "downgraded"

    def test_ceiling_caps_even_when_gate_would_keep(self) -> None:
        # Gate is satisfied (memory + token via the access token), so the gate
        # alone would KEEP it. The ceiling still caps it: no dump artifact and no
        # 4624/4688 corroboration.
        f = _f(
            "f-1",
            "Process accessed lsass memory (handle to lsass.exe) and an access "
            "token was captured",
            mitre="T1003.001",
            confidence="CONFIRMED",
        )
        refined, outcomes = correlate([f])
        assert refined[0].confidence == "INFERRED"
        assert outcomes[0].action == "downgraded"
        assert "ceiling lsass-memory-access-only" in outcomes[0].reason

    def test_ceiling_lifted_by_dump_and_log_corroboration(self) -> None:
        # A real dump artifact (lsass.dmp) + a 4688 log lifts the cap and the
        # gate is corroborated, so the finding is kept at CONFIRMED.
        f = _f(
            "f-1",
            "Process accessed lsass memory (handle to lsass.exe); lsass.dmp was "
            "written and a Security 4688 event recorded",
            mitre="T1003.001",
            confidence="CONFIRMED",
        )
        refined, outcomes = correlate([f])
        assert refined[0].confidence == "CONFIRMED"
        assert outcomes[0].action == "kept"


class TestNewTacticGateDisjointness:
    """New tactic prefixes must not capture execution techniques, and the new
    gates must not touch findings that bind to no gate."""

    def test_execution_technique_not_handled_by_new_tactic_gates(self) -> None:
        # T1053 is an execution technique handled by the execution path, not the
        # credential-access/defense-evasion/C2 gates.
        f = _f(
            "f-1",
            "Scheduled task SvcHelper exists in registry",
            mitre="T1053.005",
            confidence="CONFIRMED",
        )
        refined, outcomes = correlate([f])
        assert refined[0].confidence == "INFERRED"
        assert "single artifact class" in outcomes[0].reason

    def test_unrelated_non_execution_finding_untouched(self) -> None:
        f = _f(
            "f-1",
            "User profile directory observed on disk",
            confidence="CONFIRMED",
        )
        refined, outcomes = correlate([f])
        assert refined[0].confidence == "CONFIRMED"
        assert outcomes[0].action == "kept"
        assert "non-execution" in outcomes[0].reason


_BENIGN_EVIDENCE_GATE = "FIND_EVIL_REQUIRE_BENIGN_EVIDENCE"


class TestBenignClearanceLibrary:
    """Curated benign-exoneration library (deterministic, HOLD-only).

    ``evaluate_benign_clearance`` decides whether a benign clearance of a finding
    is admissible. It never clears or raises a finding — credential-dump /
    log-clear / destruction signatures, bare assertions, and legit-tool / vendor
    demotions are HELD (the malicious reading is kept, not exonerated)."""

    def test_credential_dump_is_non_clearable(self) -> None:
        f = _f(
            "f-1",
            "Process dumped lsass memory to lsass.dmp",
            mitre="T1003.001",
            counter_hypothesis="benign: signed admin tool, expected behavior",
        )
        d = evaluate_benign_clearance(f)
        assert isinstance(d, BenignClearanceDecision)
        assert d.benign_hold is True
        assert d.state == "hold_non_clearable"
        assert d.signature == "credential-dumping"
        assert d.admissible is False

    def test_log_clear_is_non_clearable_by_event_id(self) -> None:
        f = _f(
            "f-1",
            "Security event log was cleared (EID 1102)",
            mitre="T1070.001",
            counter_hypothesis="benign: routine maintenance per 'C:\\logs\\rotate.txt'",
        )
        d = evaluate_benign_clearance(f)
        assert d.state == "hold_non_clearable"
        assert d.signature == "event-log-clearing"

    def test_backup_destruction_is_non_clearable(self) -> None:
        f = _f(
            "f-1",
            "vssadmin delete shadows /all executed",
            counter_hypothesis="benign: disk cleanup at 2026-01-02T03:04:05Z",
        )
        d = evaluate_benign_clearance(f)
        assert d.state == "hold_non_clearable"
        assert d.signature == "backup-inhibition"

    def test_defender_disable_is_non_clearable(self) -> None:
        f = _f(
            "f-1",
            "Attacker disabled Windows Defender real-time protection",
            counter_hypothesis="benign: admin set 'C:\\policy.reg' exclusion",
        )
        d = evaluate_benign_clearance(f)
        assert d.state == "hold_non_clearable"
        assert d.signature == "defense-impairment"

    def test_non_clearable_holds_even_without_counter_hypothesis(self) -> None:
        f = _f("f-1", "mimikatz sekurlsa::logonpasswords observed", mitre="T1003")
        d = evaluate_benign_clearance(f)
        assert d.state == "hold_non_clearable"
        assert d.benign_hold is True

    def test_legit_tool_mimic_holds(self) -> None:
        # Clearable finding, but the benign explanation leans on a dual-use tool
        # name — a signed legit tool used maliciously stays a HOLD, not a clear.
        f = _f(
            "f-1",
            "Suspicious remote execution observed on a workstation",
            mitre="T1021.002",
            counter_hypothesis="benign: this is just psexec used by IT for patching",
        )
        d = evaluate_benign_clearance(f)
        assert d.state == "hold_legit_tool_mimic"
        assert d.benign_hold is True

    def test_vendor_signed_demotion_holds(self) -> None:
        f = _f(
            "f-1",
            "Unusual binary launched from a temp directory",
            counter_hypothesis="benign: the binary is digitally signed by a trusted publisher",
        )
        d = evaluate_benign_clearance(f)
        assert d.state == "hold_legit_tool_mimic"
        assert d.benign_hold is True

    def test_bare_assertion_holds_for_lack_of_verbatim_evidence(self) -> None:
        f = _f(
            "f-1",
            "Unusual binary launched from a temp directory",
            counter_hypothesis="benign: probably normal background activity, nothing to see",
        )
        d = evaluate_benign_clearance(f)
        assert d.state == "hold_no_verbatim_evidence"
        assert d.benign_hold is True

    def test_evidence_bound_clearable_clearance_is_admissible(self) -> None:
        f = _f(
            "f-1",
            "Executable dropped in a user-writable directory",
            counter_hypothesis=(
                "considered scheduled backup, but path C:\\Users\\Public\\x.exe is "
                "user-writable and not a backup location"
            ),
        )
        d = evaluate_benign_clearance(f)
        assert d.state == "admissible"
        assert d.admissible is True
        assert d.benign_hold is False

    def test_no_clearance_when_field_absent_on_clearable_finding(self) -> None:
        f = _f("f-1", "Executable dropped in a user-writable directory")
        d = evaluate_benign_clearance(f)
        assert d.state == "no_clearance"
        assert d.benign_hold is False

    def test_quoted_excerpt_satisfies_verbatim_requirement(self) -> None:
        f = _f(
            "f-1",
            "Registry autostart value observed",
            counter_hypothesis='considered vendor updater, but value data "C:\\t\\m.exe" is atypical',
        )
        d = evaluate_benign_clearance(f)
        # Quoted excerpt counts as verbatim evidence and no legit-tool/vendor term.
        assert d.state == "admissible"


class TestBenignExonerationGate:
    """Opt-in correlator wiring of the exoneration library. Default-OFF; enabled
    with FIND_EVIL_REQUIRE_BENIGN_EVIDENCE=1. HOLD-only: it annotates the outcome
    when a benign clearance is refused and NEVER changes confidence or action."""

    def test_gate_off_by_default_no_annotation(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(_BENIGN_EVIDENCE_GATE, raising=False)
        f = _f(
            "f-1",
            "Process dumped lsass memory to lsass.dmp",
            mitre="T1003.001",
        )
        _refined, outcomes = correlate([f])
        assert outcomes[0].benign_hold is False
        assert outcomes[0].benign_clearance_state is None

    def test_gate_on_annotates_non_clearable_hold(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(_BENIGN_EVIDENCE_GATE, "1")
        f = _f(
            "f-1",
            "Process dumped lsass memory to lsass.dmp",
            mitre="T1003.001",
            counter_hypothesis="benign: signed admin tool",
        )
        _refined, outcomes = correlate([f])
        assert outcomes[0].benign_hold is True
        assert outcomes[0].benign_clearance_state == "hold_non_clearable"
        assert outcomes[0].benign_hold_reason

    def test_gate_on_annotates_legit_tool_mimic(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(_BENIGN_EVIDENCE_GATE, "1")
        f = _f(
            "f-1",
            "Suspicious remote execution observed on a workstation",
            mitre="T1021.002",
            counter_hypothesis="benign: this is just psexec used by IT",
        )
        _refined, outcomes = correlate([f])
        assert outcomes[0].benign_hold is True
        assert outcomes[0].benign_clearance_state == "hold_legit_tool_mimic"

    def test_gate_on_does_not_annotate_admissible_clearance(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(_BENIGN_EVIDENCE_GATE, "1")
        f = _f(
            "f-1",
            "Executable dropped in a user-writable directory",
            counter_hypothesis=(
                "considered scheduled backup, but path C:\\Users\\Public\\x.exe is "
                "user-writable and not a backup location"
            ),
        )
        _refined, outcomes = correlate([f])
        assert outcomes[0].benign_hold is False

    def test_hold_never_changes_confidence(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # The HOLD annotation is downgrade/HOLD-only: confidence with the gate ON
        # must equal confidence with it OFF (the library never raises or lowers).
        f = _f(
            "f-1",
            "Process dumped lsass memory to lsass.dmp",
            mitre="T1003.001",
            counter_hypothesis="benign: digitally signed by a trusted publisher",
        )
        monkeypatch.delenv(_BENIGN_EVIDENCE_GATE, raising=False)
        off_refined, _ = correlate([f])
        monkeypatch.setenv(_BENIGN_EVIDENCE_GATE, "1")
        on_refined, on_outcomes = correlate([f])
        assert off_refined[0].confidence == on_refined[0].confidence
        assert on_outcomes[0].benign_hold is True

    def test_hold_does_not_raise_a_hypothesis_lead(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(_BENIGN_EVIDENCE_GATE, "1")
        f = _f(
            "f-1",
            "wmiexec lateral movement to a host suspected",
            confidence="HYPOTHESIS",
            counter_hypothesis="benign: this is just wmic admin usage",
        )
        refined, outcomes = correlate([f])
        assert refined[0].confidence == "HYPOTHESIS"
        assert outcomes[0].benign_hold is True

    def test_deterministic_same_input_same_decision(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(_BENIGN_EVIDENCE_GATE, "1")
        f = _f(
            "f-1",
            "Security event log was cleared (EID 1102)",
            mitre="T1070.001",
            counter_hypothesis="benign: routine",
        )
        _r1, o1 = correlate([f])
        _r2, o2 = correlate([f])
        assert o1[0].benign_clearance_state == o2[0].benign_clearance_state == "hold_non_clearable"

    def test_existing_incrimination_benign_gate_unaffected(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The exoneration flag must not perturb the incrimination benign gate.
        monkeypatch.delenv(_BENIGN_EVIDENCE_GATE, raising=False)
        monkeypatch.setenv("FIND_EVIL_REQUIRE_COUNTER_HYPOTHESIS_FINDING", "1")
        f = _f("f-1", _STRONG_EXEC, confidence="CONFIRMED", construct=True)
        refined, outcomes = correlate([f])
        assert refined[0].confidence == "INFERRED"
        assert outcomes[0].action == "downgraded"
        assert outcomes[0].benign_hold is False


_NEUTRALIZE_QUOTED = "FIND_EVIL_NEUTRALIZE_QUOTED_CLASSES"

# An execution finding whose ONLY second-class corroboration is attacker-style
# prose echoed inside a QUOTED excerpt. The real provenance is a single class
# (MFT); the quoted excerpt names EDR + prefetch to try to satisfy the gate.
_SPOOF_QUOTED_EXEC = (
    "MFT timeline shows attacker.exe on disk; the registry value text reads "
    '"corroborated by Sysmon EDR and prefetch — definitely ran"'
)
# The same corroboration claim made in the analyst's OWN (unquoted) wording —
# this is legitimate and must keep holding.
_LEGIT_UNQUOTED_EXEC = "Prefetch + Amcache corroborate execution of attacker.exe"


class TestAdversarialCorroborationProse:
    """Adversarial free-text vs. predicate corroboration.

    Class detection keys on the Finding's prose, so attacker-controlled evidence
    text echoed into a description (typically as a quoted excerpt) could try to
    manufacture a second artifact class and stop a downgrade. Two guarantees:

      1. BEDROCK (flag-independent): the correlator is downgrade-only, so no
         amount of corroboration prose can UPGRADE a finding above its
         engine-set tier. The CONFIRMED label is anchored by the default-on
         fact-fidelity gate + verifier, never by description text.
      2. HARDENING (opt-in FIND_EVIL_NEUTRALIZE_QUOTED_CLASSES): a class named
         only inside a quoted excerpt is neutralized before class detection, so a
         quoted attacker echo cannot satisfy the corroboration gate. Downgrade-
         only — it can remove a spoofed class, never add one.
    """

    def test_prose_cannot_upgrade_engine_tier(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # The bedrock guarantee: an INFERRED finding stuffed with "perfect"
        # multi-class corroboration prose can NEVER come out CONFIRMED. The
        # correlator only ever lowers a tier.
        monkeypatch.delenv(_NEUTRALIZE_QUOTED, raising=False)
        f = _f(
            "f-1",
            "Sysmon EDR, prefetch, amcache, 4688 process creation and a network "
            "beacon all CONFIRM attacker.exe definitely executed",
            mitre="T1059.001",
            confidence="INFERRED",
        )
        refined, _outcomes = correlate([f])
        assert refined[0].confidence != "CONFIRMED"
        assert refined[0].confidence in {"INFERRED", "HYPOTHESIS"}

    def test_default_off_documents_the_quoted_echo_hole(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # With the hardening OFF (current default), the quoted attacker echo still
        # satisfies the EDR alternative and the finding is KEPT — this documents
        # exactly the residual the opt-in flag closes. (It is never UPGRADED; the
        # engine set CONFIRMED, and the correlator merely declines to downgrade.)
        monkeypatch.delenv(_NEUTRALIZE_QUOTED, raising=False)
        f = _f("f-1", _SPOOF_QUOTED_EXEC, mitre="T1059.001", confidence="CONFIRMED")
        refined, outcomes = correlate([f])
        assert refined[0].confidence == "CONFIRMED"
        assert outcomes[0].action == "kept"

    def test_quoted_echo_downgraded_when_neutralized(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # With the hardening ON, the quoted excerpt is stripped before class
        # detection, the spoofed EDR/prefetch classes vanish, only the real
        # single class (registry value) remains, and the execution gate downgrades.
        monkeypatch.setenv(_NEUTRALIZE_QUOTED, "1")
        f = _f("f-1", _SPOOF_QUOTED_EXEC, mitre="T1059.001", confidence="CONFIRMED")
        refined, outcomes = correlate([f])
        assert refined[0].confidence == "INFERRED"
        assert outcomes[0].action == "downgraded"
        assert outcomes[0].gate == "EXECUTION"

    def test_unquoted_attribution_still_holds_when_neutralized(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Hardening must not punish a legitimate finding whose corroboration is in
        # the analyst's own unquoted wording.
        monkeypatch.setenv(_NEUTRALIZE_QUOTED, "1")
        f = _f("f-1", _LEGIT_UNQUOTED_EXEC, confidence="CONFIRMED")
        refined, outcomes = correlate([f])
        assert refined[0].confidence == "CONFIRMED"
        assert outcomes[0].action == "kept"

    def test_classify_evidence_type_not_inflated_by_quoted_classes(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The scoring annotation must also key on unquoted attribution: a single
        # real class with quoted EDR/prefetch echoes is not DIRECT/CORROBORATED.
        monkeypatch.setenv(_NEUTRALIZE_QUOTED, "1")
        f = _f("f-1", _SPOOF_QUOTED_EXEC, mitre="T1059.001", confidence="CONFIRMED")
        assert classify_evidence_type(f) == "CIRCUMSTANTIAL"
        # And without the flag the quoted echo would have read as multi-class.
        monkeypatch.delenv(_NEUTRALIZE_QUOTED, raising=False)
        assert classify_evidence_type(f) in {"DIRECT", "CORROBORATED"}

    def test_neutralization_is_deterministic(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(_NEUTRALIZE_QUOTED, "1")
        f = _f("f-1", _SPOOF_QUOTED_EXEC, mitre="T1059.001", confidence="CONFIRMED")
        first, _ = correlate([f])
        second, _ = correlate([f])
        assert first[0].confidence == second[0].confidence == "INFERRED"


_TEMPORAL_GATE = "FIND_EVIL_REQUIRE_TEMPORAL_COUPLING"

# Gate-passing (EDR) execution finding whose two genuine execution-time sources
# disagree by hours — the corroboration gate keeps it, so any downgrade here is
# the temporal check's doing.
_TEMPORAL_DISAGREEMENT = (
    "Sysmon EID 1 (4688 process creation) records attacker.exe executed at "
    "2026-01-02T03:04:05Z; Prefetch last run for the same binary shows "
    "2026-01-02T09:45:00Z"
)


class TestTemporalCouplingPure:
    """Pure-function temporal-coupling classification (deterministic timestamp math)."""

    def test_non_execution_claim_is_not_a_timing_claim(self) -> None:
        f = _f("f-1", "Registry Run key value observed at 2026-01-02T03:04:05Z")
        d = evaluate_temporal_coupling(f)
        assert d.state == "not_timing_claim"
        assert d.demote is False

    def test_execution_claim_without_timestamp_is_not_a_timing_claim(self) -> None:
        f = _f("f-1", "Prefetch shows attacker.exe was executed")
        d = evaluate_temporal_coupling(f)
        assert d.state == "not_timing_claim"
        assert d.demote is False

    def test_agreeing_execution_sources_ok(self) -> None:
        f = _f(
            "f-1",
            "Sysmon 4688 process creation of attacker.exe at 2026-01-02T03:04:05Z; "
            "Prefetch last run shows 2026-01-02T03:06:00Z",
        )
        d = evaluate_temporal_coupling(f)
        assert d.state == "ok"
        assert d.demote is False

    def test_single_execution_source_ok(self) -> None:
        f = _f("f-1", "Prefetch last run shows attacker.exe executed at 2026-01-02T03:04:05Z")
        d = evaluate_temporal_coupling(f)
        assert d.state == "ok"
        assert d.demote is False

    def test_disagreeing_execution_sources_demote(self) -> None:
        f = _f("f-1", _TEMPORAL_DISAGREEMENT)
        d = evaluate_temporal_coupling(f)
        assert d.state == "demote_source_disagreement"
        assert d.demote is True
        assert len(d.execution_times) == 2

    def test_amcache_lastmodified_only_demotes_as_catalog_time(self) -> None:
        f = _f(
            "f-1",
            "Amcache LastModified 2026-01-02T03:04:05Z indicates attacker.exe was executed",
        )
        d = evaluate_temporal_coupling(f)
        assert d.state == "demote_only_catalog_time"
        assert d.demote is True
        assert d.execution_times == ()

    def test_shimcache_only_demotes_as_catalog_time(self) -> None:
        f = _f(
            "f-1",
            "ShimCache (AppCompatCache) entry at 2026-01-02T03:04:05Z shows the binary ran",
        )
        d = evaluate_temporal_coupling(f)
        assert d.state == "demote_only_catalog_time"
        assert d.demote is True

    def test_si_standard_information_excluded_from_run_time(self) -> None:
        f = _f(
            "f-1",
            "$SI standard information modified time 2026-01-02T03:04:05Z; the binary executed",
        )
        d = evaluate_temporal_coupling(f)
        assert d.state == "demote_only_catalog_time"
        assert d.demote is True

    def test_catalog_time_does_not_save_a_disagreement(self) -> None:
        # A real execution source present alongside a catalog time -> not the
        # only-catalog case; a single execution source means no disagreement -> ok.
        f = _f(
            "f-1",
            "Amcache LastModified 2026-01-02T01:00:00Z; Sysmon 4688 process creation "
            "of attacker.exe executed at 2026-01-02T03:04:05Z",
        )
        d = evaluate_temporal_coupling(f)
        assert d.state == "ok"
        assert d.excluded_times  # the catalog time is recorded but not credited

    def test_time_only_disagreement_demotes(self) -> None:
        f = _f(
            "f-1",
            "Sysmon 4688 process creation at 03:04; Prefetch last run shows 09:45 — executed",
        )
        d = evaluate_temporal_coupling(f)
        assert d.state == "demote_source_disagreement"
        assert d.demote is True

    def test_deterministic_same_input_same_decision(self) -> None:
        f = _f("f-1", _TEMPORAL_DISAGREEMENT)
        assert evaluate_temporal_coupling(f).state == evaluate_temporal_coupling(f).state


class TestTemporalCouplingWiring:
    """Opt-in correlator wiring. Default-OFF (custody-neutral); enabled with
    FIND_EVIL_REQUIRE_TEMPORAL_COUPLING=1. Downgrade-only and never raises."""

    def test_gate_off_keeps_gate_passing_finding(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(_TEMPORAL_GATE, raising=False)
        # EDR corroboration keeps the execution gate satisfied; with the temporal
        # gate OFF the source disagreement is inert and the finding stays CONFIRMED.
        f = _f("f-1", _TEMPORAL_DISAGREEMENT, artifact_path="sysmon.evtx", confidence="CONFIRMED")
        refined, outcomes = correlate([f])
        assert refined[0].confidence == "CONFIRMED"
        assert outcomes[0].action == "kept"
        assert outcomes[0].temporal_state is None

    def test_gate_on_demotes_source_disagreement(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(_TEMPORAL_GATE, "1")
        f = _f("f-1", _TEMPORAL_DISAGREEMENT, artifact_path="sysmon.evtx", confidence="CONFIRMED")
        refined, outcomes = correlate([f])
        assert refined[0].confidence == "INFERRED"
        assert outcomes[0].action == "downgraded"
        assert outcomes[0].temporal_state == "demote_source_disagreement"

    def test_gate_on_never_raises_a_hypothesis(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(_TEMPORAL_GATE, "1")
        f = _f("f-1", _TEMPORAL_DISAGREEMENT, confidence="HYPOTHESIS")
        refined, _outcomes = correlate([f])
        assert refined[0].confidence == "HYPOTHESIS"

    def test_gate_on_leaves_agreeing_timing_untouched(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(_TEMPORAL_GATE, "1")
        f = _f(
            "f-1",
            "Sysmon 4688 process creation of attacker.exe at 2026-01-02T03:04:05Z; "
            "Prefetch last run shows 2026-01-02T03:06:00Z",
            artifact_path="sysmon.evtx",
            confidence="CONFIRMED",
        )
        refined, outcomes = correlate([f])
        assert refined[0].confidence == "CONFIRMED"
        assert outcomes[0].action == "kept"


_FP_GATE = "FIND_EVIL_REQUIRE_FP_SUPPRESSORS"
_KNOWN_GOOD_ENV = "FIND_EVIL_KNOWN_GOOD_HASHES"

# Empty-file SHA-256 — a built-in known-good (trivially-benign) content hash.
_EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


class TestFpSuppressorsPure:
    """Pure-function counter-evidence FP suppressors (deterministic, downgrade-only)."""

    def test_known_good_hash_demotes(self) -> None:
        f = _f("f-1", f"Unknown binary dropped on disk with sha256 {_EMPTY_SHA256}")
        d = evaluate_fp_suppressors(f)
        assert d.action == "demote"
        assert d.suppressor == "known_good_hash"

    def test_operator_env_extends_known_good(self, monkeypatch: pytest.MonkeyPatch) -> None:
        custom = "a" * 64
        monkeypatch.setenv(_KNOWN_GOOD_ENV, custom)
        f = _f("f-1", f"Suspicious binary with sha256 {custom} on disk")
        d = evaluate_fp_suppressors(f)
        assert d.action == "demote"
        assert d.suppressor == "known_good_hash"

    def test_unknown_hash_is_not_whitelisted(self) -> None:
        f = _f("f-1", "Suspicious binary with sha256 " + ("b" * 64) + " on disk")
        d = evaluate_fp_suppressors(f)
        assert d.suppressor != "known_good_hash"

    def test_legitimate_system_path_demotes(self) -> None:
        f = _f(
            "f-1",
            "Heuristic flagged svchost.exe at C:\\Windows\\System32\\svchost.exe",
        )
        d = evaluate_fp_suppressors(f)
        assert d.action == "demote"
        assert d.suppressor == "system_path_legit"

    def test_masquerade_path_is_not_suppressed(self) -> None:
        # svchost.exe in a non-canonical path is the masquerade tell — leave it.
        f = _f(
            "f-1",
            "svchost.exe running from C:\\Users\\Public\\svchost.exe (possible masquerade)",
        )
        d = evaluate_fp_suppressors(f)
        assert d.suppressor != "system_path_legit"
        assert d.action != "demote"

    def test_process_baseline_is_a_note_only(self) -> None:
        f = _f("f-1", "explorer.exe observed in the process listing")
        d = evaluate_fp_suppressors(f)
        assert d.action == "note"
        assert d.suppressor == "process_baseline"

    def test_non_clearable_blocks_hash_demotion(self) -> None:
        # A credential-dump finding must NOT be demoted by a coincidental
        # known-good hash — credential-dumping is a non-clearable signature.
        f = _f(
            "f-1",
            f"Credential dump: mimikatz sekurlsa harvested lsass (sha256 {_EMPTY_SHA256})",
            mitre="T1003.001",
        )
        d = evaluate_fp_suppressors(f)
        assert d.action != "demote"
        assert d.suppressor != "known_good_hash"

    def test_non_clearable_blocks_system_path_demotion(self) -> None:
        f = _f(
            "f-1",
            "Credential dump from C:\\Windows\\System32\\lsass.exe via comsvcs minidump",
            mitre="T1003.001",
        )
        d = evaluate_fp_suppressors(f)
        assert d.action != "demote"

    def test_deterministic_same_input_same_decision(self) -> None:
        f = _f("f-1", f"binary with sha256 {_EMPTY_SHA256}")
        assert evaluate_fp_suppressors(f).suppressor == evaluate_fp_suppressors(f).suppressor


class TestFpSuppressorsWiring:
    """Opt-in correlator wiring. Default-OFF (custody-neutral); enabled with
    FIND_EVIL_REQUIRE_FP_SUPPRESSORS=1. Downgrade/HOLD/NOTE-only, never raises."""

    def test_gate_off_no_annotation(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(_FP_GATE, raising=False)
        f = _f("f-1", f"Unknown binary with sha256 {_EMPTY_SHA256} dropped", confidence="CONFIRMED")
        refined, outcomes = correlate([f])
        assert refined[0].confidence == "CONFIRMED"
        assert outcomes[0].fp_suppressor is None

    def test_gate_on_known_good_hash_demotes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(_FP_GATE, "1")
        f = _f("f-1", f"Unknown binary with sha256 {_EMPTY_SHA256} dropped", confidence="CONFIRMED")
        refined, outcomes = correlate([f])
        assert refined[0].confidence == "INFERRED"
        assert outcomes[0].action == "downgraded"
        assert outcomes[0].fp_suppressor == "known_good_hash"

    def test_gate_on_system_path_demotes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(_FP_GATE, "1")
        f = _f(
            "f-1",
            "Heuristic flagged svchost.exe at C:\\Windows\\System32\\svchost.exe",
            confidence="CONFIRMED",
        )
        refined, outcomes = correlate([f])
        assert refined[0].confidence == "INFERRED"
        assert outcomes[0].fp_suppressor == "system_path_legit"

    def test_gate_on_baseline_note_does_not_change_confidence(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(_FP_GATE, "1")
        f = _f("f-1", "explorer.exe observed in the process listing", confidence="CONFIRMED")
        refined, outcomes = correlate([f])
        # NOTE-only: confidence unchanged, but the annotation is recorded.
        assert refined[0].confidence == "CONFIRMED"
        assert outcomes[0].action == "kept"
        assert outcomes[0].fp_suppressor == "process_baseline"

    def test_gate_on_does_not_demote_non_clearable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(_FP_GATE, "1")
        # Gate-passing credential-dump finding (memory + event-log classes) so the
        # only candidate demotion is the FP suppressor — which must REFUSE because
        # credential-dumping is a non-clearable signature, even with a known-good hash.
        f = _f(
            "f-1",
            "Credential dump: mimikatz sekurlsa harvested lsass memory; Sysmon 4688 "
            f"process creation and a 4624 logon recorded (sha256 {_EMPTY_SHA256})",
            mitre="T1003.001",
            confidence="CONFIRMED",
        )
        refined, outcomes = correlate([f])
        # The known-good hash must not soften a credential-dump finding.
        assert refined[0].confidence == "CONFIRMED"
        assert outcomes[0].fp_suppressor != "known_good_hash"

    def test_gate_on_never_raises_a_hypothesis(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(_FP_GATE, "1")
        f = _f("f-1", f"binary with sha256 {_EMPTY_SHA256}", confidence="HYPOTHESIS")
        refined, _outcomes = correlate([f])
        assert refined[0].confidence == "HYPOTHESIS"

    def test_gate_on_leaves_masquerade_finding_intact(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(_FP_GATE, "1")
        f = _f(
            "f-1",
            "svchost.exe running from C:\\Users\\Public\\svchost.exe (possible masquerade)",
            confidence="CONFIRMED",
        )
        refined, outcomes = correlate([f])
        # Masquerade is a tell, not a boring explanation -> not demoted by suppressor.
        assert outcomes[0].fp_suppressor != "system_path_legit"
