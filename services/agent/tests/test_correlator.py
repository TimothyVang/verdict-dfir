"""Tests for findevil_agent.correlator."""

from __future__ import annotations

from findevil_agent.correlator import correlate
from findevil_agent.events import Finding


def _f(
    finding_id: str,
    description: str,
    *,
    confidence: str = "CONFIRMED",
    artifact_path: str = "Security.evtx",
    mitre: str | None = None,
    tcid: str = "tc-1",
    derived_from: list[str] | None = None,
) -> Finding:
    return Finding(
        case_id="c",
        finding_id=finding_id,
        tool_call_id=tcid,
        artifact_path=artifact_path,
        confidence=confidence,
        description=description,
        mitre_technique=mitre,
        derived_from=derived_from,
    )


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

    def test_disk_plus_log_execution_kept(self) -> None:
        # Two findings spanning disk + log → cross-artifact corroboration.
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
        kept = [o for o in outcomes if o.action == "kept"]
        assert len(kept) == 2  # both kept
        assert all(f.confidence == "CONFIRMED" for f in refined)


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


class TestStructuralCorroboration:
    """When a tool_call_id -> artifact_class map is supplied, corroboration is derived
    from the tools a finding actually cites, not its description prose or a run-wide
    class fallback."""

    def test_structural_closes_run_wide_overclaim(self) -> None:
        # The reproduced bug: a single-artifact (registry/amcache-class) execution
        # claim is KEPT at CONFIRMED under the legacy prose+run-wide path because an
        # UNRELATED finding in the run touched a second class. Structural corroboration
        # must downgrade it — its OWN citation is one class.
        f = _f(
            "f-1",
            "attacker.exe executed on the host",
            confidence="CONFIRMED",
            tcid="tc-A",
            artifact_path="C:/Windows/AppCompat/Programs/Amcache.hve",
        )
        other = _f(
            "f-2",
            "Suspicious new account in the directory",
            confidence="CONFIRMED",
            tcid="tc-B",
            artifact_path="Security.evtx",
        )
        # Legacy (no map): run-wide class fallback KEEPS f-1 — the over-claim.
        _, legacy = correlate([f, other])
        assert legacy[0].action == "kept"
        # Structural: f-1 cites only tc-A (registry) -> one class -> downgrade.
        tool_classes = {"tc-A": "registry", "tc-B": "evtx"}
        refined, structural = correlate([f, other], tool_classes=tool_classes)
        assert structural[0].action == "downgraded"
        assert refined[0].confidence == "INFERRED"

    def test_structural_two_distinct_classes_kept(self) -> None:
        f = _f(
            "f-1",
            "attacker.exe executed",
            confidence="CONFIRMED",
            tcid="tc-A",
            derived_from=["tc-B"],
        )
        tool_classes = {"tc-A": "prefetch", "tc-B": "registry"}
        refined, outcomes = correlate([f], tool_classes=tool_classes)
        assert outcomes[0].action == "kept"
        assert refined[0].confidence == "CONFIRMED"

    def test_structural_two_weak_classes_downgrade(self) -> None:
        # memory + evtx are both weak — no disk-family anchor, so downgrade.
        f = _f(
            "f-1",
            "process executed",
            confidence="CONFIRMED",
            tcid="tc-A",
            derived_from=["tc-B"],
        )
        tool_classes = {"tc-A": "memory", "tc-B": "evtx"}
        refined, outcomes = correlate([f], tool_classes=tool_classes)
        assert outcomes[0].action == "downgraded"
        assert refined[0].confidence == "INFERRED"

    def test_structural_ignores_custody_class(self) -> None:
        # case_open custody must not count toward corroboration.
        f = _f(
            "f-1",
            "attacker.exe executed",
            confidence="CONFIRMED",
            tcid="tc-A",
            derived_from=["tc-custody"],
        )
        tool_classes = {"tc-A": "prefetch", "tc-custody": "custody"}
        _refined, outcomes = correlate([f], tool_classes=tool_classes)
        assert outcomes[0].action == "downgraded"  # only prefetch counts -> 1 class

    def test_empty_map_falls_back_to_prose(self) -> None:
        # An empty map must not nuke every execution finding; fall back to prose.
        f = _f("f-1", "Prefetch + Amcache corroborate execution of x.exe", confidence="CONFIRMED")
        refined, outcomes = correlate([f], tool_classes={})
        assert outcomes[0].action == "kept"
        assert refined[0].confidence == "CONFIRMED"
