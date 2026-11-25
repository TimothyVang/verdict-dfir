"""Tests for findevil_agent.judge."""

from __future__ import annotations

import pytest

from findevil_agent.events import Finding, VerifierAction
from findevil_agent.judge import (
    CONFIDENCE_VALUE,
    CORROBORATION_BONUS,
    INITIAL_PRIOR_ACCURACY,
    THRESHOLD_CONFIRMED,
    THRESHOLD_INFERRED,
    JudgeBudgetExceeded,
    PoolStats,
    judge_findings,
)


def _f(
    finding_id: str,
    *,
    pool: str = "A",
    confidence: str = "CONFIRMED",
    artifact_path: str = "Security.evtx",
    description: str = "evtx logon",
    tool_call_id: str = "tc-1",
    mitre: str | None = None,
) -> Finding:
    return Finding(
        case_id="c",
        finding_id=finding_id,
        tool_call_id=tool_call_id,
        artifact_path=artifact_path,
        confidence=confidence,
        description=description,
        mitre_technique=mitre,
        pool_origin=pool,
    )


def _va(action: str, *, finding_id: str = "f-x") -> VerifierAction:
    return VerifierAction(
        case_id="c",
        action=action,  # type: ignore[arg-type]
        finding_id=finding_id,
        reason="test",
    )


class TestCounterHypothesisGate:
    """Opt-in counter-hypothesis discipline (FIND_EVIL_REQUIRE_COUNTER_HYPOTHESIS).

    Default-off: a solo verifier-confirmed CONFIRMED finding is preserved. On: a
    solo CONFIRMED collapses to INFERRED unless cross-pool corroboration raises it
    back — a CONFIRMED claim must survive the other pool's challenge."""

    def test_solo_confirmed_preserved_by_default(self) -> None:
        a = PoolStats(pool="A", findings=[_f("f-1", confidence="CONFIRMED")])
        b = PoolStats(pool="B", findings=[])
        merged = judge_findings(a, b)
        assert merged[0].finding.confidence == "CONFIRMED"

    def test_solo_confirmed_downgraded_when_gate_on(self, monkeypatch) -> None:
        monkeypatch.setenv("FIND_EVIL_REQUIRE_COUNTER_HYPOTHESIS", "1")
        a = PoolStats(pool="A", findings=[_f("f-1", confidence="CONFIRMED")])
        b = PoolStats(pool="B", findings=[])
        merged = judge_findings(a, b)
        # Uncorroborated solo CONFIRMED no longer kept at CONFIRMED.
        assert merged[0].finding.confidence == "INFERRED"

    def test_cross_pool_confirmed_survives_gate(self, monkeypatch) -> None:
        monkeypatch.setenv("FIND_EVIL_REQUIRE_COUNTER_HYPOTHESIS", "1")
        # Same claim seen by BOTH pools (same tool_call_id + artifact_path + base id)
        # groups and merges — not solo — so it survives the challenge and stays CONFIRMED.
        a = PoolStats(
            pool="A",
            findings=[_f("f-A-x", pool="A", confidence="CONFIRMED")],
            verified_actions=[_va("approved", finding_id="f-A-x")],
        )
        b = PoolStats(
            pool="B",
            findings=[_f("f-B-x", pool="B", confidence="CONFIRMED")],
            verified_actions=[_va("approved", finding_id="f-B-x")],
        )
        merged = judge_findings(a, b)
        assert any(m.finding.confidence == "CONFIRMED" for m in merged)


class TestConstants:
    def test_thresholds_match_spec(self) -> None:
        # Spec #2 §8.2: 0.80 → CONFIRMED, 0.50 → INFERRED, < 0.50 → HYPOTHESIS
        assert THRESHOLD_CONFIRMED == 0.80
        assert THRESHOLD_INFERRED == 0.50
        assert CORROBORATION_BONUS == 0.2
        assert INITIAL_PRIOR_ACCURACY == 0.5

    def test_confidence_values_match_spec(self) -> None:
        assert CONFIDENCE_VALUE["CONFIRMED"] == 1.0
        assert CONFIDENCE_VALUE["INFERRED"] == 0.6
        assert CONFIDENCE_VALUE["HYPOTHESIS"] == 0.3


class TestSinglePoolFindings:
    def test_pool_a_only_passes_through(self) -> None:
        a = PoolStats(pool="A", findings=[_f("f-1", confidence="CONFIRMED")])
        b = PoolStats(pool="B", findings=[])
        merged = judge_findings(a, b)
        assert len(merged) == 1
        # A solo, verifier-approved CONFIRMED fact is NOT downgraded for lack of
        # cross-pool corroboration: the judge corroborates/raises, it does not
        # re-litigate a confirmed observation the verifier already approved.
        # (Corroboration across pools can still only push confidence higher.)
        assert merged[0].finding.confidence == "CONFIRMED"

    def test_pool_b_only(self) -> None:
        a = PoolStats(pool="A", findings=[])
        b = PoolStats(pool="B", findings=[_f("f-1", pool="B", confidence="CONFIRMED")])
        merged = judge_findings(a, b)
        assert len(merged) == 1
        assert merged[0].chosen_pool == "B"

    def test_solo_inferred_finding_is_not_downgraded_by_absent_second_pool(
        self,
    ) -> None:
        a = PoolStats(pool="A", findings=[_f("f-1", confidence="INFERRED")])
        b = PoolStats(pool="B", findings=[])
        merged = judge_findings(a, b)

        assert merged[0].finding.confidence == "INFERRED"


class TestBothPoolsFindings:
    def test_both_confirmed_with_corroboration(self) -> None:
        # Pool A has a disk finding; Pool B has a log finding on
        # the same artifact (both pools touch other artifact classes).
        a_findings = [
            _f(
                "f-A-mft",
                pool="A",
                confidence="CONFIRMED",
                artifact_path="C:\\$MFT",
                description="mft entry",
            ),
            # Shares the claim id `evtx` with the Pool B finding below → same claim,
            # different pools → corroborates (Pool A/B word it differently).
            _f(
                "f-A-evtx",
                pool="A",
                confidence="INFERRED",
                artifact_path="Security.evtx",
                description="evtx logon",
            ),
        ]
        b_findings = [
            _f(
                "f-B-evtx",
                pool="B",
                confidence="CONFIRMED",
                artifact_path="Security.evtx",
                description="evtx logon",
            ),
            _f(
                "f-B-mem",
                pool="B",
                confidence="INFERRED",
                artifact_path="memory.mem",
                description="malfind hit",
            ),
        ]
        merged = judge_findings(
            PoolStats(pool="A", findings=a_findings),
            PoolStats(pool="B", findings=b_findings),
        )
        # Three groups: $MFT (A only), Security.evtx (both), memory.mem (B only).
        assert len(merged) == 3
        # The Security.evtx group is the corroborated one.
        evtx_merged = next(m for m in merged if m.finding.artifact_path == "Security.evtx")
        assert evtx_merged.corroborated is True

    def test_distinct_findings_from_one_tool_call_do_not_collapse(self) -> None:
        # A single tool call (one pcap_triage on one capture) legitimately yields
        # several DISTINCT findings about different subjects (hosts) that share the
        # same artifact and MITRE technique (T1071.001 Web Protocols). They must NOT
        # collapse into one — doing so silently destroys recall (the nitroba case:
        # anon-email + webmail + social are three different facts, not one).
        b = PoolStats(
            pool="B",
            findings=[
                _f(
                    "f-b-anon",
                    pool="B",
                    confidence="INFERRED",
                    artifact_path="nitroba.pcap",
                    tool_call_id="tc-1",
                    mitre="T1071.001",
                    description="host 192.168.15.4 submitted to anonymous email service willselfdestruct.com",
                ),
                _f(
                    "f-b-mail",
                    pool="B",
                    confidence="INFERRED",
                    artifact_path="nitroba.pcap",
                    tool_call_id="tc-1",
                    mitre="T1071.001",
                    description="authenticated webmail session to mail.google.com",
                ),
                _f(
                    "f-b-social",
                    pool="B",
                    confidence="INFERRED",
                    artifact_path="nitroba.pcap",
                    tool_call_id="tc-1",
                    mitre="T1071.001",
                    description="authenticated social-media login to facebook",
                ),
            ],
        )
        a = PoolStats(pool="A", findings=[])
        merged = judge_findings(a, b)
        assert (
            len(merged) == 3
        ), f"distinct findings from one tool call collapsed into {len(merged)}"

    def test_disagreeing_pools_drop_to_hypothesis(self) -> None:
        a = PoolStats(
            pool="A",
            findings=[
                _f("f-1", pool="A", confidence="HYPOTHESIS"),
            ],
        )
        b = PoolStats(
            pool="B",
            findings=[
                _f("f-2", pool="B", confidence="HYPOTHESIS"),
            ],
        )
        merged = judge_findings(a, b)
        # Both HYPOTHESIS (0.3) * cred (0.6) = 0.18 each.
        # merged = 0.36 / 1.2 = 0.30 → < 0.50 → HYPOTHESIS.
        assert merged[0].finding.confidence == "HYPOTHESIS"


class TestPriorAccuracyEffect:
    def test_downgraded_actions_count_as_replay_backed_prior_accuracy(self) -> None:
        a = PoolStats(
            pool="A",
            findings=[_f("f-1", confidence="INFERRED")],
            verified_actions=[_va("downgraded")],
        )
        b = PoolStats(pool="B", findings=[])
        merged = judge_findings(a, b)

        assert merged[0].credibility_a > 0

    def test_higher_pool_accuracy_dominates(self) -> None:
        # Pool A nailed everything (3/3 approved); Pool B is sloppy (0/3 approved).
        # Pool A's credibility ≈ 1.0 * 1.2 = 1.2; Pool B's ≈ 0.0 * 1.2 = 0.0.
        # Distinct artifacts so the findings land in separate groups; otherwise
        # they'd merge into one group with chosen_pool="merged".
        a = PoolStats(
            pool="A",
            findings=[
                _f(
                    "f-a",
                    pool="A",
                    confidence="CONFIRMED",
                    artifact_path="C:\\$MFT",
                    tool_call_id="tc-a",
                )
            ],
            verified_actions=[_va("approved"), _va("approved"), _va("approved")],
        )
        b = PoolStats(
            pool="B",
            findings=[
                _f(
                    "f-b",
                    pool="B",
                    confidence="HYPOTHESIS",
                    artifact_path="memory.mem",
                    tool_call_id="tc-b",
                )
            ],
            verified_actions=[_va("rejected"), _va("rejected"), _va("rejected")],
        )
        merged = judge_findings(a, b)
        # Two groups output. Pool A's score = 1.0 * 1.2 = 1.2,
        # divided by cred_a + cred_b = 1.2 + 0.0 = 1.2 → merged = 1.0
        # → CONFIRMED.
        a_only = next(m for m in merged if m.chosen_pool == "A")
        assert a_only.finding.confidence == "CONFIRMED"


class TestBudget:
    def test_budget_exceeded_raises(self) -> None:
        # Force-fail by giving a 0-second budget; even one group will exceed.
        a = PoolStats(pool="A", findings=[_f("f-1", confidence="CONFIRMED")])
        b = PoolStats(pool="B", findings=[])
        with pytest.raises(JudgeBudgetExceeded):
            judge_findings(a, b, budget_seconds=0.0)


class TestPoolOriginPreservation:
    def test_solo_findings_keep_pool_origin(self) -> None:
        a = PoolStats(pool="A", findings=[_f("f-1", pool="A", confidence="CONFIRMED")])
        b = PoolStats(pool="B", findings=[])
        merged = judge_findings(a, b)
        assert merged[0].finding.pool_origin == "A"

    def test_dual_pool_findings_get_merged_origin(self) -> None:
        a = PoolStats(
            pool="A",
            findings=[
                _f(
                    "f-A-x",
                    pool="A",
                    confidence="CONFIRMED",
                    artifact_path="x",
                    description="same evidence",
                ),
            ],
        )
        b = PoolStats(
            pool="B",
            findings=[
                # Same claim id `x` as the Pool A finding → corroborates → merged.
                _f(
                    "f-B-x",
                    pool="B",
                    confidence="INFERRED",
                    artifact_path="x",
                    description="same evidence",
                ),
            ],
        )
        merged = judge_findings(a, b)
        assert merged[0].finding.pool_origin == "merged"
