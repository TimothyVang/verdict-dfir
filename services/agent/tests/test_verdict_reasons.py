"""Tests for ``findevil_agent.verdict_reasons``.

Typed reason-codes for an INDETERMINATE/ABSTAIN verdict. The derivation
is pure and deterministic: the same inputs always yield the same ordered
tuple of reason-codes. This surface is additive and custody-neutral — it
does not change the verdict WORD, only annotates *why* a non-committal
verdict was reached.
"""

from __future__ import annotations

import json

from pydantic import TypeAdapter

from findevil_agent.events import AgentEvent, RunVerdict
from findevil_agent.verdict_reasons import (
    IndeterminateReason,
    derive_indeterminate_reasons,
)


class TestDeriveIndeterminateReasons:
    def test_contradiction_from_cross_pool_conflict(self) -> None:
        # A representative input: one cross-pool/finding contradiction
        # (coverage is otherwise sufficient, so CONTRADICTION stands alone).
        reasons = derive_indeterminate_reasons(contradiction_count=1, artifact_class_count=3)
        assert reasons == (IndeterminateReason.CONTRADICTION,)

    def test_insufficient_coverage_from_too_few_artifact_classes(self) -> None:
        # Only one artifact class examined — below the two-class gate.
        reasons = derive_indeterminate_reasons(artifact_class_count=1)
        assert reasons == (IndeterminateReason.INSUFFICIENT_COVERAGE,)

    def test_insufficient_coverage_from_leads_only(self) -> None:
        # Plenty of classes, but every finding is a HYPOTHESIS lead.
        reasons = derive_indeterminate_reasons(artifact_class_count=5, leads_only=True)
        assert reasons == (IndeterminateReason.INSUFFICIENT_COVERAGE,)

    def test_degraded_mode_from_tool_failures(self) -> None:
        # A representative input: a tool/parse path failed.
        reasons = derive_indeterminate_reasons(artifact_class_count=5, tool_failure_count=2)
        assert reasons == (IndeterminateReason.DEGRADED_MODE,)

    def test_refuted_from_falsified_findings(self) -> None:
        # Coverage otherwise sufficient; a categorical refutation stands alone.
        reasons = derive_indeterminate_reasons(artifact_class_count=3, refuted_count=2)
        assert reasons == (IndeterminateReason.REFUTED,)

    def test_refuted_count_default_zero_does_not_trigger(self) -> None:
        # Additive param: existing callers (no refuted_count) are unaffected.
        reasons = derive_indeterminate_reasons(artifact_class_count=3)
        assert IndeterminateReason.REFUTED not in reasons

    def test_refuted_is_last_in_canonical_order(self) -> None:
        # REFUTED appended last keeps the prior three reasons' relative order.
        reasons = derive_indeterminate_reasons(
            contradiction_count=1,
            artifact_class_count=1,
            tool_failure_count=1,
            refuted_count=1,
        )
        assert reasons == (
            IndeterminateReason.CONTRADICTION,
            IndeterminateReason.INSUFFICIENT_COVERAGE,
            IndeterminateReason.DEGRADED_MODE,
            IndeterminateReason.REFUTED,
        )

    def test_none_when_nothing_triggers(self) -> None:
        reasons = derive_indeterminate_reasons(artifact_class_count=3)
        assert reasons == ()

    def test_all_three_in_canonical_order(self) -> None:
        # Deterministic ordering regardless of how the conditions arose.
        reasons = derive_indeterminate_reasons(
            contradiction_count=2,
            artifact_class_count=1,
            tool_failure_count=1,
        )
        assert reasons == (
            IndeterminateReason.CONTRADICTION,
            IndeterminateReason.INSUFFICIENT_COVERAGE,
            IndeterminateReason.DEGRADED_MODE,
        )

    def test_deterministic_repeatable(self) -> None:
        kwargs = dict(contradiction_count=1, artifact_class_count=1, tool_failure_count=3)
        assert derive_indeterminate_reasons(**kwargs) == derive_indeterminate_reasons(**kwargs)

    def test_reason_values_are_plain_strings(self) -> None:
        # str-enum so the codes serialize as JSON strings, not objects.
        assert IndeterminateReason.CONTRADICTION == "CONTRADICTION"
        assert IndeterminateReason.INSUFFICIENT_COVERAGE == "INSUFFICIENT_COVERAGE"
        assert IndeterminateReason.DEGRADED_MODE == "DEGRADED_MODE"


class TestRunVerdictReasonCodes:
    def test_reason_codes_default_empty(self) -> None:
        v = RunVerdict(
            case_id="c-1",
            verdict="INCONCLUSIVE",
            confidence_score=0.0,
            finding_count=0,
            manifest_path="/tmp/run.manifest.json",
        )
        assert v.reason_codes == []

    def test_reason_codes_round_trip_via_union(self) -> None:
        ae = TypeAdapter(AgentEvent)
        sample = {
            "event_type": "RunVerdict",
            "case_id": "c-1",
            "verdict": "INCONCLUSIVE",
            "confidence_score": 0.0,
            "finding_count": 0,
            "manifest_path": "/tmp/run.manifest.json",
            "reason_codes": ["CONTRADICTION", "INSUFFICIENT_COVERAGE"],
        }
        event = ae.validate_python(sample)
        again = ae.validate_python(json.loads(ae.dump_json(event)))
        assert again.reason_codes == [
            IndeterminateReason.CONTRADICTION,
            IndeterminateReason.INSUFFICIENT_COVERAGE,
        ]
