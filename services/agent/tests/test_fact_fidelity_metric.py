"""Tests for the fact-fidelity rejection-rate metric.

The entailment demo shows the check catching ONE misread. This module turns that
into a measured, regenerable number: of a seeded set of deliberately-false
asserted values, the fraction the deterministic ``check_entailment`` rejects
(target 1.0), plus the control that the TRUE assertions are still accepted
(target 1.0). No LLM in the loop.

The seeded fabrications are false BY CONSTRUCTION — each is a known-wrong
mutation of a value that genuinely matches the evidence (the true assertion's own
``expected``), so the metric is not tautological: the fabrication's falseness
comes from ground truth, and the SUT (``check_entailment``) is run independently
to see whether it rejects.
"""

from findevil_agent.events import AssertedValue
from findevil_agent.fact_fidelity_metric import (
    FactFidelityMetrics,
    FidelityCase,
    RateResult,
    acceptance_rate,
    builtin_cases,
    measure,
    rejection_rate,
    seed_false_variants,
)

# A real-shaped registry Run-key output (the production persistence shape, the
# same one the entailment demo replays).
_REGISTRY_OUT = {
    "entries": [
        {
            "key_path": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "last_write_time_iso": "2018-09-06T19:00:00Z",
            "values": [
                {
                    "name": "Updater",
                    "value_type": "RegSz",
                    "data_str": "C:\\Users\\bob\\AppData\\Roaming\\evil.exe",
                }
            ],
        }
    ],
    "keys_visited": 1,
}

_TRUE_EXACT = AssertedValue(
    path="entries[*].values[*].data_str",
    expected="C:\\Users\\bob\\AppData\\Roaming\\evil.exe",
    match="exact",
)
_TRUE_CONTAINS = AssertedValue(
    path="entries[*].values[*].data_str", expected="evil.exe", match="contains"
)
_TRUE_RECORD = AssertedValue(
    path="entries[*].values[*]",
    expected='{"name": "Updater", "data_str": "evil.exe"}',
    match="record",
)
_TRUE_ISO = AssertedValue(
    path="entries[*].last_write_time_iso", expected="2018-09-06T19:00:00Z", match="iso_ts"
)

_ALL_TRUE = (_TRUE_EXACT, _TRUE_CONTAINS, _TRUE_RECORD, _TRUE_ISO)


class TestSeededVariantsAreRejected:
    """Every guaranteed-false mutation of a true assertion is rejected by the
    production entailment check."""

    def test_each_true_assertion_yields_only_rejected_fabrications(self) -> None:
        for true_av in _ALL_TRUE:
            fabs = seed_false_variants(true_av)
            assert fabs, f"no fabrications produced for match={true_av.match}"
            result = rejection_rate(fabs, _REGISTRY_OUT)
            assert result.rate == 1.0, (true_av.match, result.escapes)
            assert result.escapes == ()
            assert result.count == result.total == len(fabs)

    def test_true_assertions_are_accepted(self) -> None:
        # Control: the un-mutated true assertions pass. A regression that made the
        # matcher reject real values would make the rejection metric meaningless;
        # this catches it.
        result = acceptance_rate(list(_ALL_TRUE), _REGISTRY_OUT)
        assert result.rate == 1.0
        assert result.escapes == ()


class TestStructuralFabrications:
    """Path-level fabrications (the analogs of a nonexistent / malformed citation)
    are rejected regardless of match mode."""

    def test_missing_path_variant_is_rejected(self) -> None:
        fabs = seed_false_variants(_TRUE_EXACT)
        missing = [f for f in fabs if f.label == "missing_path"]
        assert missing, "expected a missing_path fabrication"
        assert rejection_rate(missing, _REGISTRY_OUT).rate == 1.0

    def test_malformed_path_variant_is_rejected(self) -> None:
        fabs = seed_false_variants(_TRUE_EXACT)
        malformed = [f for f in fabs if f.label == "malformed_path"]
        assert malformed, "expected a malformed_path fabrication"
        assert rejection_rate(malformed, _REGISTRY_OUT).rate == 1.0


class TestMeasureBuiltinCorpus:
    """The built-in recorded-output corpus spans every match mode and meets the
    1.0 targets, so the metric is a standing gate."""

    def test_builtin_cases_cover_every_match_mode(self) -> None:
        modes = {av.match for case in builtin_cases() for av in case.true_assertions}
        assert modes == {"exact", "contains", "int", "iso_ts", "record"}

    def test_measured_metrics_meet_targets(self) -> None:
        metrics = measure(builtin_cases())
        assert metrics.rejection.rate == 1.0
        assert metrics.acceptance.rate == 1.0
        assert metrics.rejection.total > 0
        assert metrics.acceptance.total > 0
        assert metrics.meets_targets() is True

    def test_to_dict_carries_the_headline_numbers(self) -> None:
        d = measure(builtin_cases()).to_dict()
        assert d["rejection_rate"] == 1.0
        assert d["acceptance_rate"] == 1.0
        assert d["meets_targets"] is True
        assert set(d["modes_covered"]) == {"exact", "contains", "int", "iso_ts", "record"}


class TestGateLogic:
    """``meets_targets`` fails if EITHER rate dips below 1.0 (the production check
    cannot be made to leak, so the gate logic is asserted on a constructed
    result)."""

    def test_meets_targets_false_when_a_fabrication_escapes(self) -> None:
        m = FactFidelityMetrics(
            rejection=RateResult(rate=0.9, count=9, total=10, escapes=("wrong_value",)),
            acceptance=RateResult(rate=1.0, count=3, total=3, escapes=()),
            modes_covered=("exact",),
        )
        assert m.meets_targets() is False

    def test_meets_targets_false_when_a_true_assertion_is_dropped(self) -> None:
        m = FactFidelityMetrics(
            rejection=RateResult(rate=1.0, count=10, total=10, escapes=()),
            acceptance=RateResult(rate=0.5, count=1, total=2, escapes=("a-real-value",)),
            modes_covered=("exact",),
        )
        assert m.meets_targets() is False


class TestEmptyCorpusIsNotAFreePass:
    """An empty corpus must not report a passing 1.0 (vacuous truth would let the
    gate go green on zero coverage)."""

    def test_empty_measure_does_not_meet_targets(self) -> None:
        metrics = measure([FidelityCase(name="empty", parsed_output={}, true_assertions=())])
        assert metrics.meets_targets() is False
