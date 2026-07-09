"""Tests for the deterministic entailment checker.

These tests ARE the path-matching mini-spec from the plan. The checker is a
pure, LLM-free function: given the structured values a finding asserts and the
re-run tool output, confirm each asserted value is actually present. This is
what catches a "misread of real data laundered through a valid citation."
"""

import hashlib
import importlib.util
from pathlib import Path

from findevil_agent.entailment import (
    EntailmentResult,
    MatchedValue,
    check_entailment,
    entailment_slice,
    recheck_entailment_slice,
)
from findevil_agent.events import AssertedValue

# services/agent/tests/ -> repo root is parents[3].
_REPO_ROOT = Path(__file__).resolve().parents[3]
_HELD_OUT = _REPO_ROOT / "goldens" / "fact-fidelity" / "held-out-findings.json"


def _load_rate_harness():
    """Import the standalone calibration harness by path (it is a CLI script,
    not an installed module — same loader pattern the smoke scripts use)."""
    spec = importlib.util.spec_from_file_location(
        "fact_fidelity_rate", _REPO_ROOT / "scripts" / "fact-fidelity-rate.py"
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


class TestOfflineSlice:
    """The minimal entailment slice persisted into the signed chain, and its
    offline re-verification (manifest_verify re-runs the matcher over the sealed
    matched values, no tool re-run)."""

    def test_slice_captures_the_matched_evidence_value(self) -> None:
        avs = [AssertedValue(path="run_count", expected="3", match="int")]
        sl = entailment_slice(check_entailment(avs, {"run_count": 3}))
        assert sl["passed"] is True
        assert sl["matched"][0]["actual"] == "3"

    def test_clean_slice_rechecks_true(self) -> None:
        avs = [AssertedValue(path="run_count", expected="3", match="int")]
        sl = entailment_slice(check_entailment(avs, {"run_count": 3}))
        assert recheck_entailment_slice(sl) is True

    def test_tampered_sealed_value_rechecks_false(self) -> None:
        avs = [AssertedValue(path="run_count", expected="3", match="int")]
        sl = entailment_slice(check_entailment(avs, {"run_count": 3}))
        sl["matched"][0]["actual"] = "9"  # tamper the sealed evidence value
        assert recheck_entailment_slice(sl) is not True

    def test_record_slice_rechecks_true(self) -> None:
        avs = [
            AssertedValue(
                path="entries[*].values[*]",
                expected='{"name": "Updater", "data_str": "evil.exe"}',
                match="record",
            )
        ]
        out = {"entries": [{"values": [{"name": "Updater", "data_str": "C:\\x\\evil.exe"}]}]}
        sl = entailment_slice(check_entailment(avs, out))
        assert recheck_entailment_slice(sl) is True

    def test_empty_slice_is_vacuously_true(self) -> None:
        assert recheck_entailment_slice({"passed": True, "matched": [], "failures": []}) is True


_RECORD_AV = dict(
    path="entries[*].values[*]",
    expected='{"name": "Updater", "data_str": "evil.exe"}',
    match="record",
)


class TestRecordMatch:
    """Co-location: a ``record`` assertion binds several fields to the SAME
    record, so a model cannot launder a claim by taking the name from one row
    and the damning value from another."""

    def test_passes_when_one_record_satisfies_every_field(self) -> None:
        av = AssertedValue(**_RECORD_AV)
        out = {"entries": [{"values": [{"name": "Updater", "data_str": "C:\\x\\evil.exe"}]}]}
        assert check_entailment([av], out).passed is True

    def test_fails_when_fields_are_split_across_records(self) -> None:
        # name in one value, evil.exe in another — the cross-row launder.
        av = AssertedValue(**_RECORD_AV)
        out = {
            "entries": [
                {
                    "values": [
                        {"name": "Updater", "data_str": "C:\\Windows\\good.exe"},
                        {"name": "OneDrive", "data_str": "C:\\x\\evil.exe"},
                    ]
                }
            ]
        }
        assert check_entailment([av], out).passed is False

    def test_fails_when_a_required_field_is_absent(self) -> None:
        av = AssertedValue(**_RECORD_AV)
        out = {"entries": [{"values": [{"name": "Updater", "data_str": "C:\\good.exe"}]}]}
        assert check_entailment([av], out).passed is False

    def test_matched_records_the_colocated_evidence(self) -> None:
        av = AssertedValue(**_RECORD_AV)
        out = {"entries": [{"values": [{"name": "Updater", "data_str": "C:\\x\\evil.exe"}]}]}
        result = check_entailment([av], out)
        assert result.matched
        assert "evil.exe" in result.matched[0].actual.lower()


class TestExtractiveMatch:
    """The check is extractive: a passing assertion records the actual value
    the deterministic parser read out of the evidence, so the recorded fact is
    server-read, not model-transcribed."""

    def test_passing_check_reports_the_extracted_evidence_value(self) -> None:
        asserted = [AssertedValue(path="run_count", expected="3", match="int")]
        result = check_entailment(asserted, {"run_count": 3})
        assert result.passed is True
        assert len(result.matched) == 1
        m = result.matched[0]
        assert isinstance(m, MatchedValue)
        assert m.path == "run_count"
        assert m.expected == "3"
        assert m.actual == "3"  # the value the server read, normalized to str

    def test_contains_match_extracts_the_full_evidence_string(self) -> None:
        # The model asserts a substring; the server records the FULL evidence
        # string it found that substring in — richer provenance than the claim.
        asserted = [
            AssertedValue(
                path="entries[*].values[*].data_str",
                expected="evil.exe",
                match="contains",
            )
        ]
        output = {"entries": [{"values": [{"data_str": "C:\\Users\\bob\\evil.exe"}]}]}
        result = check_entailment(asserted, output)
        assert result.passed is True
        assert result.matched[0].actual == "C:\\Users\\bob\\evil.exe"

    def test_failed_assertion_contributes_no_matched_value(self) -> None:
        asserted = [AssertedValue(path="run_count", expected="9", match="int")]
        result = check_entailment(asserted, {"run_count": 3})
        assert result.passed is False
        assert result.matched == []

    def test_no_assertions_means_no_matched_values(self) -> None:
        result = check_entailment([], {"run_count": 3})
        assert result.passed is True
        assert result.matched == []


class TestExactMatch:
    def test_passes_when_top_level_value_present(self) -> None:
        asserted = [AssertedValue(path="executable_name", expected="EVIL.EXE")]
        output = {"executable_name": "EVIL.EXE", "run_count": 8}
        result = check_entailment(asserted, output)
        assert isinstance(result, EntailmentResult)
        assert result.passed is True

    def test_fails_when_value_differs(self) -> None:
        # The model claimed EVIL.EXE but the output actually says BENIGN.EXE.
        asserted = [AssertedValue(path="executable_name", expected="EVIL.EXE")]
        output = {"executable_name": "BENIGN.EXE"}
        result = check_entailment(asserted, output)
        assert result.passed is False
        assert "executable_name" in result.reason

    def test_fails_when_path_resolves_to_nothing(self) -> None:
        # Asserted field is not even in the output -> fail (not silently pass).
        asserted = [AssertedValue(path="does_not_exist", expected="x")]
        output = {"executable_name": "EVIL.EXE"}
        result = check_entailment(asserted, output)
        assert result.passed is False

    def test_trims_whitespace(self) -> None:
        asserted = [AssertedValue(path="name", expected="svchost.exe")]
        output = {"name": "  svchost.exe  "}
        assert check_entailment(asserted, output).passed is True


class TestWildcardPaths:
    def test_star_matches_value_in_a_list_of_records(self) -> None:
        # registry_query shape: entries[].values[].data_str
        asserted = [
            AssertedValue(
                path="entries[*].values[*].data_str",
                expected=r"C:\temp\evil.exe",
            )
        ]
        output = {
            "entries": [
                {
                    "key_path": r"...\Run",
                    "values": [
                        {
                            "name": "OneDrive",
                            "value_type": "REG_SZ",
                            "data_str": r"C:\Windows\od.exe",
                        },
                        {"name": "x", "value_type": "REG_SZ", "data_str": r"C:\temp\evil.exe"},
                    ],
                }
            ]
        }
        assert check_entailment(asserted, output).passed is True

    def test_star_fails_when_no_record_has_value(self) -> None:
        asserted = [AssertedValue(path="rows[*].TargetPath", expected=r"C:\temp\evil.exe")]
        output = {"rows": [{"TargetPath": r"C:\Windows\notepad.exe"}]}
        assert check_entailment(asserted, output).passed is False

    def test_indexed_segment(self) -> None:
        asserted = [AssertedValue(path="rows[0].FILENAME", expected="ntds.dit")]
        output = {"rows": [{"FILENAME": "ntds.dit"}, {"FILENAME": "other"}]}
        assert check_entailment(asserted, output).passed is True


class TestContainsMatch:
    def test_contains_is_case_insensitive_substring(self) -> None:
        asserted = [
            AssertedValue(
                path="rows[*].CommandLine",
                expected="certutil.exe -urlcache",
                match="contains",
            )
        ]
        output = {
            "rows": [
                {"CommandLine": "C:\\Windows\\System32\\CERTUTIL.EXE -urlcache -split -f http://x"}
            ]
        }
        assert check_entailment(asserted, output).passed is True


class TestContainsTokenBoundary:
    """Regression for incidental-substring laundering. A ``contains`` anchor must
    align to TOKEN boundaries: an incidental fragment of a larger word must NOT
    match, while a real whole-token hit MUST still match. The transform stays
    deterministic so the sealed-slice recheck reproduces the same decision."""

    def test_incidental_substring_does_not_match(self) -> None:
        # The canonical hole: "cain" laundered through "mccain".
        asserted = [AssertedValue(path="user", expected="cain", match="contains")]
        assert check_entailment(asserted, {"user": "mccain"}).passed is False

    def test_whole_token_still_matches(self) -> None:
        # The same anchor against a standalone token must still entail.
        asserted = [AssertedValue(path="user", expected="cain", match="contains")]
        assert check_entailment(asserted, {"user": "John Cain logged in"}).passed is True

    def test_token_glued_on_the_right_edge_does_not_match(self) -> None:
        # "evil" must not launder through "evilcorp.exe".
        asserted = [AssertedValue(path="image", expected="evil", match="contains")]
        assert check_entailment(asserted, {"image": "C:\\evilcorp.exe"}).passed is False

    def test_token_bounded_by_path_separator_matches(self) -> None:
        asserted = [AssertedValue(path="image", expected="evil.exe", match="contains")]
        assert check_entailment(asserted, {"image": "C:\\Users\\bob\\evil.exe"}).passed is True

    def test_multi_token_phrase_with_internal_separators_matches(self) -> None:
        asserted = [AssertedValue(path="cmd", expected="certutil.exe -urlcache", match="contains")]
        out = {"cmd": "C:\\Windows\\certutil.exe -urlcache -split"}
        assert check_entailment(asserted, out).passed is True

    def test_phrase_not_assembled_across_a_newline(self) -> None:
        # Per-line matching: "alpha beta" must not match when the two tokens sit
        # on different lines of the archived raw output.
        asserted = [AssertedValue(path="blob", expected="alpha beta", match="contains")]
        assert check_entailment(asserted, {"blob": "...alpha\nbeta..."}).passed is False

    def test_phrase_matches_within_a_single_line_of_a_multiline_blob(self) -> None:
        asserted = [AssertedValue(path="blob", expected="alpha beta", match="contains")]
        out = {"blob": "first line\nx alpha beta y\nlast line"}
        assert check_entailment(asserted, out).passed is True

    def test_empty_needle_keeps_field_present_semantics(self) -> None:
        asserted = [AssertedValue(path="note", expected="", match="contains")]
        assert check_entailment(asserted, {"note": "anything"}).passed is True

    def test_short_needle_below_min_token_len_keeps_plain_containment(self) -> None:
        # A single-character fragment carries no laundering-prone token, so the
        # legacy plain-containment behavior is preserved (no false rejection).
        asserted = [AssertedValue(path="flag", expected="x", match="contains")]
        assert check_entailment(asserted, {"flag": "axb"}).passed is True

    def test_sealed_token_bounded_slice_rechecks_true(self) -> None:
        # Determinism: a confirmed token-bounded contains seal still rechecks.
        asserted = [AssertedValue(path="image", expected="evil.exe", match="contains")]
        sl = entailment_slice(check_entailment(asserted, {"image": "C:\\x\\evil.exe"}))
        assert sl["passed"] is True
        assert recheck_entailment_slice(sl) is True


class TestRecordTokenBoundary:
    """The co-location matcher shares the token-boundary rule: a per-field
    constraint must hit a whole token, not an incidental fragment."""

    def test_incidental_substring_in_a_field_does_not_satisfy_record(self) -> None:
        av = AssertedValue(
            path="entries[*]",
            expected='{"user": "cain"}',
            match="record",
        )
        assert check_entailment([av], {"entries": [{"user": "mccain"}]}).passed is False

    def test_whole_token_field_satisfies_record(self) -> None:
        av = AssertedValue(
            path="entries[*]",
            expected='{"name": "Updater", "data_str": "evil.exe"}',
            match="record",
        )
        out = {"entries": [{"name": "Updater", "data_str": "C:\\x\\evil.exe"}]}
        assert check_entailment([av], out).passed is True


class TestIntMatch:
    def test_decimal_int_matches(self) -> None:
        asserted = [AssertedValue(path="run_count", expected="8", match="int")]
        output = {"run_count": 8}
        assert check_entailment(asserted, output).passed is True

    def test_hex_expected_matches_decimal_leaf(self) -> None:
        asserted = [AssertedValue(path="event_id", expected="0x1000", match="int")]
        output = {"event_id": 4096}
        assert check_entailment(asserted, output).passed is True

    def test_int_mismatch_fails(self) -> None:
        # The misread: model said run_count 8, output says 3.
        asserted = [AssertedValue(path="run_count", expected="8", match="int")]
        output = {"run_count": 3}
        assert check_entailment(asserted, output).passed is False


class TestIsoTimestampMatch:
    def test_same_instant_different_precision_matches(self) -> None:
        asserted = [
            AssertedValue(
                path="last_run_times_iso[*]",
                expected="2021-03-04T12:00:00+00:00",
                match="iso_ts",
            )
        ]
        output = {"last_run_times_iso": ["2021-03-04T12:00:00.000Z"]}
        assert check_entailment(asserted, output).passed is True

    def test_different_instant_fails(self) -> None:
        asserted = [
            AssertedValue(
                path="si_modified_iso",
                expected="2021-03-04T12:00:00Z",
                match="iso_ts",
            )
        ]
        output = {"si_modified_iso": "2021-03-04T13:00:00Z"}
        assert check_entailment(asserted, output).passed is False


class TestMultipleAssertions:
    def test_all_must_pass(self) -> None:
        asserted = [
            AssertedValue(path="a", expected="1", match="int"),
            AssertedValue(path="b", expected="two"),
        ]
        assert check_entailment(asserted, {"a": 1, "b": "two"}).passed is True
        assert check_entailment(asserted, {"a": 1, "b": "WRONG"}).passed is False

    def test_empty_assertions_passes_vacuously(self) -> None:
        # No structured assertions -> nothing to check (backward compatible).
        assert check_entailment([], {"anything": 1}).passed is True


class TestAbsentIocNegativeControl:
    """Negative control: a synthetic indicator (cryptographic hash / IP address)
    that appears in NO cited span CANNOT reach GROUNDED. An identity anchor has
    no legitimate near-miss reading, so its absence must reject outright — this
    is the floor the adversarial held-out validation rests on."""

    def test_absent_hash_cannot_ground(self) -> None:
        asserted = [AssertedValue(path="rows[*].sha256", expected="d" * 64)]
        output = {"rows": [{"sha256": "a" * 64}, {"sha256": "b" * 64}]}
        result = check_entailment(asserted, output)
        assert result.passed is False
        assert "rows[*].sha256" in result.identity_failures

    def test_absent_ip_cannot_ground(self) -> None:
        # 203.0.113.0/24 (TEST-NET-3) absent from a 198.51.100.0/24 output.
        asserted = [AssertedValue(path="conns[*].dst", expected="203.0.113.77")]
        output = {"conns": [{"dst": "198.51.100.10"}]}
        result = check_entailment(asserted, output)
        assert result.passed is False
        assert "conns[*].dst" in result.identity_failures


class TestHeldOutAdversarialValidation:
    """Blind red-team validation of the entailment detector against a committed,
    frozen held-out fixture set scored by ``scripts/fact-fidelity-rate.py``. The
    fixtures are committed (not generated at run time) so the result is
    deterministic; the harness records the detector source hash so a silent edit
    to the detector forces the validation to be re-run."""

    def test_held_out_fixtures_are_committed(self) -> None:
        assert _HELD_OUT.is_file(), "held-out adversarial fixtures must be committed"

    def test_recorded_detector_sha256_matches_module(self) -> None:
        mod = _load_rate_harness()
        from findevil_agent import entailment

        expected = hashlib.sha256(Path(entailment.__file__).read_bytes()).hexdigest()
        assert mod.detector_sha256() == expected

    def test_harness_emits_two_distinct_arm_scores(self) -> None:
        mod = _load_rate_harness()
        report = mod.score(mod.load_fixtures(_HELD_OUT))
        assert {"calibration", "held_out"} <= set(report["arms"])
        for arm in ("calibration", "held_out"):
            metrics = report["arms"][arm]
            assert "precision" in metrics and "recall" in metrics
            assert metrics["total"] > 0

    def test_no_held_out_hallucination_reaches_grounded(self) -> None:
        mod = _load_rate_harness()
        report = mod.score(mod.load_fixtures(_HELD_OUT))
        held = report["arms"]["held_out"]
        # Every in-scope hallucinated finding in the blind set is caught.
        assert held["false_negatives"] == 0
        assert held["recall"] == 1.0

    def test_no_genuine_finding_is_falsely_rejected(self) -> None:
        mod = _load_rate_harness()
        report = mod.score(mod.load_fixtures(_HELD_OUT))
        held = report["arms"]["held_out"]
        assert held["false_positives"] == 0
        assert held["precision"] == 1.0
