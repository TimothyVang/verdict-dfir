"""Tests for anchor-class grounding + the multiplicity guard.

Two LLM-free refinements layered onto the existing ``asserted_values``
entailment check (eviltrace adopt-backlog item):

* **Anchor-class classifier.** A claim's structured tokens split into HARD
  anchors (filenames, hashes, byte-sizes, IPs) that GATE — they must entail or
  the finding is rejected outright — versus CORROBORATING tokens (paths,
  timestamps) that only support. A hard anchor that does not entail is a
  laundered misread, not a tier slip, so it rejects regardless of confidence.

* **Multiplicity guard.** A finding asserting a count ("two variants", "N
  entries", "3 sessions") via ``AssertedValue.count`` must back that count with
  at least that many ENTAILED supporting leaves. When only one line is actually
  cited, the over-count is demoted below CONFIRMED instead of being approved.

These tests are the spec for both refinements.
"""

from findevil_agent.entailment import anchor_class, check_entailment
from findevil_agent.events import AssertedValue


class TestAnchorClassifier:
    """The pure hard-vs-corroborating classifier over a single asserted value."""

    def test_sha256_hash_is_hard(self) -> None:
        av = AssertedValue(path="sha256", expected="a" * 64)
        assert anchor_class(av) == "hard"

    def test_md5_hash_is_hard(self) -> None:
        av = AssertedValue(path="md5", expected="d41d8cd98f00b204e9800998ecf8427e")
        assert anchor_class(av) == "hard"

    def test_ipv4_is_hard(self) -> None:
        av = AssertedValue(path="dst_ip", expected="203.0.113.7")
        assert anchor_class(av) == "hard"

    def test_ipv6_is_hard(self) -> None:
        av = AssertedValue(path="dst_ip", expected="2001:db8::1")
        assert anchor_class(av) == "hard"

    def test_filename_with_extension_is_hard(self) -> None:
        av = AssertedValue(path="entries[*].name", expected="evil.exe")
        assert anchor_class(av) == "hard"

    def test_byte_size_int_is_hard(self) -> None:
        av = AssertedValue(path="file_size", expected="73802", match="int")
        assert anchor_class(av) == "hard"

    def test_windows_path_is_corroborating(self) -> None:
        # A full path is supporting context, not the gating anchor (the
        # filename leaf is the anchor; the directory chain corroborates).
        av = AssertedValue(path="target", expected=r"C:\Users\bob\Downloads")
        assert anchor_class(av) == "corroborating"

    def test_posix_path_is_corroborating(self) -> None:
        av = AssertedValue(path="target", expected="/var/log/secure")
        assert anchor_class(av) == "corroborating"

    def test_iso_timestamp_is_corroborating(self) -> None:
        av = AssertedValue(path="ts", expected="2021-03-04T12:00:00Z", match="iso_ts")
        assert anchor_class(av) == "corroborating"

    def test_record_match_is_corroborating(self) -> None:
        # A record co-location constraint is not a single gating token.
        av = AssertedValue(
            path="entries[*].values[*]",
            expected='{"name": "Updater", "data_str": "x"}',
            match="record",
        )
        assert anchor_class(av) == "corroborating"

    def test_plain_word_is_corroborating(self) -> None:
        av = AssertedValue(path="status", expected="success")
        assert anchor_class(av) == "corroborating"


class TestHardAnchorGating:
    """A hard anchor that fails to entail is flagged separately so the verifier
    can reject it outright (laundering), not merely downgrade."""

    def test_failed_hard_anchor_is_recorded_as_hard_failure(self) -> None:
        # The model claims this IP, but the evidence has a different one.
        asserted = [AssertedValue(path="dst_ip", expected="203.0.113.7")]
        output = {"dst_ip": "198.51.100.9"}
        result = check_entailment(asserted, output)
        assert result.passed is False
        assert result.hard_failures == ["dst_ip"]

    def test_failed_hash_is_a_hard_failure(self) -> None:
        asserted = [AssertedValue(path="sha256", expected="a" * 64)]
        output = {"sha256": "b" * 64}
        result = check_entailment(asserted, output)
        assert result.hard_failures == ["sha256"]

    def test_failed_corroborating_value_is_not_a_hard_failure(self) -> None:
        # A wrong path is a soft miss — recorded as a failure, but not hard.
        asserted = [AssertedValue(path="target", expected=r"C:\Windows\System32")]
        output = {"target": r"C:\Users\bob"}
        result = check_entailment(asserted, output)
        assert result.passed is False
        assert result.failures == ["target"]
        assert result.hard_failures == []

    def test_entailed_hard_anchor_has_no_hard_failure(self) -> None:
        asserted = [AssertedValue(path="sha256", expected="a" * 64)]
        output = {"sha256": "a" * 64}
        result = check_entailment(asserted, output)
        assert result.passed is True
        assert result.hard_failures == []


class TestMultiplicityGuard:
    """A count claim must be backed by at least that many entailed leaves."""

    def test_count_two_with_two_lines_passes_no_demotion(self) -> None:
        asserted = [
            AssertedValue(path="rows[*].name", expected="implant", match="contains", count=2)
        ]
        output = {"rows": [{"name": "implant-a"}, {"name": "implant-b"}]}
        result = check_entailment(asserted, output)
        assert result.passed is True
        assert result.multiplicity_demotions == []

    def test_count_two_with_one_line_demotes(self) -> None:
        # "two variants" but only one entailed supporting line — the lie.
        asserted = [
            AssertedValue(path="rows[*].name", expected="implant", match="contains", count=2)
        ]
        output = {"rows": [{"name": "implant-a"}, {"name": "benign.exe"}]}
        result = check_entailment(asserted, output)
        # The single real line still entails, so the assertion is not a hard
        # failure — but the multiplicity is demoted.
        assert result.passed is True
        assert result.multiplicity_demotions == ["rows[*].name"]

    def test_count_three_sessions_with_zero_lines_is_a_plain_failure(self) -> None:
        # Nothing entails at all -> ordinary failure, not just a count demotion.
        asserted = [AssertedValue(path="sessions[*].id", expected="rdp", match="contains", count=3)]
        output = {"sessions": [{"id": "console-1"}]}
        result = check_entailment(asserted, output)
        assert result.passed is False
        assert "sessions[*].id" in result.failures

    def test_singular_claim_fully_entailed_passes(self) -> None:
        # The control: a singular (count unset / count=1) claim that entails.
        asserted = [AssertedValue(path="name", expected="evil.exe")]
        output = {"name": "evil.exe"}
        result = check_entailment(asserted, output)
        assert result.passed is True
        assert result.multiplicity_demotions == []

    def test_a_legitimately_none_leaf_still_counts_as_a_match(self) -> None:
        # Regression: a leaf whose value is JSON null can legitimately satisfy a
        # contains-empty assertion; "no match" must be distinguished by an empty
        # match list, not by the leaf being None.
        asserted = [AssertedValue(path="note", expected="", match="contains")]
        output = {"note": None}
        result = check_entailment(asserted, output)
        assert result.passed is True
        assert result.matched and result.matched[0].actual == ""
