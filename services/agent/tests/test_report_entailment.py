"""Tests for rendering a finding's server-read evidence value into the report.

The verifier seals an entailment slice onto each finding's replay artifact: the
value the deterministic parser READ from the re-run evidence for every asserted
value it confirmed. The analyst report must surface that value, not only the
model's free-text description, so a tolerant match (a substring, a
differently-formatted timestamp, hex vs decimal) cannot let the model's spelling
reach the reader as the fact. These tests drive the pure helper that turns the
sealed slice into Markdown lines (kept stdlib-only so it is testable without the
report renderer's matplotlib dependency).
"""

import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

from report_entailment import entailment_evidence_lines  # noqa: E402


class TestEntailmentEvidenceLines:
    def test_renders_server_read_value_for_each_matched_assertion(self) -> None:
        finding = {
            "replay_artifact": {
                "entailment": {
                    "passed": True,
                    "matched": [
                        {
                            "path": "entries[*].values[*].data_str",
                            "expected": "evil.exe",
                            "actual": "C:\\Users\\bob\\evil.exe",
                            "match": "contains",
                        }
                    ],
                    "failures": [],
                }
            }
        }
        lines = entailment_evidence_lines(finding)
        assert len(lines) == 1
        assert "C:\\Users\\bob\\evil.exe" in lines[0]
        assert "entries[*].values[*].data_str" in lines[0]

    def test_shows_actual_not_the_models_expected_when_they_differ(self) -> None:
        # Tolerant iso_ts match: the model asserted one spelling, the evidence has
        # another. The report must show the evidence spelling (the server read),
        # never the model's.
        finding = {
            "replay_artifact": {
                "entailment": {
                    "matched": [
                        {
                            "path": "ts",
                            "expected": "2018-09-06T19:00:00+00:00",
                            "actual": "2018-09-06T19:00:00Z",
                            "match": "iso_ts",
                        }
                    ]
                }
            }
        }
        line = entailment_evidence_lines(finding)[0]
        assert "2018-09-06T19:00:00Z" in line
        assert "2018-09-06T19:00:00+00:00" not in line

    def test_each_matched_value_gets_its_own_line(self) -> None:
        finding = {
            "replay_artifact": {
                "entailment": {
                    "matched": [
                        {"path": "run_count", "expected": "8", "actual": "8", "match": "int"},
                        {
                            "path": "name",
                            "expected": "Updater",
                            "actual": "Updater",
                            "match": "exact",
                        },
                    ]
                }
            }
        }
        assert len(entailment_evidence_lines(finding)) == 2

    def test_no_entailment_slice_yields_no_lines(self) -> None:
        assert entailment_evidence_lines({"replay_artifact": {}}) == []
        assert entailment_evidence_lines({"replay_artifact": {"entailment": {}}}) == []
        assert entailment_evidence_lines({}) == []

    def test_malformed_matched_entries_are_skipped_not_crashed(self) -> None:
        finding = {
            "replay_artifact": {
                "entailment": {"matched": ["not-a-dict", {"path": "ok", "actual": "v"}]}
            }
        }
        lines = entailment_evidence_lines(finding)
        assert len(lines) == 1
        assert "ok" in lines[0]
