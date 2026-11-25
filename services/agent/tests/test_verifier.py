"""Tests for findevil_agent.verifier."""

from __future__ import annotations

from typing import Any

from findevil_agent.events import AssertedValue, Finding
from findevil_agent.mcp_client import MockMcpClient
from findevil_agent.verifier import (
    downgrade_confidence,
    reverify_finding,
    verify_findings,
)


def _make_finding(
    tool_call_id: str = "tc-1",
    confidence: str = "CONFIRMED",
    finding_id: str = "f-1",
) -> Finding:
    return Finding(
        case_id="c-1",
        finding_id=finding_id,
        tool_call_id=tool_call_id,
        artifact_path="Security.evtx",
        confidence=confidence,
        description="logon from 192.168.1.5",
    )


def _make_index(
    *,
    tool_name: str = "evtx_query",
    arguments: dict[str, Any] | None = None,
    output_sha256: str = "a" * 64,
) -> dict[str, dict[str, Any]]:
    return {
        "tc-1": {
            "tool_name": tool_name,
            "arguments": arguments or {"case_id": "c-1", "evtx_path": "x"},
            "output_sha256": output_sha256,
        }
    }


class TestRequiredCitation:
    def test_missing_tool_call_id_rejects(self) -> None:
        # Build a Finding with empty tool_call_id by directly creating
        # one (bypassing Pydantic's "required" since the runtime path
        # has agents that may emit empty strings).
        f = _make_finding(tool_call_id="")
        action, replay = reverify_finding(f, mcp=MockMcpClient(), tool_call_index={})
        assert action.action == "rejected"
        assert "tool_call_id" in action.reason
        assert replay is not None
        assert replay.artifact.drift_class == "missing_citation"

    def test_missing_audit_record_rejects(self) -> None:
        f = _make_finding(tool_call_id="tc-not-in-index")
        action, replay = reverify_finding(f, mcp=MockMcpClient(), tool_call_index={})
        assert action.action == "rejected"
        assert "not found" in action.reason
        assert replay is not None
        assert replay.artifact.drift_class == "missing_audit_record"


class TestSuccessPath:
    def test_matching_sha_approves(self) -> None:
        f = _make_finding()
        same_payload = {"row_count": 7}
        # MockMcpClient computes SHA on the canonical JSON of dict;
        # we precompute the same SHA into the index.
        import hashlib
        import json

        canonical = json.dumps(same_payload, sort_keys=True, separators=(",", ":"))
        expected_sha = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

        mcp = MockMcpClient()
        mcp.register("evtx_query", same_payload)
        index = _make_index(output_sha256=expected_sha)
        action, replay = reverify_finding(f, mcp=mcp, tool_call_index=index)
        assert action.action == "approved"
        assert replay is not None
        assert replay.matched is True
        assert replay.actual_sha256 == expected_sha
        assert replay.artifact.drift_class == "exact_match"


class TestDriftPath:
    def test_confirmed_drift_rejects_for_redispatch(self) -> None:
        # A CONFIRMED finding whose replay hash drifts is REJECTED (and
        # re-dispatched once with a fresh replay by the orchestrator) —
        # drift on the strongest tier must be re-checked, not silently
        # accepted at lower confidence.
        f = _make_finding(confidence="CONFIRMED")
        mcp = MockMcpClient()
        mcp.register("evtx_query", {"row_count": 99})
        # Index says expected SHA is 'a'*64 but the mock returns
        # something else.
        index = _make_index(output_sha256="a" * 64)
        action, replay = reverify_finding(f, mcp=mcp, tool_call_index=index)
        assert action.action == "rejected"
        assert "drift" in action.reason
        assert replay is not None
        assert replay.matched is False
        assert replay.expected_sha256 == "a" * 64
        assert replay.artifact.drift_class == "material_drift"

    def test_confirmed_drift_with_downgrade_on_drift_downgrades(self) -> None:
        # The re-dispatch attempt passes downgrade_on_drift=True: persistent
        # drift then takes the terminal downgrade (the pre-existing ladder).
        f = _make_finding(confidence="CONFIRMED")
        mcp = MockMcpClient()
        mcp.register("evtx_query", {"row_count": 99})
        index = _make_index(output_sha256="a" * 64)
        action, replay = reverify_finding(
            f, mcp=mcp, tool_call_index=index, downgrade_on_drift=True
        )
        assert action.action == "downgraded"
        assert "drift" in action.reason
        assert replay is not None
        assert replay.artifact.drift_class == "material_drift"

    def test_inferred_drift_downgrades_immediately(self) -> None:
        # Lower tiers keep the original behavior: drift -> downgrade, no
        # re-dispatch round-trip.
        f = _make_finding(confidence="INFERRED")
        mcp = MockMcpClient()
        mcp.register("evtx_query", {"row_count": 99})
        index = _make_index(output_sha256="a" * 64)
        action, replay = reverify_finding(f, mcp=mcp, tool_call_index=index)
        assert action.action == "downgraded"
        assert "drift" in action.reason


class TestRpcErrorPath:
    def test_mcp_error_rejects(self) -> None:
        f = _make_finding()
        mcp = MockMcpClient()  # no handler registered for evtx_query
        index = _make_index()
        action, replay = reverify_finding(f, mcp=mcp, tool_call_index=index)
        assert action.action == "rejected"
        assert replay is not None
        assert replay.matched is False
        assert replay.error is not None
        assert "rpc error" in replay.error


class TestBatchVerify:
    def test_batch_returns_aligned_tuples(self) -> None:
        mcp = MockMcpClient()
        mcp.register("evtx_query", {"x": 1})
        # Build expected SHA matching what the mock will produce.
        import hashlib
        import json

        canonical = json.dumps({"x": 1}, sort_keys=True, separators=(",", ":"))
        expected_sha = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        index = {
            "tc-1": {"tool_name": "evtx_query", "arguments": {}, "output_sha256": expected_sha},
            "tc-2": {"tool_name": "evtx_query", "arguments": {}, "output_sha256": expected_sha},
        }
        findings = [
            Finding(
                case_id="c",
                finding_id="f-1",
                tool_call_id="tc-1",
                artifact_path="x",
                confidence="CONFIRMED",
                description="a",
            ),
            Finding(
                case_id="c",
                finding_id="f-2",
                tool_call_id="tc-2",
                artifact_path="y",
                confidence="INFERRED",
                description="b",
            ),
        ]
        results = verify_findings(findings, mcp=mcp, tool_call_index=index)
        assert len(results) == 2
        for _original, action, replay in results:
            assert action.action == "approved"
            assert replay is not None and replay.matched


class TestEntailment:
    """Fact-fidelity (R3): after a SHA-match, the verifier re-extracts each
    asserted_value from the re-run output and treats a misread (valid citation,
    wrong value) like drift — CONFIRMED rejects, lower tiers downgrade."""

    def _exact_match(self, asserted_values: list[AssertedValue], confidence: str = "CONFIRMED"):
        import hashlib
        import json

        payload = {"row_count": 7, "entries": [{"name": "svchost.exe"}]}
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        expected_sha = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        mcp = MockMcpClient()
        mcp.register("evtx_query", payload)
        index = _make_index(output_sha256=expected_sha)
        f = Finding(
            case_id="c-1",
            finding_id="f-1",
            tool_call_id="tc-1",
            artifact_path="Security.evtx",
            confidence=confidence,
            description="seven rows, svchost present",
            asserted_values=asserted_values,
        )
        return reverify_finding(f, mcp=mcp, tool_call_index=index)

    def test_present_values_approve_and_seal_slice(self) -> None:
        action, replay = self._exact_match(
            [
                AssertedValue(path="row_count", expected="7", match="int"),
                AssertedValue(path="entries[*].name", expected="svchost.exe"),
            ]
        )
        assert action.action == "approved"
        assert "entailment confirmed from evidence" in action.reason
        assert replay is not None and replay.artifact.entailment is not None
        assert replay.artifact.entailment["passed"] is True

    def test_misread_rejects_confirmed(self) -> None:
        action, replay = self._exact_match(
            [AssertedValue(path="row_count", expected="999", match="int")]
        )
        assert action.action == "rejected"
        assert "entailment" in action.reason
        assert replay is not None and replay.artifact.entailment["passed"] is False

    def test_misread_downgrades_inferred(self) -> None:
        action, _ = self._exact_match(
            [AssertedValue(path="row_count", expected="999", match="int")],
            confidence="INFERRED",
        )
        assert action.action == "downgraded"

    def test_no_asserted_values_approves_vacuously(self) -> None:
        # Backward-compatible: a finding that declares nothing structured is not
        # gated here, and no slice is sealed.
        action, replay = self._exact_match([])
        assert action.action == "approved"
        assert replay is not None and replay.artifact.entailment is None


class TestDowngradeConfidence:
    def test_confirmed_to_inferred(self) -> None:
        f = _make_finding(confidence="CONFIRMED")
        downgraded = downgrade_confidence(f)
        assert downgraded.confidence == "INFERRED"

    def test_inferred_to_hypothesis(self) -> None:
        f = _make_finding(confidence="INFERRED")
        assert downgrade_confidence(f).confidence == "HYPOTHESIS"

    def test_hypothesis_stays_hypothesis(self) -> None:
        f = _make_finding(confidence="HYPOTHESIS")
        assert downgrade_confidence(f).confidence == "HYPOTHESIS"


class TestEntailmentCheck:
    """A finding can cite a reproducible output and still MISREAD it. The
    entailment check re-extracts the asserted value and refuses to approve a
    finding whose declared value is not actually in the (SHA-matching) output.
    """

    @staticmethod
    def _index_for(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
        import hashlib
        import json

        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        sha = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        return _make_index(tool_name="prefetch_parse", output_sha256=sha)

    def _finding(self, confidence: str, asserted: list[AssertedValue] | None) -> Finding:
        return Finding(
            case_id="c-1",
            finding_id="f-1",
            tool_call_id="tc-1",
            artifact_path="EVIL.EXE-1234.pf",
            confidence=confidence,
            description="ran 8 times",
            asserted_values=asserted or [],
        )

    def test_confirmed_finding_asserting_absent_value_is_rejected(self) -> None:
        # Citation reproduces (SHA matches) but the model said run_count 8 while
        # the real output says 3 — a laundered misread the old verifier approved.
        payload = {"run_count": 3, "executable_name": "EVIL.EXE"}
        mcp = MockMcpClient()
        mcp.register("prefetch_parse", payload)
        f = self._finding("CONFIRMED", [AssertedValue(path="run_count", expected="8", match="int")])
        action, replay = reverify_finding(f, mcp=mcp, tool_call_index=self._index_for(payload))
        assert action.action == "rejected"
        assert "asserted value" in action.reason or "entailment" in action.reason
        assert replay is not None
        # the SHA still matched — this is a misread, not drift
        assert replay.artifact.drift_class == "exact_match"

    def test_truthful_asserted_value_still_approves(self) -> None:
        payload = {"run_count": 8}
        mcp = MockMcpClient()
        mcp.register("prefetch_parse", payload)
        f = self._finding("CONFIRMED", [AssertedValue(path="run_count", expected="8", match="int")])
        action, _ = reverify_finding(f, mcp=mcp, tool_call_index=self._index_for(payload))
        assert action.action == "approved"

    def test_inferred_finding_with_absent_value_is_downgraded(self) -> None:
        payload = {"run_count": 3}
        mcp = MockMcpClient()
        mcp.register("prefetch_parse", payload)
        f = self._finding("INFERRED", [AssertedValue(path="run_count", expected="8", match="int")])
        action, _ = reverify_finding(f, mcp=mcp, tool_call_index=self._index_for(payload))
        assert action.action == "downgraded"

    def test_no_assertions_is_unaffected(self) -> None:
        # Backward compatible: no asserted_values -> approves on SHA alone.
        payload = {"run_count": 3}
        mcp = MockMcpClient()
        mcp.register("prefetch_parse", payload)
        f = self._finding("CONFIRMED", None)
        action, _ = reverify_finding(f, mcp=mcp, tool_call_index=self._index_for(payload))
        assert action.action == "approved"

    def test_replay_artifact_seals_the_entailment_slice(self) -> None:
        # The minimal entailment slice rides on the replay artifact into the
        # signed chain, and re-verifies offline (manifest_verify uses this).
        from findevil_agent.entailment import recheck_entailment_slice

        payload = {"run_count": 8}
        mcp = MockMcpClient()
        mcp.register("prefetch_parse", payload)
        f = self._finding("CONFIRMED", [AssertedValue(path="run_count", expected="8", match="int")])
        action, replay = reverify_finding(f, mcp=mcp, tool_call_index=self._index_for(payload))
        assert action.action == "approved"
        assert replay is not None and replay.artifact.entailment is not None
        assert replay.artifact.entailment["passed"] is True
        assert recheck_entailment_slice(replay.artifact.entailment) is True

    def test_approved_action_records_the_server_extracted_value(self) -> None:
        # Extractive provenance: the approval reason carries the value the
        # SERVER read out of the evidence, not just "SHA matches". The recorded
        # fact is server-read, not model-transcribed.
        payload = {"run_count": 8}
        mcp = MockMcpClient()
        mcp.register("prefetch_parse", payload)
        f = self._finding("CONFIRMED", [AssertedValue(path="run_count", expected="8", match="int")])
        action, _ = reverify_finding(f, mcp=mcp, tool_call_index=self._index_for(payload))
        assert action.action == "approved"
        assert "run_count" in action.reason
        assert "8" in action.reason
        assert "entailment" in action.reason.lower() or "confirmed" in action.reason.lower()


class TestContradictingValueRejected:
    """Regression guard for the #1 practitioner critique (claim fidelity): the
    verifier proves a citation reproduces (SHA matches) and R3 re-extracts each
    asserted_value, but a model can still MISREAD real data — here the cited
    record genuinely HOLDS a value and the finding asserts a *different,
    conflicting* one for that same field. Distinct from the absent-value tests
    above (where the field is missing or an int simply differs): the contradicted
    field is present and non-empty, so the only thing wrong is the model's claim.
    A CONFIRMED finding must be rejected, a lower tier demoted — the misread is
    treated like drift even though the SHA matched (drift_class stays exact_match).
    """

    @staticmethod
    def _index_for(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
        import hashlib
        import json

        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        sha = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        return _make_index(tool_name="prefetch_parse", output_sha256=sha)

    def _finding(self, confidence: str, asserted: list[AssertedValue]) -> Finding:
        return Finding(
            case_id="c-1",
            finding_id="f-1",
            tool_call_id="tc-1",
            artifact_path="EVIL.EXE-1234.pf",
            confidence=confidence,
            description="claims a specific executable name",
            asserted_values=asserted,
        )

    def test_exact_contradiction_rejects_confirmed(self) -> None:
        # The record genuinely names BENIGN.EXE; the model asserts EVIL.EXE.
        # The field is present and non-empty, so this is a contradiction, not a
        # missing field — the verifier must still reject on a CONFIRMED finding.
        payload = {"executable_name": "BENIGN.EXE", "run_count": 3}
        mcp = MockMcpClient()
        mcp.register("prefetch_parse", payload)
        f = self._finding("CONFIRMED", [AssertedValue(path="executable_name", expected="EVIL.EXE")])
        action, replay = reverify_finding(f, mcp=mcp, tool_call_index=self._index_for(payload))
        assert action.action == "rejected"
        assert "entailment" in action.reason
        assert replay is not None
        assert replay.artifact.drift_class == "exact_match"  # SHA matched: a misread, not drift
        assert replay.artifact.entailment["passed"] is False

    def test_exact_contradiction_downgrades_inferred(self) -> None:
        payload = {"executable_name": "BENIGN.EXE"}
        mcp = MockMcpClient()
        mcp.register("prefetch_parse", payload)
        f = self._finding("INFERRED", [AssertedValue(path="executable_name", expected="EVIL.EXE")])
        action, _ = reverify_finding(f, mcp=mcp, tool_call_index=self._index_for(payload))
        assert action.action == "downgraded"

    def test_contains_substring_absent_rejects_confirmed(self) -> None:
        # The command line is present but does NOT contain the asserted fragment;
        # the model claimed a download cradle the real evidence never shows.
        payload = {"command_line": "C:\\Windows\\System32\\notepad.exe README.txt"}
        mcp = MockMcpClient()
        mcp.register("prefetch_parse", payload)
        f = self._finding(
            "CONFIRMED",
            [AssertedValue(path="command_line", expected="certutil -urlcache", match="contains")],
        )
        action, replay = reverify_finding(f, mcp=mcp, tool_call_index=self._index_for(payload))
        assert action.action == "rejected"
        assert replay is not None and replay.artifact.entailment["passed"] is False

    def test_record_field_contradiction_rejects_confirmed(self) -> None:
        # Co-location contradiction: the record for "Updater" genuinely points at
        # a legit path; the model binds "Updater" to "evil.exe" in the SAME record.
        payload = {"rows": [{"name": "Updater", "path": "C:\\Windows\\legit.exe"}]}
        mcp = MockMcpClient()
        mcp.register("prefetch_parse", payload)
        f = self._finding(
            "CONFIRMED",
            [
                AssertedValue(
                    path="rows[*]",
                    expected='{"name": "Updater", "path": "evil.exe"}',
                    match="record",
                )
            ],
        )
        action, replay = reverify_finding(f, mcp=mcp, tool_call_index=self._index_for(payload))
        assert action.action == "rejected"
        assert replay is not None and replay.artifact.entailment["passed"] is False

    def test_truthful_value_among_contradictable_fields_still_approves(self) -> None:
        # Control: when the asserted value matches the present field, the same
        # path approves — the guard rejects contradictions, not correct reads.
        payload = {"executable_name": "EVIL.EXE", "run_count": 8}
        mcp = MockMcpClient()
        mcp.register("prefetch_parse", payload)
        f = self._finding("CONFIRMED", [AssertedValue(path="executable_name", expected="EVIL.EXE")])
        action, _ = reverify_finding(f, mcp=mcp, tool_call_index=self._index_for(payload))
        assert action.action == "approved"


class TestHardAnchorReject:
    """Verifier wiring: a HARD anchor (hash/IP/byte-size/filename) that does not
    entail is laundering, not a tier slip — reject it outright regardless of
    confidence tier (even when a corroborating miss would only downgrade)."""

    @staticmethod
    def _index_for(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
        import hashlib
        import json

        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        sha = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        return _make_index(tool_name="suricata_eve", output_sha256=sha)

    def _finding(self, confidence: str, asserted: list[AssertedValue]) -> Finding:
        return Finding(
            case_id="c-1",
            finding_id="f-1",
            tool_call_id="tc-1",
            artifact_path="eve.json",
            confidence=confidence,
            description="beacon to a specific dst_ip",
            asserted_values=asserted,
        )

    def test_wrong_hard_ip_rejects_even_on_inferred(self) -> None:
        # A corroborating miss on an INFERRED finding only downgrades; a HARD
        # anchor miss must reject the laundered claim even on a lower tier.
        payload = {"dst_ip": "198.51.100.9"}
        mcp = MockMcpClient()
        mcp.register("suricata_eve", payload)
        f = self._finding("INFERRED", [AssertedValue(path="dst_ip", expected="203.0.113.7")])
        action, replay = reverify_finding(f, mcp=mcp, tool_call_index=self._index_for(payload))
        assert action.action == "rejected"
        assert "hard anchor" in action.reason.lower()
        assert replay is not None and replay.artifact.entailment["passed"] is False

    def test_wrong_hard_hash_rejects_confirmed(self) -> None:
        payload = {"sha256": "b" * 64}
        mcp = MockMcpClient()
        mcp.register("suricata_eve", payload)
        f = self._finding("CONFIRMED", [AssertedValue(path="sha256", expected="a" * 64)])
        action, _ = reverify_finding(f, mcp=mcp, tool_call_index=self._index_for(payload))
        assert action.action == "rejected"

    def test_entailed_hard_anchor_still_approves(self) -> None:
        payload = {"dst_ip": "203.0.113.7"}
        mcp = MockMcpClient()
        mcp.register("suricata_eve", payload)
        f = self._finding("CONFIRMED", [AssertedValue(path="dst_ip", expected="203.0.113.7")])
        action, _ = reverify_finding(f, mcp=mcp, tool_call_index=self._index_for(payload))
        assert action.action == "approved"


class TestMultiplicityDemote:
    """Verifier wiring: a finding asserting a count ("two variants") whose count
    exceeds the number of entailed supporting leaves is DEMOTED below CONFIRMED
    — the single real line is genuine, the over-count is not."""

    @staticmethod
    def _index_for(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
        import hashlib
        import json

        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        sha = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        return _make_index(tool_name="yara_scan", output_sha256=sha)

    def _finding(self, confidence: str, asserted: list[AssertedValue]) -> Finding:
        return Finding(
            case_id="c-1",
            finding_id="f-1",
            tool_call_id="tc-1",
            artifact_path="scan.json",
            confidence=confidence,
            description="two implant variants on disk",
            asserted_values=asserted,
        )

    def test_two_variants_one_line_demotes_confirmed(self) -> None:
        payload = {"rows": [{"name": "implant-a"}, {"name": "benign.txt"}]}
        mcp = MockMcpClient()
        mcp.register("yara_scan", payload)
        f = self._finding(
            "CONFIRMED",
            [AssertedValue(path="rows[*].name", expected="implant", match="contains", count=2)],
        )
        action, replay = reverify_finding(f, mcp=mcp, tool_call_index=self._index_for(payload))
        assert action.action == "downgraded"
        assert "multiplicity" in action.reason.lower()
        assert replay is not None and replay.artifact.entailment["passed"] is True

    def test_two_variants_two_lines_approves(self) -> None:
        payload = {"rows": [{"name": "implant-a"}, {"name": "implant-b"}]}
        mcp = MockMcpClient()
        mcp.register("yara_scan", payload)
        f = self._finding(
            "CONFIRMED",
            [AssertedValue(path="rows[*].name", expected="implant", match="contains", count=2)],
        )
        action, _ = reverify_finding(f, mcp=mcp, tool_call_index=self._index_for(payload))
        assert action.action == "approved"
