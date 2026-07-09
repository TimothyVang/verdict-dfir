"""Tests for the deterministic categorical-impossibility falsifiers.

``findevil_agent.categorical_impossibility`` REFUTES a finding when it asserts
something physically or logically impossible for the evidence at hand. It is a
read-only scorer/verifier-side check: it never mutates the audit chain, the
manifest, or the finding — it only returns typed :class:`Falsification` records.

Two falsifiers:

- **temporal-physics** — an asserted event timestamp strictly AFTER the evidence
  capture/acquisition time. Effect cannot precede acquisition.
- **platform-consistency** — an OS-exclusive claim (e.g. a Windows registry/NTFS
  artifact) on an image whose platform is something else (e.g. Linux/ext).
"""

from __future__ import annotations

from findevil_agent.categorical_impossibility import (
    Falsification,
    RefutationReason,
    falsify_finding,
    falsify_platform_consistency,
    falsify_temporal_physics,
    lint_execution_before_creation,
    lint_findings,
    lint_presence_only_vs_execution,
    lint_same_evidence_dual_severity,
)
from findevil_agent.events import AssertedValue, Finding

_CAPTURE = "2024-03-01T12:00:00Z"


def _finding(
    *,
    description: str = "benign observation",
    confidence: str = "HYPOTHESIS",
    asserted_values: list[AssertedValue] | None = None,
    mitre: str | None = None,
    artifact_path: str = "/evidence/host.img",
) -> Finding:
    return Finding(
        case_id="case-1",
        finding_id="f-1",
        tool_call_id="tc-1",
        artifact_path=artifact_path,
        confidence=confidence,  # type: ignore[arg-type]
        mitre_technique=mitre,
        description=description,
        asserted_values=asserted_values or [],
    )


class TestTemporalPhysics:
    def test_timestamp_after_capture_is_refuted(self) -> None:
        finding = _finding(
            asserted_values=[
                AssertedValue(path="rows[0].ts", expected="2099-01-01T00:00:00Z", match="iso_ts")
            ]
        )
        refutations = falsify_temporal_physics(finding, capture_time=_CAPTURE)
        assert len(refutations) == 1
        r = refutations[0]
        assert r.reason is RefutationReason.TEMPORAL_PHYSICS
        assert r.finding_id == "f-1"
        assert r.impossible_values["asserted_time"] == "2099-01-01T00:00:00Z"
        assert r.impossible_values["capture_time"] == _CAPTURE

    def test_timestamp_before_capture_is_not_refuted(self) -> None:
        finding = _finding(
            asserted_values=[
                AssertedValue(path="rows[0].ts", expected="2024-02-01T00:00:00Z", match="iso_ts")
            ]
        )
        assert falsify_temporal_physics(finding, capture_time=_CAPTURE) == []

    def test_timestamp_equal_to_capture_is_not_refuted(self) -> None:
        finding = _finding(
            asserted_values=[AssertedValue(path="rows[0].ts", expected=_CAPTURE, match="iso_ts")]
        )
        assert falsify_temporal_physics(finding, capture_time=_CAPTURE) == []

    def test_timestamp_in_description_prose_is_scanned(self) -> None:
        finding = _finding(description="logon event observed at 2030-12-31T23:59:59Z on the host")
        refutations = falsify_temporal_physics(finding, capture_time=_CAPTURE)
        assert len(refutations) == 1
        assert refutations[0].impossible_values["asserted_time"] == "2030-12-31T23:59:59Z"

    def test_naive_timestamp_treated_as_utc(self) -> None:
        finding = _finding(
            asserted_values=[
                AssertedValue(path="rows[0].ts", expected="2099-01-01 00:00:00", match="iso_ts")
            ]
        )
        assert len(falsify_temporal_physics(finding, capture_time=_CAPTURE)) == 1

    def test_no_capture_time_is_a_noop(self) -> None:
        finding = _finding(
            asserted_values=[
                AssertedValue(path="rows[0].ts", expected="2099-01-01T00:00:00Z", match="iso_ts")
            ]
        )
        assert falsify_temporal_physics(finding, capture_time=None) == []

    def test_unparseable_strings_are_ignored(self) -> None:
        finding = _finding(
            description="run count = 3 and a note like 2024-99-99 that is not a date"
        )
        assert falsify_temporal_physics(finding, capture_time=_CAPTURE) == []

    def test_multiple_impossible_timestamps_collapse_to_worst(self) -> None:
        finding = _finding(
            asserted_values=[
                AssertedValue(path="a", expected="2099-01-01T00:00:00Z", match="iso_ts"),
                AssertedValue(path="b", expected="2100-06-01T00:00:00Z", match="iso_ts"),
            ]
        )
        refutations = falsify_temporal_physics(finding, capture_time=_CAPTURE)
        assert len(refutations) == 1
        assert refutations[0].impossible_values["asserted_time"] == "2100-06-01T00:00:00Z"


class TestPlatformConsistency:
    def test_windows_registry_claim_on_linux_image_is_refuted(self) -> None:
        finding = _finding(
            description="registry Run key HKLM\\SOFTWARE\\Microsoft persists implant.exe",
            mitre="T1547.001",
        )
        refutations = falsify_platform_consistency(finding, platform="linux")
        assert len(refutations) == 1
        r = refutations[0]
        assert r.reason is RefutationReason.PLATFORM_CONSISTENCY
        assert r.impossible_values["claimed_platform"] == "windows"
        assert r.impossible_values["image_platform"] == "linux"

    def test_windows_claim_on_windows_image_is_not_refuted(self) -> None:
        finding = _finding(
            description="registry Run key HKLM\\SOFTWARE persists implant.exe",
        )
        assert falsify_platform_consistency(finding, platform="windows") == []

    def test_linux_claim_on_windows_image_is_refuted(self) -> None:
        finding = _finding(
            description="suspicious cron entry in /etc/crontab launches /tmp/x",
        )
        refutations = falsify_platform_consistency(finding, platform="windows")
        assert len(refutations) == 1
        assert refutations[0].impossible_values["claimed_platform"] == "linux"

    def test_platform_agnostic_claim_is_not_refuted(self) -> None:
        finding = _finding(description="outbound connection to a C2 domain on port 443")
        assert falsify_platform_consistency(finding, platform="linux") == []

    def test_unknown_platform_is_a_noop(self) -> None:
        finding = _finding(description="registry Run key HKLM persists implant.exe")
        assert falsify_platform_consistency(finding, platform=None) == []


class TestFalsifyFinding:
    def test_combines_both_falsifiers(self) -> None:
        finding = _finding(
            description="registry HKLM Run key set at 2099-01-01T00:00:00Z",
            asserted_values=[
                AssertedValue(path="ts", expected="2099-01-01T00:00:00Z", match="iso_ts")
            ],
        )
        refutations = falsify_finding(finding, capture_time=_CAPTURE, platform="linux")
        reasons = {r.reason for r in refutations}
        assert reasons == {RefutationReason.TEMPORAL_PHYSICS, RefutationReason.PLATFORM_CONSISTENCY}

    def test_clean_finding_yields_no_refutations(self) -> None:
        finding = _finding(
            description="suspicious outbound connection at 2024-02-01T00:00:00Z",
            asserted_values=[
                AssertedValue(path="ts", expected="2024-02-01T00:00:00Z", match="iso_ts")
            ],
        )
        assert falsify_finding(finding, capture_time=_CAPTURE, platform="linux") == []

    def test_falsification_is_frozen(self) -> None:
        fal = Falsification(
            finding_id="f-1",
            reason=RefutationReason.TEMPORAL_PHYSICS,
            message="x",
            impossible_values={},
        )
        try:
            fal.message = "y"  # type: ignore[misc]
        except Exception:
            return
        raise AssertionError("Falsification should be frozen/immutable")


def _f(
    finding_id: str,
    *,
    confidence: str = "HYPOTHESIS",
    description: str = "benign observation",
    tool_call_id: str = "tc-1",
    artifact_path: str = "/evidence/host.img",
    mitre: str | None = None,
    asserted_values: list[AssertedValue] | None = None,
    derived_from: list[str] | None = None,
) -> Finding:
    return Finding(
        case_id="case-1",
        finding_id=finding_id,
        tool_call_id=tool_call_id,
        artifact_path=artifact_path,
        confidence=confidence,  # type: ignore[arg-type]
        mitre_technique=mitre,
        description=description,
        asserted_values=asserted_values or [],
        derived_from=derived_from,
    )


class TestExecutionBeforeCreation:
    def test_execution_before_creation_is_refuted(self) -> None:
        finding = _f(
            "f-1",
            description=(
                "binary evil.exe was created at 2024-03-05T10:00:00Z but prefetch shows it "
                "ran at 2024-03-01T09:00:00Z"
            ),
        )
        refs = lint_execution_before_creation(finding)
        assert len(refs) == 1
        assert refs[0].reason is RefutationReason.CHRONOLOGY_EXECUTION_BEFORE_CREATION
        assert refs[0].impossible_values["execution_time"] == "2024-03-01T09:00:00Z"
        assert refs[0].impossible_values["creation_time"] == "2024-03-05T10:00:00Z"

    def test_execution_after_creation_is_clean(self) -> None:
        finding = _f(
            "f-1",
            description=(
                "evil.exe was created at 2024-03-01T09:00:00Z and later ran at "
                "2024-03-05T10:00:00Z"
            ),
        )
        assert lint_execution_before_creation(finding) == []

    def test_only_one_role_present_is_noop(self) -> None:
        finding = _f("f-1", description="evil.exe was created at 2024-03-05T10:00:00Z")
        assert lint_execution_before_creation(finding) == []

    def test_role_tagged_asserted_values(self) -> None:
        finding = _f(
            "f-1",
            description="execution ordering check",
            asserted_values=[
                AssertedValue(
                    path="rows[0].create_time", expected="2024-03-05T10:00:00Z", match="iso_ts"
                ),
                AssertedValue(
                    path="rows[0].last_run_time", expected="2024-03-01T09:00:00Z", match="iso_ts"
                ),
            ],
        )
        refs = lint_execution_before_creation(finding)
        assert len(refs) == 1
        assert refs[0].impossible_values["execution_time"] == "2024-03-01T09:00:00Z"


class TestPresenceOnlyVsExecution:
    def test_execution_claim_with_amcache_only_is_flagged(self) -> None:
        finding = _f(
            "f-1",
            confidence="INFERRED",
            description="evil.exe executed according to Amcache only",
            derived_from=["tc-2"],
        )
        refs = lint_presence_only_vs_execution(finding)
        assert len(refs) == 1
        assert refs[0].reason is RefutationReason.PRESENCE_NOT_EXECUTION

    def test_real_run_trace_is_not_flagged(self) -> None:
        finding = _f(
            "f-1",
            confidence="INFERRED",
            description="evil.exe ran 3 times per the prefetch run count in Amcache",
            derived_from=["tc-2"],
        )
        assert lint_presence_only_vs_execution(finding) == []

    def test_presence_without_execution_claim_is_not_flagged(self) -> None:
        finding = _f("f-1", description="evil.exe is present in Amcache")
        assert lint_presence_only_vs_execution(finding) == []

    def test_execution_claim_without_presence_signal_is_not_flagged(self) -> None:
        # Claims execution but no presence-only artifact noun to flag against.
        finding = _f("f-1", description="a process executed on the host")
        assert lint_presence_only_vs_execution(finding) == []


class TestDualSeverity:
    def test_same_evidence_two_tiers_flags_both(self) -> None:
        a = _f(
            "f-1",
            confidence="INFERRED",
            description="binary ran from a writable temp dir",
            tool_call_id="tc-9",
            artifact_path="Amcache.hve",
            derived_from=["tc-2"],
        )
        b = _f(
            "f-2",
            confidence="HYPOTHESIS",
            description="binary ran from a writable temp dir",
            tool_call_id="tc-9",
            artifact_path="Amcache.hve",
        )
        refs = lint_same_evidence_dual_severity([a, b])
        flagged = {r.finding_id for r in refs}
        assert flagged == {"f-1", "f-2"}
        assert all(r.reason is RefutationReason.DUAL_SEVERITY_SAME_EVIDENCE for r in refs)

    def test_same_evidence_same_tier_not_flagged(self) -> None:
        a = _f(
            "f-1",
            confidence="HYPOTHESIS",
            description="binary ran from a writable temp dir",
            tool_call_id="tc-9",
        )
        b = _f(
            "f-2",
            confidence="HYPOTHESIS",
            description="binary ran from a writable temp dir",
            tool_call_id="tc-9",
        )
        assert lint_same_evidence_dual_severity([a, b]) == []

    def test_different_evidence_two_tiers_not_flagged(self) -> None:
        a = _f(
            "f-1",
            confidence="INFERRED",
            description="binary ran from a writable temp dir",
            tool_call_id="tc-9",
            mitre="T1059",
            derived_from=["tc-2"],
        )
        b = _f(
            "f-2",
            confidence="HYPOTHESIS",
            description="possible brute force on the same host",
            tool_call_id="tc-9",
            mitre="T1110",
        )
        assert lint_same_evidence_dual_severity([a, b]) == []


class TestLintFindings:
    def test_aggregates_all_lints(self) -> None:
        chrono = _f(
            "f-chrono",
            description=(
                "evil.exe was created at 2024-03-05T10:00:00Z but ran at 2024-03-01T09:00:00Z"
            ),
        )
        a = _f(
            "f-a",
            confidence="INFERRED",
            description="binary ran from a writable temp dir",
            tool_call_id="tc-9",
            artifact_path="Amcache.hve",
            derived_from=["tc-2"],
        )
        b = _f(
            "f-b",
            confidence="HYPOTHESIS",
            description="binary ran from a writable temp dir",
            tool_call_id="tc-9",
            artifact_path="Amcache.hve",
        )
        reasons = {r.reason for r in lint_findings([chrono, a, b])}
        assert RefutationReason.CHRONOLOGY_EXECUTION_BEFORE_CREATION in reasons
        assert RefutationReason.DUAL_SEVERITY_SAME_EVIDENCE in reasons


class TestCustodyNeutralFalsifyFinding:
    def test_falsify_finding_excludes_new_lints(self) -> None:
        # A finding that trips execution-before-creation must NOT surface through
        # falsify_finding (which feeds the engine REFUTED count) — the lints stay
        # custody-neutral in lint_findings.
        finding = _f(
            "f-1",
            description=(
                "evil.exe was created at 2024-03-05T10:00:00Z but ran at 2024-03-01T09:00:00Z"
            ),
        )
        reasons = {r.reason for r in falsify_finding(finding)}
        assert RefutationReason.CHRONOLOGY_EXECUTION_BEFORE_CREATION not in reasons
        assert RefutationReason.PRESENCE_NOT_EXECUTION not in reasons
