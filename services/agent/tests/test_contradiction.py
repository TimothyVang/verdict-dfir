"""Tests for findevil_agent.contradiction."""

from __future__ import annotations

from findevil_agent.contradiction import (
    AntiForensicsPattern,
    _extract_entities,
    _extract_timestamps,
    _is_confidence_extreme,
    _presence_polarity,
    _token_overlap,
    antiforensics_to_events,
    detect_antiforensics,
    detect_contradictions,
    to_events,
)
from findevil_agent.events import ContradictionFound, Finding


def _f(
    finding_id: str,
    confidence: str = "CONFIRMED",
    *,
    tool_call_id: str = "tc-1",
    artifact_path: str = "Security.evtx",
    mitre: str | None = None,
    description: str = "logon evt",
    pool: str = "A",
) -> Finding:
    return Finding(
        case_id="c",
        finding_id=finding_id,
        tool_call_id=tool_call_id,
        artifact_path=artifact_path,
        confidence=confidence,
        mitre_technique=mitre,
        description=description,
        pool_origin=pool,
    )


class TestExtremeConfidence:
    def test_confirmed_vs_hypothesis_is_extreme(self) -> None:
        assert _is_confidence_extreme("CONFIRMED", "HYPOTHESIS") is True
        assert _is_confidence_extreme("HYPOTHESIS", "CONFIRMED") is True

    def test_one_tier_apart_is_not_extreme(self) -> None:
        assert _is_confidence_extreme("CONFIRMED", "INFERRED") is False
        assert _is_confidence_extreme("INFERRED", "HYPOTHESIS") is False

    def test_same_label_not_extreme(self) -> None:
        assert _is_confidence_extreme("CONFIRMED", "CONFIRMED") is False


class TestTokenOverlap:
    def test_identical_strings(self) -> None:
        assert _token_overlap("foo bar", "foo bar") == 1.0

    def test_disjoint_strings(self) -> None:
        assert _token_overlap("foo bar", "baz quux") == 0.0

    def test_partial_overlap(self) -> None:
        # 1 shared / 3 unique = 1/3 ≈ 0.333
        assert abs(_token_overlap("foo bar", "foo baz") - (1.0 / 3.0)) < 0.01

    def test_empty_both(self) -> None:
        assert _token_overlap("", "") == 1.0

    def test_empty_one(self) -> None:
        assert _token_overlap("foo", "") == 0.0


class TestDetectContradictions:
    def test_extreme_confidence_same_tool_call(self) -> None:
        a = _f("f-1", confidence="CONFIRMED", pool="A")
        b = _f("f-2", confidence="HYPOTHESIS", pool="B")
        contradictions = detect_contradictions([a], [b])
        assert len(contradictions) == 1
        assert "CONFIRMED" in contradictions[0].reason
        assert "HYPOTHESIS" in contradictions[0].reason

    def test_one_tier_apart_does_not_contradict(self) -> None:
        a = _f("f-1", confidence="CONFIRMED", pool="A")
        b = _f("f-2", confidence="INFERRED", pool="B")
        contradictions = detect_contradictions([a], [b])
        # No tool_call_id contradiction (one tier apart isn't extreme)
        # AND descriptions are identical so no token-overlap rule
        # fires either.
        assert contradictions == []

    def test_different_mitre_technique_same_artifact(self) -> None:
        a = _f("f-1", mitre="T1053.005", pool="A", description="scheduled task")
        b = _f("f-2", mitre="T1547.001", pool="B", description="run key")
        contradictions = detect_contradictions([a], [b])
        # Same tool_call_id + same artifact + different MITRE → contradicts.
        assert len(contradictions) >= 1
        assert any("MITRE" in p.reason for p in contradictions)

    def test_low_token_overlap_same_artifact(self) -> None:
        # Same artifact_path, same tool_call_id, similar confidence,
        # but very different descriptions.
        a = _f(
            "f-1",
            description="alpha bravo charlie delta",
            pool="A",
            mitre=None,
        )
        b = _f(
            "f-2",
            description="echo foxtrot golf hotel",
            pool="B",
            mitre=None,
        )
        contradictions = detect_contradictions([a], [b])
        assert any("token-overlap" in p.reason for p in contradictions)

    def test_no_contradiction_when_descriptions_match(self) -> None:
        a = _f("f-1", pool="A", mitre=None)
        b = _f("f-2", pool="B", mitre=None)
        # Same description text → token overlap = 1.0 → no rule fires.
        contradictions = detect_contradictions([a], [b])
        assert contradictions == []


class TestEntityHelpers:
    def test_extract_binary_basename_from_path(self) -> None:
        ents = _extract_entities(r"loaded C:\Windows\System32\evil.exe at boot")
        assert "evil.exe" in ents

    def test_extract_hash(self) -> None:
        sha = "a" * 64
        assert sha in _extract_entities(f"sample sha256 {sha} flagged")

    def test_no_entities_in_plain_prose(self) -> None:
        assert _extract_entities("a logon event was recorded") == set()

    def test_presence_polarity_present(self) -> None:
        assert _presence_polarity("evil.exe was executed and present") == "present"

    def test_presence_polarity_absent(self) -> None:
        assert _presence_polarity("evil.exe not found; no evidence of it") == "absent"

    def test_presence_polarity_ambiguous_is_none(self) -> None:
        # Contains both a presence and an absence signal -> conservative None.
        assert _presence_polarity("found evil.exe but no evidence of network") is None

    def test_extract_timestamps(self) -> None:
        ts = _extract_timestamps("first ran 2024-01-01T10:00:00Z then idle")
        assert ts == {"2024-01-01T10:00:00Z"}


class TestEntityContradiction:
    def test_presence_vs_absence_cross_citation_is_flagged(self) -> None:
        # Same binary, DIFFERENT tool_call_id and artifact_path -> Rules 1-3
        # cannot fire, but the same entity is asserted present and absent.
        a = _f(
            "f-1",
            tool_call_id="tc-A",
            artifact_path="amcache.hve",
            description="evil.exe was executed and is present in Amcache",
            pool="A",
            mitre=None,
        )
        b = _f(
            "f-2",
            tool_call_id="tc-B",
            artifact_path="mft.csv",
            description="no evidence of evil.exe; evil.exe is absent / not found on disk",
            pool="B",
            mitre=None,
        )
        contradictions = detect_contradictions([a], [b])
        assert len(contradictions) == 1
        reason = contradictions[0].reason
        assert "evil.exe" in reason
        assert "present" in reason and "absent" in reason

    def test_timestamp_conflict_cross_citation_is_flagged(self) -> None:
        a = _f(
            "f-1",
            tool_call_id="tc-A",
            artifact_path="prefetch",
            description="implant.dll observed at 2024-01-01T10:00:00Z",
            pool="A",
            mitre=None,
        )
        b = _f(
            "f-2",
            tool_call_id="tc-B",
            artifact_path="amcache.hve",
            description="implant.dll observed at 2024-06-15T22:30:00Z",
            pool="B",
            mitre=None,
        )
        contradictions = detect_contradictions([a], [b])
        assert any("mutually exclusive timestamps" in p.reason for p in contradictions)

    def test_unrelated_entities_not_flagged(self) -> None:
        # Different binaries, disjoint citations, no shared entity -> no rule.
        a = _f(
            "f-1",
            tool_call_id="tc-A",
            artifact_path="prefetch",
            description="powershell.exe spawned a child process",
            pool="A",
            mitre=None,
        )
        b = _f(
            "f-2",
            tool_call_id="tc-B",
            artifact_path="amcache.hve",
            description="rundll32.exe was not found on the host",
            pool="B",
            mitre=None,
        )
        assert detect_contradictions([a], [b]) == []

    def test_same_entity_agreeing_polarity_not_flagged(self) -> None:
        # Same binary but BOTH assert presence -> not a contradiction.
        a = _f(
            "f-1",
            tool_call_id="tc-A",
            artifact_path="prefetch",
            description="evil.exe executed on the host",
            pool="A",
            mitre=None,
        )
        b = _f(
            "f-2",
            tool_call_id="tc-B",
            artifact_path="amcache.hve",
            description="evil.exe is present and ran at logon",
            pool="B",
            mitre=None,
        )
        assert detect_contradictions([a], [b]) == []

    def test_presence_absence_without_shared_entity_not_flagged(self) -> None:
        # Clear present/absent polarity but NO shared strong entity -> the
        # conservatism anchor keeps it from firing.
        a = _f(
            "f-1",
            tool_call_id="tc-A",
            artifact_path="prefetch",
            description="the service was executed and is present",
            pool="A",
            mitre=None,
        )
        b = _f(
            "f-2",
            tool_call_id="tc-B",
            artifact_path="amcache.hve",
            description="the task is absent and was not found",
            pool="B",
            mitre=None,
        )
        assert detect_contradictions([a], [b]) == []


class TestAntiForensics:
    def _patterns(self, leads: list) -> set[str]:
        return {lead.pattern.value for lead in leads}

    def test_hidden_service_fires_when_no_matching_process(self) -> None:
        svc = _f(
            "f-svc",
            tool_call_id="tc-1",
            artifact_path="SYSTEM",
            description="EID 7045: a new service was installed with ImagePath C:\\Windows\\evil.sys",
            pool="A",
            mitre=None,
        )
        proc = _f(
            "f-proc",
            tool_call_id="tc-2",
            artifact_path="memdump",
            description="pslist shows running process explorer.exe (pid 1234)",
            pool="B",
            mitre=None,
        )
        leads = detect_antiforensics([svc, proc])
        assert AntiForensicsPattern.HIDDEN_SERVICE.value in self._patterns(leads)
        hit = next(le for le in leads if le.pattern is AntiForensicsPattern.HIDDEN_SERVICE)
        assert "evil.sys" in hit.reason

    def test_hidden_service_not_fired_when_process_corroborates(self) -> None:
        svc = _f(
            "f-svc",
            tool_call_id="tc-1",
            description="EID 7045: a new service was installed running evil.exe",
            pool="A",
            mitre=None,
        )
        proc = _f(
            "f-proc",
            tool_call_id="tc-2",
            artifact_path="memdump",
            description="pslist shows running process evil.exe at pid 4242",
            pool="B",
            mitre=None,
        )
        leads = detect_antiforensics([svc, proc])
        assert AntiForensicsPattern.HIDDEN_SERVICE.value not in self._patterns(leads)

    def test_hidden_service_needs_a_process_listing_to_compare(self) -> None:
        # No process-class finding at all -> 'no matching process' is meaningless,
        # so the detector stays quiet (conservatism).
        svc = _f(
            "f-svc",
            description="EID 7045: new service installed with ImagePath C:\\Windows\\evil.sys",
            pool="A",
            mitre=None,
        )
        assert detect_antiforensics([svc]) == []

    def test_network_without_process_fires(self) -> None:
        net = _f(
            "f-net",
            tool_call_id="tc-1",
            description="outbound TCP connection on port 443 from beacon.exe to a remote host",
            pool="A",
            mitre=None,
        )
        proc = _f(
            "f-proc",
            tool_call_id="tc-2",
            description="pslist enumerates running process svchost.exe (pid 900)",
            pool="B",
            mitre=None,
        )
        leads = detect_antiforensics([net, proc])
        assert AntiForensicsPattern.NETWORK_WITHOUT_PROCESS.value in self._patterns(leads)

    def test_invisible_connection_fires_on_no_owner_prose(self) -> None:
        net = _f(
            "f-net",
            tool_call_id="tc-1",
            description="established TCP connection to a remote host with no owning process",
            pool="A",
            mitre=None,
        )
        leads = detect_antiforensics([net])
        assert AntiForensicsPattern.INVISIBLE_CONNECTION.value in self._patterns(leads)

    def test_log_wipe_fires_on_clear_signal(self) -> None:
        wipe = _f(
            "f-wipe",
            tool_call_id="tc-1",
            artifact_path="Security.evtx",
            description="EID 1102: the security audit log was cleared",
            pool="A",
            mitre=None,
        )
        leads = detect_antiforensics([wipe])
        assert AntiForensicsPattern.LOG_WIPE.value in self._patterns(leads)

    def test_log_wipe_notes_co_occurring_gap(self) -> None:
        wipe = _f(
            "f-wipe",
            tool_call_id="tc-1",
            description="security log was cleared via wevtutil cl",
            pool="A",
            mitre=None,
        )
        gap = _f(
            "f-gap",
            tool_call_id="tc-2",
            description="a timeline gap with no events between two windows",
            pool="B",
            mitre=None,
        )
        leads = detect_antiforensics([wipe, gap])
        hit = next(le for le in leads if le.pattern is AntiForensicsPattern.LOG_WIPE)
        assert "timeline-gap" in hit.reason

    def test_prefetch_without_corroboration_fires(self) -> None:
        pf = _f(
            "f-pf",
            tool_call_id="tc-1",
            artifact_path="C:\\Windows\\Prefetch\\stager.exe-AAAA.pf",
            description="prefetch indicates stager.exe present in the prefetch store",
            pool="A",
            mitre=None,
        )
        leads = detect_antiforensics([pf])
        assert AntiForensicsPattern.PREFETCH_WITHOUT.value in self._patterns(leads)

    def test_prefetch_with_process_trace_not_fired(self) -> None:
        pf = _f(
            "f-pf",
            tool_call_id="tc-1",
            artifact_path="C:\\Windows\\Prefetch\\stager.exe-AAAA.pf",
            description="prefetch indicates stager.exe in the prefetch store",
            pool="A",
            mitre=None,
        )
        trace = _f(
            "f-tr",
            tool_call_id="tc-2",
            description="EID 4688 process creation recorded for stager.exe with a command-line",
            pool="B",
            mitre=None,
        )
        leads = detect_antiforensics([pf, trace])
        assert AntiForensicsPattern.PREFETCH_WITHOUT.value not in self._patterns(leads)

    def test_benign_set_yields_no_leads(self) -> None:
        a = _f("f-1", description="a logon event was recorded", pool="A", mitre=None)
        b = _f("f-2", description="another logon event was recorded", pool="B", mitre=None)
        assert detect_antiforensics([a, b]) == []

    def test_antiforensics_events_use_afl_prefix_and_label(self) -> None:
        wipe = _f(
            "f-wipe",
            tool_call_id="tc-1",
            description="EID 1102: the security log was cleared",
            pool="A",
            mitre=None,
        )
        leads = detect_antiforensics([wipe])
        events = antiforensics_to_events(leads, case_id="c-1", resolution_required=True)
        assert len(events) == 1
        ev = events[0]
        assert ev.contradiction_id.startswith("afl-")
        assert "HYPOTHESIS" in ev.pool_b_claim
        assert "LOG_WIPE" in ev.pool_b_claim
        assert ev.conflicting_tool_call_ids == ["tc-1"]


class TestToEvents:
    def test_emits_one_event_per_pair(self) -> None:
        a = _f("f-1", confidence="CONFIRMED", pool="A")
        b = _f("f-2", confidence="HYPOTHESIS", pool="B")
        contradictions = detect_contradictions([a], [b])
        events = to_events(contradictions, case_id="c-1", resolution_required=True)
        assert len(events) == 1
        ev = events[0]
        assert isinstance(ev, ContradictionFound)
        assert ev.contradiction_id == "ctr-0001"
        assert ev.resolution_required is True
        assert "CONFIRMED" in ev.pool_a_claim
        assert "HYPOTHESIS" in ev.pool_b_claim

    def test_unattended_sets_resolution_required_false(self) -> None:
        a = _f("f-1", confidence="CONFIRMED", pool="A")
        b = _f("f-2", confidence="HYPOTHESIS", pool="B")
        contradictions = detect_contradictions([a], [b])
        events = to_events(contradictions, case_id="c-1", resolution_required=False)
        assert events[0].resolution_required is False

    def test_conflicting_tool_call_ids_deduped(self) -> None:
        a = _f("f-1", confidence="CONFIRMED", tool_call_id="tc-1", pool="A")
        b = _f("f-2", confidence="HYPOTHESIS", tool_call_id="tc-1", pool="B")
        contradictions = detect_contradictions([a], [b])
        events = to_events(contradictions, case_id="c-1", resolution_required=True)
        # Both findings cite the same tc-1 — should appear ONCE.
        assert events[0].conflicting_tool_call_ids == ["tc-1"]

    def test_cross_citation_entity_event_lists_both_ids(self) -> None:
        # Rule 4 feeds the same resolution path: both DISJOINT citations
        # surface on the emitted event for the UI's Trust A / Trust B picker.
        a = _f(
            "f-1",
            tool_call_id="tc-A",
            artifact_path="amcache.hve",
            description="evil.exe was executed and is present",
            pool="A",
            mitre=None,
        )
        b = _f(
            "f-2",
            tool_call_id="tc-B",
            artifact_path="mft.csv",
            description="evil.exe is absent and was not found",
            pool="B",
            mitre=None,
        )
        contradictions = detect_contradictions([a], [b])
        events = to_events(contradictions, case_id="c-1", resolution_required=True)
        assert len(events) == 1
        assert events[0].conflicting_tool_call_ids == ["tc-A", "tc-B"]
