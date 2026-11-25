"""A directly-observed pcap HTTP POST to a curated anonymous-email host is a
tier-1 fact (ENGINE-POLICY).

The project's confidence hierarchy defines CONFIRMED as "backed by a
tool_call_id, a raw output excerpt, and asserted_values the verifier
re-extracts". A POST parsed from ``pcap_triage``'s ``http_requests`` is exactly
that, so the anon-email POST finding must be born CONFIRMED with
``asserted_values`` the entailment check can resolve against the replayed
``parsed_output`` — nothing downstream can raise a tier, so a pcap-only case
was structurally stuck at INDETERMINATE against a CONFIRMED_EVIL key (nitroba).

Blast-radius guards in this file:

* GET stays HYPOTHESIS (mere contact is a lead, not a fact).
* The trigger is the curated host-token list; benign hosts and lookalike URIs
  never fire it (synthetic-benign / synthetic-decoy FP floor).
* The alihadi-09-encrypt shape (INFERRED/HYPOTHESIS leads only) still computes
  INDETERMINATE — no general "N INFERRED => EVIL" rule crept in.
* The asserted_values actually resolve through ``check_entailment`` against
  the real ``PcapHttpRequest`` output shape (this was flagged as unverified).
"""

from __future__ import annotations

import sys
from pathlib import Path

from findevil_agent.entailment import check_entailment
from findevil_agent.events import AssertedValue, Finding

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402

TCID = "tc-pcap-1"
PCAP = "/evidence/nitroba.pcap"


def _row(**overrides):
    """One ``http_requests`` row in the exact ``PcapHttpRequest`` shape
    (services/mcp/src/tools/pcap_triage.rs): src, host, method, uri,
    has_cookie, count, first_ts, last_ts."""
    row = {
        "src": "192.168.1.64",
        "host": "www.willselfdestruct.com",
        "method": "POST",
        "uri": "/cgi-bin/mail.cgi",
        "has_cookie": False,
        "count": 2,
        "first_ts": "1216706000.123",
        "last_ts": "1216706100.456",
    }
    row.update(overrides)
    return row


def _pcap_triage_output(rows):
    """A replayed ``parsed_output`` in the full ``PcapTriageOutput`` shape."""
    return {
        "analyzer": "tshark",
        "packets_seen": 4242,
        "conversations": [],
        "dns_queries": [],
        "http_hosts": [],
        "http_requests": rows,
        "zeek": None,
    }


def _inv():
    inv = fea.Investigation("nitroba.pcap", unattended=True, with_report=False)
    inv.handle = {"id": "case-nitroba-test"}
    return inv


def _emit(rows):
    inv = _inv()
    inv._add_pcap_http_request_findings(_pcap_triage_output(rows), TCID, PCAP)
    return inv


def _anon_findings(inv):
    return [f for f in inv.findings_pool_b if "anon-email" in str(f.get("finding_id") or "")]


class TestConfirmedPromotion:
    def test_post_to_curated_anon_email_host_is_confirmed(self) -> None:
        inv = _emit([_row()])
        found = _anon_findings(inv)
        assert len(found) == 1
        f = found[0]
        assert f["confidence"] == "CONFIRMED"
        assert f["tool_call_id"] == TCID
        assert f["mitre_technique"] is None  # identity attribution, not C2
        # CONFIRMED must carry re-extractable structured facts.
        assert f.get("asserted_values")
        # And the ruled-out benign alternative (anti-coherence gate readiness).
        assert str(f.get("counter_hypothesis") or "").strip()

    def test_get_to_anon_email_host_stays_hypothesis(self) -> None:
        inv = _emit([_row(method="GET")])
        found = _anon_findings(inv)
        assert len(found) == 1
        assert found[0]["confidence"] == "HYPOTHESIS"

    def test_confirmed_finding_validates_through_projection(self, monkeypatch) -> None:
        """The projected dict must survive the default-on fact-fidelity gate
        (CONFIRMED requires asserted_values) exactly as verify_finding,
        judge_findings and correlate_findings will validate it. The suite
        conftest relaxes the gate; restore the production default here."""
        monkeypatch.setenv("FIND_EVIL_REQUIRE_ASSERTED_VALUES", "1")
        inv = _emit([_row()])
        projected = fea.finding_for_verifier(_anon_findings(inv)[0])
        model = Finding.model_validate(projected)
        assert model.confidence == "CONFIRMED"
        assert model.asserted_values

    def test_counter_hypothesis_survives_projection_for_optin_gate(self, monkeypatch) -> None:
        """FIND_EVIL_REQUIRE_COUNTER_HYPOTHESIS_FINDING=1 rejects a CONFIRMED
        finding whose counter_hypothesis was stripped: the field is a canonical
        Finding model field (events.py) and must be in _FINDING_MODEL_FIELDS."""
        inv = _emit([_row()])
        projected = fea.finding_for_verifier(_anon_findings(inv)[0])
        monkeypatch.setenv("FIND_EVIL_REQUIRE_COUNTER_HYPOTHESIS_FINDING", "1")
        model = Finding.model_validate(projected)  # raises if stripped
        assert (model.counter_hypothesis or "").strip()


class TestEntailmentReplay:
    """The asserted_values must actually resolve through check_entailment
    against the replayed pcap_triage output — flagged as unverified before."""

    def _asserted(self, finding) -> list[AssertedValue]:
        return [AssertedValue.model_validate(av) for av in finding["asserted_values"]]

    def test_asserted_values_entail_against_replayed_output(self) -> None:
        rows = [
            _row(),
            _row(host="www.google.com", method="GET", uri="/search", count=9),
        ]
        inv = _emit(rows)
        finding = _anon_findings(inv)[0]
        result = check_entailment(self._asserted(finding), _pcap_triage_output(rows))
        assert result.passed, result.reason

    def test_asserted_values_reject_a_misread(self) -> None:
        """Same host present but only as a GET: the POST claim must NOT entail —
        proving the assertions bind method+host+src in one record instead of
        passing vacuously."""
        inv = _emit([_row()])
        finding = _anon_findings(inv)[0]
        get_only = [_row(method="GET")]
        result = check_entailment(self._asserted(finding), _pcap_triage_output(get_only))
        assert not result.passed

    def test_asserted_values_reject_wrong_source_host(self) -> None:
        inv = _emit([_row()])
        finding = _anon_findings(inv)[0]
        other_src = [_row(src="192.168.1.99")]
        result = check_entailment(self._asserted(finding), _pcap_triage_output(other_src))
        assert not result.passed


class TestFalsePositiveFloor:
    def test_benign_hosts_emit_no_anon_finding(self) -> None:
        """synthetic-benign guard: POSTs to non-curated hosts never fire."""
        inv = _emit(
            [
                _row(host="www.google.com", method="POST", uri="/upload"),
                _row(host="example.com", method="GET", uri="/"),
            ]
        )
        assert _anon_findings(inv) == []
        assert not [f for f in inv.findings_pool_b if f.get("confidence") == "CONFIRMED"]

    def test_lookalike_token_in_uri_does_not_fire(self) -> None:
        """synthetic-decoy guard: the curated token appearing in the URI (a
        lookalike mention) is not a contact with the service."""
        inv = _emit([_row(host="www.google.com", uri="/search?q=willselfdestruct", method="POST")])
        assert _anon_findings(inv) == []

    def test_alihadi_09_shape_stays_indeterminate(self) -> None:
        """alihadi-09-encrypt FP control: leads-only merged sets must not
        escalate — no general 'N INFERRED => EVIL' rule."""
        inv = fea.Investigation("Security.evtx", unattended=True, with_report=False)
        inv.handle = {"id": "case-ae"}
        inv.tool_calls = [{"tool": "evtx_query", "tool_call_id": "tc-evtx"}]
        merged = [
            {"confidence": "INFERRED", "mitre_technique": "T1027"},
            {"confidence": "INFERRED", "mitre_technique": None},
            {"confidence": "HYPOTHESIS", "mitre_technique": None},
        ]
        assert inv.compute_verdict(merged) == "INDETERMINATE"

    def test_empty_substantive_network_run_still_no_evil(self) -> None:
        inv = fea.Investigation("clean.pcap", unattended=True, with_report=False)
        inv.handle = {"id": "case-clean"}
        inv.tool_calls = [{"tool": "pcap_triage", "tool_call_id": "tc-pcap"}]
        assert inv.compute_verdict([]) == "NO_EVIL"

    def test_confirmed_anon_post_reaches_suspicious_verdict(self) -> None:
        """The polarity fix itself: a CONFIRMED finding in merged flips the
        verdict out of INDETERMINATE (SUSPICIOUS is verdict-consistent with the
        golden's CONFIRMED_EVIL per accuracy.py's evil-word vocabulary)."""
        inv = _emit([_row()])
        inv.tool_calls = [{"tool": "pcap_triage", "tool_call_id": TCID}]
        merged = list(inv.findings_pool_b)
        assert inv.compute_verdict(merged) == "SUSPICIOUS"
