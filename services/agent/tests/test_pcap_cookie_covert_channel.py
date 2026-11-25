"""A base64 archive carried inside an HTTP cookie is a covert channel the
engine used to be blind to (ENGINE-POLICY).

``pcap_triage`` recorded cookies as a bare ``has_cookie`` boolean, so a request
whose cookie value *is* a ZIP archive read as "authenticated session". This
suite pins the detector that reads the cookie VALUE: base64 that decodes to a
recognizable archive/container magic, sent to a destination IP that answers to
many unrelated ``Host:`` headers (Host-header multiplexing — the destination is
not the site the header names).

Confidence tier: the archive-in-cookie finding is born CONFIRMED. Per the
project's confidence hierarchy, CONFIRMED is "backed by a tool_call_id, a raw
output excerpt, and asserted_values the verifier re-extracts". The decoded
container magic and its member path come out of bytes that are literally in the
cited ``pcap_triage`` output, and the assertions bind cookie value + Host +
destination inside ONE replayed record — the same tier-1 argument the
anon-email POST finding already makes.

Exfiltration two-prong gate: the CONFIRMED finding deliberately does NOT use
the gate's trip tokens ("exfil", "outbound", "uploaded", "stolen",
"data theft", "staging directory"). ``EXFIL_PRESENCE_CLASSES`` excludes
network by design — network is the EGRESS class, so admitting it as presence
would let any single network finding self-satisfy both prongs and collapse the
gate for every case. Here presence and egress genuinely come from one artifact
class (the capture), which is exactly what the gate is built to distrust, so we
keep the gate intact and state the single-class limitation in the finding text
instead of routing around it.

Blast-radius guards in this file:

* A cookie that is not base64, too short, or decodes to non-archive bytes never
  fires (synthetic-benign / synthetic-decoy FP floor).
* An archive cookie to a destination serving ONE domain never fires (a
  legitimate upload endpoint is not a relay).
* Host multiplexing WITHOUT an archive payload never fires — measured: the
  nitroba capture has a destination serving 5 distinct registrable domains
  (a CDN) and zero archive cookies, so the archive prong is what keeps that
  case clean.
* The alihadi-09-encrypt shape (leads only) still computes INDETERMINATE.
"""

from __future__ import annotations

import base64
import sys
from pathlib import Path
from typing import ClassVar

from findevil_agent.entailment import check_entailment
from findevil_agent.events import AssertedValue, Finding

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402

TCID = "tc-pcap-1"
PCAP = "/evidence/suspect.pcap"

# The first 104 base64 characters of the real ``CVal`` cookie observed in a
# public DFRWS forensic-challenge Linux capture (suspect.pcap, sha1
# 8cda581bec7c87fcade87553c5e99226f4ea87dd), read with
# ``tshark -Y http.cookie -e http.cookie``. Decodes to PK\x03\x04 with member
# path ``mnt/hgfs/Admin_share/acct_prem.xls``. Real bytes, not a fabrication.
REAL_ZIP_COOKIE = (
    "UEsDBBQAAQAIAGZCiDcowcjvfjYAAAAqAgAiABUAbW50L2hnZnMv"
    "QWRtaW5fc2hhcmUvYWNjdF9wcmVtLnhsc1VUCQADz5laR6JBZUdV"
)
RELAY_IP = "219.93.175.67"
VICTIM = "192.168.151.130"

# Enough unrelated registrable domains on one IP to read as Host multiplexing.
SPOOFED_HOSTS = (
    "youtube.com",
    "www.google.com",
    "www.yahoo.com",
    "www.myspace.com",
    "www.facebook.com",
    "en.wikipedia.org",
)


def _cookie(name: str = "CVal", value: str = REAL_ZIP_COOKIE) -> dict[str, object]:
    return {"name": name, "value": value, "truncated": False}


def _row(**overrides):
    """One ``http_requests`` row in the exact ``PcapHttpRequest`` shape
    (services/mcp/src/tools/pcap_triage.rs): src, dst, host, method, uri,
    has_cookie, cookies, count, first_ts, last_ts."""
    row = {
        "src": VICTIM,
        "dst": RELAY_IP,
        "host": "youtube.com",
        "method": "GET",
        "uri": "http://youtube.com/",
        "has_cookie": True,
        "cookies": [_cookie()],
        "count": 1,
        "first_ts": "1197862336.409",
        "last_ts": "1197862336.409",
    }
    row.update(overrides)
    return row


def _multiplexed_rows(payload_row: dict | None = None) -> list[dict]:
    """One archive-carrying request plus enough plain requests to the SAME IP
    under different Host headers to establish the multiplexing."""
    rows = [payload_row if payload_row is not None else _row()]
    for host in SPOOFED_HOSTS[1:]:
        rows.append(
            _row(
                host=host,
                uri=f"http://{host}/",
                has_cookie=False,
                cookies=[],
            )
        )
    return rows


def _pcap_triage_output(rows):
    """A replayed ``parsed_output`` in the full ``PcapTriageOutput`` shape."""
    return {
        "analyzer": "tshark",
        "packets_seen": 42424,
        "conversations": [],
        "dns_queries": [],
        "http_hosts": [],
        "http_requests": rows,
        "zeek": None,
    }


def _emit(rows):
    inv = fea.Investigation("suspect.pcap", unattended=True, with_report=False)
    inv.handle = {"id": "case-pcap-cookie-test"}
    inv._add_pcap_http_request_findings(_pcap_triage_output(rows), TCID, PCAP)
    return inv


def _by_kind(inv, token: str) -> list[dict]:
    return [
        f
        for f in [*inv.findings_pool_a, *inv.findings_pool_b]
        if token in str(f.get("finding_id") or "")
    ]


class TestCookiePayloadDecoder:
    """The pure decoder: does this base64 cookie value carry a container?"""

    def test_real_zip_cookie_decodes_to_zip_with_member_path(self) -> None:
        hit = fea.cookie_payload_archive(REAL_ZIP_COOKIE)
        assert hit is not None
        container, member = hit
        assert "zip" in container.lower()
        assert member == "mnt/hgfs/Admin_share/acct_prem.xls"

    def test_gzip_payload_is_recognized(self) -> None:
        blob = base64.b64encode(b"\x1f\x8b\x08\x00" + b"\x00" * 64).decode()
        hit = fea.cookie_payload_archive(blob)
        assert hit is not None
        assert "gzip" in hit[0].lower()

    def test_ordinary_session_cookie_is_not_an_archive(self) -> None:
        # Real session-id shapes seen in the same capture.
        for value in (
            "CA1344E4C4D800FC",
            "T000V00000X501241470490271233044007956",
            "97c1cf19-761-1197186535-2",
            "",
        ):
            assert fea.cookie_payload_archive(value) is None

    def test_short_base64_is_rejected(self) -> None:
        """A handful of base64 characters can hit a 3-4 byte magic by chance;
        the floor keeps random session ids out."""
        assert fea.cookie_payload_archive(base64.b64encode(b"PK\x03\x04ab").decode()) is None

    def test_non_base64_alphabet_is_rejected(self) -> None:
        assert fea.cookie_payload_archive("PK\x03\x04" + "x" * 64) is None

    def test_truncated_prefix_still_decodes(self) -> None:
        """The tool caps cookie values, so the decoder must cope with a prefix
        whose length is not a multiple of 4."""
        assert fea.cookie_payload_archive(REAL_ZIP_COOKIE[:-3]) is not None


class TestHostMultiplexing:
    def test_one_ip_many_unrelated_domains_is_multiplexed(self) -> None:
        mux = fea.host_multiplexed_destinations(_multiplexed_rows())
        assert RELAY_IP in mux
        assert len(mux[RELAY_IP]) >= fea.HOST_MULTIPLEX_MIN_DOMAINS

    def test_subdomains_of_one_site_are_not_multiplexing(self) -> None:
        rows = [
            _row(host=h, has_cookie=False, cookies=[])
            for h in (
                "www.travelocity.com",
                "dm.travelocity.com",
                "leisure.travelocity.com",
                "i.travelocity.com",
                "svc.travelocity.com",
                "photos.travelocity.com",
            )
        ]
        assert fea.host_multiplexed_destinations(rows) == {}


class TestCovertChannelFindings:
    def test_archive_cookie_to_multiplexed_host_is_confirmed(self) -> None:
        inv = _emit(_multiplexed_rows())
        found = _by_kind(inv, "cookie-archive")
        assert len(found) == 1, [f["finding_id"] for f in found]
        f = found[0]
        assert f["confidence"] == "CONFIRMED"
        assert f["tool_call_id"] == TCID
        assert f["mitre_technique"] == "T1041"
        assert f.get("asserted_values")
        assert str(f.get("counter_hypothesis") or "").strip()

    def test_confirmed_finding_does_not_trip_the_exfil_two_prong_gate(self) -> None:
        """A network-only finding cannot clear presence+egress; the wording must
        therefore not make an exfiltration CLAIM. See module docstring."""
        inv = _emit(_multiplexed_rows())
        f = _by_kind(inv, "cookie-archive")[0]
        assert not fea._claims_exfiltration(f), f["description"]

    def test_no_finding_claims_execution(self) -> None:
        inv = _emit(_multiplexed_rows())
        for f in _by_kind(inv, "pcap-"):
            assert not fea._claims_execution(f), f["finding_id"]

    def test_relay_finding_names_the_proxy_behaviour(self) -> None:
        inv = _emit(_multiplexed_rows())
        found = _by_kind(inv, "host-spoof-relay")
        assert len(found) == 1
        assert found[0]["mitre_technique"] == "T1090"
        assert found[0]["confidence"] == "INFERRED"
        assert str(found[0].get("counter_hypothesis") or "").strip()

    def test_admin_share_member_path_raises_a_valid_accounts_lead(self) -> None:
        inv = _emit(_multiplexed_rows())
        found = _by_kind(inv, "archive-share-source")
        assert len(found) == 1
        assert found[0]["mitre_technique"] == "T1078"
        assert found[0]["confidence"] == "INFERRED"

    def test_member_path_without_a_share_segment_raises_no_share_lead(self) -> None:
        """Generalization guard: the valid-accounts lead keys on an
        administrative-share path shape, not on any one member name."""
        payload = base64.b64encode(
            b"PK\x03\x04" + b"\x00" * 22 + b"\x09\x00\x00\x00" + b"notes.txt" + b"\x00" * 40
        ).decode()
        inv = _emit(_multiplexed_rows(_row(cookies=[_cookie(value=payload)])))
        assert _by_kind(inv, "cookie-archive"), "the channel finding must still fire"
        assert _by_kind(inv, "archive-share-source") == []

    def test_descriptions_quote_only_parsed_values(self) -> None:
        inv = _emit(_multiplexed_rows())
        for f in _by_kind(inv, "pcap-"):
            desc = f["description"]
            assert RELAY_IP in desc or VICTIM in desc


class TestAccountAttributionOnASpoofedDestination:
    """A `Host:` header that provably lies cannot attribute an account.

    Measured on the real capture: `mail.yahoo.com` and `www.facebook.com` are
    both Host headers on requests that went to the relay address, so the
    pre-existing webmail/social detectors were reporting "authenticated session
    to Yahoo/Facebook" for traffic that never reached either site.
    """

    # An ordinary-looking session cookie, so ONLY the spoofed-destination rule
    # can suppress the attribution (not the archive-payload rule).
    SESSION: ClassVar[list[dict[str, object]]] = [
        {"name": "SID", "value": "T000V00000X50124147", "truncated": False}
    ]

    def test_webmail_attribution_is_withheld_on_a_multiplexed_destination(self) -> None:
        rows = _multiplexed_rows()
        rows.append(_row(host="mail.yahoo.com", uri="http://mail.yahoo.com/", cookies=self.SESSION))
        inv = _emit(rows)
        assert _by_kind(inv, "pcap-webmail") == []

    def test_social_attribution_is_withheld_on_a_multiplexed_destination(self) -> None:
        rows = _multiplexed_rows()
        rows.append(
            _row(host="www.facebook.com", uri="http://www.facebook.com/", cookies=self.SESSION)
        )
        inv = _emit(rows)
        assert _by_kind(inv, "pcap-social") == []

    def test_webmail_attribution_still_fires_on_an_ordinary_destination(self) -> None:
        """Guard against over-suppression: the nitroba webmail/social recall must
        not depend on the absence of a relay elsewhere in the capture."""
        rows = _multiplexed_rows()
        rows.append(
            _row(
                host="mail.google.com",
                uri="http://mail.google.com/",
                dst="66.102.7.99",
                cookies=self.SESSION,
            )
        )
        inv = _emit(rows)
        assert len(_by_kind(inv, "pcap-webmail")) == 1


class TestEntailmentReplay:
    def _asserted(self, finding) -> list[AssertedValue]:
        return [AssertedValue.model_validate(av) for av in finding["asserted_values"]]

    def test_asserted_values_entail_against_replayed_output(self) -> None:
        rows = _multiplexed_rows()
        inv = _emit(rows)
        finding = _by_kind(inv, "cookie-archive")[0]
        result = check_entailment(self._asserted(finding), _pcap_triage_output(rows))
        assert result.passed, result.reason

    def test_asserted_values_reject_a_different_destination(self) -> None:
        inv = _emit(_multiplexed_rows())
        finding = _by_kind(inv, "cookie-archive")[0]
        moved = [dict(r, dst="203.0.113.9") for r in _multiplexed_rows()]
        result = check_entailment(self._asserted(finding), _pcap_triage_output(moved))
        assert not result.passed

    def test_asserted_values_reject_a_payload_relocated_to_another_row(self) -> None:
        """The record assertion must co-locate the payload with the destination:
        the same cookie carried by a DIFFERENT request in the capture cannot
        satisfy a claim about this one."""
        inv = _emit(_multiplexed_rows())
        finding = _by_kind(inv, "cookie-archive")[0]
        moved = _multiplexed_rows()
        moved[0] = dict(moved[0], cookies=[], has_cookie=False)
        moved.append(_row(host="ads.example.net", dst="198.51.100.7"))
        result = check_entailment(self._asserted(finding), _pcap_triage_output(moved))
        assert not result.passed

    def test_asserted_values_reject_a_stripped_cookie_value(self) -> None:
        """The payload claim must not pass vacuously off host/dst alone."""
        inv = _emit(_multiplexed_rows())
        finding = _by_kind(inv, "cookie-archive")[0]
        stripped = [dict(r, cookies=[], has_cookie=False) for r in _multiplexed_rows()]
        result = check_entailment(self._asserted(finding), _pcap_triage_output(stripped))
        assert not result.passed

    def test_confirmed_finding_validates_through_projection(self, monkeypatch) -> None:
        monkeypatch.setenv("FIND_EVIL_REQUIRE_ASSERTED_VALUES", "1")
        inv = _emit(_multiplexed_rows())
        projected = fea.finding_for_verifier(_by_kind(inv, "cookie-archive")[0])
        model = Finding.model_validate(projected)
        assert model.confidence == "CONFIRMED"
        assert model.asserted_values


class TestFalsePositiveFloor:
    def test_benign_session_cookies_emit_nothing(self) -> None:
        rows = [
            _row(
                host=h,
                uri=f"http://{h}/",
                dst="151.193.224.81",
                cookies=[_cookie(name="SID", value="T000V00000X50124147049027123304")],
            )
            for h in ("www.travelocity.com", "leisure.travelocity.com", "i.travelocity.com")
        ]
        inv = _emit(rows)
        assert _by_kind(inv, "cookie-archive") == []
        assert _by_kind(inv, "host-spoof-relay") == []

    def test_host_multiplexing_without_an_archive_emits_nothing(self) -> None:
        """Measured nitroba shape: a CDN address serving several registrable
        domains, no archive cookie anywhere. Must stay silent."""
        rows = [
            _row(host=h, uri=f"http://{h}/", has_cookie=False, cookies=[]) for h in SPOOFED_HOSTS
        ]
        inv = _emit(rows)
        assert _by_kind(inv, "pcap-cookie-archive") == []
        assert _by_kind(inv, "host-spoof-relay") == []
        assert not [
            f
            for f in inv.findings_pool_a + inv.findings_pool_b
            if f.get("confidence") == "CONFIRMED"
        ]

    def test_archive_cookie_to_a_single_domain_destination_emits_nothing(self) -> None:
        """An encoded archive posted to one site's own upload endpoint is not a
        covert relay channel."""
        inv = _emit([_row(host="files.example.com", uri="/upload")])
        assert _by_kind(inv, "cookie-archive") == []

    def test_alihadi_09_shape_stays_indeterminate(self) -> None:
        inv = fea.Investigation("Security.evtx", unattended=True, with_report=False)
        inv.handle = {"id": "case-ae"}
        inv.tool_calls = [{"tool": "evtx_query", "tool_call_id": "tc-evtx"}]
        merged = [
            {"confidence": "INFERRED", "mitre_technique": "T1027"},
            {"confidence": "INFERRED", "mitre_technique": None},
            {"confidence": "HYPOTHESIS", "mitre_technique": None},
        ]
        assert inv.compute_verdict(merged) == "INDETERMINATE"


class TestVerdictPolarity:
    def test_confirmed_cookie_archive_reaches_suspicious(self) -> None:
        inv = _emit(_multiplexed_rows())
        inv.tool_calls = [{"tool": "pcap_triage", "tool_call_id": TCID}]
        merged = [*inv.findings_pool_a, *inv.findings_pool_b]
        assert inv.compute_verdict(merged) == "SUSPICIOUS"
