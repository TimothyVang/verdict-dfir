"""Web-tier lane — server request logs and web-root scripts carved off a disk.

Before this lane the engine had no artifact class for the web tier at all:
`disk_extract_artifacts` classified MFT / registry / evtx / lnk plus a generic
`yara_target` sweep over `users/`, `programdata/`, `windows/temp/`, so an
Apache `access.log` and a webshell dropped in `htdocs` were never extracted and
never parsed. These tests pin the classification, the two detectors, and the
findings they emit.

Fixtures are shaped exactly like the Rust `web_triage` serialized output, and
the request/script payloads are verbatim lines recovered from a real image
(`icat` of `xampp/apache/logs/access.log` and of the two `phpshell*.php` files
in `xampp/htdocs/DVWA/hackable/uploads`) — not invented strings.
"""

from __future__ import annotations

import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402

from findevil_agent.entailment import check_entailment  # noqa: E402
from findevil_agent.events import AssertedValue  # noqa: E402


def _avs(finding: dict) -> list[AssertedValue]:
    return [AssertedValue(**av) for av in finding.get("asserted_values", [])]


# --------------------------------------------------------------------------
# Raw `web_triage` outputs (mirror the Rust struct field-for-field)
# --------------------------------------------------------------------------

ACCESS_LOG_PATH = "/case/extracted/disk/x/xampp/apache/logs/access.log"
SHELL_PATH = "/case/extracted/disk/x/xampp/htdocs/DVWA/hackable/uploads/phpshell.php"
APP_SCRIPT_PATH = "/case/extracted/disk/x/xampp/htdocs/DVWA/vulnerabilities/exec/source/low.php"


def _access_log_output() -> dict:
    return {
        "artifact_path": ACCESS_LOG_PATH,
        "artifact_kind": "access_log",
        "lines_seen": 7716,
        "requests_parsed": 7716,
        "parse_errors": 0,
        "truncated": False,
        "exploit_hits": [
            {
                "line_number": 3974,
                "timestamp": "02/Sep/2015:03:49:53 -0700",
                "timestamp_iso": "2015-09-02T10:49:53Z",
                "client_ip": "192.168.56.102",
                "method": "GET",
                "target": "/dvwa/vulnerabilities/sqli/?id=a%27+or+1%3D1&Submit=Submit",
                "status": "200",
                "user_agent": "Mozilla/5.0 (X11; Linux x86_64; rv:38.0) Iceweasel/38.2.0",
                "indicators": ["encoded_quote", "sqli_boolean_tautology"],
            },
            {
                "line_number": 3983,
                "timestamp": "02/Sep/2015:04:05:00 -0700",
                "timestamp_iso": "2015-09-02T11:05:00Z",
                "client_ip": "192.168.56.102",
                "method": "GET",
                "target": (
                    "/dvwa/vulnerabilities/sqli/?id=abc%27+and+0%3D0+union+select+"
                    "table_name%2C+null+from+information_schema.tables+--+&Submit=Submit"
                ),
                "status": "200",
                "user_agent": "Mozilla/5.0 (X11; Linux x86_64; rv:38.0) Iceweasel/38.2.0",
                "indicators": [
                    "encoded_quote",
                    "sql_comment_terminator",
                    "sqli_information_schema",
                    "sqli_union_select",
                ],
            },
            {
                "line_number": 3990,
                "timestamp": "02/Sep/2015:04:15:40 -0700",
                "timestamp_iso": "2015-09-02T11:15:40Z",
                "client_ip": "192.168.56.102",
                "method": "GET",
                "target": "/dvwa/vulnerabilities/sqli/?id=2&Submit=Submit",
                "status": "302",
                "user_agent": "sqlmap/1.0-dev-nongit-20150902 (http://sqlmap.org)",
                "indicators": ["scanner_user_agent"],
            },
        ],
        "exploit_hit_count": 3,
        "indicator_counts": [
            {"indicator": "encoded_quote", "count": 2},
            {"indicator": "sql_comment_terminator", "count": 1},
            {"indicator": "sqli_boolean_tautology", "count": 1},
            {"indicator": "sqli_information_schema", "count": 1},
            {"indicator": "sqli_union_select", "count": 1},
            {"indicator": "scanner_user_agent", "count": 1},
        ],
        "attacker_clients": [{"client_ip": "192.168.56.102", "count": 3}],
        "script_hits": [],
        "script_indicator_counts": [],
        "is_probable_webshell": False,
    }


def _weak_only_output() -> dict:
    """A quote in a parameter and nothing else — not an exploitation claim."""
    out = _access_log_output()
    out["exploit_hits"] = [
        {
            "line_number": 12,
            "timestamp": "02/Sep/2015:01:00:00 -0700",
            "timestamp_iso": "2015-09-02T08:00:00Z",
            "client_ip": "10.0.0.4",
            "method": "GET",
            "target": "/search?q=o%27brien",
            "status": "200",
            "user_agent": "Mozilla/5.0",
            "indicators": ["encoded_quote"],
        }
    ]
    out["exploit_hit_count"] = 1
    out["indicator_counts"] = [{"indicator": "encoded_quote", "count": 1}]
    out["attacker_clients"] = [{"client_ip": "10.0.0.4", "count": 1}]
    return out


def _webshell_output(path: str = SHELL_PATH) -> dict:
    return {
        "artifact_path": path,
        "artifact_kind": "webroot_script",
        "lines_seen": 4,
        "requests_parsed": 0,
        "parse_errors": 0,
        "truncated": False,
        "exploit_hits": [],
        "exploit_hit_count": 0,
        "indicator_counts": [],
        "attacker_clients": [],
        "script_hits": [
            {
                "line_number": 2,
                "indicator": "php_command_exec",
                "snippet": 'system($_GET["cmd"]);',
            },
            {
                "line_number": 2,
                "indicator": "request_driven_exec",
                "snippet": 'system($_GET["cmd"]);',
            },
        ],
        "script_indicator_counts": [
            {"indicator": "php_command_exec", "count": 1},
            {"indicator": "request_driven_exec", "count": 1},
        ],
        "is_probable_webshell": True,
    }


# --------------------------------------------------------------------------
# Classification / routing
# --------------------------------------------------------------------------


class TestWebTierClassification:
    def test_web_tier_classes_are_declared(self) -> None:
        assert {"web_log", "webroot_script"} == fea.WEB_TIER_CLASSES

    def test_access_log_classifies_as_web_log(self) -> None:
        c = fea.classify_artifact_path("C:/xampp/apache/logs/access.log")
        assert c["artifact_class"] == "web_log"
        assert c["parser_tool"] == "web_triage"
        assert c["evidence_type"] == "extracted_disk"

    def test_iis_w3c_log_classifies_as_web_log(self) -> None:
        c = fea.classify_artifact_path("inetpub/logs/LogFiles/W3SVC1/u_ex150902.log")
        assert c["artifact_class"] == "web_log"

    def test_webroot_script_classifies_as_webroot_script(self) -> None:
        c = fea.classify_artifact_path("xampp/htdocs/DVWA/hackable/uploads/phpshell.php")
        assert c["artifact_class"] == "webroot_script"
        assert c["parser_tool"] == "web_triage"

    def test_script_outside_a_web_root_is_not_a_webroot_script(self) -> None:
        c = fea.classify_artifact_path("tools/deploy/build.php")
        assert c["artifact_class"] != "webroot_script"

    def test_disk_summary_template_counts_web_tier_classes(self) -> None:
        counts = fea._disk_summary_template()["artifact_counts"]
        assert "web_log" in counts
        assert "webroot_script" in counts

    def test_web_tier_classes_are_supported_for_extraction(self) -> None:
        assert fea.WEB_TIER_CLASSES <= fea.VELOCIRAPTOR_ZIP_EXTRACT_CLASSES


# --------------------------------------------------------------------------
# Detector: web access log exploitation
# --------------------------------------------------------------------------


class TestWebExploitCandidates:
    def test_structural_sqli_indicators_are_candidates(self) -> None:
        cands = fea.web_exploit_candidates(_access_log_output())
        assert cands, "union select / information_schema requests must be candidates"
        techniques = {c["indicator"] for c in cands}
        assert "sqli_union_select" in techniques
        assert "sqli_information_schema" in techniques

    def test_candidates_carry_the_client_ip_and_line_number(self) -> None:
        cands = fea.web_exploit_candidates(_access_log_output())
        assert {c["client_ip"] for c in cands} == {"192.168.56.102"}
        assert all(isinstance(c["line_number"], int) for c in cands)

    def test_an_encoded_quote_alone_is_not_a_candidate(self) -> None:
        assert fea.web_exploit_candidates(_weak_only_output()) == []

    def test_scanner_user_agent_alone_is_a_candidate(self) -> None:
        out = _weak_only_output()
        out["exploit_hits"][0]["indicators"] = ["scanner_user_agent"]
        out["indicator_counts"] = [{"indicator": "scanner_user_agent", "count": 1}]
        assert fea.web_exploit_candidates(out) != []

    def test_a_script_output_yields_no_request_candidates(self) -> None:
        assert fea.web_exploit_candidates(_webshell_output()) == []


# --------------------------------------------------------------------------
# Detector: web-root script webshell heuristic
# --------------------------------------------------------------------------


class TestWebshellCandidates:
    def test_probable_webshell_in_a_writable_upload_dir_is_a_candidate(self) -> None:
        cand = fea.webshell_script_candidate(_webshell_output())
        assert cand is not None
        assert cand["writable_location"] is True
        assert "php_command_exec" in cand["indicators"]

    def test_probable_webshell_in_the_shipped_app_tree_is_not_writable_located(
        self,
    ) -> None:
        cand = fea.webshell_script_candidate(_webshell_output(APP_SCRIPT_PATH))
        assert cand is not None
        assert cand["writable_location"] is False

    def test_a_script_without_the_pattern_is_not_a_candidate(self) -> None:
        out = _webshell_output()
        out["is_probable_webshell"] = False
        assert fea.webshell_script_candidate(out) is None

    def test_an_access_log_output_is_not_a_webshell_candidate(self) -> None:
        assert fea.webshell_script_candidate(_access_log_output()) is None


# --------------------------------------------------------------------------
# Emitters
# --------------------------------------------------------------------------


class _Inv:
    """Minimal orchestrator stand-in — the emitters only touch these fields."""

    @staticmethod
    def build() -> fea.Investigation:
        inv = object.__new__(fea.Investigation)
        inv.handle = {"id": "case-web"}
        inv.findings_pool_a = []
        inv.findings_pool_b = []
        inv._finding_id_seen = {}
        inv.evidence_inventory = None
        return inv


class TestWebExploitFinding:
    def _finding(self) -> dict:
        inv = _Inv.build()
        inv._emit_web_exploit_finding(
            fea.web_exploit_candidates(_access_log_output()),
            _access_log_output(),
            ACCESS_LOG_PATH,
            "tc-web-1",
        )
        assert len(inv.findings_pool_a) == 1
        return inv.findings_pool_a[0]

    def test_confirmed_t1190_finding_is_emitted(self) -> None:
        f = self._finding()
        assert f["confidence"] == "CONFIRMED"
        assert f["mitre_technique"] == "T1190"
        assert f["tool_call_id"] == "tc-web-1"
        assert f["artifact_path"] == ACCESS_LOG_PATH

    def test_description_names_the_observed_behaviour_and_source(self) -> None:
        desc = self._finding()["description"].lower()
        # What the tool actually saw, in the analyst's vocabulary.
        for token in ("sql", "injection", "web", "access", "log", "192.168.56.102"):
            assert token in desc, token
        # The record is a request log: it shows the attempt, not its outcome.
        assert "attempt" in desc

    def test_asserted_values_resolve_against_the_raw_web_triage_output(self) -> None:
        f = self._finding()
        assert f.get("asserted_values")
        result = check_entailment(_avs(f), _access_log_output())
        assert result.passed, result.reason

    def test_entailment_rejects_a_misread_when_the_payload_is_absent(self) -> None:
        f = self._finding()
        clean = _weak_only_output()
        assert not check_entailment(_avs(f), clean).passed

    def test_no_finding_when_only_weak_indicators_fired(self) -> None:
        inv = _Inv.build()
        out = _weak_only_output()
        inv._emit_web_exploit_finding(
            fea.web_exploit_candidates(out), out, ACCESS_LOG_PATH, "tc-web-2"
        )
        assert inv.findings_pool_a == []


class TestWebshellFinding:
    def _finding(self, path: str = SHELL_PATH, mft: dict | None = None) -> dict | None:
        inv = _Inv.build()
        out = _webshell_output(path)
        inv._emit_webshell_finding(fea.webshell_script_candidate(out), out, "tc-web-3", mft or {})
        return inv.findings_pool_a[0] if inv.findings_pool_a else None

    def test_confirmed_t1505_003_finding_for_a_shell_in_an_upload_dir(self) -> None:
        f = self._finding()
        assert f is not None
        assert f["confidence"] == "CONFIRMED"
        assert f["mitre_technique"] == "T1505.003"

    def test_shipped_app_source_is_only_inferred(self) -> None:
        f = self._finding(APP_SCRIPT_PATH)
        assert f is not None
        assert f["confidence"] == "INFERRED"

    def test_description_names_the_webshell_the_web_root_and_the_primitive(
        self,
    ) -> None:
        desc = self._finding()["description"].lower()
        for token in ("webshell", "script", "web", "root", "htdocs", "written"):
            assert token in desc, token

    def test_mft_creation_time_is_cited_and_lands_in_derived_from(self) -> None:
        mft = {
            "xampp/htdocs/dvwa/hackable/uploads/phpshell.php": {
                "created": "2015-09-02T04:22:11Z",
                "tool_call_id": "tc-mft-1",
            }
        }
        f = self._finding(mft=mft)
        assert "2015-09-02T04:22:11Z" in f["description"]
        assert "mft" in f["description"].lower()
        assert "tc-mft-1" in f["derived_from"]

    def test_asserted_values_resolve_against_the_raw_web_triage_output(self) -> None:
        f = self._finding()
        assert f.get("asserted_values")
        result = check_entailment(_avs(f), _webshell_output())
        assert result.passed, result.reason

    def test_no_finding_without_a_candidate(self) -> None:
        assert self._finding.__self__ is not None  # sanity: bound method
        inv = _Inv.build()
        inv._emit_webshell_finding(None, _webshell_output(), "tc-web-4", {})
        assert inv.findings_pool_a == []


# --------------------------------------------------------------------------
# EVTX interactive-logon widening
# --------------------------------------------------------------------------


def _logon_row(record_id: int, logon_type: str, ip: str, eid: int = 4624) -> dict:
    return {
        "event_id": eid,
        "ts": "2015-09-02T10:18:07Z",
        "channel": "Security",
        "record_id": record_id,
        "data": {
            "Event": {
                "System": {"EventID": eid, "Computer": "WIN-L0ZZQ76PMUF"},
                "EventData": {
                    "TargetUserName": "Administrator",
                    "TargetDomainName": "WIN-L0ZZQ76PMUF",
                    "LogonType": logon_type,
                    "IpAddress": ip,
                    "LogonProcessName": "User32 ",
                    "ProcessName": "C:\\Windows\\System32\\winlogon.exe",
                },
            }
        },
    }


class TestInteractiveLogonWidening:
    """The old rule fired only on EID 4624 LogonType 10 (RemoteInteractive).

    This intrusion has no Type 10 record and no TerminalServices channel at all
    (verified against the image: 636 Security.evtx records, logon types 0/2/3/5/7
    only) — its interactive sessions are Type 2 console and Type 7 unlock. The
    widened rule covers the whole interactive family, but it is NOT
    unconditional: a console logon happens on every healthy Windows host, so an
    unconditional lead would be noise on a clean machine. It fires only when the
    SAME account also shows failed logons in the same log — a successful
    interactive session for an account that was also being guessed at.
    """

    def test_type_10_still_emits_the_rdp_lead(self) -> None:
        findings = fea.evtx_rows_to_findings(
            [_logon_row(1, "10", "10.0.0.9")], "tc-evtx-1", "case-web", "/e/Security.evtx"
        )
        ids = {f["finding_id"] for f in findings}
        assert "f-B-evtx-rdp-logon" in ids

    def test_type_2_and_7_logons_after_failed_attempts_are_surfaced(self) -> None:
        rows = [
            _logon_row(100, "2", "127.0.0.1", eid=4625),
            _logon_row(481, "2", "127.0.0.1"),
            _logon_row(492, "7", "127.0.0.1"),
        ]
        findings = fea.evtx_rows_to_findings(rows, "tc-evtx-1", "case-web", "/e/Security.evtx")
        interactive = [f for f in findings if f["finding_id"] == "f-B-evtx-interactive-logon"]
        assert len(interactive) == 1, [f["finding_id"] for f in findings]
        desc = interactive[0]["description"]
        for token in ("4624", "Security", "Administrator", "127.0.0.1"):
            assert token in desc, token
        assert "interactive logon" in desc.lower()

    def test_the_interactive_lead_does_not_assert_rdp(self) -> None:
        rows = [
            _logon_row(100, "2", "127.0.0.1", eid=4625),
            _logon_row(481, "2", "127.0.0.1"),
        ]
        findings = fea.evtx_rows_to_findings(rows, "tc-evtx-1", "case-web", "/e/Security.evtx")
        lead = next(f for f in findings if f["finding_id"] == "f-B-evtx-interactive-logon")
        # No Type 10 record and no TerminalServices channel here, so an RDP
        # claim would be invented. The lead stays a valid-accounts lead, and the
        # description says plainly that a loopback address on a console logon is
        # ordinary Windows behaviour.
        assert lead["mitre_technique"] == "T1078"
        assert lead["confidence"] == "HYPOTHESIS"
        assert "loopback" in lead["description"].lower()
        # The lead states its own limit rather than reaching for a transport it
        # cannot see.
        assert "transport is unestablished" in lead["description"].lower()

    def test_a_clean_host_with_only_successful_console_logons_gets_no_lead(self) -> None:
        # False-positive floor: an ordinary interactive logon is not a finding.
        rows = [_logon_row(481, "2", "127.0.0.1"), _logon_row(492, "7", "127.0.0.1")]
        findings = fea.evtx_rows_to_findings(rows, "tc-evtx-1", "case-web", "/e/Security.evtx")
        assert not any(f["finding_id"] == "f-B-evtx-interactive-logon" for f in findings)

    def test_network_and_service_logons_do_not_produce_the_lead(self) -> None:
        rows = [
            _logon_row(100, "3", "10.0.0.9", eid=4625),
            _logon_row(9, "3", "10.0.0.9"),
            _logon_row(10, "5", "-"),
        ]
        findings = fea.evtx_rows_to_findings(rows, "tc-evtx-1", "case-web", "/e/Security.evtx")
        assert not any(f["finding_id"] == "f-B-evtx-interactive-logon" for f in findings)

    def test_a_different_account_failing_does_not_arm_the_lead(self) -> None:
        rows = [_logon_row(481, "2", "127.0.0.1")]
        failed = _logon_row(100, "2", "127.0.0.1", eid=4625)
        failed["data"]["Event"]["EventData"]["TargetUserName"] = "someone-else"
        findings = fea.evtx_rows_to_findings(
            [failed, *rows], "tc-evtx-1", "case-web", "/e/Security.evtx"
        )
        assert not any(f["finding_id"] == "f-B-evtx-interactive-logon" for f in findings)


class TestEvtxRecordBudget:
    def test_evtx_query_limit_exceeds_a_typical_security_log(self) -> None:
        # The Ali Hadi case-1 Security.evtx holds 636 records; the old limit of
        # 500 dropped the tail silently, including every logon after record 500.
        assert fea.EVTX_QUERY_LIMIT >= 10_000

    def test_truncation_is_reported_rather_than_silent(self) -> None:
        # A log bigger than the budget is still truncated — the fix is that the
        # run says so instead of quietly analysing a prefix.
        note = fea.evtx_truncation_limitation(
            "/e/Security.evtx", records_seen=fea.EVTX_QUERY_LIMIT, row_count=fea.EVTX_QUERY_LIMIT
        )
        assert note and "truncat" in note.lower()
        assert str(fea.EVTX_QUERY_LIMIT) in note
        assert (
            fea.evtx_truncation_limitation("/e/Security.evtx", records_seen=636, row_count=636)
            is None
        )
