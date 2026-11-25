"""Cloud-audit orchestrator seam: detect -> dispatch cloud_audit -> emit leads.

PR #82 landed the four identity-plane detector functions as pure code, but the
headless engine never invoked the ``cloud_audit`` verb: nothing classified a
cloud log as evidence, nothing dispatched the tool, and nothing turned its rows
into Findings. This pins the closed seam.

The wiring is exercised with a fake MCP client returning synthetic cloud-log
rows (no real tenant data). The asserts are: a cloud log is recognized as
evidence, the lane dispatches ``cloud_audit`` through the audited ``_record_tool``
path (so the Finding can cite a real ``tool_call_id``), and every detector hit is
emitted as a HYPOTHESIS lead carrying that ``tool_call_id`` and the detector's
MITRE technique. Cloud/anomaly signals are leads needing corroboration
(CLAUDE.md), never attribution/actor/intent.
"""

from __future__ import annotations

import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402

# ---------------------------------------------------------------------------
# (a) Evidence detection: a provider-tagged cloud log is recognized.
# ---------------------------------------------------------------------------


class TestCloudEvidenceDetection:
    def test_detect_evidence_type_recognizes_cloud_log(self) -> None:
        assert fea.detect_evidence_type("/case/entra_signin_2026-06-13.json") == "cloud"
        assert fea.detect_evidence_type("/case/cloudtrail.jsonl") == "cloud"
        assert fea.detect_evidence_type("/case/m365_ual_export.csv") == "cloud"

    def test_classify_artifact_path_maps_cloud_lane_and_provider(self) -> None:
        info = fea.classify_artifact_path("/case/entra_signin_audit.json")
        assert info["artifact_class"] == "cloud"
        assert info["evidence_type"] == "cloud"
        assert info["parser_tool"] == "cloud_audit"

    def test_cloud_provider_from_path_picks_allow_listed_provider(self) -> None:
        # The provider is named in the filename and must match the Rust
        # cloud_audit allow-list verbatim — the tool rejects anything else.
        assert fea.cloud_provider_for_path("/x/cloudtrail-1.json") == "cloudtrail"
        assert fea.cloud_provider_for_path("/x/entra_signin_a.json") == "entra_signin"
        assert fea.cloud_provider_for_path("/x/entra_audit_b.json") == "entra_audit"
        assert fea.cloud_provider_for_path("/x/m365_ual_c.csv") == "m365_ual"

    def test_non_cloud_json_is_not_a_cloud_log(self) -> None:
        # A bare .json/.csv with no allow-listed provider token in the name is not
        # claimed as a cloud log (no provider to safely pass to cloud_audit).
        assert fea.cloud_provider_for_path("/case/notes.json") is None
        assert fea.detect_evidence_type("/case/notes.json") != "cloud"
        assert fea.classify_artifact_path("/case/notes.json")["artifact_class"] != "cloud"


# ---------------------------------------------------------------------------
# (b) + (c) Dispatch + emit: cloud_audit is invoked and leads are emitted.
# ---------------------------------------------------------------------------

# Synthetic normalized rows the fake Rust cloud_audit returns. Each row trips
# exactly one detector. No real tenant data.
_SIGNIN_NY = {
    "timestamp": "2026-06-13T01:00:00Z",
    "actor": "user@contoso.com",
    "source_ip": "1.2.3.4",
    "action": "Azure Portal",
    "resource": None,
    "outcome": "0",
    "raw": {"location": {"geoCoordinates": {"latitude": 40.71, "longitude": -74.01}}},
}
_SIGNIN_SYDNEY = {
    "timestamp": "2026-06-13T01:30:00Z",
    "actor": "user@contoso.com",
    "source_ip": "5.6.7.8",
    "action": "Azure Portal",
    "resource": None,
    "outcome": "0",
    "raw": {"location": {"geoCoordinates": {"latitude": -33.87, "longitude": 151.21}}},
}
_OAUTH_CONSENT = {
    "timestamp": "2026-06-13T02:00:00Z",
    "actor": "victim@contoso.com",
    "source_ip": "9.9.9.9",
    "action": "Consent to application",
    "resource": "Mail Reader Pro",
    "outcome": "success",
    "raw": {
        "additionalDetails": [{"key": "Scope", "value": "Mail.Read offline_access"}],
    },
}
_INBOX_RULE = {
    "timestamp": "2026-06-13T03:00:00Z",
    "actor": "victim@contoso.com",
    "source_ip": "203.0.113.9",
    "action": "New-InboxRule",
    "resource": "Exchange",
    "outcome": "Succeeded",
    "raw": {"Parameters": [{"Name": "ForwardTo", "Value": "attacker@gmail.com"}]},
}


def _mfa_burst() -> list[dict]:
    return [
        {
            "timestamp": f"2026-06-13T04:0{i}:00Z",
            "actor": "victim@contoso.com",
            "source_ip": "1.2.3.4",
            "action": "Mobile app notification",
            "resource": "Azure Portal",
            "outcome": "500121",
            "raw": {"authenticationRequirement": "multiFactorAuthentication"},
        }
        for i in range(5)
    ]


class _FakePy:
    def __init__(self) -> None:
        self.audits: list[tuple[str, dict]] = []

    def call_tool(self, name: str, args: dict, timeout: float = 600.0) -> dict:
        if name == "audit_append":
            self.audits.append((args["kind"], args["payload"]))
        return {}


class _FakeRust:
    """cloud_audit returns a fixed set of synthetic normalized events."""

    def __init__(self, events: list[dict]) -> None:
        self._events = events
        self.calls: list[tuple[str, dict]] = []

    def call_tool(self, name: str, args: dict, timeout: float = 600.0) -> dict:
        self.calls.append((name, args))
        if name == "cloud_audit":
            return {
                "provider": args.get("provider"),
                "events": self._events,
                "events_seen": len(self._events),
            }
        return {}


def _inv() -> fea.Investigation:
    inv = fea.Investigation("/tmp/does-not-exist-cloud", case_id="case-cloud")
    inv.handle = {"id": "case-test"}
    return inv


def _entry(path: str) -> dict:
    return {"path": path, "artifact_class": "cloud"}


class TestCloudDispatch:
    def test_lane_dispatches_cloud_audit_with_allow_listed_provider(self) -> None:
        inv = _inv()
        py = _FakePy()
        rust = _FakeRust([_OAUTH_CONSENT])

        inv.investigate_cloud_artifacts(rust, py, [_entry("/case/entra_audit_export.json")])

        cloud_calls = [a for n, a in rust.calls if n == "cloud_audit"]
        assert len(cloud_calls) == 1
        args = cloud_calls[0]
        assert args["case_id"] == "case-test"
        assert args["provider"] == "entra_audit"  # named from the filename
        assert fea.is_cloud_provider_allowed(args["provider"])

    def test_dispatch_records_tool_call_with_id(self) -> None:
        inv = _inv()
        py = _FakePy()
        rust = _FakeRust([_OAUTH_CONSENT])

        inv.investigate_cloud_artifacts(rust, py, [_entry("/case/entra_audit_export.json")])

        recorded = [tc for tc in inv.tool_calls if tc["tool"] == "cloud_audit"]
        assert len(recorded) == 1
        assert recorded[0]["tool_call_id"].startswith("tc-")
        # The audited chain saw the dispatch (start + output).
        kinds = [k for k, _ in py.audits]
        assert "tool_call_start" in kinds
        assert "tool_call_output" in kinds


class TestCloudEmit:
    def _findings(self, inv: fea.Investigation) -> list[dict]:
        return inv.findings_pool_a + inv.findings_pool_b

    def _run(self, events: list[dict]) -> tuple[fea.Investigation, str]:
        inv = _inv()
        py = _FakePy()
        rust = _FakeRust(events)
        inv.investigate_cloud_artifacts(rust, py, [_entry("/case/entra_signin.json")])
        tcid = next(tc["tool_call_id"] for tc in inv.tool_calls if tc["tool"] == "cloud_audit")
        return inv, tcid

    def test_impossible_travel_emits_hypothesis_lead(self) -> None:
        inv, tcid = self._run([_SIGNIN_NY, _SIGNIN_SYDNEY])
        findings = self._findings(inv)
        assert len(findings) == 1
        f = findings[0]
        assert f["confidence"] == "HYPOTHESIS"
        assert f["tool_call_id"] == tcid
        assert f["mitre_technique"] == "T1078.004"
        assert f["pool_origin"] in {"A", "B"}

    def test_oauth_consent_emits_hypothesis_lead(self) -> None:
        inv, tcid = self._run([_OAUTH_CONSENT])
        findings = self._findings(inv)
        assert len(findings) == 1
        assert findings[0]["confidence"] == "HYPOTHESIS"
        assert findings[0]["tool_call_id"] == tcid
        assert findings[0]["mitre_technique"] == "T1528"

    def test_inbox_rule_emits_hypothesis_lead(self) -> None:
        inv, tcid = self._run([_INBOX_RULE])
        findings = self._findings(inv)
        assert len(findings) == 1
        assert findings[0]["confidence"] == "HYPOTHESIS"
        assert findings[0]["tool_call_id"] == tcid
        assert findings[0]["mitre_technique"] == "T1114.003"

    def test_mfa_fatigue_emits_hypothesis_lead(self) -> None:
        inv, tcid = self._run(_mfa_burst())
        findings = self._findings(inv)
        assert len(findings) == 1
        assert findings[0]["confidence"] == "HYPOTHESIS"
        assert findings[0]["tool_call_id"] == tcid
        assert findings[0]["mitre_technique"] == "T1621"

    def test_all_four_detectors_fire_together(self) -> None:
        events = [_SIGNIN_NY, _SIGNIN_SYDNEY, _OAUTH_CONSENT, _INBOX_RULE, *_mfa_burst()]
        inv, tcid = self._run(events)
        findings = self._findings(inv)
        techniques = {f["mitre_technique"] for f in findings}
        assert {"T1078.004", "T1528", "T1114.003", "T1621"} <= techniques
        # Every cloud lead is a HYPOTHESIS citing the dispatch's tool_call_id.
        for f in findings:
            assert f["confidence"] == "HYPOTHESIS"
            assert f["tool_call_id"] == tcid

    def test_benign_rows_emit_no_findings(self) -> None:
        # A single normal sign-in and a single satisfied MFA: nothing to flag.
        benign = [
            {
                "timestamp": "2026-06-13T08:00:00Z",
                "actor": "user@contoso.com",
                "source_ip": "1.2.3.4",
                "action": "Azure Portal",
                "resource": None,
                "outcome": "0",
                "raw": {"location": {"geoCoordinates": {"latitude": 40.71, "longitude": -74.01}}},
            }
        ]
        inv, _ = self._run(benign)
        assert self._findings(inv) == []

    def test_descriptions_carry_lead_and_corroboration_language(self) -> None:
        inv, _ = self._run([_INBOX_RULE])
        desc = self._findings(inv)[0]["description"].lower()
        assert "lead" in desc
        assert "corroborat" in desc


class TestCloudErrorHandling:
    def test_cloud_audit_error_does_not_crash_and_emits_no_findings(self) -> None:
        inv = _inv()
        py = _FakePy()

        class _ErrRust:
            def call_tool(self, name: str, args: dict, timeout: float = 600.0) -> dict:
                if name == "cloud_audit":
                    return {"_error": {"message": "cloud parse failed: bad json"}}
                return {}

        # Must not raise.
        inv.investigate_cloud_artifacts(_ErrRust(), py, [_entry("/case/cloudtrail.json")])
        assert inv.findings_pool_a == []
        assert inv.findings_pool_b == []
        assert any("cloud" in lim.lower() for lim in inv.analysis_limitations)
