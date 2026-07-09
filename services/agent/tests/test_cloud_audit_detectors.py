"""Identity-plane detectors over normalized cloud_audit events.

The host-less identity blind spot (valkyrie's genuine breadth lead per the
2026-06-19 elite-learnings adopt-backlog): the Rust ``cloud_audit`` verb already
normalizes Entra ID sign-in/audit, Azure activity, and M365 UAL into a common
envelope (``timestamp, actor, source_ip, action, resource, outcome, raw``), but
nothing downstream turns those rows into leads. These pure detector functions
close that gap.

Every detector here emits a **lead** (HYPOTHESIS downstream): host-less identity
signals need corroboration and must never assert attribution/actor/intent
(CLAUDE.md non-negotiable guardrails). Each detector fires on a positive
synthetic row and stays silent on a benign one. No real tenant data — all rows
are synthetic.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402

_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "cloud"


def _normalize_entra_signin(record: dict) -> dict:
    """Mirror the Rust ``cloud_audit`` entra_signin envelope mapping for tests.

    Keeps the fixture honest: the detector is exercised against the same six
    normalized fields ``services/mcp/src/tools/cloud_audit.rs`` produces, with the
    full record preserved under ``raw`` (where geoCoordinates live).
    """
    return {
        "timestamp": record.get("createdDateTime"),
        "actor": record.get("userPrincipalName") or record.get("userDisplayName"),
        "source_ip": record.get("ipAddress"),
        "action": record.get("appDisplayName") or record.get("clientAppUsed"),
        "resource": record.get("resourceDisplayName"),
        "outcome": str((record.get("status") or {}).get("errorCode", "")),
        "raw": record,
    }


def _cev(
    *,
    timestamp: str | None = None,
    actor: str | None = None,
    source_ip: str | None = None,
    action: str | None = None,
    resource: str | None = None,
    outcome: str | None = None,
    raw: dict | None = None,
) -> dict:
    """Build one normalized cloud event matching the Rust CloudEvent envelope."""
    return {
        "timestamp": timestamp,
        "actor": actor,
        "source_ip": source_ip,
        "action": action,
        "resource": resource,
        "outcome": outcome,
        "raw": raw or {},
    }


# ---------------------------------------------------------------------------
# Impossible travel (Entra sign-in geo-velocity).
# ---------------------------------------------------------------------------


def _signin(actor: str, ts: str, lat: float, lon: float, ip: str) -> dict:
    """An Entra sign-in event carrying geoCoordinates in raw (Graph shape)."""
    return _cev(
        timestamp=ts,
        actor=actor,
        source_ip=ip,
        action="Azure Portal",
        outcome="0",
        raw={"location": {"geoCoordinates": {"latitude": lat, "longitude": lon}}},
    )


class TestImpossibleTravel:
    def test_far_signins_in_short_window_fire(self) -> None:
        # New York -> Sydney (~16,000 km) in 30 minutes => ~32,000 km/h, far above
        # any plausible travel velocity.
        events = [
            _signin("user@contoso.com", "2026-06-13T01:00:00Z", 40.71, -74.01, "1.2.3.4"),
            _signin("user@contoso.com", "2026-06-13T01:30:00Z", -33.87, 151.21, "5.6.7.8"),
        ]
        leads = fea.cloud_impossible_travel_candidates(events)
        assert len(leads) == 1
        lead = leads[0]
        assert lead["kind"] == "impossible_travel"
        assert lead["actor"] == "user@contoso.com"
        assert lead["velocity_kmh"] > fea.IMPOSSIBLE_TRAVEL_KMH
        assert lead["from_ip"] == "1.2.3.4"
        assert lead["to_ip"] == "5.6.7.8"

    def test_plausible_travel_stays_silent(self) -> None:
        # New York -> Boston (~300 km) over 5 hours => ~60 km/h, normal.
        events = [
            _signin("user@contoso.com", "2026-06-13T01:00:00Z", 40.71, -74.01, "1.2.3.4"),
            _signin("user@contoso.com", "2026-06-13T06:00:00Z", 42.36, -71.06, "9.9.9.9"),
        ]
        assert fea.cloud_impossible_travel_candidates(events) == []

    def test_distinct_actors_are_not_compared(self) -> None:
        # Two different users, far apart, close in time — NOT impossible travel:
        # impossible travel is a per-identity signal.
        events = [
            _signin("alice@contoso.com", "2026-06-13T01:00:00Z", 40.71, -74.01, "1.2.3.4"),
            _signin("bob@contoso.com", "2026-06-13T01:10:00Z", -33.87, 151.21, "5.6.7.8"),
        ]
        assert fea.cloud_impossible_travel_candidates(events) == []

    def test_velocity_threshold_is_named_constant(self) -> None:
        assert isinstance(fea.IMPOSSIBLE_TRAVEL_KMH, int | float)
        # Commercial jets cruise ~900 km/h; the threshold must sit above that so
        # ordinary air travel does not flood, but well below orbital speed.
        assert 900 < fea.IMPOSSIBLE_TRAVEL_KMH < 30000


# ---------------------------------------------------------------------------
# OAuth illicit-consent grant (Entra audit).
# ---------------------------------------------------------------------------


class TestOAuthConsent:
    def test_consent_to_unverified_app_fires(self) -> None:
        events = [
            _cev(
                timestamp="2026-06-13T02:00:00Z",
                actor="victim@contoso.com",
                action="Consent to application",
                resource="Mail Reader Pro",
                outcome="success",
                raw={
                    "targetResources": [{"displayName": "Mail Reader Pro"}],
                    "additionalDetails": [
                        {"key": "ConsentAction", "value": "Allowed"},
                        {"key": "Scope", "value": "Mail.Read offline_access"},
                    ],
                },
            )
        ]
        leads = fea.cloud_oauth_consent_candidates(events)
        assert len(leads) == 1
        lead = leads[0]
        assert lead["kind"] == "oauth_consent"
        assert lead["actor"] == "victim@contoso.com"
        assert "mail.read" in lead["scopes"].lower()

    def test_benign_signin_action_is_ignored(self) -> None:
        events = [
            _cev(
                timestamp="2026-06-13T02:05:00Z",
                actor="user@contoso.com",
                action="Sign-in activity",
                resource="Office 365",
                outcome="success",
            )
        ]
        assert fea.cloud_oauth_consent_candidates(events) == []

    def test_consent_without_high_risk_scope_stays_silent(self) -> None:
        # Consent to an app requesting only an innocuous openid/profile scope is
        # not an illicit-grant lead.
        events = [
            _cev(
                timestamp="2026-06-13T02:10:00Z",
                actor="user@contoso.com",
                action="Consent to application",
                resource="Status Page",
                outcome="success",
                raw={
                    "additionalDetails": [
                        {"key": "Scope", "value": "openid profile email"},
                    ]
                },
            )
        ]
        assert fea.cloud_oauth_consent_candidates(events) == []


# ---------------------------------------------------------------------------
# BEC inbox-forwarding / rule (M365 UAL).
# ---------------------------------------------------------------------------


class TestInboxRule:
    def test_external_forwarding_rule_fires(self) -> None:
        events = [
            _cev(
                timestamp="2026-06-13T03:00:00Z",
                actor="victim@contoso.com",
                source_ip="203.0.113.9",
                action="New-InboxRule",
                resource="Exchange",
                outcome="Succeeded",
                raw={
                    "Parameters": [
                        {"Name": "ForwardTo", "Value": "attacker@gmail.com"},
                        {"Name": "DeleteMessage", "Value": "True"},
                    ]
                },
            )
        ]
        leads = fea.cloud_inbox_rule_candidates(events)
        assert len(leads) == 1
        lead = leads[0]
        assert lead["kind"] == "inbox_rule"
        assert lead["actor"] == "victim@contoso.com"
        assert lead["external_target"] == "attacker@gmail.com"

    def test_set_mailbox_forwarding_fires(self) -> None:
        events = [
            _cev(
                timestamp="2026-06-13T03:05:00Z",
                actor="victim@contoso.com",
                action="Set-Mailbox",
                resource="Exchange",
                outcome="Succeeded",
                raw={
                    "Parameters": [
                        {"Name": "ForwardingSmtpAddress", "Value": "smtp:exfil@proton.me"},
                    ]
                },
            )
        ]
        leads = fea.cloud_inbox_rule_candidates(events)
        assert len(leads) == 1
        assert leads[0]["external_target"].endswith("exfil@proton.me")

    def test_internal_only_rule_stays_silent(self) -> None:
        # A rule that forwards to an internal mailbox in the same tenant is normal
        # delegation, not a BEC exfil lead.
        events = [
            _cev(
                timestamp="2026-06-13T03:10:00Z",
                actor="user@contoso.com",
                action="New-InboxRule",
                resource="Exchange",
                outcome="Succeeded",
                raw={
                    "Parameters": [
                        {"Name": "ForwardTo", "Value": "teammate@contoso.com"},
                    ]
                },
            )
        ]
        leads = fea.cloud_inbox_rule_candidates(events, internal_domains=["contoso.com"])
        assert leads == []

    def test_non_rule_operation_is_ignored(self) -> None:
        events = [
            _cev(
                timestamp="2026-06-13T03:15:00Z",
                actor="user@contoso.com",
                action="MailItemsAccessed",
                resource="Exchange",
                outcome="Succeeded",
            )
        ]
        assert fea.cloud_inbox_rule_candidates(events) == []


# ---------------------------------------------------------------------------
# MFA fatigue / push-bombing (Entra sign-in repeated MFA challenges).
# ---------------------------------------------------------------------------


def _mfa(actor: str, ts: str, outcome: str, ip: str = "1.2.3.4") -> dict:
    """An Entra sign-in MFA event: outcome is the status errorCode string.

    "500121" is the canonical "Authentication failed during strong
    authentication request" (an MFA prompt the user did not approve); "0" is a
    satisfied MFA. The detector reads the normalized outcome plus the MFA-flavored
    action, so a benign single sign-in stays silent.
    """
    return _cev(
        timestamp=ts,
        actor=actor,
        source_ip=ip,
        action="Mobile app notification",
        resource="Azure Portal",
        outcome=outcome,
        raw={"authenticationRequirement": "multiFactorAuthentication"},
    )


class TestMfaFatigue:
    def test_repeated_failed_then_success_fires(self) -> None:
        # Five denied MFA pushes followed by an approval, all inside a few minutes
        # for one identity — the push-bombing shape.
        events = [
            _mfa("victim@contoso.com", "2026-06-13T04:00:00Z", "500121"),
            _mfa("victim@contoso.com", "2026-06-13T04:00:40Z", "500121"),
            _mfa("victim@contoso.com", "2026-06-13T04:01:20Z", "500121"),
            _mfa("victim@contoso.com", "2026-06-13T04:02:00Z", "500121"),
            _mfa("victim@contoso.com", "2026-06-13T04:02:30Z", "500121"),
            _mfa("victim@contoso.com", "2026-06-13T04:03:00Z", "0"),
        ]
        leads = fea.cloud_mfa_fatigue_candidates(events)
        assert len(leads) == 1
        lead = leads[0]
        assert lead["kind"] == "mfa_fatigue"
        assert lead["actor"] == "victim@contoso.com"
        assert lead["prompt_count"] >= fea.MFA_FATIGUE_MIN_PROMPTS
        # The fatigue shape: the burst ended in an approval (the dangerous case).
        assert lead["accepted_after_denials"] is True
        assert lead["technique"] == "T1621"

    def test_repeated_denied_prompts_without_success_still_fire(self) -> None:
        # A burst of denied prompts that the user never approves is still a lead
        # (the attack was attempted); it just did not succeed.
        events = [
            _mfa("victim@contoso.com", "2026-06-13T05:00:00Z", "500121"),
            _mfa("victim@contoso.com", "2026-06-13T05:00:30Z", "500121"),
            _mfa("victim@contoso.com", "2026-06-13T05:01:00Z", "500121"),
            _mfa("victim@contoso.com", "2026-06-13T05:01:30Z", "500121"),
            _mfa("victim@contoso.com", "2026-06-13T05:02:00Z", "500121"),
        ]
        leads = fea.cloud_mfa_fatigue_candidates(events)
        assert len(leads) == 1
        assert leads[0]["accepted_after_denials"] is False

    def test_single_normal_mfa_stays_silent(self) -> None:
        events = [_mfa("user@contoso.com", "2026-06-13T06:00:00Z", "0")]
        assert fea.cloud_mfa_fatigue_candidates(events) == []

    def test_few_prompts_under_threshold_stay_silent(self) -> None:
        # Two denied prompts (e.g. a fat-fingered passcode) is below the
        # push-bombing threshold and must not flood.
        events = [
            _mfa("user@contoso.com", "2026-06-13T06:10:00Z", "500121"),
            _mfa("user@contoso.com", "2026-06-13T06:10:40Z", "500121"),
        ]
        assert fea.cloud_mfa_fatigue_candidates(events) == []

    def test_prompts_spread_beyond_window_stay_silent(self) -> None:
        # Enough denied prompts, but spread across the whole day (one per hour) is
        # not a fatigue burst — it is normal intermittent re-auth.
        events = [
            _mfa("user@contoso.com", f"2026-06-13T{hour:02d}:00:00Z", "500121")
            for hour in range(6, 12)
        ]
        assert fea.cloud_mfa_fatigue_candidates(events) == []

    def test_distinct_actors_are_not_combined(self) -> None:
        # Five denied prompts spread across five different identities is not a
        # per-identity fatigue burst.
        events = [
            _mfa(f"user{i}@contoso.com", f"2026-06-13T07:0{i}:00Z", "500121") for i in range(5)
        ]
        assert fea.cloud_mfa_fatigue_candidates(events) == []

    def test_thresholds_are_named_constants(self) -> None:
        assert isinstance(fea.MFA_FATIGUE_MIN_PROMPTS, int)
        assert fea.MFA_FATIGUE_MIN_PROMPTS >= 3
        assert isinstance(fea.MFA_FATIGUE_WINDOW_MIN, int | float)
        assert fea.MFA_FATIGUE_WINDOW_MIN > 0


# ---------------------------------------------------------------------------
# Fixture-driven end-to-end shape (synthetic provider JSON -> normalize -> detect).
# ---------------------------------------------------------------------------


class TestFixtureFlow:
    def test_synthetic_entra_signin_fixture_fires_impossible_travel(self) -> None:
        raw = json.loads((_FIXTURES / "entra_signin_impossible_travel.json").read_text())
        events = [_normalize_entra_signin(r) for r in raw["value"]]
        leads = fea.cloud_impossible_travel_candidates(events)
        assert len(leads) == 1
        assert leads[0]["actor"] == "user@contoso.com"
        assert leads[0]["velocity_kmh"] > fea.IMPOSSIBLE_TRAVEL_KMH
