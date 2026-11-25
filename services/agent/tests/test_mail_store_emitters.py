"""Findings the mail-store lane emits from parsed message envelopes.

Each finding must cite the parser's own ``tool_call_id`` (so ``verify_finding``
can replay it), stay a HEADER statement rather than an actor/intent claim, and
stay evidence-agnostic — the wording reports what was parsed out of this store.
"""

from __future__ import annotations

import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402

INTERNAL = "corp.example"
OUTSIDE = "mailhost.example"
STORE = "/case/extracted/disk/mail_store/Users/cfo/Outlook/outlook.pst"


def _inv():
    inv = fea.Investigation("disk.img", unattended=True, with_report=False)
    inv.handle = {"id": "case-mail"}
    return inv


def _msg(**over):
    base = {
        "folder": "Inbox",
        "subject": "hello",
        "from_display": "",
        "from_address": f"staff@{INTERNAL}",
        "reply_to_display": "",
        "reply_to_address": "",
        "to": [f"cfo@{INTERNAL}"],
        "date": "Tue, 15 Jul 2008 09:12:44 -0700",
        "attachments": [],
    }
    base.update(over)
    return base


def _scenario():
    """A store carrying all four mail signals, built from generic addresses."""
    principal = _msg(from_display=f"pat.morgan@{INTERNAL}", from_address=f"pat.morgan@{INTERNAL}")
    phish = _msg(
        subject="urgent request",
        from_display=f"pat.morgan@{INTERNAL}",
        from_address=f"outsider@{OUTSIDE}",
        to=[f"cfo@{INTERNAL}"],
        date="Tue, 15 Jul 2008 10:00:00 -0700",
    )
    reply = _msg(
        subject="RE: urgent request",
        folder="Personal Folders/Sent Items",
        from_address=f"cfo@{INTERNAL}",
        to=[f"outsider@{OUTSIDE}"],
        date="Tue, 15 Jul 2008 10:30:00 -0700",
    )
    followup = _msg(
        subject="RE: RE: urgent request",
        from_display=f"pat.morgan@{INTERNAL}",
        from_address=f"outsider@{OUTSIDE}",
        to=[f"cfo@{INTERNAL}"],
        date="Tue, 15 Jul 2008 11:00:00 -0700",
    )
    exfil = _msg(
        subject="RE: RE: urgent request",
        folder="Personal Folders/Sent Items",
        from_address=f"cfo@{INTERNAL}",
        to=[f"outsider@{OUTSIDE}"],
        date="Tue, 15 Jul 2008 11:30:00 -0700",
        attachments=[
            {
                "name": "employee-roster.xls",
                "extension": "xls",
                "content_type": "application/vnd.ms-excel",
            }
        ],
    )
    return [principal, phish, reply, followup, exfil]


class TestMailStoreEmitters:
    def test_reply_to_divergence_is_a_confirmed_pool_a_finding(self) -> None:
        inv = _inv()
        inv._emit_mail_store_findings(_scenario(), STORE, "tc-pst")
        f = next(f for f in inv.findings_pool_a if "reply-to" in f["finding_id"])
        assert f["confidence"] == "CONFIRMED"
        assert f["pool_origin"] == "A"
        assert f["tool_call_id"] == "tc-pst"
        assert f["artifact_path"] == STORE
        assert f["mitre_technique"] == "T1534"
        desc = f["description"].lower()
        assert "reply address" in desc and "diverges" in desc
        assert f"outsider@{OUTSIDE}" in desc

    def test_impersonation_finding_names_the_display_name_and_the_divergence(self) -> None:
        inv = _inv()
        inv._emit_mail_store_findings(_scenario(), STORE, "tc-pst")
        f = next(f for f in inv.findings_pool_a if "impersonation" in f["finding_id"])
        assert f["confidence"] == "CONFIRMED"
        assert f["mitre_technique"] == "T1566.001"
        desc = f["description"]
        assert f"pat.morgan@{INTERNAL}" in desc
        assert "impersonating" in desc.lower()
        # honesty boundary: a header fact, never an authorship claim
        assert "who composed" in desc.lower() or "who sent" in desc.lower()

    def test_spreadsheet_egress_finding_names_the_attachment_and_recipient(self) -> None:
        inv = _inv()
        inv._emit_mail_store_findings(_scenario(), STORE, "tc-pst")
        f = next(f for f in inv.findings_pool_a if "attachment" in f["finding_id"])
        assert f["confidence"] == "CONFIRMED"
        assert f["mitre_technique"] == "T1567"
        desc = f["description"]
        assert "employee-roster.xls" in desc
        assert f"outsider@{OUTSIDE}" in desc
        assert "spreadsheet" in desc.lower()

    def test_thread_escalation_is_an_inferred_lead(self) -> None:
        inv = _inv()
        inv._emit_mail_store_findings(_scenario(), STORE, "tc-pst")
        f = next(f for f in inv.findings_pool_a if "thread" in f["finding_id"])
        assert f["confidence"] == "INFERRED"
        desc = f["description"].lower()
        assert "thread" in desc and "conversation" in desc

    def test_impersonation_without_a_divergence_is_only_inferred(self) -> None:
        # A plain display NAME (not an address) reused from an outside address:
        # an impersonation candidate, but nothing shows the reply path diverging.
        inv = _inv()
        msgs = [
            _msg(from_display="Pat Morgan", from_address=f"pat.morgan@{INTERNAL}"),
            _msg(from_display="Pat Morgan", from_address=f"pat.morgan@{OUTSIDE}"),
        ]
        inv._emit_mail_store_findings(msgs, STORE, "tc-pst")
        f = next(f for f in inv.findings_pool_a if "impersonation" in f["finding_id"])
        assert f["confidence"] == "INFERRED"

    def test_an_ordinary_internal_mailbox_emits_nothing(self) -> None:
        inv = _inv()
        inv._emit_mail_store_findings(
            [_msg(), _msg(subject="lunch"), _msg(subject="RE: lunch")], STORE, "tc-pst"
        )
        assert inv.findings_pool_a == []
        assert inv.findings_pool_b == []

    def test_no_messages_emits_nothing(self) -> None:
        inv = _inv()
        inv._emit_mail_store_findings([], STORE, "tc-pst")
        assert inv.findings_pool_a == []

    def test_every_finding_cites_the_parser_tool_call(self) -> None:
        inv = _inv()
        inv._emit_mail_store_findings(_scenario(), STORE, "tc-pst")
        assert inv.findings_pool_a
        for f in inv.findings_pool_a:
            assert f["tool_call_id"] == "tc-pst"
            assert f["derived_from"] == ["tc-pst"]
            assert f["case_id"] == "case-mail"

    def test_findings_do_not_use_exfiltration_vocabulary(self) -> None:
        # CLAUDE.md gates an exfiltration CONCLUSION behind a presence AND an
        # egress artifact class. The mail store records a transfer at header
        # level only, so the finding states what the headers show and leaves the
        # exfiltration conclusion to the correlator.
        inv = _inv()
        inv._emit_mail_store_findings(_scenario(), STORE, "tc-pst")
        for f in inv.findings_pool_a:
            assert not fea._claims_exfiltration(f), f["finding_id"]

    def test_findings_do_not_read_as_execution_claims(self) -> None:
        # The >=2-artifact-class execution gate fires on execution WORDING as
        # well as technique labels. A mail store proves no execution, so no
        # mail finding may read like one.
        inv = _inv()
        inv._emit_mail_store_findings(_scenario(), STORE, "tc-pst")
        for f in inv.findings_pool_a:
            assert not fea._claims_execution(f), f["finding_id"]
