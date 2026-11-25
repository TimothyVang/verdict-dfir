"""Deterministic mail-store detectors over parsed Outlook/OE message envelopes.

The mail store is an artifact class the engine could not see at all before
``pst_parse``: the Outlook Express lane was mount-gated and DBX-only, so a
rootless run over a disk image whose mail lives in a PST had zero mail coverage.

These detectors are pure header comparisons over whatever ``pst_parse`` /
``oe_dbx_parse`` actually returned. They must key on general mail signatures
(Reply-To divergence, display-name reuse, attachment media type, thread
grouping) and never on a specific image's names, domains, or subjects.
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


def _msg(**over):
    base = {
        "folder": "Inbox",
        "subject": "hello",
        "from_display": "",
        "from_address": f"staff@{INTERNAL}",
        "reply_to_display": "",
        "reply_to_address": "",
        "to": [f"cfo@{INTERNAL}"],
        "to_display": [],
        "date": "Tue, 15 Jul 2008 09:12:44 -0700",
        "attachments": [],
    }
    base.update(over)
    return base


class TestInternalDomain:
    def test_most_frequent_domain_across_the_store_is_the_internal_one(self) -> None:
        msgs = [
            _msg(),
            _msg(from_address=f"a@{INTERNAL}", to=[f"b@{INTERNAL}"]),
            _msg(from_address=f"x@{OUTSIDE}", to=[f"cfo@{INTERNAL}"]),
        ]
        assert fea.mail_internal_domains(msgs) == {INTERNAL}

    def test_empty_store_has_no_internal_domain(self) -> None:
        assert fea.mail_internal_domains([]) == set()


class TestReplyAddressDivergence:
    """The address a reply actually goes to differs from the one displayed.

    Real mailboxes are full of benign Reply-To rewriting -- a newsletter sent
    from ``newsletters@n.example.org`` with ``Reply-To: do-not-reply@example.org``
    is one organisation's own bulk mailer, not a spoof. Only a divergence that
    crosses an organisation boundary is a spoofing indicator.
    """

    def test_reply_to_on_another_organisation_is_a_divergence(self) -> None:
        msgs = [
            _msg(
                from_address=f"boss@{INTERNAL}",
                reply_to_address=f"boss@{OUTSIDE}",
                subject="urgent request",
            )
        ]
        rows = fea.mail_reply_address_divergence(msgs)
        assert len(rows) == 1
        assert rows[0]["basis"] == "reply_to_vs_from"
        assert rows[0]["displayed"] == f"boss@{INTERNAL}"
        assert rows[0]["actual"] == f"boss@{OUTSIDE}"
        assert rows[0]["subject"] == "urgent request"

    def test_bulk_mailer_reply_to_inside_one_organisation_is_not_a_divergence(self) -> None:
        # newsletters@n.example.org -> do-not-reply@example.org: a subdomain of
        # the same registrable domain, i.e. the same organisation.
        msgs = [
            _msg(
                from_address="newsletters@n.example.org",
                reply_to_address="do-not-reply@example.org",
            )
        ]
        assert fea.mail_reply_address_divergence(msgs) == []

    def test_same_address_in_both_headers_is_not_a_divergence(self) -> None:
        assert fea.mail_reply_address_divergence([_msg(reply_to_address=f"staff@{INTERNAL}")]) == []

    def test_case_and_whitespace_differences_alone_are_not_a_divergence(self) -> None:
        msgs = [_msg(from_address="Staff@Corp.Example", reply_to_address=" staff@corp.example ")]
        assert fea.mail_reply_address_divergence(msgs) == []

    def test_absent_reply_to_is_not_a_divergence(self) -> None:
        assert fea.mail_reply_address_divergence([_msg()]) == []

    def test_a_sender_display_name_that_is_another_address_is_a_divergence(self) -> None:
        # `From: outsider@elsewhere (boss@corp.example)` -- the displayed
        # identity is an address, and it is NOT the one a reply reaches.
        msgs = [
            _msg(
                from_display=f"boss@{INTERNAL}",
                from_address=f"outsider@{OUTSIDE}",
                subject="urgent request",
            )
        ]
        rows = fea.mail_reply_address_divergence(msgs)
        assert len(rows) == 1
        assert rows[0]["basis"] == "sender_display_vs_from"
        assert rows[0]["displayed"] == f"boss@{INTERNAL}"
        assert rows[0]["actual"] == f"outsider@{OUTSIDE}"

    def test_a_recipient_display_name_that_is_another_address_is_a_divergence(self) -> None:
        msgs = [
            _msg(
                from_address=f"cfo@{INTERNAL}",
                to=[f"outsider@{OUTSIDE}"],
                to_display=[f"boss@{INTERNAL}"],
            )
        ]
        rows = fea.mail_reply_address_divergence(msgs)
        assert len(rows) == 1
        assert rows[0]["basis"] == "recipient_display_vs_to"
        assert rows[0]["displayed"] == f"boss@{INTERNAL}"
        assert rows[0]["actual"] == f"outsider@{OUTSIDE}"

    def test_a_plain_display_name_is_not_an_address_divergence(self) -> None:
        msgs = [_msg(from_display="Pat Morgan", from_address=f"outsider@{OUTSIDE}")]
        assert fea.mail_reply_address_divergence(msgs) == []


class TestRegistrableDomain:
    def test_subdomains_collapse_to_the_registrable_domain(self) -> None:
        assert fea._registrable_domain("n.npr.example") == "npr.example"
        assert fea._registrable_domain("npr.example") == "npr.example"
        assert fea._registrable_domain("example") == "example"
        assert fea._registrable_domain("") == ""


class TestImpersonation:
    def test_display_name_of_an_internal_principal_sent_from_outside(self) -> None:
        msgs = [
            # the real internal principal, so the display name is known-internal
            _msg(from_display="Pat Morgan", from_address=f"pat.morgan@{INTERNAL}"),
            # the impersonating message: same display name, outside address
            _msg(
                from_display="Pat Morgan",
                from_address=f"pat.morgan@{OUTSIDE}",
                subject="urgent request",
            ),
        ]
        rows = fea.mail_impersonation_candidates(msgs, {INTERNAL})
        assert len(rows) == 1
        assert rows[0]["display_name"] == "Pat Morgan"
        assert rows[0]["from_address"] == f"pat.morgan@{OUTSIDE}"
        assert rows[0]["basis"] == "internal_display_name_external_sender"

    def test_internal_from_with_external_reply_to_is_an_impersonation_candidate(self) -> None:
        msgs = [
            _msg(
                from_display="Pat Morgan",
                from_address=f"pat.morgan@{INTERNAL}",
                reply_to_address=f"pat.morgan@{OUTSIDE}",
            )
        ]
        rows = fea.mail_impersonation_candidates(msgs, {INTERNAL})
        assert len(rows) == 1
        assert rows[0]["basis"] == "internal_sender_external_reply_to"

    def test_ordinary_internal_mail_is_not_an_impersonation_candidate(self) -> None:
        msgs = [_msg(from_display="Pat Morgan", from_address=f"pat.morgan@{INTERNAL}")]
        assert fea.mail_impersonation_candidates(msgs, {INTERNAL}) == []

    def test_ordinary_external_mail_from_an_unknown_name_is_not_a_candidate(self) -> None:
        msgs = [_msg(from_display="Newsletter", from_address=f"news@{OUTSIDE}")]
        assert fea.mail_impersonation_candidates(msgs, {INTERNAL}) == []

    def test_display_name_that_is_itself_an_internal_address_is_impersonation(self) -> None:
        # RFC822 ``actual@outside (inside@org)``: the shown identity is an
        # internal address even if that address never appears as a From
        # display name elsewhere in the store.
        msgs = [
            _msg(
                from_display=f"boss@{INTERNAL}",
                from_address=f"outsider@{OUTSIDE}",
                subject="urgent request",
            )
        ]
        rows = fea.mail_impersonation_candidates(msgs, {INTERNAL})
        assert len(rows) == 1
        assert rows[0]["basis"] == "internal_display_address_external_sender"
        assert rows[0]["display_name"] == f"boss@{INTERNAL}"
        assert rows[0]["from_address"] == f"outsider@{OUTSIDE}"

    def test_display_name_that_is_an_external_address_is_not_impersonation(self) -> None:
        msgs = [_msg(from_display=f"news@{OUTSIDE}", from_address=f"news@{OUTSIDE}")]
        assert fea.mail_impersonation_candidates(msgs, {INTERNAL}) == []


class TestSpreadsheetEgress:
    def _sent(self, **over):
        base = {
            "folder": "Personal Folders/Sent Items",
            "from_address": f"cfo@{INTERNAL}",
            "to": [f"outsider@{OUTSIDE}"],
            "subject": "as requested",
            "attachments": [{"name": "staff-roster.xls", "extension": "xls", "content_type": ""}],
        }
        base.update(over)
        return _msg(**base)

    def test_spreadsheet_attachment_to_an_external_recipient_is_a_candidate(self) -> None:
        rows = fea.mail_attachment_egress_candidates([self._sent()], {INTERNAL})
        assert len(rows) == 1
        assert rows[0]["attachment"] == "staff-roster.xls"
        assert rows[0]["external_recipients"] == [f"outsider@{OUTSIDE}"]
        assert rows[0]["folder"] == "Personal Folders/Sent Items"

    def test_media_type_alone_identifies_a_spreadsheet(self) -> None:
        msg = self._sent(
            attachments=[
                {
                    "name": "roster",
                    "extension": "",
                    "content_type": "application/vnd.ms-excel",
                }
            ]
        )
        assert len(fea.mail_attachment_egress_candidates([msg], {INTERNAL})) == 1

    def test_same_spreadsheet_to_an_internal_recipient_only_is_not_a_candidate(self) -> None:
        msg = self._sent(to=[f"hr@{INTERNAL}"])
        assert fea.mail_attachment_egress_candidates([msg], {INTERNAL}) == []

    def test_non_spreadsheet_attachment_is_not_a_candidate(self) -> None:
        msg = self._sent(
            attachments=[{"name": "logo.png", "extension": "png", "content_type": "image/png"}]
        )
        assert fea.mail_attachment_egress_candidates([msg], {INTERNAL}) == []

    def test_inbound_spreadsheet_from_outside_is_not_egress(self) -> None:
        msg = self._sent(
            folder="Inbox",
            from_address=f"outsider@{OUTSIDE}",
            to=[f"cfo@{INTERNAL}"],
        )
        assert fea.mail_attachment_egress_candidates([msg], {INTERNAL}) == []

    def test_spreadsheet_to_displayed_internal_address_is_not_external_egress(self) -> None:
        # The store records a send to the displayed inside address. That is
        # not proof the file left the organisation, so the egress detector
        # must stay silent.
        msg = self._sent(to=[f"boss@{INTERNAL}"])
        assert fea.mail_attachment_egress_candidates([msg], {INTERNAL}) == []


class TestSpreadsheetReplyToDivergence:
    """A spreadsheet sent to the address a spoofed inbound displayed.

    Distinct from egress: the ``To`` is inside the organisation. The fact is
    that the outbound attachment continues a conversation whose inbound side
    displayed that inside address while sending from outside it.
    """

    def _pair(self, outbound_to, outbound_subject="RE: urgent request"):
        inbound = _msg(
            subject="urgent request",
            from_display=f"boss@{INTERNAL}",
            from_address=f"outsider@{OUTSIDE}",
            to=[f"cfo@{INTERNAL}"],
            date="Sat, 19 Jul 2008 18:22:45 -0700",
        )
        outbound = _msg(
            folder="Personal Folders/Sent Items",
            subject=outbound_subject,
            from_address=f"cfo@{INTERNAL}",
            to=[outbound_to],
            date="Sun, 20 Jul 2008 01:28:47 -0700",
            attachments=[{"name": "staff-roster.xls", "extension": "xls", "content_type": ""}],
        )
        return [inbound, outbound]

    def test_spreadsheet_reply_to_displayed_address_is_a_candidate(self) -> None:
        rows = fea.mail_attachment_reply_to_divergence_candidates(
            self._pair(f"boss@{INTERNAL}"), {INTERNAL}
        )
        assert len(rows) == 1
        assert rows[0]["attachment"] == "staff-roster.xls"
        assert rows[0]["displayed"] == f"boss@{INTERNAL}"
        assert rows[0]["actual_senders"] == [f"outsider@{OUTSIDE}"]

    def test_unrelated_spreadsheet_to_same_address_is_not_a_candidate(self) -> None:
        rows = fea.mail_attachment_reply_to_divergence_candidates(
            self._pair(f"boss@{INTERNAL}", outbound_subject="quarterly numbers"),
            {INTERNAL},
        )
        assert rows == []

    def test_reply_without_spreadsheet_is_not_a_candidate(self) -> None:
        msgs = self._pair(f"boss@{INTERNAL}")
        msgs[1]["attachments"] = []
        assert fea.mail_attachment_reply_to_divergence_candidates(msgs, {INTERNAL}) == []


class TestCounterpartyEscalation:
    """A conversation is grouped by WHO it is with, not by subject text.

    Subject threading fragments a real exchange (a reply can change the
    subject) and, worse, lumps a mailbox's bulk mail into one enormous
    pseudo-thread. Grouping by the external counterparty models the exchange
    the analyst cares about and keeps newsletters out of it.
    """

    def _exchange(self) -> list[dict]:
        return [
            _msg(
                subject="urgent request",
                from_display=f"boss@{INTERNAL}",
                from_address=f"outsider@{OUTSIDE}",
                to=[f"cfo@{INTERNAL}"],
                date="Sat, 19 Jul 2008 18:22:45 -0700",
            ),
            _msg(
                subject="RE: urgent request",
                folder="Sent Items",
                from_address=f"cfo@{INTERNAL}",
                to=[f"outsider@{OUTSIDE}"],
                date="Sun, 20 Jul 2008 01:28:47 -0700",
                attachments=[{"name": "roster.xls", "extension": "xls", "content_type": ""}],
            ),
            _msg(
                subject="Thanks!",
                from_display=f"boss@{INTERNAL}",
                from_address=f"outsider@{OUTSIDE}",
                to=[f"cfo@{INTERNAL}"],
                date="Sun, 20 Jul 2008 02:00:00 -0700",
            ),
        ]

    def test_exchange_with_one_external_counterparty_is_grouped(self) -> None:
        rows = fea.mail_counterparty_escalation(self._exchange(), {INTERNAL})
        assert len(rows) == 1
        row = rows[0]
        assert row["counterparty"] == f"outsider@{OUTSIDE}"
        assert row["message_count"] == 3
        assert row["inbound_count"] == 2
        assert row["outbound_count"] == 1
        assert row["diverging_message_count"] == 2
        assert row["outbound_attachments"] == ["roster.xls"]
        assert "urgent request" in row["subjects"]

    def test_bulk_sender_with_no_reply_and_no_divergence_is_not_an_exchange(self) -> None:
        # 200 newsletters from one address, never replied to: high volume, zero
        # signal. It must not become a "conversation".
        msgs = [
            _msg(subject=f"issue {i}", from_address=f"news@{OUTSIDE}", to=[f"cfo@{INTERNAL}"])
            for i in range(200)
        ]
        assert fea.mail_counterparty_escalation(msgs, {INTERNAL}) == []

    def test_a_purely_internal_exchange_has_no_external_counterparty(self) -> None:
        msgs = [
            _msg(subject=s, from_address=f"a@{INTERNAL}", to=[f"b@{INTERNAL}"])
            for s in ("one", "two", "three")
        ]
        assert fea.mail_counterparty_escalation(msgs, {INTERNAL}) == []

    def test_a_single_message_is_below_the_exchange_floor(self) -> None:
        assert fea.mail_counterparty_escalation(self._exchange()[:1], {INTERNAL}) == []

    def test_two_way_exchange_of_two_messages_still_counts(self) -> None:
        # A request and a reply carrying data out IS the exchange; the floor is
        # on two-way contact, not on message volume.
        rows = fea.mail_counterparty_escalation(self._exchange()[:2], {INTERNAL})
        assert len(rows) == 1
        assert rows[0]["message_count"] == 2

    def test_reply_to_displayed_internal_address_joins_the_spoofed_exchange(self) -> None:
        # Inbound displayed an inside address; the reply went to that displayed
        # address, not to the external SMTP sender. The exchange is still with
        # the outsider — the displayed address is the lure, not a second party.
        msgs = [
            _msg(
                subject="urgent request",
                from_display=f"boss@{INTERNAL}",
                from_address=f"outsider@{OUTSIDE}",
                to=[f"cfo@{INTERNAL}"],
                date="Sat, 19 Jul 2008 18:22:45 -0700",
            ),
            _msg(
                subject="RE: urgent request",
                folder="Sent Items",
                from_address=f"cfo@{INTERNAL}",
                to=[f"boss@{INTERNAL}"],
                date="Sun, 20 Jul 2008 01:28:47 -0700",
                attachments=[{"name": "roster.xls", "extension": "xls", "content_type": ""}],
            ),
            _msg(
                subject="quarterly numbers",
                folder="Sent Items",
                from_address=f"cfo@{INTERNAL}",
                to=[f"boss@{INTERNAL}"],
                date="Mon, 21 Jul 2008 09:00:00 -0700",
            ),
        ]
        rows = fea.mail_counterparty_escalation(msgs, {INTERNAL})
        assert len(rows) == 1
        row = rows[0]
        assert row["counterparty"] == f"outsider@{OUTSIDE}"
        assert row["message_count"] == 2
        assert row["inbound_count"] == 1
        assert row["outbound_count"] == 1
        assert row["diverging_message_count"] == 1
        assert row["outbound_attachments"] == ["roster.xls"]


class TestMailStoreRouting:
    def test_pst_and_ost_route_to_pst_parse_and_dbx_routes_to_oe_dbx_parse(self) -> None:
        assert fea.mail_store_tool_for("/x/mail_store/Outlook/outlook.pst") == "pst_parse"
        assert fea.mail_store_tool_for("/x/mail_store/Outlook/ARCHIVE.OST") == "pst_parse"
        assert fea.mail_store_tool_for("/x/mail_store/OE/Inbox.dbx") == "oe_dbx_parse"

    def test_an_unknown_extension_is_not_routed(self) -> None:
        assert fea.mail_store_tool_for("/x/mail_store/notes.txt") is None


class TestMessageDateOrdering:
    """A store carries two date formats: RFC822 transport dates on received
    mail and libpff's MAPI property format on mail the host composed. Sorting
    them as text puts "Jul 20" before "Sat, 19 Jul", so a reported date span
    would be backwards. Order on parsed instants, and report no span at all
    when something will not parse."""

    def test_rfc822_and_mapi_dates_order_chronologically(self) -> None:
        rfc = "Sat, 19 Jul 2008 18:22:45 -0700 (PDT)"
        mapi = "Jul 20, 2008 01:28:47.828125000 UTC"
        assert fea._mail_date_instant(rfc) is not None
        assert fea._mail_date_instant(mapi) is not None
        assert fea._mail_date_instant(rfc) < fea._mail_date_instant(mapi)

    def test_an_unparseable_date_is_none(self) -> None:
        assert fea._mail_date_instant("whenever") is None
        assert fea._mail_date_instant("") is None

    def test_exchange_span_runs_earliest_to_latest(self) -> None:
        msgs = [
            _msg(
                from_display=f"boss@{INTERNAL}",
                from_address=f"outsider@{OUTSIDE}",
                to=[f"cfo@{INTERNAL}"],
                date="Sat, 19 Jul 2008 18:22:45 -0700 (PDT)",
            ),
            _msg(
                folder="Sent Items",
                from_address=f"cfo@{INTERNAL}",
                to=[f"outsider@{OUTSIDE}"],
                date="Jul 20, 2008 01:28:47.828125000 UTC",
            ),
        ]
        row = fea.mail_counterparty_escalation(msgs, {INTERNAL})[0]
        assert row["first_date"] == "Sat, 19 Jul 2008 18:22:45 -0700 (PDT)"
        assert row["last_date"] == "Jul 20, 2008 01:28:47.828125000 UTC"

    def test_an_unorderable_date_suppresses_the_span(self) -> None:
        msgs = [
            _msg(
                from_display=f"boss@{INTERNAL}",
                from_address=f"outsider@{OUTSIDE}",
                to=[f"cfo@{INTERNAL}"],
                date="whenever",
            ),
            _msg(
                folder="Sent Items",
                from_address=f"cfo@{INTERNAL}",
                to=[f"outsider@{OUTSIDE}"],
                date="Jul 20, 2008 01:28:47.828125000 UTC",
            ),
        ]
        row = fea.mail_counterparty_escalation(msgs, {INTERNAL})[0]
        assert row["first_date"] == ""
        assert row["last_date"] == ""
