"""Tests for the Outlook Express ``.dbx`` emitters in the orchestrator.

Two leads, both ONE Pool B HYPOTHESIS finding that cites the originating
``oe_dbx_parse`` call and stays an *artifact* statement — never an intrusion
claim and never actor identity/intent (host-artifact guardrail):

* newsgroup-affiliation — the store subscribes to hacking/cracking newsgroups.
* deleted-email-recovery (nhc-003) — messages recovered from the OE "Deleted
  Items" trash store, keyed on the general OE trash-folder name.
"""

from __future__ import annotations

import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402


class TestNewsgroupAffiliationEmitter:
    def _inv(self):
        inv = fea.Investigation("disk.img", unattended=True, with_report=False)
        inv.handle = {"id": "case-ng"}
        return inv

    def _stores(self):
        return [
            (
                "/m/alt.2600.hackerz.dbx",
                "tc-a",
                {
                    "hacking_newsgroups": ["alt.2600.hackerz"],
                    "subjects": ["How to hack hotmail"],
                },
            ),
            (
                "/m/alt.binaries.hacking.beginner.dbx",
                "tc-b",
                {
                    "hacking_newsgroups": ["alt.binaries.hacking.beginner", "alt.hacking"],
                    "subjects": ["Bios Password Hacking"],
                },
            ),
        ]

    def test_emits_one_hypothesis_finding_citing_primary(self) -> None:
        inv = self._inv()
        inv._emit_newsgroup_affiliation_finding(self._stores())
        assert len(inv.findings_pool_b) == 1
        f = inv.findings_pool_b[0]
        assert f["confidence"] == "HYPOTHESIS"
        assert f["pool_origin"] == "B"
        assert f.get("mitre_technique") is None  # affiliation maps to no ATT&CK technique
        # primary = the store with the most hacking newsgroups (tc-b)
        assert f["tool_call_id"] == "tc-b"
        assert set(f["derived_from"]) == {"tc-a", "tc-b"}
        desc = f["description"].lower()
        assert "alt.2600.hackerz" in desc and "alt.binaries.hacking.beginner" in desc
        # honesty boundary: artifact-only, no intrusion/intent/identity claim
        assert "not, on its own, evidence of any specific intrusion" in desc
        assert "out of scope" in desc

    def test_no_stores_emits_nothing(self) -> None:
        inv = self._inv()
        inv._emit_newsgroup_affiliation_finding([])
        assert inv.findings_pool_b == []


# --------------------------------------------------------------------------- #
# nhc-003 — recovered deleted email from the OE "Deleted Items" trash store.   #
# A lead DISTINCT from the newsgroup-affiliation finding, keyed on the general #
# OE trash-folder name (never an image-specific value).                        #
# --------------------------------------------------------------------------- #


def _store(
    source_name: str,
    *,
    is_oe_dbx: bool = True,
    is_message_store: bool = True,
    subjects: list[str] | None = None,
    senders: list[str] | None = None,
    message_subject_count: int | None = None,
    tool_call_id: str = "tc-del",
):
    subjects = subjects if subjects is not None else []
    return {
        "source_name": source_name,
        "persisted_path": f"/run/oe/{source_name}",
        "tool_call_id": tool_call_id,
        "is_oe_dbx": is_oe_dbx,
        "is_message_store": is_message_store,
        "message_subject_count": (
            len(subjects) if message_subject_count is None else message_subject_count
        ),
        "subjects": subjects,
        "senders": senders if senders is not None else [],
    }


class TestDeletedEmailCandidates:
    def test_deleted_items_store_with_messages_is_a_candidate(self) -> None:
        cands = fea.oe_dbx_deleted_email_candidates(
            [_store("Deleted Items.dbx", subjects=["RE: meeting", "fwd: keys"])]
        )
        assert len(cands) == 1
        c = cands[0]
        assert c["kind"] == "deleted_email"
        assert c["message_count"] == 2
        assert c["tool_call_id"] == "tc-del"

    def test_backslash_windows_source_name_still_matches(self) -> None:
        cands = fea.oe_dbx_deleted_email_candidates(
            [_store(r"C:\\Store\\Deleted Items.dbx", subjects=["a"])]
        )
        assert len(cands) == 1

    def test_sender_only_recovery_is_a_candidate(self) -> None:
        # Headers recovered from slack may yield a From: with no Subject:.
        cands = fea.oe_dbx_deleted_email_candidates(
            [_store("Deleted Items.dbx", subjects=[], senders=["bob@example.net"])]
        )
        assert len(cands) == 1
        assert cands[0]["message_count"] == 0  # no subjects, but recovered via sender

    def test_empty_deleted_items_store_is_not_a_candidate(self) -> None:
        # Trash emptied + store compacted: nothing recovered -> no lead (FP safety).
        assert (
            fea.oe_dbx_deleted_email_candidates(
                [_store("Deleted Items.dbx", subjects=[], senders=[])]
            )
            == []
        )

    def test_non_trash_folder_with_messages_is_not_a_candidate(self) -> None:
        # Inbox/Sent etc. are live mail, not recovered deleted email.
        assert fea.oe_dbx_deleted_email_candidates([_store("Inbox.dbx", subjects=["hello"])]) == []

    def test_folders_index_is_not_a_candidate(self) -> None:
        # Folders.dbx is the index, not a message store.
        assert (
            fea.oe_dbx_deleted_email_candidates(
                [_store("Deleted Items.dbx", is_message_store=False, subjects=["x"])]
            )
            == []
        )

    def test_non_oe_file_is_not_a_candidate(self) -> None:
        assert (
            fea.oe_dbx_deleted_email_candidates(
                [_store("Deleted Items.dbx", is_oe_dbx=False, subjects=["x"])]
            )
            == []
        )

    def test_empty_input_yields_nothing(self) -> None:
        assert fea.oe_dbx_deleted_email_candidates([]) == []


class TestDeletedEmailRecoveryEmitter:
    def _inv(self):
        inv = fea.Investigation("disk.img", unattended=True, with_report=False)
        inv.handle = {"id": "case-del"}
        return inv

    def _candidates(self):
        return [
            {
                "kind": "deleted_email",
                "source_name": "Deleted Items.dbx",
                "persisted_path": "/run/oe/000_Deleted Items.dbx",
                "tool_call_id": "tc-1",
                "message_count": 3,
                "subjects": ["RE: meeting", "fwd: keys"],
                "senders": [],
            },
            {
                "kind": "deleted_email",
                "source_name": "Deleted Items (1).dbx",
                "persisted_path": "/run/oe/001_Deleted Items (1).dbx",
                "tool_call_id": "tc-2",
                "message_count": 1,
                "subjects": ["old note"],
                "senders": [],
            },
        ]

    def test_candidates_become_one_hypothesis_pool_b_finding(self) -> None:
        inv = self._inv()
        inv._emit_deleted_email_recovery_finding(self._candidates())
        assert len(inv.findings_pool_b) == 1
        f = inv.findings_pool_b[0]
        assert f["confidence"] == "HYPOTHESIS"
        assert f["pool_origin"] == "B"
        # recovery is a data artifact -> no ATT&CK technique (never auto-CONFIRMED)
        assert f.get("mitre_technique") is None
        # distinct from the newsgroup-affiliation finding id
        assert f["finding_id"].startswith("f-B-oe-deleted-email")
        # primary = store with the most recovered messages (tc-1)
        assert f["tool_call_id"] == "tc-1"
        assert set(f["derived_from"]) == {"tc-1", "tc-2"}
        desc = f["description"].lower()
        assert "deleted" in desc and "deleted items" in desc
        assert "re: meeting" in desc  # actual recovered subject is reported
        # honesty boundary: artifact-only, no intent/intrusion/identity claim
        assert "not, on its own, evidence of intent" in desc
        assert "out of scope" in desc

    def test_no_candidates_emits_nothing(self) -> None:
        inv = self._inv()
        inv._emit_deleted_email_recovery_finding([])
        assert inv.findings_pool_b == []
