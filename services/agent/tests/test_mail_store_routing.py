"""The carved ``mail_store`` class must reach the mail lane.

Before this, a disk image whose mail lived in an Outlook PST had ZERO mail
coverage: ``mail_store`` was not an extraction class at all, and the only mail
lane (Outlook Express ``.dbx``) was gated on a live filesystem mount that a
rootless run never has.
"""

from __future__ import annotations

import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402


def test_mail_store_is_an_extracted_disk_class() -> None:
    assert "mail_store" in fea.EXTRACTED_DISK_CLASSES


def test_disk_summary_tracks_the_mail_store_class() -> None:
    assert "mail_store" in fea._disk_summary_template()["artifact_counts"]


def test_extracted_investigation_hands_mail_stores_to_the_mail_lane() -> None:
    inv = fea.Investigation("disk.img", unattended=True, with_report=False)
    inv.handle = {"id": "case-route"}
    seen: list[list[dict]] = []
    inv.investigate_mail_stores = lambda rust, py, entries: seen.append(entries)  # type: ignore[method-assign]

    entries = [
        {
            "path": "/case/extracted/disk/mail_store/Users/x/Outlook/outlook.pst",
            "artifact_class": "mail_store",
            "evidence_type": "extracted_disk",
            "size_bytes": 2326528,
        }
    ]
    inv.investigate_extracted_disk_artifacts(_NullMcp(), _NullMcp(), entries)

    assert seen, "mail_store entries never reached investigate_mail_stores"
    assert seen[0][0]["artifact_class"] == "mail_store"


class _NullMcp:
    """Minimal stand-in: every tool call returns an empty, error-free result."""

    def call_tool(self, name, args, timeout=None):
        return {}

    def call_tool_async(self, name, args, timeout=None):
        return {}
