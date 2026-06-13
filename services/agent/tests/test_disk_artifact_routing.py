"""Headless disk artifact routing for decoded Windows evidence classes."""

from __future__ import annotations

import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402


def test_extended_disk_classes_are_routed_to_extracted_investigation() -> None:
    expected = {
        "lnk",
        "recyclebin",
        "browser_db",
        "amcache",
        "legacy_evt",
        "ie_history",
        "thumbnail",
    }

    assert expected.issubset(fea.EXTRACTED_DISK_CLASSES)


def test_disk_summary_tracks_extended_classes() -> None:
    summary = fea._disk_summary_template()

    for artifact_class in (
        "lnk",
        "recyclebin",
        "browser_db",
        "amcache",
        "legacy_evt",
        "ie_history",
        "thumbnail",
    ):
        assert artifact_class in summary["artifact_counts"]
