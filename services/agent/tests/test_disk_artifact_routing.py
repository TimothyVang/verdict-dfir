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


def test_chromium_history_under_profile_routes_to_browser_db() -> None:
    c = fea.classify_artifact_path(
        "Users/jsmith/AppData/Local/Google/Chrome/User Data/Default/History"
    )
    assert c["artifact_class"] == "browser_db"
    assert c["parser_tool"] == "browser_history"


def test_midnight_commander_history_is_not_browser_db() -> None:
    c = fea.classify_artifact_path(
        "Documents and Settings/Jean/.mc/history"
    )
    assert c["artifact_class"] != "browser_db"
    assert c["parser_tool"] != "browser_history"


def test_shell_history_named_history_is_not_browser_db() -> None:
    c = fea.classify_artifact_path("home/user/.local/share/fish/history")
    assert c["artifact_class"] != "browser_db"


def test_places_sqlite_still_routes_regardless_of_path() -> None:
    c = fea.classify_artifact_path("anywhere/places.sqlite")
    assert c["artifact_class"] == "browser_db"


def test_dotsqlite_still_routes_regardless_of_path() -> None:
    c = fea.classify_artifact_path("tmp/whatever.sqlite")
    assert c["artifact_class"] == "browser_db"
