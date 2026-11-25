"""Registry triage hive prioritization — live hives before backup hives.

A SCHARDT (NIST Hacking Case) extraction contains BOTH the live SYSTEM hive
(``WINDOWS/system32/config/system``) and a stale backup copy
(``WINDOWS/repair/system``). The triage loop has a per-run registry_query budget;
when the backup hive is iterated first it can consume the budget before the live
hive's USBSTOR / MountedDevices keys are ever queried, so a real USB-history /
mounted-device lead is silently lost behind an empty backup hive.

``_prioritize_registry_hives`` is a pure helper that sorts the discovered
registry hives so the live system32/config hives and live user-profile NTUSER
hives are triaged before backup copies (``repair/``, ``RegBack/``). It does not
drop the backup hives — they are still queried if budget remains — it only
ensures the live hive is never starved.
"""

from __future__ import annotations

import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402


def _entry(path: str) -> dict:
    return {"path": path, "artifact_class": "registry", "evidence_type": "extracted_disk"}


class TestPrioritizeRegistryHives:
    def test_live_system_hive_ordered_before_repair_backup(self) -> None:
        backup = _entry("registry/WINDOWS/repair/system")
        live = _entry("registry/WINDOWS/system32/config/system")
        ordered = fea._prioritize_registry_hives([backup, live])
        paths = [e["path"] for e in ordered]
        assert paths.index("registry/WINDOWS/system32/config/system") < paths.index(
            "registry/WINDOWS/repair/system"
        )

    def test_live_ntuser_ordered_before_repair_ntuser(self) -> None:
        backup = _entry("registry/WINDOWS/repair/ntuser.dat")
        live = _entry("registry/Documents and Settings/Mr. Evil/NTUSER.DAT")
        ordered = fea._prioritize_registry_hives([backup, live])
        paths = [e["path"] for e in ordered]
        assert paths.index("registry/Documents and Settings/Mr. Evil/NTUSER.DAT") < paths.index(
            "registry/WINDOWS/repair/ntuser.dat"
        )

    def test_regback_backup_is_deprioritized(self) -> None:
        backup = _entry("registry/Windows/System32/config/RegBack/SYSTEM")
        live = _entry("registry/Windows/System32/config/SYSTEM")
        ordered = fea._prioritize_registry_hives([backup, live])
        # Live config hive wins over the RegBack copy.
        assert ordered[0]["path"] == "registry/Windows/System32/config/SYSTEM"

    def test_no_backup_hives_preserves_input_order(self) -> None:
        a = _entry("registry/Windows/System32/config/SYSTEM")
        b = _entry("registry/Windows/System32/config/SOFTWARE")
        c = _entry("registry/Users/bob/NTUSER.DAT")
        ordered = fea._prioritize_registry_hives([a, b, c])
        # Stable: same relative order when nothing is a backup.
        assert [e["path"] for e in ordered] == [a["path"], b["path"], c["path"]]

    def test_backup_hives_are_kept_not_dropped(self) -> None:
        backup = _entry("registry/WINDOWS/repair/system")
        live = _entry("registry/WINDOWS/system32/config/system")
        ordered = fea._prioritize_registry_hives([backup, live])
        assert len(ordered) == 2
        assert {e["path"] for e in ordered} == {backup["path"], live["path"]}

    def test_empty_input_yields_empty(self) -> None:
        assert fea._prioritize_registry_hives([]) == []
