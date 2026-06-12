"""Gap 5 registry-activity emitters — USB device history (USBSTOR).

T14 of the gap-5 recall plan: SYSTEM\\...\\Enum\\USBSTOR rows must surface as
Pool B (exfil-biased) HYPOTHESIS findings — USB insertion history is the
staging/exfil lead the NIST golden (nhc-002) expects. Device presence is
normal on most machines, so the epistemic level is HYPOTHESIS, never
CONFIRMED (a benign disk must not flip the verdict).
"""

from __future__ import annotations

import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402

USBSTOR_KEY = "ROOT\\ControlSet001\\Enum\\USBSTOR"
DEVICE_KEY = USBSTOR_KEY + "\\Disk&Ven_SanDisk&Prod_Cruzer&Rev_8.02"
SERIAL_KEY = DEVICE_KEY + "\\0774230FB1E0C2A2&0"


def _row(key_path: str, values: list[dict] | None = None, lw: str = "2004-08-26T15:40:00Z") -> dict:
    return {
        "key_path": key_path,
        "last_write_time_iso": lw,
        "values": values or [],
        "subkeys": [],
    }


def _val(name: str, data: str) -> dict:
    return {"name": name, "value_type": "RegSz", "data_str": data}


class TestUsbCandidates:
    def test_serial_level_row_is_a_candidate(self) -> None:
        rows = [
            _row(USBSTOR_KEY),
            _row(DEVICE_KEY),
            _row(SERIAL_KEY, [_val("FriendlyName", "SanDisk Cruzer USB Device")]),
        ]
        cands = fea.registry_usb_candidates(rows)
        assert len(cands) == 1
        c = cands[0]
        assert c["kind"] == "usb_device"
        assert c["vendor"] == "SanDisk"
        assert c["product"] == "Cruzer"
        assert c["serial"] == "0774230FB1E0C2A2&0"
        assert c["friendly_name"] == "SanDisk Cruzer USB Device"
        assert c["last_write_time_iso"] == "2004-08-26T15:40:00Z"

    def test_serial_row_without_friendlyname_still_candidates(self) -> None:
        rows = [_row(SERIAL_KEY)]
        cands = fea.registry_usb_candidates(rows)
        assert len(cands) == 1
        assert cands[0]["friendly_name"] is None

    def test_device_class_and_root_rows_are_not_candidates(self) -> None:
        assert fea.registry_usb_candidates([_row(USBSTOR_KEY), _row(DEVICE_KEY)]) == []

    def test_non_usbstor_rows_yield_nothing(self) -> None:
        rows = [_row("ROOT\\ControlSet001\\Services\\Spooler", [_val("ImagePath", "x")])]
        assert fea.registry_usb_candidates(rows) == []

    def test_empty_rows_yield_nothing(self) -> None:
        assert fea.registry_usb_candidates([]) == []


class TestPoolBUsbEmitter:
    def _inv(self):
        inv = fea.Investigation("memory.img", unattended=True, with_report=False)
        inv.handle = {"id": "case-usbtest"}
        return inv

    def test_usb_candidate_becomes_hypothesis_pool_b_finding(self) -> None:
        inv = self._inv()
        cand = {
            "kind": "usb_device",
            "vendor": "SanDisk",
            "product": "Cruzer",
            "serial": "0774230FB1E0C2A2&0",
            "friendly_name": "SanDisk Cruzer USB Device",
            "hive_key": SERIAL_KEY,
            "last_write_time_iso": "2004-08-26T15:40:00Z",
        }
        inv._emit_registry_activity_findings([cand], "/evidence/SYSTEM", USBSTOR_KEY, "tc-usb-1")
        assert len(inv.findings_pool_b) == 1
        f = inv.findings_pool_b[0]
        assert f["pool_origin"] == "B"
        assert f["tool_call_id"] == "tc-usb-1"
        assert f["confidence"] == "HYPOTHESIS"
        assert f["description"].startswith("hypothesis: ")
        assert f["mitre_technique"] == "T1052.001"
        assert f["finding_id"].startswith("f-B-usb-")
        # The claim is insertion HISTORY of an external drive — never that
        # data actually left on it.
        desc = f["description"].lower()
        assert "usb" in desc and "insertion history" in desc and "external" in desc

    def test_unknown_kind_is_skipped(self) -> None:
        inv = self._inv()
        inv._emit_registry_activity_findings(
            [{"kind": "mystery"}], "/evidence/SYSTEM", USBSTOR_KEY, "tc-usb-2"
        )
        assert inv.findings_pool_b == []
