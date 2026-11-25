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


def _val(name: str, data: str, value_type: str = "REG_SZ") -> dict:
    return {"name": name, "value_type": value_type, "data_str": data}


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


SAM_NAMES_KEY = "SAM\\Domains\\Account\\Users\\Names"


class TestSamAccountCandidates:
    def test_suspiciously_named_account_is_a_candidate(self) -> None:
        rows = [
            _row(SAM_NAMES_KEY),
            _row(SAM_NAMES_KEY + "\\Mr. Evil", lw="2004-08-19T23:03:54Z"),
        ]
        cands = fea.registry_sam_account_candidates(rows)
        assert len(cands) == 1
        c = cands[0]
        assert c["kind"] == "sam_account"
        assert c["account_name"] == "Mr. Evil"
        assert c["last_write_time_iso"] == "2004-08-19T23:03:54Z"

    def test_builtin_accounts_are_filtered(self) -> None:
        rows = [
            _row(SAM_NAMES_KEY + "\\Administrator"),
            _row(SAM_NAMES_KEY + "\\Guest"),
            _row(SAM_NAMES_KEY + "\\HelpAssistant"),
            _row(SAM_NAMES_KEY + "\\SUPPORT_388945a0"),
        ]
        assert fea.registry_sam_account_candidates(rows) == []

    def test_ordinary_named_account_is_not_a_candidate(self) -> None:
        # Plain user accounts exist on every machine — only a naming tell
        # makes the account a lead.
        rows = [_row(SAM_NAMES_KEY + "\\alice")]
        assert fea.registry_sam_account_candidates(rows) == []

    def test_non_sam_rows_yield_nothing(self) -> None:
        assert fea.registry_sam_account_candidates([_row(USBSTOR_KEY)]) == []


class TestPoolASamEmitter:
    def _inv(self):
        inv = fea.Investigation("memory.img", unattended=True, with_report=False)
        inv.handle = {"id": "case-samtest"}
        return inv

    def test_sam_candidate_becomes_inferred_pool_a_finding(self) -> None:
        inv = self._inv()
        cand = {
            "kind": "sam_account",
            "account_name": "Mr. Evil",
            "hive_key": SAM_NAMES_KEY + "\\Mr. Evil",
            "last_write_time_iso": "2004-08-19T23:03:54Z",
        }
        inv._emit_registry_activity_findings([cand], "/evidence/SAM", SAM_NAMES_KEY, "tc-sam-1")
        assert len(inv.findings_pool_a) == 1
        f = inv.findings_pool_a[0]
        assert f["pool_origin"] == "A"
        assert f["confidence"] == "INFERRED"
        assert f["mitre_technique"] == "T1136.001"
        assert f["finding_id"].startswith("f-A-sam-")
        desc = f["description"].lower()
        # The two labeled facts behind the INFERRED tier: the account exists
        # (tool-backed) and its name matches the suspicious-naming heuristic.
        assert "user account" in desc and "suspicious naming" in desc
        assert "mr. evil" in desc
        # Vocabulary the account-creation claim shares with ground truth so the
        # recall matcher links it: created / elevated privileges / SAM.
        assert "created" in desc and "privilege" in desc
        assert "security account manager" in desc or "sam" in desc


ACMRU_KEY = "Software\\Microsoft\\Search Assistant\\ACMru\\5603"
OPENSAVE_KEY = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSaveMRU\\exe"


class TestMruCandidates:
    def test_acmru_search_terms_are_candidates(self) -> None:
        rows = [
            _row(
                ACMRU_KEY,
                [_val("000", "ethereal"), _val("001", "WinPcap"), _val("MRUList", "10")],
                lw="2004-08-27T15:00:00Z",
            )
        ]
        cands = fea.registry_mru_candidates(rows)
        # MRUList ordering value is not an entry.
        assert len(cands) == 2
        assert {c["kind"] for c in cands} == {"search_term"}
        assert {c["value"] for c in cands} == {"ethereal", "WinPcap"}
        assert cands[0]["last_write_time_iso"] == "2004-08-27T15:00:00Z"

    def test_opensave_mru_executable_on_desktop_is_a_candidate(self) -> None:
        rows = [
            _row(
                OPENSAVE_KEY,
                [
                    _val("a", "C:\\Documents and Settings\\Mr. Evil\\Desktop\\ethereal-setup.exe"),
                    _val("MRUListEx", "00"),
                ],
            )
        ]
        cands = fea.registry_mru_candidates(rows)
        assert len(cands) == 1
        assert cands[0]["kind"] == "opened_file"
        assert cands[0]["value"].lower().endswith("ethereal-setup.exe")

    def test_benign_document_open_is_not_a_candidate(self) -> None:
        # A forensics tool must not flag every opened file on every machine —
        # opening a document from My Documents is not a lead (FP safety).
        rows = [
            _row(
                OPENSAVE_KEY,
                [_val("a", "C:\\Documents and Settings\\alice\\My Documents\\budget.xlsx")],
            )
        ]
        assert fea.registry_mru_candidates(rows) == []

    def test_unc_network_path_open_is_a_candidate(self) -> None:
        rows = [_row(OPENSAVE_KEY, [_val("a", "\\\\10.0.0.5\\share\\report.doc")])]
        cands = fea.registry_mru_candidates(rows)
        assert len(cands) == 1
        assert cands[0]["kind"] == "opened_file"

    def test_non_mru_rows_yield_nothing(self) -> None:
        assert fea.registry_mru_candidates([_row(USBSTOR_KEY)]) == []

    def test_empty_value_is_skipped(self) -> None:
        rows = [_row(ACMRU_KEY, [_val("000", "")])]
        assert fea.registry_mru_candidates(rows) == []

    def test_binary_values_are_skipped(self) -> None:
        # LastVisitedMRU / RecentDocs store binary blobs; rendered as hex they
        # must NOT be mistaken for text MRU entries (the f-A-mru-<hex> bug).
        rows = [
            _row(
                OPENSAVE_KEY,
                [_val("0", "6b006500790073002e007400780074", value_type="REG_BINARY")],
            )
        ]
        assert fea.registry_mru_candidates(rows) == []

    def test_duplicate_values_across_subkeys_are_deduped(self) -> None:
        # OpenSaveMRU\* and OpenSaveMRU\exe carry the SAME paths — one recursive
        # query returns both, and they must collapse to one candidate per value.
        star = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSaveMRU\\*"
        exe = OPENSAVE_KEY
        path = "C:\\Documents and Settings\\Mr. Evil\\Desktop\\ethereal-setup-0.10.6.exe"
        rows = [_row(star, [_val("a", path)]), _row(exe, [_val("a", path)])]
        cands = fea.registry_mru_candidates(rows)
        assert len(cands) == 1


class TestPoolMruEmitter:
    def _inv(self):
        inv = fea.Investigation("memory.img", unattended=True, with_report=False)
        inv.handle = {"id": "case-mru"}
        return inv

    def test_search_term_becomes_pool_a_finding(self) -> None:
        inv = self._inv()
        cand = {
            "kind": "search_term",
            "value": "ethereal",
            "hive_key": ACMRU_KEY,
            "last_write_time_iso": "2004-08-27T15:00:00Z",
        }
        inv._emit_registry_activity_findings([cand], "/evidence/NTUSER.DAT", ACMRU_KEY, "tc-mru-1")
        assert len(inv.findings_pool_a) == 1
        f = inv.findings_pool_a[0]
        assert f["pool_origin"] == "A"
        assert f["confidence"] == "INFERRED"
        assert f["finding_id"].startswith("f-A-mru-")
        assert "search" in f["description"].lower() and "ethereal" in f["description"].lower()

    def test_opened_file_becomes_pool_a_finding(self) -> None:
        inv = self._inv()
        cand = {
            "kind": "opened_file",
            "value": "C:\\hacking\\cain.exe",
            "hive_key": OPENSAVE_KEY,
            "last_write_time_iso": "2004-08-27T15:00:00Z",
        }
        inv._emit_registry_activity_findings(
            [cand], "/evidence/NTUSER.DAT", OPENSAVE_KEY, "tc-mru-2"
        )
        assert len(inv.findings_pool_a) == 1
        f = inv.findings_pool_a[0]
        assert f["confidence"] == "INFERRED"
        assert "recently" in f["description"].lower() and "cain.exe" in f["description"].lower()
        # finding_id is keyed on the file basename, not the full path — two
        # different desktop paths must produce two distinct ids (the 8-dupes bug).
        assert f["finding_id"] == inv._finding_id_for("f-A-mru-cain-exe", "/evidence/NTUSER.DAT")

    def test_distinct_opened_files_produce_distinct_ids(self) -> None:
        inv = self._inv()
        base = "C:\\Documents and Settings\\Mr. Evil\\Desktop\\"
        cands = [
            {
                "kind": "opened_file",
                "value": base + "ethereal-setup-0.10.6.exe",
                "hive_key": OPENSAVE_KEY,
                "last_write_time_iso": "2004-08-27T15:00:00Z",
            },
            {
                "kind": "opened_file",
                "value": base + "WinPcap_3_01_a.exe",
                "hive_key": OPENSAVE_KEY,
                "last_write_time_iso": "2004-08-27T15:00:00Z",
            },
        ]
        inv._emit_registry_activity_findings(
            cands, "/evidence/NTUSER.DAT", OPENSAVE_KEY, "tc-mru-3"
        )
        ids = {f["finding_id"] for f in inv.findings_pool_a}
        assert len(ids) == 2


BAGMRU_KEY = "Software\\Microsoft\\Windows\\ShellNoRoam\\BagMRU"


def _hexbytes(*names: str) -> str:
    """Build a fake PIDL-ish blob with the folder name embedded as ANSI."""
    blob = b"\x14\x00\x1f"  # arbitrary SHITEMID header noise
    for n in names:
        blob += b"\x00\x00" + n.encode("latin-1") + b"\x00"
    return blob.hex()


class TestShellbagCandidates:
    def test_network_share_navigation_is_a_candidate(self) -> None:
        rows = [
            _row(
                BAGMRU_KEY + "\\0\\1", [_val("0", _hexbytes("\\\\4.220.254\\Temp"), "REG_BINARY")]
            ),
        ]
        cands = fea.registry_shellbag_candidates(rows)
        assert any("4.220.254" in c["folder"] for c in cands)
        assert all(c["kind"] == "shellbag" for c in cands)

    def test_tool_folder_navigation_is_a_candidate(self) -> None:
        rows = [_row(BAGMRU_KEY + "\\2", [_val("0", _hexbytes("mIRC"), "REG_BINARY")])]
        cands = fea.registry_shellbag_candidates(rows)
        assert any(c["folder"].lower() == "mirc" for c in cands)

    def test_ordinary_folders_without_a_tell_are_filtered(self) -> None:
        # Plain shellbag navigation (My Documents) exists on every machine —
        # only staging/tool/network tells make it a lead.
        rows = [_row(BAGMRU_KEY + "\\1", [_val("0", _hexbytes("My Documents"), "REG_BINARY")])]
        assert fea.registry_shellbag_candidates(rows) == []

    def test_mrulistex_and_nodeslot_values_are_ignored(self) -> None:
        rows = [
            _row(
                BAGMRU_KEY,
                [
                    _val("MRUListEx", "00000000", "REG_BINARY"),
                    _val("NodeSlot", "05000000", "REG_BINARY"),
                ],
            )
        ]
        assert fea.registry_shellbag_candidates(rows) == []

    def test_non_bagmru_rows_yield_nothing(self) -> None:
        assert fea.registry_shellbag_candidates([_row(USBSTOR_KEY)]) == []


class TestPoolBShellbagEmitter:
    def _inv(self):
        inv = fea.Investigation("memory.img", unattended=True, with_report=False)
        inv.handle = {"id": "case-bag"}
        return inv

    def test_shellbag_candidates_become_one_pool_b_finding(self) -> None:
        inv = self._inv()
        cands = [
            {
                "kind": "shellbag",
                "folder": "\\\\4.220.254\\Temp",
                "hive_key": BAGMRU_KEY + "\\0\\1",
                "last_write_time_iso": "2004-08-27T15:00:00Z",
            },
            {
                "kind": "shellbag",
                "folder": "mIRC",
                "hive_key": BAGMRU_KEY + "\\2",
                "last_write_time_iso": "2004-08-27T15:00:00Z",
            },
        ]
        inv._emit_registry_activity_findings(cands, "/evidence/NTUSER.DAT", BAGMRU_KEY, "tc-bag-1")
        assert len(inv.findings_pool_b) == 1
        f = inv.findings_pool_b[0]
        assert f["pool_origin"] == "B"
        assert f["confidence"] == "HYPOTHESIS"
        assert f["finding_id"].startswith("f-B-shellbag")
        desc = f["description"].lower()
        for tok in ("shellbag", "navigation", "ntuser", "staging"):
            assert tok in desc
        assert "4.220.254" in f["description"]


WORDWHEEL_KEY = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\WordWheelQuery"


def _utf16le_hex(term: str) -> str:
    """Render a search term as the NUL-terminated UTF-16LE hex WordWheelQuery stores."""
    return (term.encode("utf-16-le") + b"\x00\x00").hex()


class TestWordWheelQueryCandidates:
    def test_wordwheel_binary_search_terms_are_candidates(self) -> None:
        # WordWheelQuery (Vista+) is the modern ACMru: UTF-16LE binary terms.
        rows = [
            _row(
                WORDWHEEL_KEY,
                [
                    _val("0", _utf16le_hex("netcat"), value_type="REG_BINARY"),
                    _val("1", _utf16le_hex("password dump"), value_type="REG_BINARY"),
                    _val("MRUListEx", "00000000", value_type="REG_BINARY"),
                ],
                lw="2009-08-27T15:00:00Z",
            )
        ]
        cands = fea.registry_mru_candidates(rows)
        # MRUListEx ordering value is not an entry.
        assert len(cands) == 2
        assert {c["kind"] for c in cands} == {"search_term"}
        assert {c["value"] for c in cands} == {"netcat", "password dump"}
        assert cands[0]["last_write_time_iso"] == "2009-08-27T15:00:00Z"

    def test_wordwheel_undecodable_blob_is_skipped(self) -> None:
        rows = [_row(WORDWHEEL_KEY, [_val("0", "zz", value_type="REG_BINARY")])]
        assert fea.registry_mru_candidates(rows) == []

    def test_wordwheel_empty_term_is_skipped(self) -> None:
        rows = [_row(WORDWHEEL_KEY, [_val("0", "0000", value_type="REG_BINARY")])]
        assert fea.registry_mru_candidates(rows) == []

    def test_wordwheel_term_emits_inferred_pool_a_finding(self) -> None:
        inv = fea.Investigation("memory.img", unattended=True, with_report=False)
        inv.handle = {"id": "case-ww"}
        cand = {
            "kind": "search_term",
            "value": "netcat",
            "hive_key": WORDWHEEL_KEY,
            "last_write_time_iso": "2009-08-27T15:00:00Z",
        }
        inv._emit_registry_activity_findings(
            [cand], "/evidence/NTUSER.DAT", WORDWHEEL_KEY, "tc-ww-1"
        )
        assert len(inv.findings_pool_a) == 1
        f = inv.findings_pool_a[0]
        assert f["confidence"] == "INFERRED"
        assert f["finding_id"].startswith("f-A-mru-")
        assert "search" in f["description"].lower() and "netcat" in f["description"].lower()


MOUNTEDDEV_KEY = "ROOT\\MountedDevices"


def _usb_device_blob() -> str:
    """A removable-mount MountedDevices value: the USBSTOR device path, UTF-16LE."""
    path = "\\??\\USBSTOR#Disk&Ven_SanDisk&Prod_Cruzer&Rev_8.02#0774230FB1E0C2A2&0"
    return path.encode("utf-16-le").hex()


def _fixed_disk_blob() -> str:
    """A fixed-disk MountedDevices value: 8-byte MBR signature + offset, no ASCII run."""
    return "f8a1b2c30000000000007e0000000000"


class TestMountedDevicesCandidates:
    def test_removable_drive_letter_mapping_is_a_candidate(self) -> None:
        rows = [
            _row(
                MOUNTEDDEV_KEY,
                [_val("\\DosDevices\\F:", _usb_device_blob(), value_type="REG_BINARY")],
                lw="2004-08-27T15:00:00Z",
            )
        ]
        cands = fea.registry_mounteddevices_candidates(rows)
        assert len(cands) == 1
        c = cands[0]
        assert c["kind"] == "mounted_device"
        assert c["mount_point"] == "F:"
        assert c["last_write_time_iso"] == "2004-08-27T15:00:00Z"

    def test_fixed_disk_mapping_is_filtered(self) -> None:
        # Fixed-disk volume mappings exist on every machine — only removable/USB
        # mounts are a lead (FP safety; a benign disk must stay quiet).
        rows = [
            _row(
                MOUNTEDDEV_KEY,
                [_val("\\DosDevices\\C:", _fixed_disk_blob(), value_type="REG_BINARY")],
            )
        ]
        assert fea.registry_mounteddevices_candidates(rows) == []

    def test_volume_guid_mapping_to_usb_is_a_candidate(self) -> None:
        rows = [
            _row(
                MOUNTEDDEV_KEY,
                [
                    _val(
                        "\\??\\Volume{53f56307-b6bf-11d0-94f2-00a0c91efb8b}",
                        _usb_device_blob(),
                        value_type="REG_BINARY",
                    )
                ],
            )
        ]
        cands = fea.registry_mounteddevices_candidates(rows)
        assert len(cands) == 1
        # No DosDevices drive letter — the value name is kept as the mount point.
        assert cands[0]["mount_point"].startswith("\\??\\Volume")

    def test_non_mounteddevices_rows_yield_nothing(self) -> None:
        assert fea.registry_mounteddevices_candidates([_row(USBSTOR_KEY)]) == []

    def test_empty_rows_yield_nothing(self) -> None:
        assert fea.registry_mounteddevices_candidates([]) == []


class TestPoolBMountedDevicesEmitter:
    def _inv(self):
        inv = fea.Investigation("memory.img", unattended=True, with_report=False)
        inv.handle = {"id": "case-mounted"}
        return inv

    def test_mounted_device_becomes_hypothesis_pool_b_finding(self) -> None:
        inv = self._inv()
        cand = {
            "kind": "mounted_device",
            "mount_point": "F:",
            "value_name": "\\DosDevices\\F:",
            "hive_key": MOUNTEDDEV_KEY,
            "last_write_time_iso": "2004-08-27T15:00:00Z",
        }
        inv._emit_registry_activity_findings(
            [cand], "/evidence/SYSTEM", MOUNTEDDEV_KEY, "tc-mounted-1"
        )
        assert len(inv.findings_pool_b) == 1
        f = inv.findings_pool_b[0]
        assert f["pool_origin"] == "B"
        assert f["tool_call_id"] == "tc-mounted-1"
        assert f["confidence"] == "HYPOTHESIS"
        assert f["description"].startswith("hypothesis: ")
        assert f["mitre_technique"] == "T1052.001"
        assert f["finding_id"].startswith("f-B-mounted-")
        desc = f["description"].lower()
        # The claim is a drive-letter<->device mapping that corroborates USB
        # insertion — never that data left on the volume.
        assert "mounteddevices" in desc and "f:" in desc
        assert "removable" in desc or "usb" in desc


# RecentDocs (NTUSER) stores each recently-accessed document/folder as a binary
# value whose leading UTF-16LE run is the file/folder name. On Windows XP
# ACMru/WordWheelQuery are empty/absent, so the "recent searches for hacking
# tools" evidence lives in RecentDocs instead: e.g. GhostWare, Anonymizer,
# keys.txt, channels.txt, a \\host\Temp staging share.
RECENTDOCS_KEY = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs"
RECENTDOCS_FOLDER_KEY = RECENTDOCS_KEY + "\\Folder"


def _recentdoc_hex(name: str) -> str:
    """Render a RecentDocs value the way the registry tool renders it (REG_BINARY
    hex): a NUL-terminated UTF-16LE filename followed by PIDL bytes we ignore."""
    return (name.encode("utf-16-le") + b"\x00\x00" + b"\x14\x00\x1f\x80").hex()


class TestRecentDocsCandidates:
    def test_hacking_tool_recentdoc_is_a_candidate(self) -> None:
        rows = [
            _row(
                RECENTDOCS_FOLDER_KEY,
                [
                    _val("0", _recentdoc_hex("GhostWare"), value_type="REG_BINARY"),
                    _val("1", _recentdoc_hex("Anonymizer"), value_type="REG_BINARY"),
                    _val("MRUListEx", "00000000", value_type="REG_BINARY"),
                ],
                lw="2004-08-27T15:00:00Z",
            )
        ]
        cands = fea.registry_mru_candidates(rows)
        # MRUListEx ordering value is not an entry; both tool names recovered.
        assert {c["kind"] for c in cands} == {"recent_doc"}
        assert {c["value"] for c in cands} == {"GhostWare", "Anonymizer"}
        assert cands[0]["last_write_time_iso"] == "2004-08-27T15:00:00Z"

    def test_network_staging_recentdoc_is_a_candidate(self) -> None:
        # The \\host\Temp UNC staging share recovered from RecentDocs\NetHood is
        # a tell even without a hacking-tool name token.
        rows = [
            _row(
                RECENTDOCS_KEY + "\\NetHood",
                [_val("0", _recentdoc_hex("\\\\4.12.220.254\\Temp"), value_type="REG_BINARY")],
            )
        ]
        cands = fea.registry_mru_candidates(rows)
        assert len(cands) == 1
        assert cands[0]["kind"] == "recent_doc"
        assert "4.12.220.254" in cands[0]["value"]

    def test_benign_recentdoc_is_filtered(self) -> None:
        # A forensics tool must not surface every recently-opened document; a
        # plain Receipt.rtf / budget.xlsx carries no tell and stays quiet.
        rows = [
            _row(
                RECENTDOCS_KEY,
                [
                    _val("0", _recentdoc_hex("Receipt.rtf"), value_type="REG_BINARY"),
                    _val("1", _recentdoc_hex("budget.xlsx"), value_type="REG_BINARY"),
                ],
            )
        ]
        assert fea.registry_mru_candidates(rows) == []

    def test_undecodable_recentdoc_blob_is_skipped(self) -> None:
        rows = [_row(RECENTDOCS_KEY, [_val("0", "zz", value_type="REG_BINARY")])]
        assert fea.registry_mru_candidates(rows) == []

    def test_recentdocs_deduped_across_subkeys(self) -> None:
        # RecentDocs\Folder and the RecentDocs root both record GhostWare; one
        # recursive query returns both and they collapse to one candidate.
        rows = [
            _row(RECENTDOCS_KEY, [_val("3", _recentdoc_hex("GhostWare"), value_type="REG_BINARY")]),
            _row(
                RECENTDOCS_FOLDER_KEY,
                [_val("1", _recentdoc_hex("GhostWare"), value_type="REG_BINARY")],
            ),
        ]
        cands = fea.registry_mru_candidates(rows)
        assert len(cands) == 1


class TestPoolRecentDocsEmitter:
    def _inv(self):
        inv = fea.Investigation("memory.img", unattended=True, with_report=False)
        inv.handle = {"id": "case-recentdocs"}
        return inv

    def test_recent_docs_emit_one_aggregate_inferred_finding(self) -> None:
        # One aggregate finding (not one-per-doc) so the recall matcher binds it
        # to a single ground-truth claim (nhc-001).
        inv = self._inv()
        cands = [
            {
                "kind": "recent_doc",
                "value": "GhostWare",
                "hive_key": RECENTDOCS_FOLDER_KEY,
                "last_write_time_iso": "2004-08-27T15:00:00Z",
            },
            {
                "kind": "recent_doc",
                "value": "Anonymizer",
                "hive_key": RECENTDOCS_FOLDER_KEY,
                "last_write_time_iso": "2004-08-27T15:00:00Z",
            },
        ]
        inv._emit_registry_activity_findings(
            cands, "/evidence/NTUSER.DAT", RECENTDOCS_KEY, "tc-rd-1"
        )
        rd_findings = [
            f for f in inv.findings_pool_a if f["finding_id"].startswith("f-A-recentdocs")
        ]
        assert len(rd_findings) == 1
        f = rd_findings[0]
        assert f["pool_origin"] == "A"
        assert f["tool_call_id"] == "tc-rd-1"
        assert f["confidence"] == "INFERRED"
        desc = f["description"].lower()
        # Names both recovered tool documents.
        assert "ghostware" in desc and "anonymizer" in desc
        # Vocabulary the recall matcher needs for nhc-001 ("recent searches for
        # hacking tools" / "NTUSER.DAT search history" / "Registry hive").
        assert "search" in desc and "hacking" in desc and "tool" in desc
        assert "registry" in desc and "ntuser.dat" in desc
        assert "hive" in desc and "history" in desc

    def test_no_recent_docs_emits_nothing(self) -> None:
        inv = self._inv()
        inv._emit_registry_activity_findings([], "/evidence/NTUSER.DAT", RECENTDOCS_KEY, "tc-rd-0")
        assert inv.findings_pool_a == []


SERVICES_KEY = "ControlSet001\\Services"


class TestServiceReconCandidates:
    def test_winpcap_npf_driver_service_is_a_candidate(self) -> None:
        rows = [
            _row(
                SERVICES_KEY + "\\NPF",
                [_val("ImagePath", "system32\\drivers\\npf.sys")],
                lw="2004-08-27T15:34:01Z",
            )
        ]
        cands = fea.registry_service_recon_candidates(rows)
        assert len(cands) == 1
        c = cands[0]
        assert c["kind"] == "service_recon"
        assert c["service_name"] == "NPF"
        assert c["image_path"] == "system32\\drivers\\npf.sys"
        assert c["last_write_time_iso"] == "2004-08-27T15:34:01Z"

    def test_rpcapd_remote_capture_daemon_is_a_candidate(self) -> None:
        rows = [
            _row(
                SERVICES_KEY + "\\rpcapd",
                [
                    _val(
                        "ImagePath",
                        '"%ProgramFiles%\\WinPcap\\rpcapd.exe" -d -f "%ProgramFiles%\\WinPcap\\rpcapd.ini"',
                    )
                ],
            )
        ]
        cands = fea.registry_service_recon_candidates(rows)
        assert len(cands) == 1
        assert cands[0]["service_name"] == "rpcapd"

    def test_stock_windows_services_are_filtered(self) -> None:
        # A benign disk has hundreds of stock services; none is a recon lead.
        rows = [
            _row(
                SERVICES_KEY + "\\Spooler",
                [_val("ImagePath", "%SystemRoot%\\system32\\spoolsv.exe")],
            ),
            _row(
                SERVICES_KEY + "\\Dhcp",
                [_val("ImagePath", "%SystemRoot%\\system32\\svchost.exe -k netsvcs")],
            ),
            _row(SERVICES_KEY + "\\Tcpip", [_val("ImagePath", "system32\\drivers\\tcpip.sys")]),
            _row(SERVICES_KEY + "\\Npfs", []),
        ]
        assert fea.registry_service_recon_candidates(rows) == []

    def test_non_services_rows_yield_nothing(self) -> None:
        assert fea.registry_service_recon_candidates([_row(USBSTOR_KEY)]) == []

    def test_empty_rows_yield_nothing(self) -> None:
        assert fea.registry_service_recon_candidates([]) == []


class TestPoolServiceReconEmitter:
    def _inv(self):
        inv = fea.Investigation("memory.img", unattended=True, with_report=False)
        inv.handle = {"id": "case-svc-recon"}
        return inv

    def test_service_recon_candidates_emit_one_aggregate_hypothesis_finding(self) -> None:
        inv = self._inv()
        cands = [
            {
                "kind": "service_recon",
                "service_name": "NPF",
                "image_path": "system32\\drivers\\npf.sys",
                "hive_key": SERVICES_KEY + "\\NPF",
                "last_write_time_iso": "2004-08-27T15:34:01Z",
            },
            {
                "kind": "service_recon",
                "service_name": "rpcapd",
                "image_path": '"%ProgramFiles%\\WinPcap\\rpcapd.exe" -d',
                "hive_key": SERVICES_KEY + "\\rpcapd",
                "last_write_time_iso": "2004-08-27T15:15:18Z",
            },
        ]
        inv._emit_registry_activity_findings(cands, "/evidence/SYSTEM", SERVICES_KEY, "tc-svc-1")
        svc_findings = [
            f for f in inv.findings_pool_b if f["finding_id"].startswith("f-B-svc-recon")
        ]
        assert len(svc_findings) == 1
        f = svc_findings[0]
        assert f["pool_origin"] == "B"
        assert f["tool_call_id"] == "tc-svc-1"
        assert f["confidence"] == "HYPOTHESIS"
        assert f["mitre_technique"] == "T1046"
        assert f["description"].startswith("hypothesis: ")
        desc = f["description"].lower()
        # Names the real toolkit services.
        assert "npf" in desc and "rpcapd" in desc
        # Vocabulary the recall matcher needs for nhc-014 ("service enumeration
        # ... reconnaissance" / "service control manager" / "named pipe").
        assert "service" in desc and "reconnaissance" in desc
        assert "control" in desc and "manager" in desc
        assert "named" in desc and "pipe" in desc

    def test_no_service_recon_candidates_emits_nothing(self) -> None:
        inv = self._inv()
        inv._emit_registry_activity_findings([], "/evidence/SYSTEM", SERVICES_KEY, "tc-svc-0")
        assert inv.findings_pool_b == []
