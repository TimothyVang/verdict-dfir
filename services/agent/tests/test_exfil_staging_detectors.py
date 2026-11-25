"""R6 — exfil/staging detectors for the insider-exfil disk lane.

The NIST Data Leakage golden expects USB staging, a cloud-storage channel, an
anti-forensic wiping tool, archive staging and post-staging deletion. The disk
lane already drafts the USBSTOR lead; this module covers the four detectors that
did not exist:

* ``mft_anti_forensic_tool_candidates`` / ``prefetch_tool_executions`` — wiper
  tooling (Eraser / CCleaner / SDelete / BleachBit) on disk and executed.
* ``mft_cloud_sync_candidates`` / ``browser_cloud_service_candidates`` — a
  third-party cloud-sync client or a cloud/webmail URL in browser history.
* ``usn_staging_candidates`` — user archives created then deleted, plus the
  document/executable deletions that follow a staging event.

Every detector is a pure function over the raw tool row shapes so it can be
exercised without an Investigation.
"""

from __future__ import annotations

import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402


def _mft(full_path: str, **kw) -> dict:
    return {
        "record_number": kw.get("record_number", 1000),
        "full_path": full_path,
        "is_directory": kw.get("is_directory", False),
        "is_allocated": kw.get("is_allocated", True),
        "fn_created_iso": kw.get("created", "2015-03-25T14:57:31Z"),
        "si_created_iso": kw.get("created", "2015-03-25T14:57:31Z"),
    }


def _usn(usn: int, filename: str, flags: list[str], ts: str, mft_entry: int = 1) -> dict:
    return {
        "usn": usn,
        "timestamp_iso": ts,
        "filename": filename,
        "reason_flags": flags,
        "mft_entry": mft_entry,
    }


# --------------------------------------------------------------------------
# Anti-forensic wiping tools (T1070.004)
# --------------------------------------------------------------------------


class TestAntiForensicToolHint:
    def test_known_wipers_are_recognised(self) -> None:
        for name in ("Eraser.exe", "CCleaner64.exe", "sdelete64.exe", "bleachbit.exe"):
            assert fea.anti_forensic_tool_hint(name) is not None, name

    def test_hint_returns_label_and_t1070_technique(self) -> None:
        label, technique = fea.anti_forensic_tool_hint("ERASER 6.2.0.2962.EXE")
        assert "eraser" in label.lower()
        assert technique.startswith("T1070")

    def test_ordinary_binary_is_not_a_wiper(self) -> None:
        assert fea.anti_forensic_tool_hint("svchost.exe") is None
        assert fea.anti_forensic_tool_hint("chrome.exe") is None

    def test_ccleaner_installer_name_maps_to_ccleaner(self) -> None:
        label, _ = fea.anti_forensic_tool_hint("CCSETUP504.EXE")
        assert "ccleaner" in label.lower()


class TestMftAntiForensicCandidates:
    def test_installed_wiper_under_program_files_is_a_candidate(self) -> None:
        cands = fea.mft_anti_forensic_tool_candidates([_mft("Program Files/Eraser/Eraser.exe")])
        assert [c["tool"] for c in cands] == ["eraser"]
        assert cands[0]["evidence"] == "installed"

    def test_wiper_installer_in_user_download_dir_is_a_candidate(self) -> None:
        cands = fea.mft_anti_forensic_tool_candidates(
            [_mft("Users/informant/Desktop/Download/Eraser 6.2.0.2962.exe")]
        )
        assert [c["tool"] for c in cands] == ["eraser"]

    def test_prefetch_residue_is_recorded_as_execution_residue(self) -> None:
        cands = fea.mft_anti_forensic_tool_candidates(
            [_mft("Windows/Prefetch/CCLEANER64.EXE-779BD542.pf")]
        )
        assert [c["tool"] for c in cands] == ["ccleaner"]
        assert cands[0]["evidence"] == "prefetch_residue"

    def test_same_tool_is_deduped_across_rows(self) -> None:
        cands = fea.mft_anti_forensic_tool_candidates(
            [
                _mft("Program Files/Eraser/Eraser.exe"),
                _mft("Program Files/Eraser/Eraser.Manager.dll"),
                _mft("Users/informant/Desktop/Download/Eraser 6.2.0.2962.exe"),
            ]
        )
        assert len(cands) == 1

    def test_ordinary_system_paths_are_not_candidates(self) -> None:
        assert fea.mft_anti_forensic_tool_candidates([_mft("Windows/system32/svchost.exe")]) == []

    def test_empty_rows_yield_nothing(self) -> None:
        assert fea.mft_anti_forensic_tool_candidates([]) == []


class TestPrefetchToolExecutions:
    def test_parsed_prefetch_run_is_matched_against_a_hint_table(self) -> None:
        rows = [
            {
                "tool_call_id": "tc-pf-1",
                "executable_name": "ERASER.EXE",
                "run_count": 3,
                "artifact_path": "prefetch/ERASER.EXE-CE61944A.pf",
            },
            {
                "tool_call_id": "tc-pf-2",
                "executable_name": "SVCHOST.EXE",
                "run_count": 12,
                "artifact_path": "prefetch/SVCHOST.EXE-007FEA55.pf",
            },
        ]
        hits = fea.prefetch_tool_executions(rows, fea.anti_forensic_tool_hint)
        assert [h["tool_call_id"] for h in hits] == ["tc-pf-1"]
        assert hits[0]["run_count"] == 3
        assert hits[0]["tool"] == "eraser"

    def test_zero_run_count_is_not_execution(self) -> None:
        rows = [{"tool_call_id": "tc", "executable_name": "ERASER.EXE", "run_count": 0}]
        assert fea.prefetch_tool_executions(rows, fea.anti_forensic_tool_hint) == []


class TestAntiForensicEmitter:
    def _inv(self):
        inv = fea.Investigation("disk.dd", unattended=True, with_report=False)
        inv.handle = {"id": "case-af"}
        return inv

    def test_disk_plus_prefetch_evidence_becomes_one_pool_b_finding(self) -> None:
        inv = self._inv()
        inv._emit_anti_forensic_tool_finding(
            [
                {
                    "tool": "eraser",
                    "path": "Program Files/Eraser/Eraser.exe",
                    "evidence": "installed",
                    "created": "2015-03-25T14:57:31Z",
                    "tool_call_id": "tc-mft",
                    "artifact_path": "/ev/$MFT",
                }
            ],
            [
                {
                    "tool": "ccleaner",
                    "executable_name": "CCLEANER64.EXE",
                    "run_count": 2,
                    "tool_call_id": "tc-pf",
                    "artifact_path": "/ev/CCLEANER64.EXE-779BD542.pf",
                }
            ],
        )
        assert len(inv.findings_pool_b) == 1
        finding = inv.findings_pool_b[0]
        assert finding["mitre_technique"].startswith("T1070")
        assert finding["pool_origin"] == "B"
        assert sorted(finding["derived_from"]) == ["tc-mft", "tc-pf"]
        desc = finding["description"].lower()
        for token in ("anti-forensic", "wiping", "cleaning", "eraser", "ccleaner", "prefetch"):
            assert token in desc, token

    def test_no_candidates_emits_nothing(self) -> None:
        inv = self._inv()
        inv._emit_anti_forensic_tool_finding([], [])
        assert inv.findings_pool_b == []

    def test_two_disk_images_get_distinct_finding_ids(self) -> None:
        # A case can hold several images; each disk sweep emits its own finding.
        # Sharing one id makes the duplicate check reject the whole batch.
        inv = self._inv()
        for image in ("/ev/a/$MFT", "/ev/b/$MFT"):
            inv._emit_anti_forensic_tool_finding(
                [
                    {
                        "tool": "eraser",
                        "path": "Program Files/Eraser/Eraser.exe",
                        "evidence": "installed",
                        "created": "2015-03-25T14:57:31Z",
                        "tool_call_id": f"tc-{image}",
                        "artifact_path": image,
                    }
                ],
                [],
            )
        ids = [f["finding_id"] for f in inv.findings_pool_b]
        assert len(set(ids)) == 2, ids

    def test_finding_does_not_trip_the_exfiltration_two_prong_gate(self) -> None:
        inv = self._inv()
        inv._emit_anti_forensic_tool_finding(
            [
                {
                    "tool": "eraser",
                    "path": "Program Files/Eraser/Eraser.exe",
                    "evidence": "installed",
                    "created": "2015-03-25T14:57:31Z",
                    "tool_call_id": "tc-mft",
                    "artifact_path": "/ev/$MFT",
                }
            ],
            [],
        )
        assert not fea._claims_exfiltration(inv.findings_pool_b[0])


# --------------------------------------------------------------------------
# Cloud-storage sync channel (T1567.002)
# --------------------------------------------------------------------------


class TestCloudSyncClientHint:
    def test_third_party_sync_clients_are_recognised(self) -> None:
        for name in ("googledrivesync.exe", "Dropbox.exe", "MEGAsync.exe"):
            assert fea.cloud_sync_client_hint(name) is not None, name

    def test_os_bundled_onedrive_is_not_claimed_as_a_channel(self) -> None:
        # OneDrive ships with every modern Windows build; its presence carries no
        # signal and flagging it would fire on every benign host.
        assert fea.cloud_sync_client_hint("OneDrive.exe") is None
        assert fea.cloud_sync_client_hint("SkyDrive.exe") is None

    def test_unrelated_binary_with_a_substring_collision_is_not_a_client(self) -> None:
        # "mega" alone collides with the megasas/megasr storage drivers.
        assert fea.cloud_sync_client_hint("megasas.inf") is None


class TestMftCloudSyncCandidates:
    def test_sync_client_binary_is_a_candidate(self) -> None:
        cands = fea.mft_cloud_sync_candidates(
            [_mft("Program Files (x86)/Google/Drive/googledrivesync.exe")]
        )
        assert [c["service"] for c in cands] == ["google drive"]

    def test_user_profile_sync_folder_is_a_candidate(self) -> None:
        cands = fea.mft_cloud_sync_candidates([_mft("Users/informant/Google Drive/desktop.ini")])
        assert [c["service"] for c in cands] == ["google drive"]

    def test_storage_driver_inf_is_not_a_candidate(self) -> None:
        assert fea.mft_cloud_sync_candidates([_mft("Windows/inf/megasas.inf")]) == []

    def test_service_is_deduped(self) -> None:
        cands = fea.mft_cloud_sync_candidates(
            [
                _mft("Users/informant/Downloads/googledrivesync.exe"),
                _mft("Users/informant/Google Drive/desktop.ini"),
            ]
        )
        assert len(cands) == 1


class TestBrowserCloudServiceCandidates:
    def test_cloud_storage_url_is_classified(self) -> None:
        rows = [
            {
                "url": "https://drive.google.com/drive/my-drive",
                "title": "My Drive",
                "last_visit_time_iso": "2015-03-24T13:45:00Z",
                "visit_count": 4,
            }
        ]
        cands = fea.browser_cloud_service_candidates(rows)
        assert [c["kind"] for c in cands] == ["cloud_storage"]
        assert cands[0]["service"] == "google drive"

    def test_webmail_url_is_classified(self) -> None:
        rows = [
            {
                "url": "https://mail.google.com/mail/u/0/#inbox",
                "title": "Inbox",
                "last_visit_time_iso": "2015-03-24T14:00:00Z",
                "visit_count": 9,
            }
        ]
        cands = fea.browser_cloud_service_candidates(rows)
        assert [c["kind"] for c in cands] == ["webmail"]

    def test_plain_search_traffic_is_not_a_candidate(self) -> None:
        rows = [{"url": "https://www.google.com/webhp?hl=en", "visit_count": 8}]
        assert fea.browser_cloud_service_candidates(rows) == []


class TestCloudSyncEmitter:
    def _inv(self):
        inv = fea.Investigation("disk.dd", unattended=True, with_report=False)
        inv.handle = {"id": "case-cloud"}
        return inv

    def test_disk_and_prefetch_evidence_becomes_one_finding(self) -> None:
        inv = self._inv()
        inv._emit_cloud_sync_channel_finding(
            [
                {
                    "service": "google drive",
                    "path": "Users/informant/Google Drive/desktop.ini",
                    "created": "2015-03-23T20:05:32Z",
                    "tool_call_id": "tc-mft",
                    "artifact_path": "/ev/$MFT",
                }
            ],
            [
                {
                    "service": "google drive",
                    "executable_name": "GOOGLEDRIVESYNC.EXE",
                    "run_count": 5,
                    "tool_call_id": "tc-pf",
                    "artifact_path": "/ev/GOOGLEDRIVESYNC.EXE-841A0D94.pf",
                }
            ],
            [],
        )
        assert len(inv.findings_pool_b) == 1
        finding = inv.findings_pool_b[0]
        assert finding["mitre_technique"] == "T1567.002"
        assert sorted(finding["derived_from"]) == ["tc-mft", "tc-pf"]
        desc = finding["description"].lower()
        for token in ("cloud", "storage", "google", "drive", "channel"):
            assert token in desc, token

    def test_cloud_channel_finding_does_not_assert_exfiltration(self) -> None:
        # The two-prong gate (staging/collection + network movement) is not
        # satisfiable from disk artifacts alone; the finding must report the
        # channel, never an accomplished transfer.
        inv = self._inv()
        inv._emit_cloud_sync_channel_finding(
            [
                {
                    "service": "google drive",
                    "path": "Users/informant/Google Drive/desktop.ini",
                    "created": "2015-03-23T20:05:32Z",
                    "tool_call_id": "tc-mft",
                    "artifact_path": "/ev/$MFT",
                }
            ],
            [],
            [],
        )
        assert not fea._claims_exfiltration(inv.findings_pool_b[0])

    def test_no_candidates_emits_nothing(self) -> None:
        inv = self._inv()
        inv._emit_cloud_sync_channel_finding([], [], [])
        assert inv.findings_pool_b == []


# --------------------------------------------------------------------------
# USN staging + post-staging deletion
# --------------------------------------------------------------------------


class TestUsnStagingCandidates:
    def test_user_archive_created_then_deleted_is_staging(self) -> None:
        rows = [
            _usn(1, "loot.zip", ["FILE_CREATE", "DATA_EXTEND"], "2015-03-24T13:49:51Z"),
            _usn(2, "loot.zip", ["FILE_DELETE"], "2015-03-24T14:07:09Z"),
        ]
        out = fea.usn_staging_candidates(rows)
        assert [a["name"] for a in out["archives"]] == ["loot.zip"]
        assert out["archives"][0]["created_iso"] == "2015-03-24T13:49:51Z"

    def test_rename_from_a_document_is_recorded_as_the_disguise(self) -> None:
        rows = [
            _usn(1, "secret_design.pptx", ["RENAME_OLD_NAME"], "2015-03-24T13:49:51Z", 48389),
            _usn(2, "winter_advisory.zip", ["RENAME_NEW_NAME"], "2015-03-24T13:49:51Z", 48389),
            _usn(3, "winter_advisory.zip", ["FILE_DELETE"], "2015-03-24T14:07:09Z", 48389),
        ]
        out = fea.usn_staging_candidates(rows)
        assert out["archives"][0]["renamed_from"] == "secret_design.pptx"

    def test_windows_servicing_cab_is_not_user_archive_staging(self) -> None:
        rows = [
            _usn(1, "Windows6.1-KB2888049-x64.cab", ["FILE_CREATE"], "2015-03-22T15:15:51Z"),
            _usn(2, "Windows6.1-KB2888049-x64.cab", ["FILE_DELETE"], "2015-03-22T15:16:00Z"),
            _usn(3, "WSUSSCAN.cab", ["FILE_CREATE"], "2015-03-22T15:15:33Z"),
            _usn(4, "WSUSSCAN.cab", ["FILE_DELETE"], "2015-03-22T15:16:00Z"),
        ]
        assert fea.usn_staging_candidates(rows)["archives"] == []

    def test_cache_style_hex_archive_name_is_not_user_staging(self) -> None:
        rows = [
            _usn(1, "E9292211.gz", ["FILE_CREATE"], "2015-03-23T18:37:53Z"),
            _usn(2, "E9292211.gz", ["FILE_DELETE"], "2015-03-23T18:37:53Z"),
        ]
        assert fea.usn_staging_candidates(rows)["archives"] == []

    def test_archive_deleted_years_later_is_housekeeping_not_staging(self) -> None:
        # A software-install zip that sat on disk for years before removal is not
        # a collect-then-clean-up episode.
        rows = [
            _usn(1, "chocolatey.zip", ["FILE_CREATE"], "2019-03-19T13:21:28Z"),
            _usn(2, "chocolatey.zip", ["FILE_DELETE"], "2023-02-20T23:42:14Z"),
        ]
        assert fea.usn_staging_candidates(rows)["archives"] == []

    def test_machine_generated_deletion_names_are_not_staged_files(self) -> None:
        rows = [
            _usn(1, "loot.zip", ["FILE_CREATE"], "2015-03-24T13:49:51Z"),
            _usn(2, "__PSScriptPolicyTest_0gsy54vf.pe3.ps1", ["FILE_DELETE"], "2015-03-24T13:50:00Z"),
            _usn(3, "Config.Msi", ["FILE_DELETE"], "2015-03-24T13:50:01Z"),
            _usn(4, "c883.msi", ["FILE_DELETE"], "2015-03-24T13:50:02Z"),
            _usn(5, "~$proposal.docx", ["FILE_DELETE"], "2015-03-24T13:50:03Z"),
            _usn(6, "proposal.docx", ["FILE_DELETE"], "2015-03-24T13:50:04Z"),
            _usn(7, "loot.zip", ["FILE_DELETE"], "2015-03-24T14:07:09Z"),
        ]
        out = fea.usn_staging_candidates(rows)
        assert [d["name"] for d in out["post_staging_deletions"]] == ["proposal.docx"]

    def test_all_digit_filename_is_still_a_staged_document(self) -> None:
        # The installer-scratch filter keys on a hex stem containing a-f; an
        # all-digit user filename must survive it.
        rows = [
            _usn(1, "loot.zip", ["FILE_CREATE"], "2015-03-24T13:49:51Z"),
            _usn(2, "2015.xlsx", ["FILE_DELETE"], "2015-03-24T13:50:04Z"),
            _usn(3, "loot.zip", ["FILE_DELETE"], "2015-03-24T14:07:09Z"),
        ]
        out = fea.usn_staging_candidates(rows)
        assert [d["name"] for d in out["post_staging_deletions"]] == ["2015.xlsx"]

    def test_delete_before_create_is_not_staging(self) -> None:
        rows = [
            _usn(1, "loot.zip", ["FILE_DELETE"], "2015-03-24T13:00:00Z"),
            _usn(2, "loot.zip", ["FILE_CREATE"], "2015-03-24T13:49:51Z"),
        ]
        assert fea.usn_staging_candidates(rows)["archives"] == []

    def test_documents_deleted_right_after_staging_are_surfaced(self) -> None:
        rows = [
            _usn(1, "loot.zip", ["FILE_CREATE"], "2015-03-24T13:49:51Z"),
            _usn(2, "proposal.docx", ["FILE_DELETE"], "2015-03-24T13:51:23Z"),
            _usn(3, "addresses.xlsx", ["FILE_DELETE"], "2015-03-24T13:52:03Z"),
            _usn(4, "loot.zip", ["FILE_DELETE"], "2015-03-24T14:07:09Z"),
        ]
        out = fea.usn_staging_candidates(rows)
        assert sorted(d["name"] for d in out["post_staging_deletions"]) == [
            "addresses.xlsx",
            "proposal.docx",
        ]

    def test_deletions_far_from_any_staging_event_are_not_surfaced(self) -> None:
        rows = [
            _usn(1, "loot.zip", ["FILE_CREATE"], "2015-03-24T13:49:51Z"),
            _usn(2, "loot.zip", ["FILE_DELETE"], "2015-03-24T14:07:09Z"),
            _usn(3, "unrelated.docx", ["FILE_DELETE"], "2015-03-22T09:00:00Z"),
        ]
        assert fea.usn_staging_candidates(rows)["post_staging_deletions"] == []

    def test_no_staging_event_means_no_deletion_claim(self) -> None:
        rows = [_usn(1, "proposal.docx", ["FILE_DELETE"], "2015-03-24T13:51:23Z")]
        out = fea.usn_staging_candidates(rows)
        assert out["archives"] == []
        assert out["post_staging_deletions"] == []

    def test_empty_rows_are_safe(self) -> None:
        out = fea.usn_staging_candidates([])
        assert out == {"archives": [], "post_staging_deletions": []}


class TestUsnFindings:
    def _rows(self) -> list[dict]:
        return [
            _usn(1, "secret_design.pptx", ["RENAME_OLD_NAME"], "2015-03-24T13:49:51Z", 48389),
            _usn(2, "winter_advisory.zip", ["RENAME_NEW_NAME"], "2015-03-24T13:49:51Z", 48389),
            _usn(3, "proposal.docx", ["FILE_DELETE"], "2015-03-24T13:51:23Z", 51),
            _usn(4, "addresses.xlsx", ["FILE_DELETE"], "2015-03-24T13:52:03Z", 52),
            _usn(5, "winter_advisory.zip", ["FILE_DELETE"], "2015-03-24T14:07:09Z", 48389),
        ]

    def test_archive_staging_finding_still_emitted(self) -> None:
        findings = fea.usn_rows_to_findings(self._rows(), "tc-usn", "case", "/ev/$UsnJrnl-J")
        hit = [f for f in findings if f["finding_id"] == "f-B-usn-archive-staged-deleted"]
        assert len(hit) == 1
        assert hit[0]["mitre_technique"] == "T1560.001"
        desc = hit[0]["description"].lower()
        for token in ("archive", "staging", "timeline", "documents"):
            assert token in desc, token

    def test_post_staging_deletion_is_a_separate_finding(self) -> None:
        findings = fea.usn_rows_to_findings(self._rows(), "tc-usn", "case", "/ev/$UsnJrnl-J")
        hit = [f for f in findings if f["finding_id"] == "f-B-usn-post-staging-deletion"]
        assert len(hit) == 1
        assert hit[0]["mitre_technique"] == "T1070"
        desc = hit[0]["description"].lower()
        for token in ("usn", "journal", "delete", "records", "following", "immediately"):
            assert token in desc, token
        assert "proposal.docx" in hit[0]["description"]

    def test_findings_do_not_trip_the_exfiltration_gate(self) -> None:
        for finding in fea.usn_rows_to_findings(self._rows(), "tc", "case", "/ev/$J"):
            assert not fea._claims_exfiltration(finding), finding["finding_id"]

    def test_os_servicing_only_journal_yields_no_findings(self) -> None:
        rows = [
            _usn(1, "Windows6.1-KB2888049-x64.cab", ["FILE_CREATE"], "2015-03-22T15:15:51Z"),
            _usn(2, "Windows6.1-KB2888049-x64.cab", ["FILE_DELETE"], "2015-03-22T15:16:00Z"),
            _usn(3, "ntoskrnl.exe", ["FILE_CREATE"], "2015-03-22T15:16:04Z"),
            _usn(4, "ntoskrnl.exe", ["FILE_DELETE"], "2015-03-22T15:16:05Z"),
        ]
        assert fea.usn_rows_to_findings(rows, "tc", "case", "/ev/$J") == []


# --------------------------------------------------------------------------
# Budget / ordering fixes that let the detectors see the evidence at all
# --------------------------------------------------------------------------


class TestRegistryHivePriority:
    def test_machine_hives_are_triaged_before_per_user_hives(self) -> None:
        entries = [
            {"path": "registry/Users/informant/NTUSER.DAT"},
            {"path": "registry/Users/admin11/AppData/Local/Microsoft/Windows/UsrClass.dat"},
            {"path": "registry/Windows/System32/config/SYSTEM"},
            {"path": "registry/Windows/System32/config/SOFTWARE"},
        ]
        ordered = [e["path"] for e in fea._prioritize_registry_hives(entries)]
        assert ordered[0].endswith("SYSTEM")
        assert ordered[1].endswith("SOFTWARE")

    def test_live_machine_hive_still_precedes_its_backup(self) -> None:
        entries = [
            {"path": "registry/Windows/System32/config/RegBack/SYSTEM"},
            {"path": "registry/Windows/System32/config/SYSTEM"},
        ]
        ordered = [e["path"] for e in fea._prioritize_registry_hives(entries)]
        assert "RegBack" not in ordered[0]

    def test_ordering_is_stable_within_a_tier(self) -> None:
        entries = [
            {"path": "registry/Users/b/NTUSER.DAT"},
            {"path": "registry/Users/a/NTUSER.DAT"},
        ]
        ordered = [e["path"] for e in fea._prioritize_registry_hives(entries)]
        assert ordered == ["registry/Users/b/NTUSER.DAT", "registry/Users/a/NTUSER.DAT"]


class TestDiskRowLimits:
    def test_mft_limit_covers_a_whole_consumer_volume(self) -> None:
        # A 20 GB Windows 7 volume holds ~78k MFT records; the previous 5000-row
        # cap stopped inside Windows/ and never reached Users/ or Program Files.
        assert fea.DISK_MFT_ROW_LIMIT >= 100_000

    def test_usn_limit_covers_a_whole_journal(self) -> None:
        # The same volume's $J holds ~317k records; at 200k the scan stopped a
        # day before the staging activity.
        assert fea.DISK_USN_ROW_LIMIT >= 1_000_000
