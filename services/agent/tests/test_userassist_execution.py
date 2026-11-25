"""UserAssist / Compatibility-Assistant execution leads, decoupled from prefetch.

Before this, ``_corroborate_execution_with_userassist`` returned early unless a
prefetch execution finding already existed, so on a host whose Prefetch
directory had been wiped the engine never looked at UserAssist at all — even
though UserAssist (per-user GUI execution) and the Program Compatibility
Assistant Store both record the full path of the executed binary.

Two hard constraints shape the confidence policy here and are pinned below:

* An execution artifact pair for a binary in a **shared, world-writable** root
  (``C:\\Users\\Public\\``, ``ProgramData``, ``Windows\\Temp``) is CONFIRMED —
  no legitimate installer runs a program from there.
* The same pair for a binary in the user's **own** profile
  (``C:\\Users\\<name>\\AppData\\Local\\Downloads\\setup.exe``) is the single
  most common benign pattern on any Windows host and must stay INFERRED. The
  ``alihadi-09-encrypt`` false-positive control is exactly this shape — six
  user-downloaded installers recorded in BOTH UserAssist and the Compatibility
  Assistant Store — and ``compute_verdict`` escalates on ANY CONFIRMED finding,
  so a CONFIRMED here would flip that control's required INDETERMINATE verdict.
"""

from __future__ import annotations

import codecs
from datetime import datetime, timezone
import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402

from findevil_agent.entailment import check_entailment  # noqa: E402
from findevil_agent.events import AssertedValue  # noqa: E402

# The UserAssist "executable file execution" GUID; value names under its Count
# subkey are the ROT13 of the executed path.
_EXEC_GUID = "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}"
UA_COUNT_KEY = (
    "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\" + _EXEC_GUID + "\\Count"
)
COMPAT_STORE_KEY = (
    "Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\"
    "Compatibility Assistant\\Store"
)


def _rot13(text: str) -> str:
    return codecs.encode(text, "rot_13")


def _userassist_data(last_run_iso: str) -> str:
    when = datetime.fromisoformat(last_run_iso.replace("Z", "+00:00"))
    epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
    ticks = int((when - epoch).total_seconds() * 10_000_000)
    payload = bytearray(72)
    payload[60:68] = ticks.to_bytes(8, "little")
    return payload.hex()


def _row(
    key_path: str,
    names: list[str],
    lw: str = "2022-11-15T21:21:07Z",
    *,
    data_str: str | None = None,
) -> dict:
    """One ``registry_query`` entry. UserAssist/CompatStore carry the fact in the
    value NAME; the data is an opaque REG_BINARY blob."""
    return {
        "key_path": key_path,
        "last_write_time_iso": lw,
        "values": [
            {
                "name": n,
                "value_type": "REG_BINARY",
                "data_str": data_str if data_str is not None else "00" * 8,
            }
            for n in names
        ],
        "subkeys": [],
    }


def _raw_registry_output(rows: list[dict]) -> dict:
    """Mirror the serialized Rust ``RegistryOutput`` the verifier re-runs."""
    return {
        "entries": rows,
        "keys_visited": len(rows),
        "parse_errors": 0,
        "key_present": True,
    }


class TestUserAssistNameDecoding:
    def test_legacy_ueme_runpath_still_decodes(self) -> None:
        # XP-era shape. nist-hacking-case depends on this: 8 prefetch findings
        # are promoted to CONFIRMED off it, so the modern support below must be
        # purely additive.
        encoded = _rot13("UEME_RUNPATH:C:\\Program Files\\Cain\\Cain.exe")
        assert fea._userassist_exe(encoded) == "cain.exe"

    def test_modern_win7_plus_full_path_decodes(self) -> None:
        # Win7+ drops the UEME_RUNPATH prefix: the value name IS the path.
        encoded = _rot13("C:\\Users\\Public\\Downloads\\SysInternals.exe")
        assert fea._userassist_path(encoded) == "C:\\Users\\Public\\Downloads\\SysInternals.exe"
        assert fea._userassist_exe(encoded) == "sysinternals.exe"

    def test_knownfolder_relative_name_decodes(self) -> None:
        encoded = _rot13("{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\cmd.exe")
        assert fea._userassist_exe(encoded) == "cmd.exe"

    def test_non_execution_entries_are_ignored(self) -> None:
        for raw in (
            _rot13("UEME_CTLSESSION"),
            _rot13("UEME_CTLCUACount:ctor"),
            _rot13("UEME_RUNPIDL:C:\\Users\\bob\\Desktop"),
            _rot13("{01234}\\Accessories\\Snipping Tool.lnk"),
            "",
        ):
            assert fea._userassist_path(raw) is None, raw


class TestExecutionCandidates:
    def test_shared_public_root_userassist_entry_is_a_candidate(self) -> None:
        # The real alihadi-07 row shape, verified against registry_query on the
        # IEUser NTUSER.DAT carved out of the SysInternals E01.
        name = _rot13("C:\\Users\\Public\\Downloads\\SysInternals.exe")
        cands = fea.registry_execution_candidates([_row(UA_COUNT_KEY, [name])], UA_COUNT_KEY)
        assert len(cands) == 1
        c = cands[0]
        assert c["kind"] == "userassist_exec"
        assert c["exe_path"] == "C:\\Users\\Public\\Downloads\\SysInternals.exe"
        assert c["exe_name"] == "sysinternals.exe"
        assert c["shared_root"] is True
        assert c["value_name"] == name, "the raw encoded name is kept for entailment"

    def test_compat_store_entry_is_a_candidate(self) -> None:
        cands = fea.registry_execution_candidates(
            [_row(COMPAT_STORE_KEY, ["C:\\Users\\Public\\Downloads\\SysInternals.exe"])],
            COMPAT_STORE_KEY,
        )
        assert len(cands) == 1
        assert cands[0]["kind"] == "compatstore_exec"
        assert cands[0]["exe_name"] == "sysinternals.exe"
        assert cands[0]["shared_root"] is True

    def test_per_user_profile_path_is_a_candidate_but_not_shared(self) -> None:
        name = _rot13("C:\\Users\\IEUser\\AppData\\Local\\Downloads\\gpg4win-4.1.0.exe")
        cands = fea.registry_execution_candidates([_row(UA_COUNT_KEY, [name])], UA_COUNT_KEY)
        assert len(cands) == 1
        assert cands[0]["shared_root"] is False

    def test_system_and_program_files_paths_are_not_candidates(self) -> None:
        # These are not user-writable; every Windows host has dozens of them.
        for path in (
            "C:\\Windows\\System32\\cmd.exe",
            "C:\\Program Files\\HxD\\HxD.exe",
            "C:\\Program Files (x86)\\Gpg4win\\bin\\kleopatra.exe",
            "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\notepad.exe",
        ):
            assert (
                fea.registry_execution_candidates(
                    [_row(UA_COUNT_KEY, [_rot13(path)])], UA_COUNT_KEY
                )
                == []
            ), path
        assert (
            fea.registry_execution_candidates(
                [_row(COMPAT_STORE_KEY, ["C:\\Program Files\\HxD\\HxD.exe"])], COMPAT_STORE_KEY
            )
            == []
        )

    def test_unrelated_key_yields_nothing(self) -> None:
        run_key = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        assert fea.registry_execution_candidates([_row(run_key, ["Updater"])], run_key) == []


class TestTriagePlaybook:
    def test_ntuser_playbook_queries_userassist_and_compat_store(self) -> None:
        keys = fea.Investigation._registry_triage_keys(
            object.__new__(fea.Investigation), "/x/Users/IEUser/NTUSER.DAT"
        )
        assert any(k.lower().endswith("explorer\\userassist") for k in keys), keys
        assert any("compatibility assistant\\store" in k.lower() for k in keys), keys

    def test_userassist_is_queried_recursively(self) -> None:
        ua = next(
            k
            for k in fea.Investigation._registry_triage_keys(
                object.__new__(fea.Investigation), "NTUSER.DAT"
            )
            if k.lower().endswith("explorer\\userassist")
        )
        # The value names live two levels down, under <GUID>\Count.
        assert ua in fea._RECURSIVE_TRIAGE_KEYS

    def test_execution_keys_are_exempt_from_the_triage_budget(self) -> None:
        # On a real disk the 60-call triage budget is already exhausted before
        # the per-user hives are reached; an execution key that can be crowded
        # out is a key that silently never runs.
        keys = fea.Investigation._registry_triage_keys(
            object.__new__(fea.Investigation), "NTUSER.DAT"
        )
        exec_keys = [
            k
            for k in keys
            if k.lower().endswith("explorer\\userassist")
            or "compatibility assistant\\store" in k.lower()
        ]
        assert exec_keys
        for k in exec_keys:
            assert k in fea._EXECUTION_TRIAGE_KEYS, k


class TestExecutionFindingEmission:
    def _inv(self) -> fea.Investigation:
        inv = fea.Investigation("disk.E01", unattended=True, with_report=False)
        inv.handle = {"id": "case-uatest"}
        return inv

    def _record(
        self,
        inv,
        hive: str,
        key: str,
        tcid: str,
        names: list[str],
        *,
        data_str: str | None = None,
    ) -> None:
        rows = [_row(key, names, data_str=data_str)]
        inv._collect_registry_execution_candidates(rows, hive, key, tcid)

    def test_two_registry_artifacts_are_one_class_so_the_lead_stays_hypothesis(self) -> None:
        # UserAssist and the Compatibility Assistant Store are two independent
        # execution ARTIFACTS but both live in the registry, i.e. ONE artifact
        # class. CLAUDE.md/SOUL.md require >=2 CLASSES for an execution claim,
        # and report_qa's execution_requires_two_current_artifact_classes gate
        # counts classes, not artifacts — so anything above HYPOTHESIS here
        # would both over-claim and fail the engine's own release gate.
        inv = self._inv()
        hive = "/x/registry/Users/IEUser/NTUSER.DAT"
        self._record(
            inv,
            hive,
            UA_COUNT_KEY,
            "tc-ua-1",
            [_rot13("C:\\Users\\Public\\Downloads\\SysInternals.exe")],
        )
        self._record(
            inv,
            hive,
            COMPAT_STORE_KEY,
            "tc-cs-1",
            ["C:\\Users\\Public\\Downloads\\SysInternals.exe"],
        )
        inv._emit_registry_execution_findings()
        findings = inv.findings_pool_a + inv.findings_pool_b
        assert len(findings) == 1, findings
        f = findings[0]
        assert f["confidence"] == "HYPOTHESIS"
        assert f["mitre_technique"] == "T1204.002"
        assert "SysInternals.exe" in f["description"]
        assert "tc-ua-1" in f["derived_from"] and "tc-cs-1" in f["derived_from"]
        assert f["asserted_values"], "even a lead declares its re-extractable value"

    def test_confirmed_assertions_entail_against_raw_registry_output(self) -> None:
        inv = self._inv()
        hive = "/x/registry/Users/IEUser/NTUSER.DAT"
        encoded = _rot13("C:\\Users\\Public\\Downloads\\SysInternals.exe")
        self._record(inv, hive, UA_COUNT_KEY, "tc-ua-1", [encoded])
        self._record(
            inv,
            hive,
            COMPAT_STORE_KEY,
            "tc-cs-1",
            ["C:\\Users\\Public\\Downloads\\SysInternals.exe"],
        )
        inv._emit_registry_execution_findings()
        f = (inv.findings_pool_a + inv.findings_pool_b)[0]
        avs = [AssertedValue(**av) for av in f["asserted_values"]]
        out = _raw_registry_output([_row(UA_COUNT_KEY, [encoded])])
        assert check_entailment(avs, out).passed

    def test_misread_is_caught_when_the_value_is_absent_from_the_output(self) -> None:
        inv = self._inv()
        hive = "/x/registry/Users/IEUser/NTUSER.DAT"
        self._record(
            inv,
            hive,
            UA_COUNT_KEY,
            "tc-ua-1",
            [_rot13("C:\\Users\\Public\\Downloads\\SysInternals.exe")],
        )
        self._record(
            inv,
            hive,
            COMPAT_STORE_KEY,
            "tc-cs-1",
            ["C:\\Users\\Public\\Downloads\\SysInternals.exe"],
        )
        inv._emit_registry_execution_findings()
        f = (inv.findings_pool_a + inv.findings_pool_b)[0]
        avs = [AssertedValue(**av) for av in f["asserted_values"]]
        other = _raw_registry_output([_row(UA_COUNT_KEY, [_rot13("C:\\Users\\bob\\x.exe")])])
        assert not check_entailment(avs, other).passed

    def test_per_user_installer_with_prefetch_never_reaches_confirmed(self) -> None:
        # THE false-positive floor. alihadi-09-encrypt's IEUser hive records
        # these installers in BOTH registry execution artifacts, and its
        # Prefetch directory is intact so a genuine second artifact class also
        # records them. Two classes alone must not be enough: the golden
        # requires INDETERMINATE and compute_verdict escalates to SUSPICIOUS on
        # ANY CONFIRMED finding. The shared-root gate is what holds the floor.
        inv = self._inv()
        hive = "/x/registry/Users/IEUser/NTUSER.DAT"
        benign = [
            "C:\\Users\\IEUser\\AppData\\Local\\Downloads\\gpg4win-4.1.0.exe",
            "C:\\Users\\IEUser\\AppData\\Local\\Downloads\\7z2201-x64.exe",
            "C:\\Users\\IEUser\\AppData\\Local\\Downloads\\HxDSetup\\HxDSetup.exe",
        ]
        for path in benign:
            name = path.rsplit("\\", 1)[-1].lower()
            inv._prefetch_exec_index[name] = ("tc-pf-x", None)
        self._record(inv, hive, UA_COUNT_KEY, "tc-ua-1", [_rot13(p) for p in benign])
        self._record(inv, hive, COMPAT_STORE_KEY, "tc-cs-1", benign)
        inv._emit_registry_execution_findings()
        findings = inv.findings_pool_a + inv.findings_pool_b
        assert findings, "the leads are still surfaced"
        assert all(f["confidence"] != "CONFIRMED" for f in findings), [
            (f["finding_id"], f["confidence"]) for f in findings
        ]

    def test_single_artifact_class_in_a_user_profile_emits_nothing(self) -> None:
        # One registry key recording a user-downloaded installer is normal on
        # every host; with no corroborating class it is not worth a finding.
        inv = self._inv()
        self._record(
            inv,
            "/x/NTUSER.DAT",
            UA_COUNT_KEY,
            "tc-ua-1",
            [_rot13("C:\\Users\\IEUser\\AppData\\Local\\Downloads\\7z2201-x64.exe")],
        )
        inv._emit_registry_execution_findings()
        assert inv.findings_pool_a + inv.findings_pool_b == []

    def test_single_registry_artifact_in_a_shared_root_is_a_hypothesis_lead(self) -> None:
        inv = self._inv()
        self._record(
            inv,
            "/x/NTUSER.DAT",
            UA_COUNT_KEY,
            "tc-ua-1",
            [_rot13("C:\\ProgramData\\stager.exe")],
        )
        inv._emit_registry_execution_findings()
        findings = inv.findings_pool_a + inv.findings_pool_b
        assert len(findings) == 1
        assert findings[0]["confidence"] == "HYPOTHESIS"

    def test_any_parsed_prefetch_supplies_the_second_class(self) -> None:
        # The second class must come from ANY prefetch the lane parsed, not
        # only from the curated suspicious-tool hint list: a payload nobody has
        # named yet still leaves a .pf, and gating on the hint list would make
        # the corroboration depend on a name allowlist rather than on evidence.
        inv = self._inv()
        inv._prefetch_exec_index["stager.exe"] = ("tc-pf-1", "2019-03-19T13:00:00Z")
        self._record(
            inv,
            "/x/NTUSER.DAT",
            UA_COUNT_KEY,
            "tc-ua-1",
            [_rot13("C:\\ProgramData\\stager.exe")],
        )
        inv._emit_registry_execution_findings()
        f = (inv.findings_pool_a + inv.findings_pool_b)[0]
        assert f["confidence"] == "CONFIRMED"
        assert "tc-pf-1" in f["derived_from"]

    def test_prefetch_supplies_the_second_class_for_a_shared_root(self) -> None:
        # Prefetch is a genuinely DIFFERENT artifact class, so registry +
        # prefetch clears the two-class bar. Combined with a shared,
        # world-writable placement this is the one CONFIRMED shape.
        inv = self._inv()
        inv._prefetch_exec_index["stager.exe"] = ("tc-pf-1", None)
        self._record(
            inv,
            "/x/NTUSER.DAT",
            UA_COUNT_KEY,
            "tc-ua-1",
            [_rot13("C:\\ProgramData\\stager.exe")],
        )
        inv._emit_registry_execution_findings()
        f = (inv.findings_pool_a + inv.findings_pool_b)[0]
        assert f["confidence"] == "CONFIRMED"
        assert "tc-pf-1" in f["derived_from"]

    def test_matching_deleted_mft_path_uses_userassist_value_time(self) -> None:
        inv = self._inv()
        inv._index_mft_execution_paths(
            [
                {
                    "full_path": "Users/Public/Downloads/SysInternals.exe",
                    "is_allocated": False,
                    "fn_created_iso": "2022-11-15T21:18:51Z",
                }
            ],
            "/case/extracted/disk/disk-extract-1/mft/$MFT",
            "tc-mft-1",
        )
        self._record(
            inv,
            "/case/extracted/disk/disk-extract-1/registry/Users/IEUser/NTUSER.DAT",
            UA_COUNT_KEY,
            "tc-ua-1",
            [_rot13(r"C:\Users\Public\Downloads\SysInternals.exe")],
            data_str=_userassist_data("2022-11-15T21:19:00.261Z"),
        )

        inv._emit_registry_execution_findings()

        f = (inv.findings_pool_a + inv.findings_pool_b)[0]
        assert f["confidence"] == "CONFIRMED"
        assert f["derived_from"] == ["tc-ua-1", "tc-mft-1"]
        assert inv.execution_corroboration[f["finding_id"]] == ["tc-mft-1"]
        assert "MFT" in f["description"]

    def test_key_last_write_cannot_time_correlate_a_stale_userassist_value(self) -> None:
        inv = self._inv()
        inv._index_mft_execution_paths(
            [
                {
                    "full_path": "Users/Public/Downloads/SysInternals.exe",
                    "is_allocated": False,
                    "fn_created_iso": "2022-11-15T21:18:51Z",
                }
            ],
            "/case/extracted/disk/disk-extract-1/mft/$MFT",
            "tc-mft-1",
        )
        self._record(
            inv,
            "/case/extracted/disk/disk-extract-1/registry/Users/IEUser/NTUSER.DAT",
            UA_COUNT_KEY,
            "tc-ua-1",
            [_rot13(r"C:\Users\Public\Downloads\SysInternals.exe")],
            data_str=_userassist_data("2019-03-19T13:18:51Z"),
        )

        inv._emit_registry_execution_findings()

        f = (inv.findings_pool_a + inv.findings_pool_b)[0]
        assert f["confidence"] == "HYPOTHESIS"
        assert "tc-mft-1" not in f["derived_from"]

    def test_deleted_mft_row_needs_a_decodable_userassist_value_time(self) -> None:
        inv = self._inv()
        inv._index_mft_execution_paths(
            [
                {
                    "full_path": "Users/Public/Downloads/SysInternals.exe",
                    "is_allocated": False,
                    "fn_created_iso": "2022-11-15T21:18:51Z",
                }
            ],
            "/case/extracted/disk/disk-extract-1/mft/$MFT",
            "tc-mft-1",
        )
        self._record(
            inv,
            "/case/extracted/disk/disk-extract-1/registry/Users/IEUser/NTUSER.DAT",
            UA_COUNT_KEY,
            "tc-ua-1",
            [_rot13(r"C:\Users\Public\Downloads\SysInternals.exe")],
            data_str="not-hex",
        )

        inv._emit_registry_execution_findings()

        f = (inv.findings_pool_a + inv.findings_pool_b)[0]
        assert f["confidence"] == "HYPOTHESIS"

    def test_non_system_drive_does_not_join_drive_less_mft_path(self) -> None:
        inv = self._inv()
        inv._index_mft_execution_paths(
            [
                {
                    "full_path": "Users/Public/Downloads/SysInternals.exe",
                    "is_allocated": True,
                    "fn_created_iso": "2022-11-15T21:18:51Z",
                }
            ],
            "/case/extracted/disk/disk-extract-1/mft/$MFT",
            "tc-mft-1",
        )
        self._record(
            inv,
            "/case/extracted/disk/disk-extract-1/registry/Users/IEUser/NTUSER.DAT",
            UA_COUNT_KEY,
            "tc-ua-1",
            [_rot13(r"D:\Users\Public\Downloads\SysInternals.exe")],
        )

        inv._emit_registry_execution_findings()

        f = (inv.findings_pool_a + inv.findings_pool_b)[0]
        assert f["confidence"] == "HYPOTHESIS"

    def test_different_extracted_volume_does_not_join(self) -> None:
        inv = self._inv()
        inv._index_mft_execution_paths(
            [
                {
                    "full_path": "Users/Public/Downloads/SysInternals.exe",
                    "is_allocated": True,
                    "fn_created_iso": "2022-11-15T21:18:51Z",
                }
            ],
            "/case/extracted/disk/disk-extract-other/mft/$MFT",
            "tc-mft-other",
        )
        self._record(
            inv,
            "/case/extracted/disk/disk-extract-1/registry/Users/IEUser/NTUSER.DAT",
            UA_COUNT_KEY,
            "tc-ua-1",
            [_rot13(r"C:\Users\Public\Downloads\SysInternals.exe")],
        )

        inv._emit_registry_execution_findings()

        f = (inv.findings_pool_a + inv.findings_pool_b)[0]
        assert f["confidence"] == "HYPOTHESIS"

    def test_later_allocated_observation_beats_first_stale_deleted_row(self) -> None:
        inv = self._inv()
        inv._index_mft_execution_paths(
            [
                {
                    "full_path": "Users/Public/Downloads/SysInternals.exe",
                    "is_allocated": False,
                    "fn_created_iso": "2019-03-19T13:18:51Z",
                },
                {
                    "full_path": "Users/Public/Downloads/SysInternals.exe",
                    "is_allocated": True,
                    "fn_created_iso": "2022-11-15T21:18:51Z",
                },
            ],
            "/case/extracted/disk/disk-extract-1/mft/$MFT",
            "tc-mft-1",
        )
        self._record(
            inv,
            "/case/extracted/disk/disk-extract-1/registry/Users/IEUser/NTUSER.DAT",
            UA_COUNT_KEY,
            "tc-ua-1",
            [_rot13(r"C:\Users\Public\Downloads\SysInternals.exe")],
        )

        inv._emit_registry_execution_findings()

        f = (inv.findings_pool_a + inv.findings_pool_b)[0]
        assert f["confidence"] == "CONFIRMED"
        assert "tc-mft-1" in f["derived_from"]

    def test_same_basename_at_a_different_mft_path_does_not_corroborate(self) -> None:
        inv = self._inv()
        inv._index_mft_execution_paths(
            [
                {
                    "full_path": "Users/bob/Downloads/SysInternals.exe",
                    "is_allocated": True,
                    "fn_created_iso": "2022-11-15T21:18:51Z",
                }
            ],
            "/case/extracted/disk/disk-extract-1/mft/$MFT",
            "tc-mft-other",
        )
        self._record(
            inv,
            "/case/extracted/disk/disk-extract-1/registry/Users/IEUser/NTUSER.DAT",
            UA_COUNT_KEY,
            "tc-ua-1",
            [_rot13(r"C:\Users\Public\Downloads\SysInternals.exe")],
        )

        inv._emit_registry_execution_findings()

        f = (inv.findings_pool_a + inv.findings_pool_b)[0]
        assert f["confidence"] == "HYPOTHESIS"
        assert "tc-mft-other" not in f["derived_from"]

    def test_confirmed_finding_records_the_second_class_on_the_timeline(self) -> None:
        # report_qa's execution_requires_two_current_artifact_classes gate reads
        # artifact classes off the timeline events linked to the finding. A
        # CONFIRMED execution claim whose second class never reaches the
        # timeline fails the engine's own release gate.
        inv = self._inv()
        inv._prefetch_exec_index["stager.exe"] = ("tc-pf-1", None)
        self._record(
            inv,
            "/x/NTUSER.DAT",
            UA_COUNT_KEY,
            "tc-ua-1",
            [_rot13("C:\\ProgramData\\stager.exe")],
        )
        inv._emit_registry_execution_findings()
        f = (inv.findings_pool_a + inv.findings_pool_b)[0]
        assert inv.execution_corroboration.get(f["finding_id"]) == ["tc-pf-1"]

    def test_prefetch_in_a_user_profile_stays_below_confirmed(self) -> None:
        inv = self._inv()
        inv._prefetch_exec_index["setup.exe"] = ("tc-pf-1", None)
        self._record(
            inv,
            "/x/NTUSER.DAT",
            UA_COUNT_KEY,
            "tc-ua-1",
            [_rot13("C:\\Users\\bob\\Downloads\\setup.exe")],
        )
        inv._emit_registry_execution_findings()
        f = (inv.findings_pool_a + inv.findings_pool_b)[0]
        assert f["confidence"] == "INFERRED"


class TestUserAssistDecoupledFromPrefetch:
    def _inv(self) -> fea.Investigation:
        inv = fea.Investigation("disk.E01", unattended=True, with_report=False)
        inv.handle = {"id": "case-uatest"}
        return inv

    def test_execution_findings_emit_with_no_prefetch_findings_at_all(self) -> None:
        # The R3 bug: with self._prefetch_exec_findings empty the engine used to
        # never consult UserAssist. A wiped Prefetch directory is precisely when
        # UserAssist matters most.
        inv = self._inv()
        assert inv._prefetch_exec_findings == []
        hive = "/x/NTUSER.DAT"
        inv._collect_registry_execution_candidates(
            [_row(UA_COUNT_KEY, [_rot13("C:\\Users\\Public\\Downloads\\SysInternals.exe")])],
            hive,
            UA_COUNT_KEY,
            "tc-ua-1",
        )
        inv._collect_registry_execution_candidates(
            [_row(COMPAT_STORE_KEY, ["C:\\Users\\Public\\Downloads\\SysInternals.exe"])],
            hive,
            COMPAT_STORE_KEY,
            "tc-cs-1",
        )
        inv._emit_registry_execution_findings()
        assert inv.findings_pool_a + inv.findings_pool_b

    def test_prefetch_promotion_uses_the_playbook_userassist_index(self) -> None:
        # The promotion path (nist-hacking-case: 8 findings) keeps working, now
        # reading the UserAssist rows the per-hive playbook already fetched
        # instead of issuing its own duplicate registry_query per hive.
        inv = self._inv()
        finding = {
            "finding_id": "f-B-prefetch-cain",
            "tool_call_id": "tc-pf-1",
            "confidence": "INFERRED",
            "derived_from": ["tc-pf-1"],
        }
        inv._prefetch_exec_findings.append(("cain.exe", finding))
        inv._collect_registry_execution_candidates(
            [_row(UA_COUNT_KEY, [_rot13("UEME_RUNPATH:C:\\Program Files\\Cain\\Cain.exe")])],
            "/x/NTUSER.DAT",
            UA_COUNT_KEY,
            "tc-ua-1",
        )
        inv._promote_prefetch_findings_with_userassist()
        assert finding["confidence"] == "CONFIRMED"
        assert "tc-ua-1" in finding["derived_from"]
        assert inv.execution_corroboration["f-B-prefetch-cain"] == ["tc-ua-1"]


class TestAntiForensicToolHint:
    def test_sdelete_is_an_anti_forensic_prefetch_hint(self) -> None:
        hint = fea.suspicious_prefetch_tool_hint("SDELETE.EXE")
        assert hint is not None
        description, technique = hint
        assert technique == "T1070.004"
        assert "sdelete" in description.lower()

    def test_unrelated_binary_has_no_hint(self) -> None:
        assert fea.suspicious_prefetch_tool_hint("NOTEPAD.EXE") is None


class TestExtractionLimitationsPropagate:
    def test_disk_extract_analysis_limitations_reach_the_case(self) -> None:
        # disk_extract_artifacts now reports a Prefetch directory that yields
        # zero allocated files. That limitation must survive into the verdict —
        # a gap the engine drops on the floor is the same silent gap as before.
        inv = fea.Investigation("disk.E01", unattended=True, with_report=False)
        extracted = {
            "artifacts": [],
            "analysis_limitations": [
                "Windows Prefetch directory holds 195 entries and ZERO are allocated"
            ],
        }
        inv._record_disk_extract_limitations(extracted, "/evidence/case.E01")
        assert any(
            "Prefetch" in item for item in inv.analysis_limitations
        ), inv.analysis_limitations
