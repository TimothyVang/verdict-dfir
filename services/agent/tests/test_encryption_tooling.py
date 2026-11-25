"""Tests for the dual-use encryption-tooling prefetch detectors.

Before this detector the engine parsed ``GPG.EXE``, ``GPG4WIN-4.1.0.EXE``,
``KLEOPATRA.EXE``, ``BDEUNLOCK.EXE`` and ``BITLOCKERWIZARDELEV.EXE`` out of
Windows Prefetch and then said nothing about any of them: the only path from
``prefetch_parse`` to a finding was ``suspicious_prefetch_tool_hint``, whose
table covers hacking utilities only. Recall on the ``alihadi-09-encrypt``
golden was 0.

``detect_encryption_tooling`` turns those already-collected prefetch names into
Pool-B INFERRED findings. Load-bearing properties pinned here:

* The table is deliberately SEPARATE from ``SUSPICIOUS_PREFETCH_TOOL_HINTS``.
  Encryption tooling is dual-use, so it must never reach the hacking-tool
  escalation path.
* The findings are never appended to ``Investigation._prefetch_exec_findings``.
  That list is what ``_corroborate_execution_with_userassist`` promotes to
  CONFIRMED, and any CONFIRMED finding makes ``compute_verdict`` return
  SUSPICIOUS — which would break ``alihadi-09-encrypt``'s deliberate
  INDETERMINATE false-positive control.
* PRESENCE wording only — no finding may trip ``_claims_execution``: prefetch
  is a single artifact class, so an execution claim could not clear the
  >=2-artifact-class gate.
* The BitLocker volume claim is gated on the USER-FACING binaries
  (BdeUnlock / BitLockerWizard), never the always-resident service binaries
  (BdeUISrv / FVENotify) that appear on a stock Windows image.
* The findings genuinely satisfy the offline recall scorer's eligibility
  matcher against the real alihadi-09 golden (measured with the scorer's own
  ``_is_eligible``, not hoped for).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[3]
_SCRIPTS = _REPO / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402

from findevil_agent.accuracy import (  # noqa: E402
    MATCH_COVERAGE,
    MATCH_MIN_SHARED,
    _coverage,
    _is_eligible,
    _tokens,
)

CASE = "case-encrypt"
PREFETCH_DIR = "/case/extracted/disk/prefetch/Windows/Prefetch"


def _obs(name: str, run_count: int, tcid: str, artifact: str | None = None) -> dict:
    """One parsed prefetch observation, shaped like the wiring passes it."""
    pf = artifact or f"{name}-DEADBEEF.pf"
    return {
        "executable_name": name,
        "artifact_name": pf,
        "run_count": run_count,
        "artifact_path": f"{PREFETCH_DIR}/{pf}",
        "tool_call_id": tcid,
    }


# The binaries the real alihadi-09-encrypt run actually parsed out of Prefetch
# (quoted from /srv/verdict-lab/logs/goldens-local/alihadi-09-encrypt-run.log).
REAL_ALIHADI_09_OBSERVATIONS = [
    _obs("BDEUISRV.EXE", 3, "tc-bdeuisrv"),
    _obs("BDEUNLOCK.EXE", 2, "tc-bdeunlock"),
    _obs("BITLOCKERWIZARDELEV.EXE", 1, "tc-bitlockerwizard"),
    _obs("CMD.EXE", 19, "tc-cmd"),
    _obs("CONHOST.EXE", 49, "tc-conhost"),
    _obs("FVENOTIFY.EXE", 2, "tc-fvenotify"),
    _obs("GNUPG-W32-2.4.0_20221216-BIN.", 1, "tc-gnupg-w32"),
    _obs("GPG-AGENT.EXE", 6, "tc-gpg-agent"),
    _obs("GPG-CONNECT-AGENT.EXE", 3, "tc-gpg-connect"),
    _obs("GPG.EXE", 19, "tc-gpg"),
    _obs("GPG4WIN-4.1.0.EXE", 1, "tc-gpg4win"),
    _obs("GPGCONF.EXE", 13, "tc-gpgconf"),
    _obs("GPGME-W32SPAWN.EXE", 21, "tc-gpgme"),
    _obs("GPGSM.EXE", 12, "tc-gpgsm"),
    _obs("KLEOPATRA.EXE", 4, "tc-kleopatra"),
    _obs("LOGONUI.EXE", 4, "tc-logonui"),
]

# A stock Windows surface: BitLocker's always-resident service binaries plus
# ordinary system processes. Must produce nothing.
STOCK_WINDOWS_OBSERVATIONS = [
    _obs("BDEUISRV.EXE", 3, "tc-bdeuisrv"),
    _obs("FVENOTIFY.EXE", 2, "tc-fvenotify"),
    _obs("SVCHOST.EXE", 120, "tc-svchost"),
    _obs("EXPLORER.EXE", 40, "tc-explorer"),
    _obs("DLLHOST.EXE", 11, "tc-dllhost"),
]

OPENPGP_ID = "f-B-encryption-openpgp-artifacts"
BITLOCKER_ID = "f-B-encryption-volume-bitlocker"
TOOLING_ID = "f-B-encryption-tooling-present"


def _by_id(findings: list[dict]) -> dict[str, dict]:
    return {f["finding_id"]: f for f in findings}


def _detect(observations: list[dict], **kwargs) -> list[dict]:
    return fea.detect_encryption_tooling(observations, CASE, **kwargs)


# ---------------------------------------------------------------------------
# Hint table — classification, and separation from the hacking-tool table
# ---------------------------------------------------------------------------


class TestEncryptionToolPrefetchHint:
    def test_gpg_prefixed_binaries_classify_as_openpgp(self) -> None:
        for name in (
            "GPG.EXE",
            "GPG2.EXE",
            "GPG-AGENT.EXE",
            "GPGCONF.EXE",
            "GPGSM.EXE",
            "GPGME-W32SPAWN.EXE",
            "GPG4WIN-4.1.0.EXE",
        ):
            hit = fea.encryption_tool_prefetch_hint(name)
            assert hit is not None, name
            assert hit[0] == "openpgp", name

    def test_gnupg_and_kleopatra_classify_as_openpgp(self) -> None:
        assert fea.encryption_tool_prefetch_hint("GNUPG-W32-2.4.0_20221216-BIN.")[0] == "openpgp"
        assert fea.encryption_tool_prefetch_hint("KLEOPATRA.EXE")[0] == "openpgp"

    def test_container_tools_classify_as_container(self) -> None:
        for name in ("VERACRYPT.EXE", "TRUECRYPT.EXE", "AXCRYPT.EXE"):
            assert fea.encryption_tool_prefetch_hint(name)[0] == "container", name

    def test_user_facing_bitlocker_binaries_classify_as_bitlocker(self) -> None:
        assert fea.encryption_tool_prefetch_hint("BDEUNLOCK.EXE")[0] == "bitlocker"
        assert fea.encryption_tool_prefetch_hint("BITLOCKERWIZARDELEV.EXE")[0] == "bitlocker"

    def test_always_resident_bitlocker_service_binaries_do_not_match(self) -> None:
        # FP floor: these run on a stock Windows image whether or not any volume
        # is BitLocker-protected.
        for name in ("BDEUISRV.EXE", "FVENOTIFY.EXE", "BDESVC.DLL"):
            assert fea.encryption_tool_prefetch_hint(name) is None, name

    def test_ordinary_windows_binaries_do_not_match(self) -> None:
        for name in ("SVCHOST.EXE", "EXPLORER.EXE", "CMD.EXE", "NOTEPAD.EXE"):
            assert fea.encryption_tool_prefetch_hint(name) is None, name

    def test_matching_is_case_insensitive_and_path_tolerant(self) -> None:
        assert fea.encryption_tool_prefetch_hint("gpg.exe")[0] == "openpgp"
        assert (
            fea.encryption_tool_prefetch_hint(r"C:\Program Files\GnuPG\bin\gpg.exe")[0] == "openpgp"
        )

    def test_encryption_table_is_disjoint_from_the_hacking_tool_table(self) -> None:
        """Dual-use encryption tooling must never ride the hacking-tool path.

        ``suspicious_prefetch_tool_hint`` feeds ``_prefetch_exec_findings``,
        which is what UserAssist corroboration promotes to CONFIRMED.
        """
        for needle, _family, _desc in fea.ENCRYPTION_TOOL_PREFETCH_HINTS:
            assert fea.suspicious_prefetch_tool_hint(f"{needle}.EXE") is None, needle
        for name in ("GPG.EXE", "KLEOPATRA.EXE", "VERACRYPT.EXE", "BDEUNLOCK.EXE"):
            assert fea.suspicious_prefetch_tool_hint(name) is None, name


# ---------------------------------------------------------------------------
# Detector shape
# ---------------------------------------------------------------------------


class TestDetectorShape:
    def test_real_alihadi_09_observations_emit_all_three_findings(self) -> None:
        ids = set(_by_id(_detect(REAL_ALIHADI_09_OBSERVATIONS)))
        assert ids == {OPENPGP_ID, BITLOCKER_ID, TOOLING_ID}

    def test_every_finding_is_inferred_pool_b_and_cites_a_tool_call(self) -> None:
        for f in _detect(REAL_ALIHADI_09_OBSERVATIONS):
            assert f["case_id"] == CASE
            assert f["confidence"] == "INFERRED"
            assert f["pool_origin"] == "B"
            assert f["tool_call_id"]
            assert f["tool_call_id"] in f["derived_from"]
            assert f["artifact_path"]

    def test_mitre_techniques_match_what_the_artifact_attests(self) -> None:
        found = _by_id(_detect(REAL_ALIHADI_09_OBSERVATIONS))
        # On-disk OpenPGP material is obfuscated-data tooling (on-host).
        assert found[OPENPGP_ID]["mitre_technique"] == "T1027"
        # BitLocker volume presence has no honest technique — it is stock
        # Windows functionality, not adversary tradecraft.
        assert found[BITLOCKER_ID]["mitre_technique"] is None
        # Deliberately untagged. The golden's ae-004 key says T1588.002, but
        # that is an OFF-HOST pre-attack technique and
        # test_mitre_mappings.test_no_execution_artifact_tagged_obtain_capabilities
        # bans assigning it to a host-image artifact. Recall does not depend on
        # it: accuracy._is_eligible matches description tokens only.
        assert found[TOOLING_ID]["mitre_technique"] is None

    def test_no_finding_claims_the_off_host_obtain_capabilities_technique(self) -> None:
        for f in _detect(REAL_ALIHADI_09_OBSERVATIONS):
            assert f["mitre_technique"] != "T1588.002", f["finding_id"]
            assert "T1588" not in f["description"], f["finding_id"]

    def test_derived_from_cites_only_the_calls_that_observed_the_family(self) -> None:
        found = _by_id(_detect(REAL_ALIHADI_09_OBSERVATIONS))
        assert found[BITLOCKER_ID]["derived_from"] == ["tc-bdeunlock", "tc-bitlockerwizard"]
        # No unrelated prefetch call may be cited.
        for f in _detect(REAL_ALIHADI_09_OBSERVATIONS):
            assert "tc-cmd" not in f["derived_from"]
            assert "tc-bdeuisrv" not in f["derived_from"]
            assert "tc-fvenotify" not in f["derived_from"]

    def test_observed_binaries_are_named_in_the_descriptions(self) -> None:
        found = _by_id(_detect(REAL_ALIHADI_09_OBSERVATIONS))
        assert "GPG.EXE" in found[OPENPGP_ID]["description"]
        assert "BDEUNLOCK.EXE" in found[BITLOCKER_ID]["description"]
        assert "BITLOCKERWIZARDELEV.EXE" in found[BITLOCKER_ID]["description"]

    def test_dual_use_caveat_is_stated_in_every_finding(self) -> None:
        for f in _detect(REAL_ALIHADI_09_OBSERVATIONS):
            assert "presence alone is not malicious intent" in f["description"], f["finding_id"]

    def test_finding_id_for_callable_is_applied(self) -> None:
        findings = _detect(
            REAL_ALIHADI_09_OBSERVATIONS, finding_id_for=lambda base: f"{base}-cafe1234"
        )
        for f in findings:
            assert f["finding_id"].endswith("-cafe1234")

    def test_asserted_values_declare_the_primary_prefetch_facts(self) -> None:
        found = _by_id(_detect(REAL_ALIHADI_09_OBSERVATIONS))
        asserted = {a["path"]: a for a in found[BITLOCKER_ID]["asserted_values"]}
        assert asserted["run_count"]["expected"] == "2"
        assert asserted["run_count"]["match"] == "int"
        assert asserted["executable_name"]["expected"] == "BDEUNLOCK.EXE"
        assert asserted["executable_name"]["match"] == "exact"

    def test_unreported_executable_name_is_not_asserted(self) -> None:
        obs = [
            {
                "executable_name": None,
                "artifact_name": "GPG.EXE-9397A9C0.pf",
                "run_count": 19,
                "artifact_path": f"{PREFETCH_DIR}/GPG.EXE-9397A9C0.pf",
                "tool_call_id": "tc-gpg",
            }
        ]
        f = _by_id(_detect(obs))[OPENPGP_ID]
        assert [a["path"] for a in f["asserted_values"]] == ["run_count"]
        assert "GPG.EXE" in f["description"]


# ---------------------------------------------------------------------------
# Family gating
# ---------------------------------------------------------------------------


class TestFamilyGating:
    def test_bitlocker_only_host_makes_no_third_party_tooling_claim(self) -> None:
        """BitLocker ships with Windows — it is not obtained tooling (T1588.002)."""
        ids = set(_by_id(_detect([_obs("BDEUNLOCK.EXE", 2, "tc-bdeunlock")])))
        assert ids == {BITLOCKER_ID}

    def test_openpgp_only_host_makes_no_bitlocker_volume_claim(self) -> None:
        ids = set(_by_id(_detect([_obs("GPG.EXE", 19, "tc-gpg")])))
        assert ids == {OPENPGP_ID, TOOLING_ID}

    def test_container_tool_alone_emits_tooling_but_not_openpgp(self) -> None:
        ids = set(_by_id(_detect([_obs("VERACRYPT.EXE", 3, "tc-veracrypt")])))
        assert ids == {TOOLING_ID}


# ---------------------------------------------------------------------------
# False-positive floors
# ---------------------------------------------------------------------------


class TestFalsePositiveFloors:
    def test_stock_windows_prefetch_surface_emits_nothing(self) -> None:
        assert _detect(STOCK_WINDOWS_OBSERVATIONS) == []

    def test_empty_observation_list_emits_nothing(self) -> None:
        assert _detect([]) == []

    def test_observation_without_a_tool_call_id_is_dropped(self) -> None:
        assert _detect([_obs("GPG.EXE", 19, "")]) == []

    def test_no_finding_trips_the_execution_claim_predicate(self) -> None:
        for f in _detect(REAL_ALIHADI_09_OBSERVATIONS):
            assert not fea._claims_execution(f), f["description"]


# ---------------------------------------------------------------------------
# Verdict discipline — alihadi-09-encrypt is a false-positive control
# ---------------------------------------------------------------------------


class TestVerdictFpFloor:
    """``goldens/alihadi-09-encrypt`` expects INDETERMINATE on purpose: the mere
    presence of encryption tooling is not proof of malicious intent. CONFIRMED
    would make ``compute_verdict`` return SUSPICIOUS and fail the golden."""

    def test_no_encryption_finding_is_ever_confirmed(self) -> None:
        for f in _detect(REAL_ALIHADI_09_OBSERVATIONS):
            assert f["confidence"] == "INFERRED", f["finding_id"]

    def test_encryption_only_merged_set_stays_indeterminate(self) -> None:
        stub = object.__new__(fea.Investigation)
        verdict = fea.Investigation.compute_verdict(stub, _detect(REAL_ALIHADI_09_OBSERVATIONS))
        assert verdict == "INDETERMINATE"

    def _stub_investigation(self):
        inv = object.__new__(fea.Investigation)
        inv.handle = {"id": CASE}
        inv.evidence_inventory = None
        inv.findings_pool_b = []
        inv._prefetch_exec_findings = []
        return inv

    def test_emitter_never_feeds_the_userassist_confirmed_promotion_list(self) -> None:
        """``_prefetch_exec_findings`` is promoted to CONFIRMED whenever a
        UserAssist entry names the same binary. Encryption tooling must never
        enter that list, or a host where the user opened Kleopatra would flip
        to SUSPICIOUS."""
        inv = self._stub_investigation()
        fea.Investigation._emit_encryption_tooling_findings(inv, REAL_ALIHADI_09_OBSERVATIONS)
        assert len(inv.findings_pool_b) == 3
        assert inv._prefetch_exec_findings == []

    def test_userassist_promotion_cannot_reach_the_encryption_findings(self) -> None:
        """The promotion loop iterates ``_prefetch_exec_findings`` only.

        Exercised with a UserAssist index that DOES name every encryption
        binary, so this proves the encryption findings are unreachable by
        construction rather than merely unreached because the index was empty.
        """
        inv = self._stub_investigation()
        inv._userassist_exec_index = {
            "gpg.exe": ("tc-userassist-1", "2024-01-01T00:00:00Z"),
            "kleopatra.exe": ("tc-userassist-2", "2024-01-01T00:00:00Z"),
            "bdeunlock.exe": ("tc-userassist-3", "2024-01-01T00:00:00Z"),
        }
        inv.execution_corroboration = {}
        fea.Investigation._emit_encryption_tooling_findings(inv, REAL_ALIHADI_09_OBSERVATIONS)
        fea.Investigation._promote_prefetch_findings_with_userassist(inv)
        assert all(f["confidence"] == "INFERRED" for f in inv.findings_pool_b)
        assert inv._prefetch_exec_findings == []


# ---------------------------------------------------------------------------
# Golden eligibility — measured with the recall scorer's own matcher
# ---------------------------------------------------------------------------


def _golden_findings(case_id: str) -> dict[str, dict]:
    path = _REPO / "goldens" / case_id / "expected-findings.json"
    doc = json.loads(path.read_text(encoding="utf-8"))
    return {f["finding_id"]: f for f in doc["findings"]}


class TestGoldenEligibility:
    """Measured against the real golden with ``accuracy._is_eligible``."""

    def _run(self) -> dict[str, dict]:
        return _by_id(_detect(REAL_ALIHADI_09_OBSERVATIONS))

    def test_ae_001_gpg_artifacts_on_disk_is_recalled(self) -> None:
        expected = _golden_findings("alihadi-09-encrypt")["ae-001"]
        assert _is_eligible(expected, self._run()[OPENPGP_ID])

    def test_ae_002_encrypted_volume_present_is_recalled(self) -> None:
        expected = _golden_findings("alihadi-09-encrypt")["ae-002"]
        assert _is_eligible(expected, self._run()[BITLOCKER_ID])

    def test_ae_004_encryption_tooling_on_host_is_recalled(self) -> None:
        expected = _golden_findings("alihadi-09-encrypt")["ae-004"]
        assert _is_eligible(expected, self._run()[TOOLING_ID])

    def test_measured_coverage_clears_the_scorer_thresholds(self) -> None:
        """Report the numbers, do not just assert the boolean."""
        golden = _golden_findings("alihadi-09-encrypt")
        run = self._run()
        for exp_id, run_id in (
            ("ae-001", OPENPGP_ID),
            ("ae-002", BITLOCKER_ID),
            ("ae-004", TOOLING_ID),
        ):
            exp = golden[exp_id]
            exp_tokens = _tokens(exp.get("description"), exp.get("artifact_hint"))
            cand = _tokens(run[run_id].get("description"), run[run_id].get("artifact_path"))
            cov, shared = _coverage(exp_tokens, cand)
            print(
                f"{exp_id} <- {run_id}: shared={shared}/{len(exp_tokens)} "
                f"coverage={cov:.3f} (need coverage>={MATCH_COVERAGE}, "
                f"shared>={MATCH_MIN_SHARED})"
            )
            assert shared >= MATCH_MIN_SHARED
            assert cov >= MATCH_COVERAGE

    def test_ae_003_aes_files_is_honestly_not_claimed(self) -> None:
        """Residual, pinned so it is not quietly faked later: prefetch cannot
        show that AES-encrypted FILES exist. No emitted finding may match the
        ae-003 claim."""
        expected = _golden_findings("alihadi-09-encrypt")["ae-003"]
        assert not any(_is_eligible(expected, f) for f in self._run().values())
