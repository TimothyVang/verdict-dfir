"""Pool A disk-persistence emitters — registry Run/RunOnce + Services triage.

Extracted-disk registry data must produce Pool A persistence Findings (it
previously fed only the timeline), so the two-team debate and
detect_contradictions can fire on disk-only cases.
"""

from __future__ import annotations

import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402

from findevil_agent.entailment import check_entailment  # noqa: E402
from findevil_agent.events import AssertedValue  # noqa: E402

RUN_KEY = "ROOT\\Microsoft\\Windows\\CurrentVersion\\Run"
SVC_KEY = "ROOT\\ControlSet001\\Services"


def _row(key_path: str, values: list[dict], lw: str = "2018-09-06T19:00:00Z") -> dict:
    return {"key_path": key_path, "last_write_time_iso": lw, "values": values, "subkeys": []}


def _val(name: str, data: str) -> dict:
    return {"name": name, "value_type": "RegSz", "data_str": data}


class TestRunKeyCandidates:
    def test_user_writable_target_is_a_candidate(self) -> None:
        rows = [_row(RUN_KEY, [_val("Updater", "C:\\Users\\bob\\AppData\\Roaming\\evil.exe")])]
        cands = fea.registry_persistence_candidates(rows, RUN_KEY)
        assert len(cands) == 1
        c = cands[0]
        assert c["kind"] == "run_key"
        assert c["value_name"] == "Updater"
        assert c["target"].lower().endswith("evil.exe")
        assert c["hive_key"] == RUN_KEY

    def test_quoted_target_with_args_parses(self) -> None:
        rows = [
            _row(
                RUN_KEY,
                [_val("Sync", '"C:\\Users\\x\\AppData\\Local\\Temp\\payload.exe" -silent')],
            )
        ]
        cands = fea.registry_persistence_candidates(rows, RUN_KEY)
        assert len(cands) == 1
        assert cands[0]["target"].lower().endswith("payload.exe")

    def test_benign_value_name_is_filtered(self) -> None:
        rows = [
            _row(
                RUN_KEY,
                [_val("SecurityHealth", "C:\\Windows\\System32\\SecurityHealthSystray.exe")],
            )
        ]
        assert fea.registry_persistence_candidates(rows, RUN_KEY) == []

    def test_common_windows_binary_in_system_dir_is_filtered(self) -> None:
        rows = [_row(RUN_KEY, [_val("Host", "C:\\Windows\\System32\\svchost.exe")])]
        assert fea.registry_persistence_candidates(rows, RUN_KEY) == []

    def test_unqualified_stock_autostart_commands_are_filtered(self) -> None:
        rows = [
            _row(
                RUN_KEY,
                [
                    _val("SRFirstRun", "rundll32 srclient.dll"),
                    _val("SchedulingAgent", "mstinit.exe"),
                ],
            )
        ]
        assert fea.registry_persistence_candidates(rows, RUN_KEY) == []

    def test_known_attack_tool_is_a_candidate_even_outside_user_dirs(self) -> None:
        # suspicious_prefetch_tool_hint knows CAIN — the tell fires on the
        # basename even when the path is not user-writable.
        rows = [_row(RUN_KEY, [_val("cain", "C:\\Tools\\CAIN.EXE")])]
        cands = fea.registry_persistence_candidates(rows, RUN_KEY)
        assert len(cands) == 1
        assert cands[0]["kind"] == "run_key"

    def test_empty_rows_yield_nothing(self) -> None:
        assert fea.registry_persistence_candidates([], RUN_KEY) == []


class TestServiceCandidates:
    def test_service_imagepath_under_user_dir_is_a_candidate(self) -> None:
        rows = [
            _row(
                SVC_KEY + "\\EvilSvc",
                [_val("ImagePath", "C:\\Users\\bob\\AppData\\evil_svc.exe")],
            )
        ]
        cands = fea.registry_persistence_candidates(rows, SVC_KEY)
        assert len(cands) == 1
        c = cands[0]
        assert c["kind"] == "service"
        assert c["service_name"] == "EvilSvc"
        assert c["image_path"].lower().endswith("evil_svc.exe")

    def test_system32_service_is_filtered(self) -> None:
        rows = [
            _row(
                SVC_KEY + "\\Spooler",
                [_val("ImagePath", "C:\\Windows\\System32\\spoolsv.exe")],
            )
        ]
        assert fea.registry_persistence_candidates(rows, SVC_KEY) == []


class TestPoolAEmitter:
    def _inv(self):
        inv = fea.Investigation("memory.img", unattended=True, with_report=False)
        inv.handle = {"id": "case-regtest"}
        return inv

    def test_run_key_candidate_becomes_confirmed_pool_a_finding(self) -> None:
        inv = self._inv()
        cand = {
            "kind": "run_key",
            "value_name": "Updater",
            "target": "C:\\Users\\bob\\AppData\\Roaming\\evil.exe",
            "hive_key": RUN_KEY,
            "last_write_time_iso": "2018-09-06T19:00:00Z",
        }
        inv._emit_registry_persistence_findings(
            [cand], "/evidence/SOFTWARE", RUN_KEY, "tc-reg-1", {}
        )
        assert len(inv.findings_pool_a) == 1
        f = inv.findings_pool_a[0]
        assert f["pool_origin"] == "A"
        assert f["tool_call_id"] == "tc-reg-1"
        assert f["confidence"] == "CONFIRMED"
        assert f["mitre_technique"] == "T1547.001"
        assert f["finding_id"].startswith("f-A-reg-persist-")
        # CONFIRMED claims only the persistence mechanism's existence. Runtime
        # activity needs an additional artifact class.
        assert "mechanism's existence" in f["description"].lower()
        assert "runtime" not in f["description"].lower()

    def test_prefetch_corroboration_lands_in_derived_from(self) -> None:
        inv = self._inv()
        cand = {
            "kind": "run_key",
            "value_name": "Updater",
            "target": "C:\\Users\\bob\\AppData\\Roaming\\evil.exe",
            "hive_key": RUN_KEY,
            "last_write_time_iso": "2018-09-06T19:00:00Z",
        }
        inv._emit_registry_persistence_findings(
            [cand], "/evidence/SOFTWARE", RUN_KEY, "tc-reg-1", {"evil.exe": "tc-pf-9"}
        )
        f = inv.findings_pool_a[0]
        assert "tc-pf-9" in f["derived_from"]
        assert "tc-reg-1" in f["derived_from"]
        assert "prefetch" in f["description"].lower()

    def test_service_candidate_is_a_hypothesis_with_prefix(self) -> None:
        inv = self._inv()
        cand = {
            "kind": "service",
            "service_name": "EvilSvc",
            "image_path": "C:\\Users\\bob\\AppData\\evil_svc.exe",
            "hive_key": SVC_KEY + "\\EvilSvc",
            "last_write_time_iso": "2018-09-06T19:00:00Z",
        }
        inv._emit_registry_persistence_findings([cand], "/evidence/SYSTEM", SVC_KEY, "tc-reg-2", {})
        f = inv.findings_pool_a[0]
        assert f["confidence"] == "HYPOTHESIS"
        assert f["description"].startswith("hypothesis: ")
        assert f["mitre_technique"] == "T1543.003"


def _registry_output(
    value_name: str,
    data_str: str,
    key_path: str = RUN_KEY,
    lw: str = "2018-09-06T19:00:00Z",
) -> dict:
    """A registry_query parsed output the emitted finding cites, shaped exactly
    like the real Rust tool: ``{"entries": [{"key_path", "last_write_time_iso",
    "values": [{"name", "data_str"}]}]}``."""
    return {
        "entries": [_row(key_path, [_val(value_name, data_str)], lw)],
        "keys_visited": 1,
        "parse_errors": 0,
    }


class TestPoolAEmitterAssertedValues:
    """Phase 2a: a CONFIRMED registry finding must declare the structured
    value(s) it asserts, so the deterministic entailment check can re-extract
    them from the cited output and kill a misread behind a valid citation."""

    def _inv(self):
        inv = fea.Investigation("memory.img", unattended=True, with_report=False)
        inv.handle = {"id": "case-regtest"}
        return inv

    def _emit_run_key(self, inv, value_name: str, target: str) -> dict:
        cand = {
            "kind": "run_key",
            "value_name": value_name,
            "target": target,
            "hive_key": RUN_KEY,
            "last_write_time_iso": "2018-09-06T19:00:00Z",
        }
        inv._emit_registry_persistence_findings(
            [cand], "/evidence/SOFTWARE", RUN_KEY, "tc-reg-1", {}
        )
        return inv.findings_pool_a[0]

    def test_run_key_finding_declares_a_colocated_record_assertion(self) -> None:
        import json

        inv = self._inv()
        f = self._emit_run_key(inv, "Updater", "C:\\Users\\bob\\AppData\\Roaming\\evil.exe")
        avs = f.get("asserted_values", [])
        assert len(avs) == 1, "CONFIRMED run_key finding must declare one record assertion"
        av = avs[0]
        # Co-located: name AND target must share one entries[].values[] record,
        # so the claim cannot be assembled from two different rows.
        assert av["match"] == "record"
        assert av["path"] == "entries[*].values[*]"
        constraints = json.loads(av["expected"])
        assert constraints["name"] == "Updater"
        assert "evil.exe" in constraints["data_str"].lower()

    def test_asserted_values_pass_entailment_against_the_cited_output(self) -> None:
        inv = self._inv()
        target = "C:\\Users\\bob\\AppData\\Roaming\\evil.exe"
        f = self._emit_run_key(inv, "Updater", target)
        avs = [AssertedValue(**av) for av in f["asserted_values"]]
        out = _registry_output("Updater", target)
        result = check_entailment(avs, out)
        assert result.passed, result.reason

    def test_misread_is_caught_when_value_absent_from_cited_output(self) -> None:
        # The finding asserts the Run value "Updater" -> evil.exe, but the cited
        # output actually holds a different, benign value. A misread laundered
        # through a valid tool_call_id: the asserted facts are NOT entailed.
        inv = self._inv()
        f = self._emit_run_key(inv, "Updater", "C:\\Users\\bob\\AppData\\Roaming\\evil.exe")
        avs = [AssertedValue(**av) for av in f["asserted_values"]]
        out = _registry_output("OneDrive", "C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe")
        result = check_entailment(avs, out)
        assert not result.passed, "entailment must reject a value absent from the output"
