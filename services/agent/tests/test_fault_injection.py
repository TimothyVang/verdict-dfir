"""Tests for the audit-labeled verifier fault-injection hook.

``FIND_EVIL_FAULT_INJECT=verifier_reject_once:<finding-id-fragment>`` corrupts
the cited ``tool_call_index`` entry's tool_name for the FIRST verify attempt of
the first matching finding — and nothing else. The rejection then flows through
the production verifier path and the Task-1 re-dispatch recovers it, which is
what the committed showcase run demonstrates. The injection is never silent: a
``fault_injection`` audit record lands in the chain before any verifier action.

- F1: the fault corrupts attempt 1 only; re-dispatch (attempt 2) gets a clean
      index and recovers; the fault_injection record precedes verifier_action.
- F2: the fragment matches by substring (directory-mode finding ids carry an
      8-hex suffix).
- F3: env unset -> byte-identical behavior, no fault_injection records.
- F4: the fault fires at most once per run, even across pools.
"""

from __future__ import annotations

import sys
import threading
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402

_SENTINEL = "__fault_injected__"


class _FakePy:
    """verify_finding approves unless the cited index entry was corrupted;
    records every call and every audit_append (kind, payload)."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []
        self.audits: list[tuple[str, dict]] = []
        self._lock = threading.Lock()

    def call_tool(self, name: str, args: dict, timeout: float = 600.0) -> dict:
        with self._lock:
            self.calls.append((name, args))
            if name == "audit_append":
                self.audits.append((args["kind"], args["payload"]))
                return {}
        if name == "verify_finding":
            fid = str(args["finding"]["finding_id"])
            tcid = str(args["finding"].get("tool_call_id") or "")
            entry = args["tool_call_index"].get(tcid) or {}
            if str(entry.get("tool_name") or "").startswith(_SENTINEL):
                return {
                    "finding_id": fid,
                    "action": "rejected",
                    "reason": "tool re-run failed: unknown tool",
                    "replay_matched": False,
                    "replay_error": "tool re-run failed: unknown tool",
                    "replay_artifact": {"drift_class": "replay_error"},
                }
            if entry.get("output_sha256") == "f" * 64:
                # Mirrors the production verifier's drift-reject on a
                # CONFIRMED finding (first pass) — a corrupted recorded hash
                # makes the (clean) replay output mismatch.
                return {
                    "finding_id": fid,
                    "action": "rejected",
                    "reason": (
                        "tool re-run output_sha256 drift on a CONFIRMED "
                        "finding — fresh replay required"
                    ),
                    "replay_matched": False,
                    "replay_artifact": {"drift_class": "material_drift"},
                }
            return {
                "finding_id": fid,
                "action": "approved",
                "reason": "replay matched",
                "replay_matched": True,
                "replay_tool_name": entry.get("tool_name"),
                "replay_expected_sha256": "abc",
                "replay_actual_sha256": "abc",
                "replay_artifact": {"drift_class": "exact_match"},
            }
        return {}

    def verify_calls(self, fid: str) -> list[dict]:
        return [
            args
            for name, args in self.calls
            if name == "verify_finding" and str(args["finding"]["finding_id"]) == fid
        ]

    def kinds(self) -> list[str]:
        return [kind for kind, _ in self.audits]


def _inv() -> fea.Investigation:
    inv = fea.Investigation("/tmp/does-not-exist-evidence", case_id="case-fault")
    inv.handle = {"id": "case-test"}
    inv.parallel = False
    return inv


def _with_tool_call(inv: fea.Investigation, fid: str) -> dict:
    tcid = f"tc-{fid}"
    inv.tool_calls.append({"tool_call_id": tcid, "tool": "evtx_query", "output_hash": "abc"})
    return {"finding_id": fid, "tool_call_id": tcid, "description": f"d-{fid}"}


def test_fault_injects_first_verify_attempt_only(monkeypatch) -> None:
    monkeypatch.setenv("FIND_EVIL_FAULT_INJECT", "verifier_reject_once:f-01")
    inv = _inv()
    finding = _with_tool_call(inv, "f-01")
    py = _FakePy()

    actions = inv._verify_pool(py, [finding])

    verify_calls = py.verify_calls("f-01")
    assert len(verify_calls) == 2  # rejected once, re-dispatched once
    first_entry = verify_calls[0]["tool_call_index"]["tc-f-01"]
    second_entry = verify_calls[1]["tool_call_index"]["tc-f-01"]
    assert str(first_entry["tool_name"]).startswith(_SENTINEL)
    assert second_entry["tool_name"] == "evtx_query"

    kinds = py.kinds()
    assert kinds.count("fault_injection") == 1
    assert kinds.index("fault_injection") < kinds.index("verifier_action")

    assert [a["action"] for a in actions] == ["approved"]
    assert inv.verifier_redispatches["f-01"]["recovered"] is True


def test_fault_matches_by_substring(monkeypatch) -> None:
    monkeypatch.setenv("FIND_EVIL_FAULT_INJECT", "verifier_reject_once:audit-log")
    inv = _inv()
    finding = _with_tool_call(inv, "f-A-evtx-audit-log-cleared-1a2b3c4d")
    py = _FakePy()

    inv._verify_pool(py, [finding])

    assert py.kinds().count("fault_injection") == 1


def test_no_env_no_behavior_change(monkeypatch) -> None:
    monkeypatch.delenv("FIND_EVIL_FAULT_INJECT", raising=False)
    inv = _inv()
    finding = _with_tool_call(inv, "f-01")
    py = _FakePy()

    actions = inv._verify_pool(py, [finding])

    verify_calls = py.verify_calls("f-01")
    assert len(verify_calls) == 1
    assert verify_calls[0]["tool_call_index"] == inv._tool_call_index()
    assert "fault_injection" not in py.kinds()
    assert [a["action"] for a in actions] == ["approved"]


def test_hash_mismatch_mode_drives_true_drift_reject_then_recovery(monkeypatch) -> None:
    # The verifier_hash_mismatch_once mode corrupts the RECORDED output_sha256
    # (not the tool name), so attempt 1 exercises the genuine hash-mismatch
    # reject path; the re-dispatch sees the clean index and recovers.
    monkeypatch.setenv("FIND_EVIL_FAULT_INJECT", "verifier_hash_mismatch_once:f-h1")
    inv = _inv()
    finding = _with_tool_call(inv, "f-h1")
    py = _FakePy()

    actions = inv._verify_pool(py, [finding])

    verify_calls = py.verify_calls("f-h1")
    assert len(verify_calls) == 2
    first_entry = verify_calls[0]["tool_call_index"]["tc-f-h1"]
    second_entry = verify_calls[1]["tool_call_index"]["tc-f-h1"]
    assert first_entry["output_sha256"] == "f" * 64  # corrupted recorded hash
    assert first_entry["tool_name"] == "evtx_query"  # tool name untouched
    assert second_entry["output_sha256"] == "abc"  # re-dispatch sees clean index
    # The re-dispatch carries the terminal drift policy.
    assert verify_calls[1].get("downgrade_on_drift") is True

    fault_payloads = [p for k, p in py.audits if k == "fault_injection"]
    assert len(fault_payloads) == 1
    assert fault_payloads[0]["mode"] == "verifier_hash_mismatch_once"

    assert [a["action"] for a in actions] == ["approved"]
    assert inv.verifier_redispatches["f-h1"]["recovered"] is True


def test_hash_mismatch_mode_fires_at_most_once(monkeypatch) -> None:
    monkeypatch.setenv("FIND_EVIL_FAULT_INJECT", "verifier_hash_mismatch_once:f-hh")
    inv = _inv()
    pool_a = [_with_tool_call(inv, "f-hh-1")]
    pool_b = [_with_tool_call(inv, "f-hh-2")]
    py = _FakePy()

    inv._verify_pool(py, pool_a)
    inv._verify_pool(py, pool_b)

    assert py.kinds().count("fault_injection") == 1
    assert len(py.verify_calls("f-hh-1")) == 2
    assert len(py.verify_calls("f-hh-2")) == 1


def test_fault_fires_at_most_once_per_run(monkeypatch) -> None:
    monkeypatch.setenv("FIND_EVIL_FAULT_INJECT", "verifier_reject_once:f-aa")
    inv = _inv()
    pool_a = [_with_tool_call(inv, "f-aa-1")]
    pool_b = [_with_tool_call(inv, "f-aa-2")]
    py = _FakePy()

    inv._verify_pool(py, pool_a)
    inv._verify_pool(py, pool_b)

    assert py.kinds().count("fault_injection") == 1
    assert len(py.verify_calls("f-aa-1")) == 2  # faulted + re-dispatched
    assert len(py.verify_calls("f-aa-2")) == 1  # untouched


# --- entailment_misread_once: break the READ, not the citation ---------------
# The two modes above corrupt the citation/SHA. This mode corrupts the value the
# finding asserts so it no longer matches the (reproducing) evidence — a
# reproducible "the model misread the evidence" fault, which the deterministic
# entailment check must catch. This is the mutation test behind the demo clip.

from findevil_agent.entailment import check_entailment  # noqa: E402
from findevil_agent.events import AssertedValue  # noqa: E402

_RUN_KEY = "ROOT\\Microsoft\\Windows\\CurrentVersion\\Run"


def _registry_output(value_name: str, data_str: str) -> dict:
    return {
        "entries": [
            {
                "key_path": _RUN_KEY,
                "last_write_time_iso": "2018-09-06T19:00:00Z",
                "values": [{"name": value_name, "value_type": "RegSz", "data_str": data_str}],
            }
        ],
        "keys_visited": 1,
        "parse_errors": 0,
    }


def test_misread_mode_is_recognized_by_the_spec(monkeypatch) -> None:
    monkeypatch.setenv("FIND_EVIL_FAULT_INJECT", "entailment_misread_once:f-reg")
    assert fea.fault_inject_spec() == ("entailment_misread_once", "f-reg")


def test_fault_inject_misread_breaks_a_record_assertion_without_mutating_input() -> None:
    original_expected = '{"name": "Updater", "data_str": "evil.exe"}'
    finding = {
        "finding_id": "f-1",
        "confidence": "CONFIRMED",
        "asserted_values": [
            {"path": "entries[*].values[*]", "expected": original_expected, "match": "record"}
        ],
    }
    faulted = fea.fault_inject_misread(finding)
    # immutability: the original finding is untouched
    assert finding["asserted_values"][0]["expected"] == original_expected
    # the faulted assertion no longer matches the evidence it used to
    out = _registry_output("Updater", "C:\\Users\\bob\\evil.exe")
    avs = [AssertedValue(**av) for av in faulted["asserted_values"]]
    assert check_entailment(avs, out).passed is False


def test_misread_injection_kills_a_real_registry_finding() -> None:
    # Mutation test on the REAL emitter path: build a CONFIRMED registry
    # finding, confirm its declared fact is entailed by the cited output, then
    # inject the misread and confirm the same output no longer entails it.
    inv = fea.Investigation("memory.img", unattended=True, with_report=False)
    inv.handle = {"id": "case-fault"}
    cand = {
        "kind": "run_key",
        "value_name": "Updater",
        "target": "C:\\Users\\bob\\AppData\\Roaming\\evil.exe",
        "hive_key": _RUN_KEY,
        "last_write_time_iso": "2018-09-06T19:00:00Z",
    }
    inv._emit_registry_persistence_findings([cand], "/evidence/SOFTWARE", _RUN_KEY, "tc-1", {})
    finding = inv.findings_pool_a[0]
    out = _registry_output("Updater", "C:\\Users\\bob\\AppData\\Roaming\\evil.exe")

    truthful = [AssertedValue(**av) for av in finding["asserted_values"]]
    assert check_entailment(truthful, out).passed is True  # honest finding: entailed

    faulted = fea.fault_inject_misread(finding)
    misread = [AssertedValue(**av) for av in faulted["asserted_values"]]
    assert check_entailment(misread, out).passed is False  # injected misread: caught
