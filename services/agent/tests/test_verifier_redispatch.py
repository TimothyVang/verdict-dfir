"""Tests for the verifier-reject -> re-dispatch loop in find_evil_auto.py.

Before this change a ``verify_finding`` rejection silently dropped the finding:
``_apply_verifier_actions`` skipped it with no second attempt, so a transient
replay failure (timeout, dropped MCP connection) cost a real finding. HEARTBEAT
doctrine says reason about the failure and try again before giving up.

The loop is a serial Stage A-and-a-half between the parallel verify (Stage A)
and the audit-chained action recording (Stage B): each *re-runnable* rejection
is re-dispatched exactly once (audited as ``verifier_redispatch``), and a
rejection that persists routes through ``_course_correct`` so two consecutive
ones trip the documented HEARTBEAT escalation.

- R1: rejected -> approved recovers: one re-dispatch, force_fresh_replay, no
      blocker entry, the chain shows verifier_redispatch before the final
      verifier_action.
- R2: persistent rejection is capped at one re-dispatch and becomes a
      course_correction + blocker.
- R3: citation vetoes (missing_citation / missing_audit_record) are never
      re-dispatched — the tool_call_id invariant is not retried around.
- R4: two persistent rejections trip heartbeat_failure (streak == 2).
- R5: parallel and sequential verify produce identical actions, Stage B call
      sequences, and redispatch bookkeeping (audit-chain determinism).
- R6: a transport _error from verify_finding is re-runnable and re-dispatched.
- R7: clean approvals are untouched (one call, no new records).
"""

from __future__ import annotations

import sys
import threading
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402


def _approved(fid: str) -> dict:
    return {
        "finding_id": fid,
        "action": "approved",
        "reason": "replay matched",
        "replay_matched": True,
        "replay_tool_name": "vol_pslist",
        "replay_expected_sha256": "abc",
        "replay_actual_sha256": "abc",
        "replay_artifact": {"drift_class": "exact_match"},
    }


def _rejected(fid: str, drift_class: str = "replay_error") -> dict:
    return {
        "finding_id": fid,
        "action": "rejected",
        "reason": f"tool re-run failed ({drift_class})",
        "replay_matched": False,
        "replay_tool_name": "vol_pslist",
        "replay_expected_sha256": "abc",
        "replay_actual_sha256": None,
        "replay_error": f"tool re-run failed ({drift_class})",
        "replay_artifact": {"drift_class": drift_class},
    }


class _FakePy:
    """Scripted MCP client: per-finding verify_finding results consumed in
    attempt order; records every call and every audit_append (kind, payload)."""

    def __init__(self, script: dict[str, list[dict]]) -> None:
        self.script = {fid: list(results) for fid, results in script.items()}
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
                queue = self.script[fid]
                return queue.pop(0) if len(queue) > 1 else dict(queue[0])
        return {}

    def verify_calls(self, fid: str) -> list[dict]:
        return [
            args
            for name, args in self.calls
            if name == "verify_finding" and str(args["finding"]["finding_id"]) == fid
        ]

    def kinds(self) -> list[str]:
        return [kind for kind, _ in self.audits]

    def stage_b_calls(self) -> list[tuple[str, dict]]:
        return [c for c in self.calls if c[0] in ("audit_append", "pool_handoff")]


def _inv(parallel: bool = False, workers: int = 4) -> fea.Investigation:
    inv = fea.Investigation("/tmp/does-not-exist-evidence", case_id="case-redispatch")
    inv.handle = {"id": "case-test"}
    inv.parallel = parallel
    inv.workers = workers
    return inv


def _finding(fid: str) -> dict:
    return {"finding_id": fid, "tool_call_id": f"tc-{fid}", "description": f"d-{fid}"}


def test_rejected_then_approved_redispatches_once() -> None:
    py = _FakePy({"f-01": [_rejected("f-01"), _approved("f-01")]})
    inv = _inv()

    actions = inv._verify_pool(py, [_finding("f-01")])

    verify_calls = py.verify_calls("f-01")
    assert len(verify_calls) == 2
    assert verify_calls[1].get("force_fresh_replay") is True

    redispatches = [p for k, p in py.audits if k == "verifier_redispatch"]
    assert len(redispatches) == 1
    assert redispatches[0]["finding_id"] == "f-01"
    assert redispatches[0]["attempt"] == 2
    assert "replay_error" in redispatches[0]["first_reason"]

    # The chain shows re-dispatch BEFORE the final verifier action.
    kinds = py.kinds()
    assert kinds.index("verifier_redispatch") < kinds.index("verifier_action")

    assert [a["action"] for a in actions] == ["approved"]
    assert inv.verifier_replay_failures == []
    assert inv.verifier_redispatches["f-01"]["recovered"] is True


def test_persistent_rejection_capped_at_one_redispatch() -> None:
    py = _FakePy({"f-02": [_rejected("f-02")]})
    inv = _inv()

    actions = inv._verify_pool(py, [_finding("f-02")])

    assert len(py.verify_calls("f-02")) == 2  # cap: exactly one re-dispatch
    assert [a["action"] for a in actions] == ["rejected"]
    assert len(inv.verifier_replay_failures) == 1
    assert inv.verifier_redispatches["f-02"]["recovered"] is False
    assert len(inv.verifier_rejected_leads) == 1
    lead = inv.verifier_rejected_leads[0]
    assert lead["finding_id"] == "f-02"
    assert lead["tool_call_id"] == "tc-f-02"
    assert lead["description"] == "d-f-02"
    assert lead["verifier_action"] == "rejected"
    assert lead["verifier_reason"] == "tool re-run failed (replay_error)"
    assert lead["replay_matched"] is False
    assert lead["replay_error"] == "tool re-run failed (replay_error)"
    assert lead["replay_record_sha256"]
    assert lead["verdict_effect"] == "excluded_from_final_findings"
    assert lead["analyst_action"].startswith("Inspect this as a rejected lead")

    corrections = [p for k, p in py.audits if k == "course_correction"]
    assert len(corrections) == 1
    assert corrections[0]["failed_tool"] == "verify_finding"
    rejected_leads = [p for k, p in py.audits if k == "verifier_rejected_lead"]
    assert rejected_leads == inv.verifier_rejected_leads


def test_citation_veto_is_not_redispatched() -> None:
    py = _FakePy(
        {
            "f-03": [_rejected("f-03", drift_class="missing_citation")],
            "f-04": [_rejected("f-04", drift_class="missing_audit_record")],
        }
    )
    inv = _inv()

    inv._verify_pool(py, [_finding("f-03"), _finding("f-04")])

    assert len(py.verify_calls("f-03")) == 1
    assert len(py.verify_calls("f-04")) == 1
    assert "verifier_redispatch" not in py.kinds()


def test_two_persistent_rejections_trip_heartbeat() -> None:
    py = _FakePy({"f-05": [_rejected("f-05")], "f-06": [_rejected("f-06")]})
    inv = _inv()

    inv._verify_pool(py, [_finding("f-05"), _finding("f-06")])

    heartbeats = [p for k, p in py.audits if k == "heartbeat_failure"]
    assert len(heartbeats) == 1
    assert heartbeats[0]["consecutive_failures"] == 2
    assert inv._heartbeat_escalated is True


def test_parallel_matches_sequential_with_redispatch() -> None:
    script = {
        "f-10": [_rejected("f-10"), _approved("f-10")],
        "f-11": [_approved("f-11")],
        "f-12": [_rejected("f-12")],
        "f-13": [_approved("f-13")],
    }
    findings = [_finding(fid) for fid in script]

    seq_py = _FakePy(script)
    seq_inv = _inv(parallel=False)
    seq_actions = seq_inv._verify_pool(seq_py, findings)

    par_py = _FakePy(script)
    par_inv = _inv(parallel=True)
    par_actions = par_inv._verify_pool(par_py, findings)

    assert par_actions == seq_actions
    assert par_py.stage_b_calls() == seq_py.stage_b_calls()
    assert par_inv.verifier_redispatches == seq_inv.verifier_redispatches
    assert par_inv.verifier_replay_failures == seq_inv.verifier_replay_failures


def test_transport_error_is_redispatched() -> None:
    error = {"_error": {"message": "verify_finding timed out"}}
    py = _FakePy({"f-20": [error, _approved("f-20")]})
    inv = _inv()

    actions = inv._verify_pool(py, [_finding("f-20")])

    assert len(py.verify_calls("f-20")) == 2
    assert [a["action"] for a in actions] == ["approved"]
    assert inv.verifier_redispatches["f-20"]["recovered"] is True


def test_approved_finding_untouched() -> None:
    py = _FakePy({"f-30": [_approved("f-30")]})
    inv = _inv()

    actions = inv._verify_pool(py, [_finding("f-30")])

    assert len(py.verify_calls("f-30")) == 1
    assert [a["action"] for a in actions] == ["approved"]
    assert "verifier_redispatch" not in py.kinds()
    assert "course_correction" not in py.kinds()
    assert inv.verifier_redispatches == {}


# ---------------------------------------------------------------------------
# Report-QA interaction: a RECOVERED re-dispatch is transparency, not a
# blocker — the final verifier action was approved and replay evidence is
# intact. A rejection that persists must still fail the QA gate.
# ---------------------------------------------------------------------------


def _qa_for(limitations: list[str]) -> dict:
    return fea.build_report_qa_signoff(
        findings=[],
        tool_calls=[],
        verdict="INDETERMINATE",
        case_completeness={},
        attack_coverage={},
        normalized_timeline={},
        analysis_limitations=limitations,
    )


def _qa_status(qa: dict, check_id: str) -> str:
    return next(c for c in qa["checks"] if c["check_id"] == check_id)["status"]


def test_recovered_redispatch_is_not_a_replay_failure_blocker() -> None:
    qa = _qa_for(
        [
            "verify_finding for f-01 recovered on re-dispatch "
            "(first attempt: mcp rpc error: timeout)"
        ]
    )
    assert _qa_status(qa, "verify_finding_replay_failures") == "PASS"


def test_persistent_rejection_still_fails_replay_qa() -> None:
    qa = _qa_for(["verify_finding rejected or failed for f-02: tool re-run failed"])
    assert _qa_status(qa, "verify_finding_replay_failures") == "FAIL"


# ---------------------------------------------------------------------------
# The re-dispatch must be VISIBLE in the live terminal (not only the audit
# chain) — the self-correction is the demo's headline moment and every other
# lane prints its progress. capsys asserts the recovery/drop is on stdout.
# ---------------------------------------------------------------------------


def test_redispatch_recovery_prints_to_stdout(capsys) -> None:
    py = _FakePy({"f-01": [_rejected("f-01"), _approved("f-01")]})
    inv = _inv()

    inv._verify_pool(py, [_finding("f-01")])

    out = capsys.readouterr().out.lower()
    assert "f-01" in out
    assert "re-dispatch" in out
    assert "recover" in out


def test_persistent_rejection_prints_drop_to_stdout(capsys) -> None:
    py = _FakePy({"f-02": [_rejected("f-02")]})
    inv = _inv()

    inv._verify_pool(py, [_finding("f-02")])

    out = capsys.readouterr().out.lower()
    assert "re-dispatch" in out
    assert "f-02" in out
