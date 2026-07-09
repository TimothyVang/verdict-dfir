"""score-overclaim.py suppression-funnel + untested-surface ledger.

The goldens-FREE grounding view needs a deterministic, read-only account of HOW a
run got from raw candidate findings to the reported set — and which product DFIR
tools it left on the table. These tests pin that ledger:

  - the suppression funnel names the gates that removed/downgraded candidates
    (verifier-rejected, fact-fidelity/entailment-vetoed, correlator-downgraded,
    below-confidence/leads-only) and reconciles raw -> reported;
  - the untested-surface table lists product MCP DFIR tools available but never
    exercised in this case;
  - both derive from the run dir (audit.jsonl preferred, verdict.json fallback)
    with no goldens and no audit-chain mutation.

The scorer is a hyphenated maintainer tool, loaded via importlib.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[3]
_SCRIPTS = _REPO_ROOT / "scripts"
_spec = importlib.util.spec_from_file_location("score_overclaim", _SCRIPTS / "score-overclaim.py")
assert _spec and _spec.loader
score_overclaim = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(score_overclaim)


def _write_case(
    tmp_path: Path,
    findings: list[dict],
    audit: list[dict] | None = None,
    verdict_extra: dict | None = None,
) -> Path:
    doc = {"case_id": "t", "verdict": "SUSPICIOUS", "findings": findings}
    if verdict_extra:
        doc.update(verdict_extra)
    (tmp_path / "verdict.json").write_text(json.dumps(doc), encoding="utf-8")
    if audit is not None:
        (tmp_path / "audit.jsonl").write_text(
            "\n".join(json.dumps(rec) for rec in audit) + "\n", encoding="utf-8"
        )
    return tmp_path


def _verifier_action(action: str, *, replay_matched, reason: str) -> dict:
    return {
        "kind": "verifier_action",
        "payload": {
            "action": action,
            "replay_matched": replay_matched,
            "reason": reason,
        },
    }


def _tool_start(tool: str) -> dict:
    return {"kind": "tool_call_start", "payload": {"tool": tool}}


def test_funnel_reconciles_raw_to_reported_from_audit(tmp_path):
    # Arrange: 2 reported findings; audit shows 1 hash-drift rejection, plus a
    # correlation pass that downgraded 2 (tier only) and dropped 1 to leads.
    audit = [
        _verifier_action("approved", replay_matched=True, reason="hash matches"),
        _verifier_action("approved", replay_matched=True, reason="hash matches"),
        _verifier_action("rejected", replay_matched=False, reason="replay output_sha256 drifted"),
        {
            "kind": "correlation_outcomes",
            "payload": {
                "outcomes": [
                    {"action": "downgraded", "finding_id": "a"},
                    {"action": "downgraded", "finding_id": "b"},
                    {"action": "rejected", "finding_id": "c"},
                    {"action": "kept", "finding_id": "d"},
                ]
            },
        },
    ]
    case = _write_case(tmp_path, [{"finding_id": "a"}, {"finding_id": "b"}], audit=audit)

    # Act
    funnel = score_overclaim.score(case)["suppression_funnel"]

    # Assert: classes and the raw -> reported reconciliation.
    assert funnel["reported_findings_n"] == 2
    classes = funnel["classes"]
    assert classes["verifier_rejected"] == 1
    assert classes["fact_fidelity_vetoed"] == 0
    assert classes["correlator_downgraded"] == 2
    assert classes["below_confidence_leads_only"] == 1
    # raw = reported + removing classes (downgrade is tier-only, NOT subtracted).
    assert funnel["raw_candidate_findings_n"] == 2 + 1 + 0 + 1
    assert funnel["source"] == "audit.jsonl"


def test_funnel_splits_fact_fidelity_veto_from_hash_drift(tmp_path):
    # Arrange: a rejection whose SHA reproduced but the asserted value was not
    # entailed is a fact-fidelity veto, NOT a replay/hash rejection.
    audit = [
        _verifier_action(
            "rejected",
            replay_matched=True,
            reason="asserted value not entailed by cited evidence",
        ),
    ]
    case = _write_case(tmp_path, [], audit=audit)

    # Act / Assert
    classes = score_overclaim.score(case)["suppression_funnel"]["classes"]
    assert classes["fact_fidelity_vetoed"] == 1
    assert classes["verifier_rejected"] == 0


def test_untested_surface_lists_allowed_but_not_run(tmp_path):
    # Arrange: only two DFIR tools were exercised.
    audit = [_tool_start("case_open"), _tool_start("registry_query"), _tool_start("registry_query")]
    case = _write_case(tmp_path, [], audit=audit)

    # Act
    surface = score_overclaim.score(case)["untested_surface"]

    # Assert: exercised set is de-duped + sorted; the rest are allowed-but-not-run.
    assert surface["exercised_tools"] == ["case_open", "registry_query"]
    assert surface["exercised_n"] == 2
    assert surface["product_dfir_tools_n"] == len(score_overclaim._PRODUCT_DFIR_TOOLS)
    assert surface["allowed_not_run_n"] == surface["product_dfir_tools_n"] - 2
    assert "yara_scan" in surface["allowed_not_run"]
    assert "case_open" not in surface["allowed_not_run"]
    assert surface["allowed_not_run"] == sorted(surface["allowed_not_run"])


def test_funnel_and_surface_fall_back_to_verdict_json_without_audit(tmp_path):
    # Arrange: no audit.jsonl. verdict.json carries the rejected leads + the
    # correlation summary + the tool_calls list.
    verdict_extra = {
        "rejected_finding_leads": [{"finding_id": "x"}, {"finding_id": "y"}],
        "findings_summary": {
            "correlation_outcomes": [
                {"action": "downgraded", "finding_id": "a"},
                {"action": "kept", "finding_id": "b"},
            ]
        },
        "tool_calls": [{"tool": "case_open"}, {"tool": "evtx_query"}],
    }
    case = _write_case(tmp_path, [{"finding_id": "a"}], verdict_extra=verdict_extra)

    # Act
    result = score_overclaim.score(case)
    funnel = result["suppression_funnel"]
    surface = result["untested_surface"]

    # Assert
    assert funnel["source"] == "verdict.json"
    assert funnel["classes"]["verifier_rejected"] == 2
    assert funnel["classes"]["correlator_downgraded"] == 1
    assert funnel["reported_findings_n"] == 1
    assert surface["exercised_tools"] == ["case_open", "evtx_query"]
    assert surface["allowed_not_run_n"] == surface["product_dfir_tools_n"] - 2
