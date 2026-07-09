"""Verifier-regression catch-rate guard.

Runs a small, committed corpus of KNOWN-BAD findings through the REAL verification
pipeline and asserts a minimum catch-rate, so a future edit that silently weakens
a gate is caught here instead of in production.

Two real production stages vet each finding (no mocked decision logic — only a
``MockMcpClient`` standing in for the Rust binary on replay):

* ``findevil_agent.verifier.reverify_finding`` — the entailment / claim-fidelity
  check. After it proves the citation reproduces (output SHA-256 matches), it
  re-extracts each ``asserted_value`` from the re-run output and rejects (CONFIRMED)
  or downgrades (lower tiers) a value that is not actually there. This catches the
  phantom-PID, attribution-overclaim, and exfil-without-staging known-bads, whose
  asserted value is absent from the cited evidence.
* ``findevil_agent.correlator.correlate`` — the per-technique corroboration gate
  family. It downgrades, e.g., a CONFIRMED execution claim backed by a single
  artifact class. This catches the single-citation-execution known-bad, which the
  verifier (correctly) approves on its own because the asserted value IS present —
  it is the missing second class, not a fabricated value, that makes it bad.

A known-bad is "caught" if EITHER stage rejects or downgrades it. The corpus also
carries benign CONTROLS the pipeline must leave untouched, so a passing catch-rate
reflects real discrimination, not a harness that flags everything.

The corpus lives at ``goldens/verifier-regression/known-bad-findings.json`` and is
evidence-agnostic (all synthetic values). This test imports the production code but
edits none of it; it is read-only and deterministic.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from findevil_agent.correlator import correlate
from findevil_agent.events import Finding
from findevil_agent.mcp_client import MockMcpClient
from findevil_agent.verifier import reverify_finding

# goldens/verifier-regression/ lives at the repo root: tests -> agent -> services -> repo.
_REPO_ROOT = Path(__file__).resolve().parents[3]
_CORPUS_PATH = _REPO_ROOT / "goldens" / "verifier-regression" / "known-bad-findings.json"

_CAUGHT_ACTIONS = frozenset({"rejected", "downgraded"})


def _load_corpus() -> dict[str, Any]:
    return json.loads(_CORPUS_PATH.read_text(encoding="utf-8"))


_CORPUS = _load_corpus()
_KNOWN_BAD: list[dict[str, Any]] = _CORPUS["known_bad"]
_CONTROLS: list[dict[str, Any]] = _CORPUS["controls"]
_MIN_CATCH_RATE: float = float(_CORPUS["min_catch_rate"])


def _expected_sha(parsed_output: dict[str, Any]) -> str:
    """Mirror MockMcpClient's hashing: SHA-256 over the canonical JSON it emits."""
    canonical = json.dumps(parsed_output, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _finding_from(entry: dict[str, Any]) -> Finding:
    # Pydantic coerces the asserted_values dicts into AssertedValue models.
    return Finding(**entry["finding"])


def _verifier_action(entry: dict[str, Any]) -> str:
    """The real verifier's action for this entry, replaying the cited tool call."""
    finding = _finding_from(entry)
    replay = entry["replay"]
    payload = replay["parsed_output"]
    mcp = MockMcpClient()
    mcp.register(replay["tool_name"], payload)
    index = {
        finding.tool_call_id: {
            "tool_name": replay["tool_name"],
            "arguments": replay["arguments"],
            "output_sha256": _expected_sha(payload),
        }
    }
    action, _replay = reverify_finding(finding, mcp=mcp, tool_call_index=index)
    return action.action


def _correlator_action(entry: dict[str, Any]) -> str:
    """The real correlator gate family's outcome action for this entry."""
    finding = _finding_from(entry)
    _refined, outcomes = correlate([finding])
    return outcomes[0].action


def _catchers(entry: dict[str, Any]) -> set[str]:
    """The set of pipeline stages that flagged (rejected/downgraded) this entry."""
    caught: set[str] = set()
    if _verifier_action(entry) in _CAUGHT_ACTIONS:
        caught.add("verifier")
    if _correlator_action(entry) in _CAUGHT_ACTIONS:
        caught.add("correlator")
    return caught


def test_corpus_is_well_formed() -> None:
    """Guard the guard: the corpus must carry all four named known-bad categories
    and at least one benign control, so nobody can pass this gate by emptying it."""
    assert _KNOWN_BAD, "known-bad corpus is empty"
    assert _CONTROLS, "control corpus is empty (catch-rate would be untrustworthy)"
    categories = {entry["category"] for entry in _KNOWN_BAD}
    for required in (
        "phantom/nonexistent PID",
        "attribution overclaim",
        "single-citation CONFIRMED execution",
        "exfil-without-staging",
    ):
        assert required in categories, f"missing known-bad category: {required}"


def test_min_catch_rate_floor_stays_strict() -> None:
    """The floor itself must stay meaningful: a silent edit dropping it toward 0
    would defeat the purpose. The known-bad set must be required to (nearly) all
    be caught."""
    assert (
        _MIN_CATCH_RATE >= 0.75
    ), f"min_catch_rate {_MIN_CATCH_RATE} is too lax to be a real regression guard"


def test_known_bad_catch_rate_meets_floor() -> None:
    """The verification pipeline must catch at least ``min_catch_rate`` of the
    known-bad corpus. This is the headline regression guard: weaken a gate and the
    catch-rate drops below the floor."""
    caught = [entry for entry in _KNOWN_BAD if _catchers(entry)]
    rate = len(caught) / len(_KNOWN_BAD)
    missed = [entry["id"] for entry in _KNOWN_BAD if not _catchers(entry)]
    assert rate >= _MIN_CATCH_RATE, (
        f"catch-rate {rate:.2f} < floor {_MIN_CATCH_RATE:.2f}; "
        f"verification pipeline missed: {missed}"
    )


@pytest.mark.parametrize("entry", _KNOWN_BAD, ids=[e["id"] for e in _KNOWN_BAD])
def test_each_known_bad_caught_by_its_expected_stage(entry: dict[str, Any]) -> None:
    """Per-category strictness: each known-bad must be caught by the stage the
    corpus names, with the action it declares — so a gate cannot silently stop
    catching one category while another masks the aggregate rate."""
    expected_stage = entry["expected_catcher"]
    expected_action = entry["expected_action"]
    actual = _verifier_action(entry) if expected_stage == "verifier" else _correlator_action(entry)
    assert (
        actual == expected_action
    ), f"{entry['id']}: expected {expected_stage} to {expected_action}, got {actual!r}"


@pytest.mark.parametrize("entry", _CONTROLS, ids=[e["id"] for e in _CONTROLS])
def test_controls_are_not_caught(entry: dict[str, Any]) -> None:
    """Benign controls must pass clean (no stage rejects/downgrades), proving the
    catch-rate measures discrimination rather than a flag-everything harness."""
    caught_by = _catchers(entry)
    assert not caught_by, f"control {entry['id']} was wrongly flagged by: {sorted(caught_by)}"
