"""Gate-coverage guard (Stage A): every fact-bearing finding the engine emits
must satisfy the fact-fidelity gate with the gate ON.

The corpus in ``fixtures/gate_coverage_findings.json`` is the CONFIRMED/INFERRED
findings from a live full-coverage gate-ON SCHARDT run (recall 10/14 = 71% held,
0 gate rejections, manifest_verify overall true). If a future emitter produces a
CONFIRMED finding without ``asserted_values`` (or an INFERRED finding without
``asserted_values``/``derived_from``), refreshing this fixture from a new run and
re-running this test catches it — the same guarantee the live run enforces, as a
fast deterministic check.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from findevil_agent.events import Finding

_FIXTURE = Path(__file__).parent / "fixtures" / "gate_coverage_findings.json"
_FINDINGS: list[dict] = json.loads(_FIXTURE.read_text(encoding="utf-8"))["findings"]


def test_fixture_has_confirmed_and_inferred() -> None:
    tiers = {f["confidence"] for f in _FINDINGS}
    assert "CONFIRMED" in tiers, "fixture must include CONFIRMED findings"
    assert _FINDINGS, "fixture must not be empty"


@pytest.mark.parametrize("raw", _FINDINGS, ids=lambda r: r["finding_id"])
def test_emitted_finding_satisfies_gate_on(monkeypatch: pytest.MonkeyPatch, raw: dict) -> None:
    # Gate ON (override the suite's conftest baseline): a real emitted
    # CONFIRMED/INFERRED finding must build — i.e. it declares the value(s) the
    # entailment check re-extracts, or the confirmed facts it rests on.
    monkeypatch.setenv("FIND_EVIL_REQUIRE_ASSERTED_VALUES", "1")
    Finding.model_validate({k: v for k, v in raw.items() if v is not None})
