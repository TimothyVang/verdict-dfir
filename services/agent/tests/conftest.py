"""Test-suite baseline for the fact-fidelity gate.

The fact-fidelity gate (`Finding._require_asserted_values`, enforced when
`FIND_EVIL_REQUIRE_ASSERTED_VALUES != "0"`) is **production-default-ON** as of
Stage A (2026-06-22): a CONFIRMED/INFERRED finding that reaches a verdict must
declare the structured value(s) the entailment check re-extracts.

Component unit tests (judge, verifier, expectation, …) construct findings as
*fixtures* to exercise those components' own logic — they are not testing the
gate, and forcing every fixture to carry gate-valid `asserted_values` would be
noise that tests nothing. So this autouse fixture relaxes the **model-construction**
gate to off for the suite by default. It does NOT weaken what those tests check:
the verifier's `check_entailment` / `check_expectation` logic runs regardless of
this flag — the flag only governs whether `Finding(...)` may be *built* without
declarations.

Gate behavior itself stays covered with the gate ON by:
  * `tests/test_events.py::TestAssertedValuesGate` (explicit flag control),
  * the gate-coverage guard test over real emitted findings, and
  * the live full-coverage validation run recorded in `docs/fact-fidelity.md`.

A test that wants the production default restored sets the env var itself
(`monkeypatch.setenv("FIND_EVIL_REQUIRE_ASSERTED_VALUES", "1")` or
`monkeypatch.delenv(...)`), which overrides this baseline for that test.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _fact_fidelity_gate_off_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FIND_EVIL_REQUIRE_ASSERTED_VALUES", "0")
