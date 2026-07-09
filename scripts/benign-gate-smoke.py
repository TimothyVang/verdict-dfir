#!/usr/bin/env python3
"""Benign-explanation gate smoke (P0-5a).

Locks the presumption-of-benignity gate and guards against doc-rot:

  1. SOUL.md / TOOLS.md / AGENTS.md teach the counter_hypothesis doctrine (so the
     emitters are instructed before stage 5b flips the gate on).
  2. With the gate flag ON, the schema validator rejects a CONFIRMED finding that
     records no counter_hypothesis at construction.
  3. With the gate flag ON, the correlator downgrades an execution/intent finding
     that reached it (via the wire) without a counter_hypothesis, and KEEPS one
     that carries it.

The gate is opt-in (FIND_EVIL_REQUIRE_COUNTER_HYPOTHESIS_FINDING, default-OFF), so
it is inert on live runs until the emitters are verified to populate the field
(stage 5b). This smoke exercises it with the flag explicitly ON.

Run under the agent venv:
    uv run --directory services/agent python ../../scripts/benign-gate-smoke.py
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "services" / "agent"))

# Isolate the benign gate from the asserted-values gate.
os.environ["FIND_EVIL_REQUIRE_ASSERTED_VALUES"] = "0"
os.environ["FIND_EVIL_REQUIRE_COUNTER_HYPOTHESIS_FINDING"] = "1"

from pydantic import ValidationError  # noqa: E402

from findevil_agent.correlator import correlate  # noqa: E402
from findevil_agent.events import Finding  # noqa: E402

_FAILURES: list[str] = []
_EXEC = "Prefetch + Amcache corroborate execution of attacker.exe"


def _check(label: str, ok: bool, detail: str = "") -> None:
    if ok:
        print(f"OK   {label}")
    else:
        _FAILURES.append(label)
        print(f"FAIL {label}{f': {detail}' if detail else ''}")


def _finding(**over: object) -> Finding:
    fields: dict[str, object] = {
        "case_id": "c",
        "finding_id": "f-1",
        "tool_call_id": "tc-1",
        "artifact_path": "x",
        "confidence": "CONFIRMED",
        "description": _EXEC,
    }
    fields.update(over)
    return Finding(**fields)  # type: ignore[arg-type]


def main() -> int:
    # 1. Doc-rot guard: the doctrine must be taught where the emitters read it.
    for doc in ("SOUL.md", "TOOLS.md", "AGENTS.md"):
        text = (REPO / "agent-config" / doc).read_text(encoding="utf-8")
        _check(f"{doc} teaches counter_hypothesis", "counter_hypothesis" in text)

    # 2. Schema gate: CONFIRMED without counter_hypothesis is rejected at build.
    try:
        _finding()
    except ValidationError:
        _check("schema rejects CONFIRMED without counter_hypothesis", True)
    else:
        _check(
            "schema rejects CONFIRMED without counter_hypothesis", False, "constructed"
        )

    _check(
        "schema accepts CONFIRMED with counter_hypothesis",
        _finding(
            counter_hypothesis="benign: vendor updater ruled out"
        ).counter_hypothesis
        is not None,
    )

    # 3. Correlator gate: a wire-arriving execution finding (schema bypassed via
    #    model_construct) missing counter_hypothesis is downgraded; one with it is kept.
    wire_missing = Finding.model_construct(
        case_id="c",
        finding_id="f-1",
        tool_call_id="tc-1",
        artifact_path="x",
        confidence="CONFIRMED",
        description=_EXEC,
        counter_hypothesis=None,
    )
    refined, outcomes = correlate([wire_missing])
    _check(
        "correlator downgrades execution missing counter_hypothesis",
        refined[0].confidence == "INFERRED" and outcomes[0].action == "downgraded",
        f"got {refined[0].confidence}/{outcomes[0].action}",
    )

    kept = _finding(counter_hypothesis="benign: legitimate admin task ruled out")
    refined2, outcomes2 = correlate([kept])
    _check(
        "correlator keeps execution with counter_hypothesis",
        refined2[0].confidence == "CONFIRMED" and outcomes2[0].action == "kept",
        f"got {refined2[0].confidence}/{outcomes2[0].action}",
    )

    if _FAILURES:
        print(f"\nFAIL: {len(_FAILURES)} benign-gate invariant(s) broken")
        return 1
    print("\nPASS: benign-explanation gate holds and the doctrine is taught")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
