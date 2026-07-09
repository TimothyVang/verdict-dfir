#!/usr/bin/env python3
"""Smoke: the Finding evidence-anchor firewall holds at construction.

Locks the P0-4 invariant (events.py ``_require_tool_call_id_for_anchored``): a
CONFIRMED/INFERRED Finding cannot be *constructed* with a blank ``tool_call_id``,
while a HYPOTHESIS lead may. Default-on; opt out with
``FIND_EVIL_REQUIRE_TOOL_CALL_ID=0``.

Run under the agent venv:
    uv run --directory services/agent python ../../scripts/finding-schema-smoke.py

The asserted-values gate is opted out here so this smoke isolates the
tool_call_id invariant (a CONFIRMED fixture intentionally carries no
asserted_values).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "services" / "agent"))

# Isolate the tool_call_id gate from the asserted-values gate.
os.environ["FIND_EVIL_REQUIRE_ASSERTED_VALUES"] = "0"
os.environ.pop("FIND_EVIL_REQUIRE_TOOL_CALL_ID", None)  # exercise the default (on)

from pydantic import ValidationError  # noqa: E402

from findevil_agent.events import Finding  # noqa: E402

_FAILURES: list[str] = []


def _finding(confidence: str, tool_call_id: str) -> Finding:
    return Finding(
        case_id="c-1",
        finding_id="f-1",
        tool_call_id=tool_call_id,
        artifact_path="x",
        confidence=confidence,  # type: ignore[arg-type]
        description="y",
    )


def _expect_raises(label: str, confidence: str, tool_call_id: str) -> None:
    try:
        _finding(confidence, tool_call_id)
    except ValidationError:
        print(f"OK   {label}")
    else:
        _FAILURES.append(label)
        print(
            f"FAIL {label}: constructed a {confidence} finding with a blank tool_call_id"
        )


def _expect_ok(label: str, confidence: str, tool_call_id: str) -> None:
    try:
        _finding(confidence, tool_call_id)
    except ValidationError as exc:
        _FAILURES.append(label)
        print(f"FAIL {label}: {exc.errors()[0].get('msg', exc)}")
    else:
        print(f"OK   {label}")


def main() -> int:
    _expect_raises("CONFIRMED + blank tool_call_id rejected", "CONFIRMED", "")
    _expect_raises("INFERRED + blank tool_call_id rejected", "INFERRED", "")
    _expect_raises("CONFIRMED + whitespace tool_call_id rejected", "CONFIRMED", "   ")
    _expect_ok("HYPOTHESIS + blank tool_call_id allowed (lead)", "HYPOTHESIS", "")
    _expect_ok("CONFIRMED + valid tool_call_id allowed", "CONFIRMED", "tc-1")

    # Opt-out escape hatch disables the gate.
    os.environ["FIND_EVIL_REQUIRE_TOOL_CALL_ID"] = "0"
    _expect_ok("opt-out (=0) allows blank", "CONFIRMED", "")
    os.environ.pop("FIND_EVIL_REQUIRE_TOOL_CALL_ID", None)

    if _FAILURES:
        print(f"\nFAIL: {len(_FAILURES)} finding-schema invariant(s) broken")
        return 1
    print("\nPASS: Finding evidence-anchor firewall holds")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
