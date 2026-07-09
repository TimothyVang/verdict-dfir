"""Render a finding's server-read evidence value (the sealed entailment slice).

The verifier seals an entailment slice onto each finding's replay artifact
(`findevil_agent.verifier`): for every asserted value it confirmed, the value the
deterministic parser READ from the re-run evidence (server-read, not
model-transcribed). The analyst report should surface that value, not only the
model's free-text description, so a tolerant match (a substring, a
differently-formatted timestamp, hex vs decimal) cannot let the model's spelling
reach the reader as the fact.

This turns the sealed slice into Markdown lines. It is deliberately stdlib-only
and operates on the already-serialized slice (a plain dict), so it is testable
without the report renderer's matplotlib dependency and adds no import weight to
the render path.
"""

from __future__ import annotations

from typing import Any


def entailment_evidence_lines(finding: dict[str, Any]) -> list[str]:
    """Markdown bullet lines naming the value the parser read from evidence for
    each confirmed asserted value, or ``[]`` when the finding carries no
    entailment slice. Malformed matched entries are skipped, never raised on."""
    artifact = finding.get("replay_artifact") or {}
    slice_ = artifact.get("entailment") or {}
    matched = slice_.get("matched") or []
    lines: list[str] = []
    for m in matched:
        if not isinstance(m, dict):
            continue
        path = str(m.get("path", "?"))
        actual = str(m.get("actual", ""))
        lines.append(
            f"- read from evidence (entailment-confirmed, not transcribed): "
            f"`{path}` = `{actual}`"
        )
    return lines
