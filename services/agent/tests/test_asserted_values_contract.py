"""Doc-rot guard for the fact-fidelity contract.

`asserted_values` only has teeth against the LLM authoring path if the agent's
operating files actually tell it to declare them. If that teaching is deleted,
the model silently stops declaring verifiable facts and the entailment check
no-ops — a regression invisible to every other test. These guards fail loudly
if the contract leaves SOUL.md / TOOLS.md.
"""

from __future__ import annotations

from pathlib import Path

_ROOT = Path(__file__).resolve().parents[3]


def _read(rel: str) -> str:
    return (_ROOT / rel).read_text(encoding="utf-8").lower()


def test_soul_teaches_the_asserted_values_contract() -> None:
    soul = _read("agent-config/SOUL.md")
    assert "asserted_values" in soul
    # The epistemic point: a SHA-match is not a correct read.
    assert "re-extract" in soul or "misread" in soul


def test_tools_teaches_entailment_and_asserted_values() -> None:
    tools = _read("agent-config/TOOLS.md")
    assert "asserted_values" in tools
    assert "entailment" in tools
    # The scope must stay honest — structured-value fidelity, not "malice".
    assert "honest scope" in tools
