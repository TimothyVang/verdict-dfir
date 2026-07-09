"""Tests for ATT&CK Navigator layer emitter."""

from pathlib import Path

from findevil_agent.attackflow.model import load_case
from findevil_agent.attackflow.navigator import navigator_layer

FIX = Path(__file__).resolve().parent / "fixtures" / "attackflow" / "memory-case"


def test_layer_lists_observed_techniques():
    """Navigator layer includes all observed techniques."""
    layer = navigator_layer(load_case(FIX))
    assert layer["domain"] == "enterprise-attack"
    tids = {t["techniqueID"] for t in layer["techniques"]}
    assert "T1543.003" in tids and "T1070.001" in tids


def test_layer_scores_confirmed_higher():
    """Navigator layer scores CONFIRMED techniques at 100."""
    layer = navigator_layer(load_case(FIX))
    by_id = {t["techniqueID"]: t for t in layer["techniques"]}
    assert by_id["T1543.003"]["score"] == 100  # CONFIRMED
