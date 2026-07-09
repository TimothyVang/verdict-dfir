"""ATT&CK Navigator layer emitter (v4.5 layer schema)."""

from __future__ import annotations

from .model import CONFIDENCE_COLORS, AttackFlowModel

_SCORE = {"CONFIRMED": 100, "INFERRED": 60, "HYPOTHESIS": 30}


def navigator_layer(model: AttackFlowModel) -> dict:
    """Emit an ATT&CK Navigator layer v4.5 from an AttackFlowModel.

    Scores observed techniques by maximum finding confidence.
    Deterministic and stable: techniques are sorted for consistent output.

    Args:
        model: AttackFlowModel with actions and observed techniques.

    Returns:
        ATT&CK Navigator v4.5 layer dict.
    """
    best: dict[str, int] = {}

    # Score techniques from actions by confidence.
    for a in model.actions:
        if not a.technique:
            continue
        best[a.technique] = max(
            best.get(a.technique, 0),
            _SCORE.get(a.confidence or "HYPOTHESIS", 30),
        )

    # Ensure all observed techniques appear at minimum score.
    for t in model.observed_techniques:
        best.setdefault(t, 30)

    # Build techniques list, sorted for stable output.
    techniques = [
        {"techniqueID": tid, "score": score, "enabled": True} for tid, score in sorted(best.items())
    ]

    return {
        "name": f"VERDICT {model.case_id}",
        "versions": {"layer": "4.5", "navigator": "4.9.1", "attack": "14"},
        "domain": "enterprise-attack",
        "description": "Techniques observed in this VERDICT case (presentation only).",
        "techniques": techniques,
        "gradient": {
            "colors": [CONFIDENCE_COLORS["HYPOTHESIS"], CONFIDENCE_COLORS["CONFIRMED"]],
            "minValue": 0,
            "maxValue": 100,
        },
    }
