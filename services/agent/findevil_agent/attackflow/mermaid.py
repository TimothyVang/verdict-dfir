"""Mermaid emitter for the attack flow panel."""

from __future__ import annotations

from .model import AttackFlowModel

# Brand confidence tiers: (border/stroke, light fill). Text on fills is #20242e.
_TIER_STYLE: dict[str, tuple[str, str]] = {
    "CONFIRMED": ("#73D9C2", "#D6F4EC"),
    "INFERRED": ("#FFD76A", "#FFF6DC"),
    "HYPOTHESIS": ("#4D5DFF", "#E7E9FF"),
}
_TEXT_COLOR = "#20242e"


def _san(text: str) -> str:
    """Mermaid node labels: strip quotes/newlines/brackets that break parsing."""
    return (
        (text or "").replace('"', "'").replace("\n", " ").replace("[", "(").replace("]", ")")[:80]
    )


def _class_for(confidence: str | None) -> str:
    tier = (confidence or "").upper()
    return tier.lower() if tier in _TIER_STYLE else "hypothesis"


def _nid(node_id: str) -> str:
    """Mermaid ids can't contain '-'; strip hyphens from the uuid tail to an alnum token."""
    return "n" + node_id.split("--")[-1].replace("-", "")


def _class_defs() -> list[str]:
    lines = []
    for tier in ("CONFIRMED", "INFERRED", "HYPOTHESIS"):
        stroke, fill = _TIER_STYLE[tier]
        lines.append(
            f"  classDef {tier.lower()} fill:{fill},stroke:{stroke},"
            f"stroke-width:2px,color:{_TEXT_COLOR};"
        )
    return lines


def flow_mermaid(model: AttackFlowModel) -> str:
    """Generate a left-right graph of actions connected by chronological edges."""
    if not model.actions:
        return 'graph LR\n  none["no reportable findings"]\n'
    lines = ["flowchart LR"]
    lines.extend(_class_defs())
    for a in model.actions:
        technique = _san(a.technique or "unmapped")
        name = _san(a.name or "")
        if name == technique:  # technique-only finding: don't repeat the code
            name = ""
        label = f"{technique}<br/>{name}" if name else technique
        lines.append(f'  {_nid(a.id)}(["{label}"]):::{_class_for(a.confidence)}')
    for e in model.edges:
        lines.append(f"  {_nid(e.src)} --> {_nid(e.dst)}")
    return "\n".join(lines) + "\n"
