"""Technique-grouped SUMMARY view: one card per ATT&CK technique, Confirmed-first.

The raw ``attack-flow.mmd`` renders every finding as its own node, which repeats
heavily when several findings map to the same technique. This module collapses
those repeats into one card per technique so a reader sees "what we're sure of"
first, then leads.

Deterministic, offline, presentation only: this never creates or alters a
Finding, and reuses the same ``AttackFlowModel`` the other emitters consume.
"""

from __future__ import annotations

from html import escape

from .model import ActionNode, AttackFlowModel

_TIER_RANK: dict[str, int] = {"CONFIRMED": 0, "INFERRED": 1, "HYPOTHESIS": 2}

# Brand confidence tiers: (fill, stroke). Shared with the other attack-flow emitters.
_TIER_STYLE: dict[str, tuple[str, str]] = {
    "CONFIRMED": ("#D6F4EC", "#73D9C2"),
    "INFERRED": ("#FFF6DC", "#FFD76A"),
    "HYPOTHESIS": ("#E7E9FF", "#4D5DFF"),
}

_INK = "#101426"
_CREAM = "#F5F1E8"
_COBALT = "#4D5DFF"
_CORAL = "#FF6257"
_SEAFOAM = "#73D9C2"


def _tier(confidence: str | None) -> str:
    tier = (confidence or "").upper()
    return tier if tier in _TIER_RANK else "HYPOTHESIS"


def _tier_rank(confidence: str | None) -> int:
    return _TIER_RANK[_tier(confidence)]


def _best_confidence(members: list[ActionNode]) -> str:
    return min((_tier(m.confidence) for m in members), key=lambda t: _TIER_RANK[t])


def _group_name(technique: str, members: list[ActionNode]) -> str:
    """Prefer the longest member name that differs from the bare technique id."""
    candidates = [m.name for m in members if m.name and m.name != technique]
    if not candidates:
        return technique
    return max(candidates, key=len)


def group_by_technique(model: AttackFlowModel) -> list[dict]:
    """Collapse ``model.actions`` into one dict per ATT&CK technique.

    Each group: technique, name, count, best_confidence, members (ts/finding_id
    stable order), hosts (sorted unique), tool_call_ids (sorted unique),
    linked_pids (sorted unique pids from members' process_ref). Deterministic —
    no wall-clock time or randomness, stable-sorted throughout.
    """
    by_technique: dict[str, list[ActionNode]] = {}
    for action in model.actions:
        key = action.technique or "unmapped"
        by_technique.setdefault(key, []).append(action)

    groups: list[dict] = []
    for technique, members in by_technique.items():
        ordered = sorted(members, key=lambda m: (m.ts or "", m.finding_id or ""))
        hosts = sorted({m.host for m in ordered if m.host})
        tool_call_ids = sorted({m.tool_call_id for m in ordered if m.tool_call_id})
        linked_pids = sorted({m.process_ref[1] for m in ordered if m.process_ref})
        groups.append(
            {
                "technique": technique,
                "name": _group_name(technique, ordered),
                "count": len(ordered),
                "best_confidence": _best_confidence(ordered),
                "members": ordered,
                "hosts": hosts,
                "tool_call_ids": tool_call_ids,
                "linked_pids": linked_pids,
            }
        )

    groups.sort(key=lambda g: (_TIER_RANK[g["best_confidence"]], -g["count"], g["technique"]))
    return groups


_STYLE = f"""
<style>
.afs-root {{
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
  color: {_INK};
  background: {_CREAM};
  border-radius: 8px;
  padding: 1rem 1.25rem;
  font-size: 13px;
  line-height: 1.45;
}}
.afs-root .afs-headline {{
  font-weight: 700;
  font-size: 15px;
  margin-bottom: 0.15rem;
}}
.afs-root .afs-synthesis {{
  opacity: 0.75;
  font-size: 12px;
  margin-bottom: 0.9rem;
}}
.afs-root .afs-cards {{
  display: flex;
  flex-direction: column;
  gap: 0.35rem;
}}
.afs-root .afs-card {{
  position: relative;
  border-radius: 8px;
  padding: 0.4rem 0.7rem 0.4rem 0.85rem;
  background: rgba(255,255,255,0.55);
  border: 1px solid rgba(16,20,38,0.12);
}}
.afs-root .afs-card::before {{
  content: "";
  position: absolute;
  left: 0;
  top: 0;
  bottom: 0;
  width: 5px;
  border-radius: 8px 0 0 8px;
}}
.afs-root .afs-card.afs-confirmed {{
  border-color: {_SEAFOAM};
  border-width: 2px;
  box-shadow: 0 1px 6px rgba(115, 217, 194, 0.18);
}}
.afs-root .afs-card-head {{
  display: flex;
  align-items: baseline;
  gap: 0.5rem;
  flex-wrap: wrap;
}}
.afs-root .afs-technique {{
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-weight: 700;
}}
.afs-root .afs-name {{
  font-weight: 500;
}}
.afs-root .afs-pill {{
  display: inline-block;
  padding: 0.05rem 0.5rem;
  border-radius: 999px;
  font-size: 11px;
  font-weight: 600;
  margin-left: auto;
}}
.afs-root .afs-pill-count {{
  background: rgba(16,20,38,0.08);
  color: {_INK};
}}
.afs-root .afs-band {{
  display: inline-block;
  padding: 0.05rem 0.5rem;
  border-radius: 999px;
  font-size: 10px;
  font-weight: 700;
  letter-spacing: 0.04em;
  text-transform: uppercase;
}}
.afs-root .afs-meta {{
  opacity: 0.7;
  font-size: 11px;
  margin-top: 0.1rem;
}}
.afs-root .afs-linked {{
  font-weight: 600;
}}
.afs-root details {{
  margin-top: 0.2rem;
}}
.afs-root details > summary {{
  cursor: pointer;
  font-size: 12px;
  color: {_COBALT};
}}
.afs-root .afs-member {{
  padding: 0.3rem 0 0.3rem 0.6rem;
  border-left: 2px solid rgba(16,20,38,0.1);
  margin-top: 0.3rem;
  font-size: 12px;
}}
.afs-root .afs-member-meta {{
  opacity: 0.65;
  font-size: 11px;
}}
@media (prefers-color-scheme: dark) {{
  .afs-root {{
    background: #171b2e;
    color: {_CREAM};
  }}
  .afs-root .afs-card {{
    background: rgba(255,255,255,0.05);
    border-color: rgba(245,241,232,0.15);
  }}
  .afs-root .afs-pill-count {{
    background: rgba(245,241,232,0.12);
    color: {_CREAM};
  }}
  .afs-root .afs-member {{
    border-left-color: rgba(245,241,232,0.18);
  }}
}}
</style>
""".strip()


def _pill(text: str, fill: str, stroke: str) -> str:
    return (
        f'<span class="afs-band" style="background:{fill};color:{_INK};'
        f'border:1px solid {stroke};">{escape(text)}</span>'
    )


def _member_html(member: ActionNode) -> str:
    desc = escape(member.description or "")
    tool_call = escape(member.tool_call_id or "unknown")
    ts = escape(member.ts or "unknown")
    host = escape(member.host or "unknown")
    artifact = escape(member.artifact_path or "unknown")
    return (
        '<div class="afs-member">'
        f"<div>{desc}</div>"
        f'<div class="afs-member-meta">tool_call_id <code>{tool_call}</code> '
        f"&middot; {ts} &middot; {host} &middot; {artifact}</div>"
        "</div>"
    )


def _card_html(group: dict, procs_by_pid: dict[int, str]) -> str:
    tier = group["best_confidence"]
    fill, stroke = _TIER_STYLE[tier]
    technique = escape(group["technique"])
    # only show the name when it adds something beyond the bare technique code
    name = escape(group["name"]) if group["name"] != group["technique"] else ""
    name_span = f'<span class="afs-name">{name}</span>' if name else ""
    count = group["count"]
    # Only show the host line when we actually have one — repeating "unknown host"
    # on every card (findings without a host, common on disk cases) is just noise.
    hosts_line = (
        f'<span class="afs-host">Host{"s" if len(group["hosts"]) != 1 else ""}: '
        f"{escape(', '.join(group['hosts']))}</span>"
        if group["hosts"]
        else ""
    )
    card_cls = "afs-card afs-confirmed" if tier == "CONFIRMED" else "afs-card"

    linked_inline = ""
    if group["linked_pids"]:
        images = [procs_by_pid.get(pid, "?") for pid in group["linked_pids"]]
        linked_inline = '<span class="afs-linked">Linked process{}: {}</span>'.format(
            "es" if len(group["linked_pids"]) > 1 else "",
            escape(
                ", ".join(
                    f"{img} (pid {pid})"
                    for img, pid in zip(images, group["linked_pids"], strict=True)
                )
            ),
        )

    # One compact meta line, only rendered when there's something to show.
    meta_bits = [b for b in (hosts_line, linked_inline) if b]
    meta_line = f'<div class="afs-meta">{" &middot; ".join(meta_bits)}</div>' if meta_bits else ""

    members_html = "".join(_member_html(m) for m in group["members"])

    return (
        f'<div class="{card_cls}" style="border-left-color:{stroke};">'
        '<div class="afs-card-head">'
        f'<span class="afs-technique">{technique}</span>'
        f"{name_span}"
        f"{_pill(tier, fill, stroke)}"
        f'<span class="afs-pill afs-pill-count">{count}x finding{"s" if count != 1 else ""}</span>'
        "</div>"
        f"{meta_line}"
        f"<details><summary>Show {count} finding{'s' if count != 1 else ''}</summary>"
        f"{members_html}</details>"
        "</div>"
    )


def summary_html(model: AttackFlowModel) -> str:
    """Render one card per ATT&CK technique, Confirmed-first, as an HTML fragment."""
    if not model.actions:
        return (
            '<div class="afs-root">'
            '<div class="afs-headline">No reportable findings</div>'
            f"{_STYLE}"
            "</div>"
        )

    groups = group_by_technique(model)
    procs_by_pid = {p.pid: (p.image_name or "?") for p in model.procs}

    counts: dict[str, int] = {"CONFIRMED": 0, "INFERRED": 0, "HYPOTHESIS": 0}
    for g in groups:
        counts[g["best_confidence"]] += g["count"]
    synthesis = (
        f"{counts['CONFIRMED']} confirmed, {counts['INFERRED']} inferred, "
        f"{counts['HYPOTHESIS']} hypothesis findings across {len(groups)} "
        f"technique{'s' if len(groups) != 1 else ''} — presentation only"
    )

    cards = "".join(_card_html(g, procs_by_pid) for g in groups)
    headline = escape(model.headline or "Attack flow")

    return (
        '<div class="afs-root">'
        f'<div class="afs-headline">{headline}</div>'
        f'<div class="afs-synthesis">{escape(synthesis)}</div>'
        f'<div class="afs-cards">{cards}</div>'
        f"{_STYLE}"
        "</div>"
    )
