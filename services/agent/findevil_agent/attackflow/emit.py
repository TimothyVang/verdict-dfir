"""Orchestrate all emitters: build model once, write every artifact."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .mermaid import flow_mermaid
from .model import AttackFlowModel, load_case
from .navigator import navigator_layer
from .process_tree_html import process_tree_html
from .stix import to_stix_bundle
from .summary import summary_html
from .timeline_html import timeline_html


@dataclass
class EmitResult:
    out_dir: Path
    paths: list[Path]
    html_snippet: str
    process_tree_available: bool
    proc_reason: str | None


def _dump_json(obj: object) -> str:
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _linked_actions(model: AttackFlowModel) -> list[tuple[str, str, str, int, str]]:
    """Actions with a resolvable process_ref, as (finding_id, name, technique, pid, image_name)."""
    by_pid = {p.pid: p for p in model.procs}
    out: list[tuple[str, str, str, int, str]] = []
    for a in model.actions:
        if not a.process_ref:
            continue
        pid = a.process_ref[1]
        proc = by_pid.get(pid)
        if proc is None:
            continue
        out.append((a.finding_id, a.name or "", a.technique or "", pid, proc.image_name or "?"))
    return out


def _linkage_md(model: AttackFlowModel) -> str:
    def _esc_md_cell(val: str) -> str:
        r"""Escape markdown table cell: replace | with \| and collapse newlines."""
        return str(val or "").replace("|", "\\|").replace("\n", " ")

    linked = _linked_actions(model)
    if not linked:
        return "No action is process-linked in this case.\n"
    lines = [
        "| Finding | Action | Technique | PID | Process |",
        "|---|---|---|---|---|",
    ]
    for fid, name, technique, pid, image_name in linked:
        lines.append(
            f"| `{_esc_md_cell(fid)}` | {_esc_md_cell(name)} | {_esc_md_cell(technique or '—')} | {_esc_md_cell(str(pid))} | {_esc_md_cell(image_name)} |"
        )
    return "\n".join(lines) + "\n"


def _index_md(model: AttackFlowModel) -> str:
    tree_line = (
        f"- Process tree: **{model.proc_source}** source"
        if model.proc_source != "none"
        else f"- Process tree: **omitted** — {model.proc_reason}"
    )
    return (
        f"# Attack Flow — {model.headline}\n\n"
        f"Case: `{model.case_id}` · presentation only (no findings created here).\n\n"
        f"- **Recommended first view:** `attack-summary.html` — technique-grouped overview, "
        f"Confirmed first, collapses repeated findings per technique.\n"
        f"- Attack Flow graph: `attack-flow.mmd` / `incident.attack-flow.json`\n"
        f"- Open `incident.attack-flow.json` in MITRE Attack Flow Builder "
        f"(https://center-for-threat-informed-defense.github.io/attack-flow/builder/) "
        f"for the polished interactive canvas.\n"
        f"- Branded forensic timeline (interactive): `timeline.html`\n"
        f"{tree_line}\n"
        f"- Process tree (interactive): `process-tree.html`\n"
        f"- Navigator layer: `navigator-layer.json`\n\n"
        f"## Action <-> Process linkage\n\n"
        f"{_linkage_md(model)}"
    )


def _pointer_html() -> str:
    return (
        "<p class='attackflow-more'>"
        "For the full forensic timeline, open <code>timeline.html</code>. "
        "For process lineage, open <code>process-tree.html</code>. "
        "For the interactive MITRE Attack Flow canvas, open "
        "<code>incident.attack-flow.json</code> in the "
        "<a href='https://center-for-threat-informed-defense.github.io/attack-flow/builder/'>"
        "Attack Flow Builder</a>."
        "</p>"
    )


def emit(case_dir: Path) -> EmitResult:
    case_dir = Path(case_dir)
    if not (case_dir / "verdict.json").exists():
        raise FileNotFoundError(f"no verdict.json in {case_dir}")

    model = load_case(case_dir)
    out = case_dir / "attack-flow"
    out.mkdir(parents=True, exist_ok=True)

    summary = summary_html(model)
    artifacts: dict[str, str] = {
        "incident.attack-flow.json": _dump_json(to_stix_bundle(model)),
        "attack-flow.mmd": flow_mermaid(model),
        "process-tree.html": process_tree_html(model),
        "attack-summary.html": summary,
        "timeline.html": timeline_html(model),
        "navigator-layer.json": _dump_json(navigator_layer(model)),
        "attack-flow.md": _index_md(model),
    }
    paths: list[Path] = []
    for name, text in artifacts.items():
        p = out / name
        p.write_text(text, encoding="utf-8")
        paths.append(p)

    return EmitResult(
        out_dir=out,
        paths=paths,
        html_snippet=summary + _pointer_html(),
        process_tree_available=model.proc_source != "none",
        proc_reason=model.proc_reason,
    )
