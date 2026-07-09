"""Parse a finished case dir into a single in-memory AttackFlowModel.

Presentation-only transform: reads only the case dir's own JSON files
(``verdict.json`` plus optional ``psscan.json`` / ``pslist.json``), makes no
network or LLM calls, and is fully deterministic. Stable ids are derived with
``uuid.uuid5`` against a fixed namespace so the same case dir always yields
the same ids.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from itertools import pairwise
from pathlib import Path
from typing import Any

# Fixed namespace so ids are byte-stable across runs/machines (no randomness).
NS = uuid.UUID("6f2c9d40-a1b2-4c3d-8e5f-a1b2c3d4e5f6")

# Brand confidence tokens (docs/brand.md / scripts/_report_style.css): Seafoam,
# Butter, Cobalt. Also the set of valid confidence tiers used by _confidence().
CONFIDENCE_COLORS: dict[str, str] = {
    "CONFIRMED": "#73D9C2",  # Seafoam
    "INFERRED": "#FFD76A",  # Butter
    "HYPOTHESIS": "#4D5DFF",  # Cobalt
}


def stable_id(prefix: str, *parts: str) -> str:
    return f"{prefix}--{uuid.uuid5(NS, '|'.join(parts))}"


@dataclass
class ActionNode:
    id: str
    finding_id: str
    technique: str | None
    name: str | None
    description: str | None
    host: str | None
    ts: str | None
    confidence: str | None
    tool_call_id: str | None
    artifact_path: str | None
    process_ref: tuple[str | None, int] | None


@dataclass
class AssetNode:
    id: str
    kind: str
    value: str


@dataclass
class Edge:
    src: str
    dst: str
    kind: str


@dataclass
class ProcNode:
    key: tuple[str | None, int]
    host: str | None
    pid: int
    ppid: int | None
    image_name: str | None
    create_time_iso: str | None
    tool_call_id: str | None
    source: str
    linked_action_ids: list[str] = field(default_factory=list)


@dataclass
class AttackFlowModel:
    case_id: str
    headline: str
    description: str
    actions: list[ActionNode]
    assets: list[AssetNode]
    edges: list[Edge]
    procs: list[ProcNode]
    proc_source: str  # "psscan" | "pslist" | "timeline" | "none"
    proc_reason: str | None
    observed_techniques: list[str]
    timeline_events: list[dict[str, Any]] = field(default_factory=list)


def _read_json(path: Path) -> Any:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def _confidence(raw: Any) -> str:
    val = str(raw or "").upper()
    return val if val in CONFIDENCE_COLORS else "HYPOTHESIS"


def _build_actions(
    findings: list[dict[str, Any]], timeline_pid: dict[str, int]
) -> list[ActionNode]:
    actions: list[ActionNode] = []
    for f in sorted(findings, key=lambda f: str(f.get("ts") or "")):
        fid = str(f.get("finding_id") or f.get("event_id") or "")
        tech = f.get("mitre_technique") or None
        host = f.get("host") or None
        pid = timeline_pid.get(fid)
        actions.append(
            ActionNode(
                id=stable_id("attack-action", fid),
                finding_id=fid,
                technique=tech,
                name=f.get("named_technique") or tech or "unmapped",
                description=f.get("description") or "",
                host=host,
                ts=f.get("ts") or None,
                confidence=_confidence(f.get("confidence")),
                tool_call_id=f.get("tool_call_id") or None,
                artifact_path=f.get("artifact_path") or None,
                process_ref=(host, pid) if pid is not None else None,
            )
        )
    return actions


def _build_assets(entity_index: dict[str, Any], indicators: dict[str, Any]) -> list[AssetNode]:
    assets: list[AssetNode] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, value: Any) -> None:
        value_str = str(value).strip()
        if not value_str or (kind, value_str) in seen:
            return
        seen.add((kind, value_str))
        assets.append(
            AssetNode(id=stable_id("attack-asset", kind, value_str), kind=kind, value=value_str)
        )

    for kind_key, kind in (
        ("hosts", "host"),
        ("accounts", "account"),
        ("processes", "process"),
        ("source_ips", "ip"),
        ("destination_ips", "ip"),
    ):
        for ent in (entity_index or {}).get(kind_key, []) or []:
            add(kind, ent.get("value") if isinstance(ent, dict) else ent)
    for kind_key, kind in (
        ("hosts", "host"),
        ("accounts", "account"),
        ("processes", "process"),
        ("ip_addresses", "ip"),
    ):
        for val in (indicators or {}).get(kind_key, []) or []:
            add(kind, val)
    return assets


def _timeline_pid_by_finding(timeline: dict[str, Any]) -> dict[str, int]:
    out: dict[str, int] = {}
    for ev in (timeline or {}).get("events", []) or []:
        pid = (ev.get("entities") or {}).get("pid")
        if pid is None:
            continue
        for fid in ev.get("linked_finding_ids") or []:
            out[str(fid)] = int(pid)
    return out


def _coerce_int(val: Any) -> int | None:
    try:
        return int(val)
    except (TypeError, ValueError):
        return None


def _build_procs(case_dir: Path, host_hint: str | None) -> tuple[list[ProcNode], str, str | None]:
    for name, source in (("psscan.json", "psscan"), ("pslist.json", "pslist")):
        rows = _read_json(case_dir / name)
        if not isinstance(rows, list) or not rows:
            continue
        if not all(isinstance(r, dict) and _coerce_int(r.get("pid")) is not None for r in rows):
            return [], "none", "process artifact present but unreadable"
        # psscan (and pid reuse) can list the same pid more than once — terminated
        # plus live entries. A process tree is one node per pid, so keep the first
        # occurrence deterministically; duplicates would otherwise double whole
        # subtrees when a repeated pid is a parent.
        procs = []
        seen_pids: set[int] = set()
        for r in rows:
            pid = _coerce_int(r["pid"])
            if pid in seen_pids:
                continue
            seen_pids.add(pid)
            procs.append(
                ProcNode(
                    key=(host_hint, pid),
                    host=host_hint,
                    pid=pid,
                    ppid=_coerce_int(r.get("ppid")),
                    image_name=r.get("image_name"),
                    create_time_iso=r.get("create_time_iso"),
                    tool_call_id=None,  # displayed later from audit if resolvable
                    source=source,
                )
            )
        return procs, source, None
    return [], "none", "no process-lineage artifact in this case"


def load_case(case_dir: Path) -> AttackFlowModel:
    case_dir = Path(case_dir)
    verdict = _read_json(case_dir / "verdict.json") or {}
    findings = verdict.get("findings") or []
    timeline = verdict.get("normalized_timeline") or {}
    story = verdict.get("attack_story") or {}
    host_hint = None
    hosts = (verdict.get("indicators") or {}).get("hosts") or []
    if hosts:
        host_hint = hosts[0]

    actions = _build_actions(findings, _timeline_pid_by_finding(timeline))
    assets = _build_assets(verdict.get("entity_index") or {}, verdict.get("indicators") or {})

    edges: list[Edge] = [
        Edge(src=prev.id, dst=nxt.id, kind="chronological") for prev, nxt in pairwise(actions)
    ]

    procs, proc_source, proc_reason = _build_procs(case_dir, host_hint)
    # cross-link actions <-> procs by pid
    by_pid = {p.pid: p for p in procs}
    for a in actions:
        if a.process_ref and a.process_ref[1] in by_pid:
            by_pid[a.process_ref[1]].linked_action_ids.append(a.id)

    return AttackFlowModel(
        case_id=str(verdict.get("case_id") or case_dir.name),
        headline=str(story.get("headline") or "Attack flow"),
        description=str(story.get("attack_chain") or ""),
        actions=actions,
        assets=assets,
        edges=edges,
        procs=procs,
        proc_source=proc_source,
        proc_reason=proc_reason,
        observed_techniques=list(
            (verdict.get("attack_coverage") or {}).get("observed_techniques") or []
        ),
        timeline_events=list(timeline.get("events") or []),
    )
