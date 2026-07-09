"""Serialize an AttackFlowModel to a MITRE CTID Attack Flow STIX 2.1 bundle."""

from __future__ import annotations

from .model import AttackFlowModel, stable_id

_EXT_ID = "extension-definition--fb9c968a-745b-4ade-9b25-c324172197f4"  # CTID Attack Flow ext
_CREATED = "2020-01-01T00:00:00.000Z"  # fixed constant: deterministic, not a real timestamp


def _obj(otype: str, oid: str, **props) -> dict:
    base = {
        "type": otype,
        "spec_version": "2.1",
        "id": oid,
        "created": _CREATED,
        "modified": _CREATED,
    }
    base.update({k: v for k, v in props.items() if v is not None})
    return base


def _extension_definition() -> dict:
    return {
        "type": "extension-definition",
        "spec_version": "2.1",
        "id": _EXT_ID,
        "created": _CREATED,
        "modified": _CREATED,
        "name": "Attack Flow",
        "description": "Extends STIX 2.1 with Attack Flow objects and properties.",
        "created_by_ref": "identity--fb9c968a-745b-4ade-9b25-c324172197f4",
        "schema": "https://center-for-threat-informed-defense.github.io/attack-flow/stix/attack-flow-schema-2.0.0.json",
        "version": "2.0.0",
        "extension_types": ["new-sdo", "new-sco"],
    }


def to_stix_bundle(model: AttackFlowModel) -> dict:
    objects: list[dict] = [_extension_definition()]
    action_ids = [a.id for a in model.actions]
    flow_id = stable_id("attack-flow", model.case_id)

    objects.append(
        _obj(
            "attack-flow",
            flow_id,
            name=model.headline,
            description=model.description or None,
            start_refs=action_ids[:1] or None,
            extensions={_EXT_ID: {"extension_type": "new-sdo"}},
        )
    )

    by_pid = {p.pid: p for p in model.procs}
    proc_asset_ids: dict[int, str] = {}

    next_by = {e.src: e.dst for e in model.edges}
    for a in model.actions:
        effect = [next_by[a.id]] if a.id in next_by else None
        asset_refs: list[str] = []
        if a.host:
            asset_refs.append(stable_id("attack-asset", "host", a.host))
        if a.process_ref and a.process_ref[1] in by_pid:
            pid = a.process_ref[1]
            proc_asset_ids.setdefault(pid, stable_id("attack-asset", "process", str(pid)))
            asset_refs.append(proc_asset_ids[pid])
        objects.append(
            _obj(
                "attack-action",
                a.id,
                name=a.name or (a.technique or "unmapped"),
                technique_id=a.technique,
                description=a.description or None,
                effect_refs=effect,
                asset_refs=asset_refs or None,
                extensions={_EXT_ID: {"extension_type": "new-sdo"}},
            )
        )

    for asset in model.assets:
        objects.append(
            _obj(
                "attack-asset",
                asset.id,
                name=f"{asset.kind}:{asset.value}",
                extensions={_EXT_ID: {"extension_type": "new-sdo"}},
            )
        )

    for pid, asset_id in proc_asset_ids.items():
        proc = by_pid[pid]
        objects.append(
            _obj(
                "attack-asset",
                asset_id,
                name=f"process:{proc.image_name or '?'} (pid {pid})",
                extensions={_EXT_ID: {"extension_type": "new-sdo"}},
            )
        )

    return {"type": "bundle", "id": stable_id("bundle", model.case_id), "objects": objects}
