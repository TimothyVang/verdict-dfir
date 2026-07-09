from pathlib import Path

from findevil_agent.attackflow.model import load_case
from findevil_agent.attackflow.stix import to_stix_bundle

FIX = Path(__file__).resolve().parent / "fixtures" / "attackflow" / "memory-case"


def test_bundle_has_flow_and_action_objects():
    b = to_stix_bundle(load_case(FIX))
    assert b["type"] == "bundle"
    types = [o["type"] for o in b["objects"]]
    assert "attack-flow" in types
    assert types.count("attack-action") == 2
    actions = [o for o in b["objects"] if o["type"] == "attack-action"]
    assert actions[0]["technique_id"] == "T1543.003"
    assert "effect_refs" in actions[0]


def test_bundle_is_deterministic():
    a = to_stix_bundle(load_case(FIX))
    b = to_stix_bundle(load_case(FIX))
    import json

    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def test_bundle_first_object_is_extension_definition():
    b = to_stix_bundle(load_case(FIX))
    assert b["objects"][0]["type"] == "extension-definition"
    assert b["objects"][0]["name"] == "Attack Flow"


def test_bundle_links_process_asset_to_action():
    """memory-case: finding f-1 links to pid 1200 (svc.exe) via process_ref."""
    b = to_stix_bundle(load_case(FIX))
    actions = [o for o in b["objects"] if o["type"] == "attack-action"]
    process_assets = [
        o for o in b["objects"] if o["type"] == "attack-asset" and o["name"].startswith("process:")
    ]
    assert process_assets, "expected a process attack-asset for the pid-linked action"
    proc_asset = next(a for a in process_assets if "1200" in a["name"])
    assert "svc.exe" in proc_asset["name"]

    f1_action = actions[0]  # f-1 is first by ts
    assert proc_asset["id"] in f1_action["asset_refs"]
