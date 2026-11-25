"""Tests for replay artifacts and cache behavior."""

from __future__ import annotations

import hashlib
import json

from findevil_agent.mcp_client import MockMcpClient
from findevil_agent.replay import ReplayPool, classify_drift, replay_tool_call


def _sha(obj: object) -> str:
    text = json.dumps(obj, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def test_classify_exact_and_material_drift() -> None:
    assert classify_drift(expected_sha256="a", actual_sha256="a") == (
        "exact_match",
        "replay output_sha256 matches audit log",
    )
    drift, reason = classify_drift(expected_sha256="a", actual_sha256="b")
    assert drift == "material_drift"
    assert "differs" in reason


def test_replay_artifact_records_structured_fields() -> None:
    client = MockMcpClient()
    client.register("evtx_query", {"rows": [1]})
    artifact = replay_tool_call(
        tool_call_id="tc-1",
        record={
            "tool_name": "evtx_query",
            "arguments": {"case_id": "c"},
            "output_sha256": _sha({"rows": [1]}),
        },
        mcp=client,
    )
    assert artifact.schema_version == "findevil.replay.v1"
    assert artifact.drift_class == "exact_match"
    assert artifact.matched is True
    assert artifact.arguments_sha256 is not None


def test_replay_pool_caches_unless_force_fresh() -> None:
    calls = {"count": 0}
    client = MockMcpClient()

    def handler(_args: dict[str, object]) -> dict[str, int]:
        calls["count"] += 1
        return {"count": calls["count"]}

    client.register("counter", handler)
    pool = ReplayPool(client)
    try:
        first = pool.replay("counter", {})
        second = pool.replay("counter", {})
        fresh = pool.replay("counter", {}, force_fresh=True)
    finally:
        pool.close()

    assert first.output_sha256 == second.output_sha256
    assert fresh.output_sha256 != first.output_sha256
    assert calls["count"] == 2


def test_replay_pool_submit_supports_concurrent_replay() -> None:
    client = MockMcpClient()
    client.register("echo", lambda args: {"value": args["value"]})
    pool = ReplayPool(client, max_workers=2)
    try:
        futures = [pool.submit("echo", {"value": idx}) for idx in range(2)]
        results = [future.result(timeout=5) for future in futures]
    finally:
        pool.close()

    assert {result.parsed["value"] for result in results if result.parsed} == {0, 1}
