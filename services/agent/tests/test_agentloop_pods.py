"""Pod definitions + the record_finding meta-tool shape.

The production finding sink is AgentToolBridge (integration.py); pods.py now only
provides the two pod prompts and the record_finding tool spec.
"""

from __future__ import annotations

from findevil_agent.agentloop.pods import POOL_A, POOL_B, RECORD_FINDING_TOOL


def test_pod_definitions_and_record_tool_shape() -> None:
    assert POOL_A.pool_origin == "A" and POOL_B.pool_origin == "B"
    assert POOL_A.name != POOL_B.name
    assert len(POOL_A.system_prompt) > 100 and len(POOL_B.system_prompt) > 100
    # the citation contract is taught in the system prompt
    assert "record_finding" in POOL_A.system_prompt
    assert "tool_call_id" in POOL_A.system_prompt
    assert RECORD_FINDING_TOOL["function"]["name"] == "record_finding"
    required = RECORD_FINDING_TOOL["function"]["parameters"]["required"]
    assert "tool_call_id" in required and "confidence" in required
