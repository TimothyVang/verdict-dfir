"""``verify_finding`` tool — re-run a Finding's cited tool call.

Wraps :func:`findevil_agent.verifier.reverify_finding`. The wrapper
spawns its own short-lived stdio connection to ``findevil-mcp`` (the
Rust DFIR tool server) so the re-execution path is byte-for-byte
identical to what the original agent saw — same binary, same args,
same SHA-256.

Returns the verifier action ('approved' / 'rejected' / 'downgraded')
plus a replay record describing the comparison.

The Rust binary is spawned as a child process for each call. That's
not the cheapest possible path, but it's the cleanest — the
verifier is intentionally a deliberation step (Spec #2 §8.1 budgets
30s/finding), not a hot loop, and a fresh subprocess avoids any
state leak between findings.
"""

from __future__ import annotations

from typing import Any

from findevil_agent.events import Finding
from findevil_agent.mcp_client import McpClient, StdioMcpClient
from findevil_agent.replay import ReplayArtifact
from findevil_agent.verifier import reverify_finding
from pydantic import BaseModel, ConfigDict, Field

from findevil_agent_mcp.tools._base import ToolSpec


class VerifyFindingInput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    finding: dict[str, Any] = Field(
        ...,
        description=(
            "The Finding to re-verify, as a dict matching the Finding "
            "AgentEvent schema (case_id, finding_id, tool_call_id, "
            "artifact_path, confidence, description, etc.). A CONFIRMED/"
            "INFERRED finding SHOULD carry asserted_values "
            "[{path, expected, match, count?}] — the structured fact(s) it "
            "claims; after the cited output reproduces, the verifier re-extracts "
            "each from that output (entailment check) and rejects a misread. A "
            "wrong hard IDENTITY anchor (hash/IP) is rejected outright; a count "
            "claim (set count>1) backed by fewer entailed lines is demoted."
        ),
    )
    tool_call_index: dict[str, dict[str, Any]] = Field(
        ...,
        description=(
            "Map tool_call_id -> {tool_name, arguments, output_sha256} "
            "from the audit log. The verifier looks up the cited "
            "tool_call_id here, then re-runs that exact call."
        ),
    )
    findevil_mcp_command: list[str] = Field(
        ...,
        description=(
            "Argv to launch findevil-mcp (the Rust DFIR tool server). "
            "Example: ['cargo', 'run', '--release', '-p', 'findevil-mcp', "
            "'--quiet']."
        ),
        min_length=1,
    )
    force_fresh_replay: bool = Field(
        default=False,
        description="Bypass replay cache when a caller supplies pooled verifier execution.",
    )
    downgrade_on_drift: bool = Field(
        default=False,
        description=(
            "Terminal drift policy. False (first pass): sha256 drift on a "
            "CONFIRMED finding is rejected so the orchestrator re-dispatches "
            "once with a fresh replay. True (the re-dispatch attempt): "
            "persistent drift takes the terminal downgrade."
        ),
    )


class VerifyFindingOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    action: str = Field(..., description="'approved', 'rejected', or 'downgraded'.")
    finding_id: str
    reason: str
    replay_tool_name: str | None
    replay_expected_sha256: str | None
    replay_actual_sha256: str | None
    replay_matched: bool | None
    replay_error: str | None
    replay_artifact: ReplayArtifact | None = Field(
        default=None,
        description="Structured replay artifact. Legacy top-level replay_* fields are preserved.",
    )


# Replay re-runs the finding's cited tool, which may be a slow memory plugin
# (vol_malfind on a multi-GB image runs for many minutes — the main
# investigation budgets it 1800s). The StdioMcpClient default request timeout
# is 120s, which falsely rejected legitimate slow-tool findings with an "MCP
# request timed out after 120.0s" replay error. Match the main run's slowest
# budget so verification rejects on real drift, not on a too-short clock. The
# timeout is a ceiling, so fast tools still return immediately.
_REPLAY_TIMEOUT_S = 1800.0


# Indirection to let tests monkeypatch the client factory.
def _make_mcp_client(command: list[str]) -> McpClient:
    return StdioMcpClient(command, request_timeout_s=_REPLAY_TIMEOUT_S)


async def _handle(inp: BaseModel) -> VerifyFindingOutput:
    assert isinstance(inp, VerifyFindingInput)
    finding = Finding.model_validate(inp.finding)
    client = _make_mcp_client(list(inp.findevil_mcp_command))
    try:
        action, replay = reverify_finding(
            finding,
            mcp=client,
            tool_call_index=inp.tool_call_index,
            force_fresh=inp.force_fresh_replay,
            downgrade_on_drift=inp.downgrade_on_drift,
        )
    finally:
        client.close()

    return VerifyFindingOutput(
        action=action.action,
        finding_id=action.finding_id,
        reason=action.reason,
        replay_tool_name=replay.tool_name if replay else None,
        replay_expected_sha256=replay.expected_sha256 if replay else None,
        replay_actual_sha256=replay.actual_sha256 if replay else None,
        replay_matched=replay.matched if replay else None,
        replay_error=replay.error if replay else None,
        replay_artifact=replay.artifact if replay else None,
    )


SPEC = ToolSpec(
    name="verify_finding",
    description=(
        "M4 verifier stage — re-run the Rust DFIR tool call cited by a Finding's "
        "tool_call_id and decide approve / reject / downgrade. Run this AFTER both "
        "pools have emitted findings and BEFORE judge_findings. The verifier is the "
        "architectural guard for the 'every Finding cites a tool_call_id' invariant: "
        "rejected = no tool_call_id (Spec violation) or replay raised an MCP error; "
        "downgraded = output_sha256 drifted between original run and replay (still "
        "real evidence, just one tier less confident); approved = byte-for-byte match. "
        "Spawns a fresh findevil-mcp subprocess per call so replays are independent. "
        "tool_call_index must map every cited tool_call_id to its original "
        "{tool_name, arguments, output_sha256} from the audit log — build this index "
        "from your audit_verify pass before calling here. "
        "On error: if an MCP rpc error code surfaces, check that findevil_mcp_command "
        "is correct (default: ['cargo','run','--release','-p','findevil-mcp','--quiet'])."
    ),
    input_model=VerifyFindingInput,
    output_model=VerifyFindingOutput,
    handler=_handle,
)

__all__ = [
    "SPEC",
    "VerifyFindingInput",
    "VerifyFindingOutput",
    "_make_mcp_client",
]
