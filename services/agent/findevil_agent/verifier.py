"""Verifier node — vetoes uncited Findings + re-runs tool calls.

Spec #2 §8.1 (Verify stage) + ``CLAUDE.md`` invariant
"Every Finding cites a ``tool_call_id``."

The verifier sits between the contradiction-resolution node and
the correlator in the LangGraph state machine. For every candidate
Finding it:

1. **Required-citation check.** Reject if ``tool_call_id`` is
   missing or empty. The agent system prompts already enforce
   this, but the verifier is the architectural guard.
2. **Re-execution check.** Re-runs the tool call and confirms the
   output_sha256 matches what the audit log declared. If the
   digests diverge, downgrade the Finding's confidence (a tool
   that produced different output on replay is, at best, racy
   evidence).
3. **Confidence floor.** If the re-execution fails entirely, the
   Finding is rejected — the underlying evidence is no longer
   reproducible.

The verifier uses ``McpClient`` (production: ``StdioMcpClient``;
tests: ``MockMcpClient``) so we never need a live Rust binary in
unit tests.

This module is pure orchestration over the existing ``mcp_client``
+ ``events`` types. No LLM calls — confidence decisions are
deterministic given the same inputs, which is what the M2 chain
requires for replay.
"""

from __future__ import annotations

from typing import Any

from findevil_agent.events import Finding, VerifierAction
from findevil_agent.mcp_client import McpClient
from findevil_agent.replay import (
    ReplayArtifact,
    ReplayPool,
    missing_replay_artifact,
    replay_tool_call,
)


class CallReplay:
    """Backward-compatible view over :class:`ReplayArtifact`."""

    def __init__(self, artifact: ReplayArtifact, arguments: dict[str, Any] | None = None) -> None:
        self.artifact = artifact
        self.tool_name = artifact.tool_name or ""
        self.arguments = arguments or {}
        self.expected_sha256 = artifact.expected_sha256 or ""
        self.actual_sha256 = artifact.actual_sha256
        self.matched = bool(artifact.matched)
        self.error = artifact.error
        self.drift_class = artifact.drift_class


def reverify_finding(
    finding: Finding,
    *,
    mcp: McpClient,
    tool_call_index: dict[str, dict[str, Any]],
    replay_pool: ReplayPool | None = None,
    force_fresh: bool = False,
    downgrade_on_drift: bool = False,
) -> tuple[VerifierAction, CallReplay | None]:
    """Re-run the single tool call cited by ``finding`` and decide
    approve / reject / downgrade.

    ``tool_call_index`` maps ``tool_call_id`` → the original
    ``{"tool_name", "arguments", "output_sha256"}`` triple recorded
    in the audit log. The supervisor builds this index before
    invoking the verifier.

    ``downgrade_on_drift`` selects the terminal drift policy: the first
    pass over a CONFIRMED finding leaves it False, so sha256 drift on the
    strongest tier is REJECTED and re-dispatched once with a fresh replay;
    the re-dispatch attempt passes True, so persistent drift takes the
    terminal downgrade instead of looping. Lower tiers always downgrade.
    """
    if not finding.tool_call_id:
        reason = "missing tool_call_id (Spec #2 invariant)"
        artifact = missing_replay_artifact(
            tool_call_id=None, drift_class="missing_citation", reason=reason
        )
        return (
            VerifierAction(
                case_id=finding.case_id,
                action="rejected",
                finding_id=finding.finding_id,
                reason=reason,
            ),
            CallReplay(artifact),
        )

    record = tool_call_index.get(finding.tool_call_id)
    if record is None:
        reason = f"tool_call_id {finding.tool_call_id!r} not found in audit log"
        artifact = missing_replay_artifact(
            tool_call_id=finding.tool_call_id,
            drift_class="missing_audit_record",
            reason=reason,
        )
        return (
            VerifierAction(
                case_id=finding.case_id,
                action="rejected",
                finding_id=finding.finding_id,
                reason=reason,
            ),
            CallReplay(artifact),
        )

    arguments = dict(record.get("arguments") or {})
    expected = str(record.get("output_sha256", ""))

    artifact = replay_tool_call(
        tool_call_id=finding.tool_call_id,
        record=record,
        mcp=mcp,
        replay_pool=replay_pool,
        force_fresh=force_fresh,
    )
    replay = CallReplay(artifact, arguments)
    if artifact.drift_class == "replay_error":
        return (
            VerifierAction(
                case_id=finding.case_id,
                action="rejected",
                finding_id=finding.finding_id,
                reason=replay.error or "tool re-run failed",
            ),
            replay,
        )

    if artifact.drift_class == "exact_match":
        return (
            VerifierAction(
                case_id=finding.case_id,
                action="approved",
                finding_id=finding.finding_id,
                reason="tool re-run output_sha256 matches audit log",
            ),
            replay,
        )
    # Drift: re-run produced different output. On a CONFIRMED finding the
    # first pass REJECTS (drift_class material_drift is re-dispatchable, so
    # the orchestrator re-runs the tool once with a fresh replay); the
    # re-dispatch attempt — and every lower tier — takes the terminal
    # downgrade: the evidence path is still real, but confidence drops.
    if finding.confidence == "CONFIRMED" and not downgrade_on_drift:
        return (
            VerifierAction(
                case_id=finding.case_id,
                action="rejected",
                finding_id=finding.finding_id,
                reason=(
                    f"tool re-run output_sha256 drift on a CONFIRMED finding "
                    f"(expected={expected[:12]}…, got={(artifact.actual_sha256 or '')[:12]}…) "
                    "— fresh replay required"
                ),
            ),
            replay,
        )
    return (
        VerifierAction(
            case_id=finding.case_id,
            action="downgraded",
            finding_id=finding.finding_id,
            reason=(
                f"tool re-run output_sha256 drift "
                f"(expected={expected[:12]}…, got={(artifact.actual_sha256 or '')[:12]}…)"
            ),
        ),
        replay,
    )


def verify_findings(
    findings: list[Finding],
    *,
    mcp: McpClient,
    tool_call_index: dict[str, dict[str, Any]],
    replay_pool: ReplayPool | None = None,
    force_fresh: bool = False,
    downgrade_on_drift: bool = False,
) -> list[tuple[Finding, VerifierAction, CallReplay | None]]:
    """Verify a batch of findings. Returns aligned (finding, action, replay) tuples.

    Uses the same ``mcp`` client for every re-run. Callers that need
    cache/concurrency primitives can pass a ``ReplayPool`` built over
    that client; the default path remains serial and minimal.
    """
    out: list[tuple[Finding, VerifierAction, CallReplay | None]] = []
    for finding in findings:
        action, replay = reverify_finding(
            finding,
            mcp=mcp,
            tool_call_index=tool_call_index,
            replay_pool=replay_pool,
            force_fresh=force_fresh,
            downgrade_on_drift=downgrade_on_drift,
        )
        out.append((finding, action, replay))
    return out


def downgrade_confidence(finding: Finding) -> Finding:
    """Drop confidence one tier per the verifier's downgrade ladder.

    CONFIRMED → INFERRED → HYPOTHESIS. HYPOTHESIS stays HYPOTHESIS
    (further drift is handled by rejecting the Finding outright at
    the verifier level).
    """
    ladder = {
        "CONFIRMED": "INFERRED",
        "INFERRED": "HYPOTHESIS",
        "HYPOTHESIS": "HYPOTHESIS",
    }
    new_confidence = ladder.get(finding.confidence, finding.confidence)
    if new_confidence == finding.confidence:
        return finding
    # Pydantic v2 frozen models: ``model_copy`` for safe mutation.
    return finding.model_copy(update={"confidence": new_confidence})


__all__ = [
    "CallReplay",
    "downgrade_confidence",
    "reverify_finding",
    "verify_findings",
]
