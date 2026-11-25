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

import os
from posixpath import basename as _posix_basename
from typing import Any

from findevil_agent.entailment import check_entailment, check_expectation, entailment_slice
from findevil_agent.events import Finding, VerifierAction
from findevil_agent.mcp_client import McpClient
from findevil_agent.replay import (
    ReplayArtifact,
    ReplayPool,
    missing_replay_artifact,
    replay_tool_call,
)


def _path_arguments(arguments: dict[str, Any]) -> list[str]:
    """The artifact path(s) a recorded tool call was actually given.

    Every Rust DFIR tool names its evidence input with a ``*_path`` argument
    (``evtx_path``, ``memory_path``, ``pcap_path``, ``artifact_path``,
    ``hive_path``, …). Re-binding compares the model's claimed
    ``finding.artifact_path`` against this set, re-derived from the cited call —
    not from anything the model said.
    """
    return [
        str(v)
        for k, v in arguments.items()
        if isinstance(k, str) and k.endswith("_path") and isinstance(v, str) and v.strip()
    ]


def _artifact_matches_call(claimed: str, call_paths: list[str]) -> bool:
    """True if the model's claimed artifact corresponds to a path the cited call
    read — full-path equality OR basename equality (a finding routinely cites the
    bare filename while the tool was given the absolute path). Backslash paths are
    normalized so a Windows ``\\``-style claim still binds to a POSIX call path.
    """
    claimed_norm = claimed.strip().replace("\\", "/")
    claimed_base = _posix_basename(claimed_norm)
    for raw in call_paths:
        call_norm = raw.replace("\\", "/")
        if claimed_norm == call_norm or claimed_base == _posix_basename(call_norm):
            return True
    return False


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

    # Preflight gate 1 — EVIDENCE RE-BINDING (opt-in,
    # FIND_EVIL_REQUIRE_ARTIFACT_REBIND=1). The model PROPOSES
    # ``finding.artifact_path``; the server RE-DERIVES the artifact from the
    # cited call's recorded ``*_path`` argument(s) and rejects a finding that
    # glues a real ``tool_call_id`` to an artifact the cited call never read.
    # Runs BEFORE replay so a fabricated artifact is caught without spending a
    # re-run. No ``*_path`` argument => nothing to bind against => not gated.
    if os.environ.get("FIND_EVIL_REQUIRE_ARTIFACT_REBIND") == "1":
        call_paths = _path_arguments(arguments)
        if call_paths and not _artifact_matches_call(finding.artifact_path, call_paths):
            reason = (
                f"artifact re-bind mismatch: finding claims artifact "
                f"{finding.artifact_path!r} but cited tool_call_id "
                f"{finding.tool_call_id!r} read {call_paths!r}"
            )
            return (
                VerifierAction(
                    case_id=finding.case_id,
                    action="rejected",
                    finding_id=finding.finding_id,
                    reason=reason,
                ),
                CallReplay(
                    missing_replay_artifact(
                        tool_call_id=finding.tool_call_id,
                        drift_class="artifact_rebind_mismatch",
                        reason=reason,
                    )
                ),
            )

    # Preflight gate 2 — ANTI-COHERENCE "TOO CLEAN" (opt-in,
    # FIND_EVIL_REQUIRE_COUNTER_HYPOTHESIS_FINDING=1). A CONFIRMED finding that
    # ruled out NO benign alternative fails before any replay — the coherence
    # tell that the model talked itself into a clean story. Mirrors the events.py
    # schema gate so a finding that reaches the verifier from another path is
    # still caught. Lower tiers are exempt (leads / cross-fact inferences).
    if (
        os.environ.get("FIND_EVIL_REQUIRE_COUNTER_HYPOTHESIS_FINDING") == "1"
        and finding.confidence == "CONFIRMED"
        and not (finding.counter_hypothesis or "").strip()
    ):
        reason = (
            f"counter-hypothesis missing: CONFIRMED finding {finding.finding_id} "
            "records no benign/alternative explanation it ruled out "
            "(anti-coherence 'too clean' gate)"
        )
        return (
            VerifierAction(
                case_id=finding.case_id,
                action="rejected",
                finding_id=finding.finding_id,
                reason=reason,
            ),
            CallReplay(
                missing_replay_artifact(
                    tool_call_id=finding.tool_call_id,
                    drift_class="counter_hypothesis_missing",
                    reason=reason,
                )
            ),
        )

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
        # The citation reproduces (output bytes unchanged). That proves the
        # finding points at real, unchanged evidence — NOT that the model read
        # it correctly. Entailment check: re-extract each asserted value from
        # the re-run output and confirm it is actually present. A misread
        # (valid citation, wrong value) is treated like drift: a CONFIRMED
        # finding is rejected (re-dispatchable once), lower tiers downgrade.
        approved_reason = "tool re-run output_sha256 matches audit log"
        if finding.asserted_values:
            entailment = check_entailment(finding.asserted_values, artifact.parsed_output or {})
            # Seal the minimal entailment slice into the replay artifact so it
            # rides into the signed audit chain and manifest_verify can re-confirm
            # the facts offline (the value the parser read, not the model's claim).
            replay.artifact = artifact.model_copy(
                update={"entailment": entailment_slice(entailment)}
            )
            if not entailment.passed:
                # Hard-anchor grounding: a forgery-resistant IDENTITY anchor
                # (cryptographic hash / IP address) that does not entail is a
                # laundered claim, not a confidence near-miss — reject it outright
                # regardless of tier, even where a corroborating or filename miss
                # on a lower tier would only downgrade. (Filename / byte-size hard
                # anchors stay on the existing per-tier contract below.)
                if entailment.identity_failures:
                    return (
                        VerifierAction(
                            case_id=finding.case_id,
                            action="rejected",
                            finding_id=finding.finding_id,
                            reason=(
                                "entailment: hard anchor not found in tool output for: "
                                + ", ".join(entailment.identity_failures)
                            ),
                        ),
                        replay,
                    )
                misread_action = (
                    "rejected"
                    if finding.confidence == "CONFIRMED" and not downgrade_on_drift
                    else "downgraded"
                )
                return (
                    VerifierAction(
                        case_id=finding.case_id,
                        action=misread_action,
                        finding_id=finding.finding_id,
                        reason=f"entailment: {entailment.reason}",
                    ),
                    replay,
                )
            # Multiplicity guard: the asserted values all entail, but a count
            # claim ("two variants", "N entries") was backed by FEWER entailed
            # leaves than it asserted. The single real line is genuine, so demote
            # below CONFIRMED rather than reject.
            if entailment.multiplicity_demotions:
                return (
                    VerifierAction(
                        case_id=finding.case_id,
                        action="downgraded",
                        finding_id=finding.finding_id,
                        reason=(
                            "entailment: multiplicity claim exceeds entailed supporting "
                            "lines for: " + ", ".join(entailment.multiplicity_demotions)
                        ),
                    ),
                    replay,
                )
            # Extractive provenance: record the value(s) the deterministic
            # parser READ from the re-run evidence, so the chain carries a
            # server-read fact, not the model's transcription.
            if entailment.matched:
                extracted = "; ".join(f"{m.path}={m.actual!r}" for m in entailment.matched)
                approved_reason += f"; entailment confirmed from evidence: {extracted}"
        # Falsifiable expectation (opt-in, FIND_EVIL_REQUIRE_EXPECTATION=1,
        # default-off so default verdicts never change). The finding committed to
        # a refutable PREDICTION; if the cited output reaches that path and holds
        # a CONTRADICTING value, the prediction is refuted and the finding is
        # demoted like a misread — CONFIRMED rejected (re-dispatchable once),
        # lower tiers downgraded. Path-absent / consistent = not refuted.
        if (
            finding.expectation is not None
            and os.environ.get("FIND_EVIL_REQUIRE_EXPECTATION") == "1"
        ):
            prediction = check_expectation(finding.expectation, artifact.parsed_output or {})
            if not prediction.passed:
                refuted_action = (
                    "rejected"
                    if finding.confidence == "CONFIRMED" and not downgrade_on_drift
                    else "downgraded"
                )
                return (
                    VerifierAction(
                        case_id=finding.case_id,
                        action=refuted_action,
                        finding_id=finding.finding_id,
                        reason=f"expectation refuted: {prediction.reason}",
                    ),
                    replay,
                )
        return (
            VerifierAction(
                case_id=finding.case_id,
                action="approved",
                finding_id=finding.finding_id,
                reason=approved_reason,
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
