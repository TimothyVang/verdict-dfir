# Local Agent High-Signal Recall Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Recover verifier-grade high-signal EVTX findings from evidence the native local agent already queried, beginning with EID 1102, so the Spark agent reaches parity with Claude Code on the pinned fair-fight case without a whole-engine fallback.

**Architecture:** Capture successful current-run `evtx_query` outputs inside `_run_agent_pools`, pass them through a narrow pure recovery helper, and append only non-duplicate allowlisted candidates to Pool A. Recovered candidates retain the exact current-run `tool_call_id`, use the existing asserted-value contract, emit an explicit audit record, and continue through the unchanged verifier, judge, report-QA, and manifest pipeline.

**Tech Stack:** Python 3.12, pytest, existing `find_evil_auto.py` deterministic EVTX emitters, native agent loop, Rust MCP `evtx_query`, VERDICT recall goldens.

---

## File Structure

- Modify `scripts/find_evil_auto.py`: add the pure high-signal recovery helper, capture successful agent query outputs, audit recovered candidates, and reinforce the EVTX task instruction.
- Create `services/agent/tests/test_agent_high_signal_recall.py`: pin recovery, deduplication, benign-output, current-run citation, and integration behavior.
- Modify `services/agent/tests/test_agent_tool_scope.py`: pin the concise prompt reinforcement and retain the EVTX-only/no-fallback contract.
- Modify `docs/adr/0001-phase-4-native-agent-runtime.md`: clarify that current-run high-signal recovery is allowed and is not deterministic whole-engine fallback.
- Create a timestamped lab receipt under `docs/receipts/` in the `dgx-spark-lab` evidence branch after the live Spark run.

### Task 1: Pure EID 1102 Recovery

**Files:**
- Modify: `scripts/find_evil_auto.py:8031-8148`
- Create: `services/agent/tests/test_agent_high_signal_recall.py`

- [ ] **Step 1: Write the failing recovery tests**

Create `services/agent/tests/test_agent_high_signal_recall.py` with imports matching the other script-level tests and these fixtures/assertions:

```python
from __future__ import annotations

import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402


def _evtx_output(event_id: int, channel: str = "Security") -> dict:
    return {
        "rows": [
            {
                "event_id": event_id,
                "channel": channel,
                "record_id": 42,
                "ts": "2019-03-19T23:35:07Z",
                "data": {},
            }
        ],
        "row_count": 1,
        "records_seen": 1,
        "parse_errors": 0,
    }


def test_recovers_confirmed_1102_from_current_agent_query() -> None:
    findings = fea.recover_agent_high_signal_findings(
        [("tc-agent-1", _evtx_output(1102))],
        existing_findings=[],
        case_id="case-agent",
        artifact_path="/evidence/Security.evtx",
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding["tool_call_id"] == "tc-agent-1"
    assert finding["confidence"] == "CONFIRMED"
    assert finding["mitre_technique"] == "T1070.001"
    assert finding["asserted_values"] == [
        {
            "path": "rows[*]",
            "expected": '{"event_id": "1102", "channel": "Security"}',
            "match": "record",
        }
    ]


def test_benign_agent_query_recovers_nothing() -> None:
    assert fea.recover_agent_high_signal_findings(
        [("tc-agent-1", _evtx_output(4624))],
        existing_findings=[],
        case_id="case-agent",
        artifact_path="/evidence/Security.evtx",
    ) == []


def test_existing_1102_assertion_suppresses_duplicate() -> None:
    existing = [
        {
            "mitre_technique": "T1070.001",
            "asserted_values": [
                {"path": "rows[0].event_id", "expected": "1102", "match": "exact"}
            ],
        }
    ]
    assert fea.recover_agent_high_signal_findings(
        [("tc-agent-1", _evtx_output(1102))],
        existing_findings=existing,
        case_id="case-agent",
        artifact_path="/evidence/Security.evtx",
    ) == []
```

- [ ] **Step 2: Run the tests and verify RED**

Run:

```bash
uv run --directory services/agent pytest tests/test_agent_high_signal_recall.py -q
```

Expected: FAIL because `find_evil_auto` has no `recover_agent_high_signal_findings`.

- [ ] **Step 3: Implement the narrow recovery helper**

Add near `evtx_rows_to_findings` in `scripts/find_evil_auto.py`:

```python
_AGENT_HIGH_SIGNAL_FINDING_IDS = frozenset({"f-A-evtx-audit-log-cleared"})


def _asserts_eid_1102(finding: dict[str, Any]) -> bool:
    if finding.get("mitre_technique") != "T1070.001":
        return False
    return any(
        "1102" in str(asserted.get("expected", ""))
        for asserted in finding.get("asserted_values") or []
    )


def recover_agent_high_signal_findings(
    observations: list[tuple[str, dict[str, Any]]],
    *,
    existing_findings: list[dict[str, Any]],
    case_id: str,
    artifact_path: str,
) -> list[dict[str, Any]]:
    """Recover allowlisted findings from successful current-run agent queries."""
    if any(_asserts_eid_1102(finding) for finding in existing_findings):
        return []

    for tool_call_id, output in observations:
        rows = output.get("rows")
        if not isinstance(rows, list):
            continue
        for finding in evtx_rows_to_findings(rows, tool_call_id, case_id, artifact_path):
            if finding.get("finding_id") in _AGENT_HIGH_SIGNAL_FINDING_IDS:
                return [finding]
    return []
```

Keep the allowlist at EID 1102 only. Do not expose all deterministic EVTX emitters through agent recovery in this task.

- [ ] **Step 4: Run the recovery and entailment tests**

Run:

```bash
uv run --directory services/agent pytest \
  tests/test_agent_high_signal_recall.py \
  tests/test_confirmed_emitter_coverage.py::TestEvtxAuditLogClearedAssertedValues -q
```

Expected: all tests PASS.

- [ ] **Step 5: Commit the pure recovery unit**

```bash
git add scripts/find_evil_auto.py services/agent/tests/test_agent_high_signal_recall.py
git commit -m "feat(agent): recover high-signal EVTX findings"
```

### Task 2: Wire Current-Run Query Capture Into Agent Pools

**Files:**
- Modify: `scripts/find_evil_auto.py:9220-9344`
- Modify: `services/agent/tests/test_agent_high_signal_recall.py`

- [ ] **Step 1: Write the failing integration test**

Extend `test_agent_high_signal_recall.py` with an integration test that stubs the provider and MCP surface but executes the real `AgentToolBridge`. The fake loop must call the supplied dispatch once per pod and intentionally omit `record_finding`:

```python
from types import SimpleNamespace

from findevil_agent.agentloop.loop import LoopResult, ToolInvocation


class _Rust:
    def call(self, method: str, _params: dict) -> dict:
        assert method == "tools/list"
        return {"tools": [{"name": "evtx_query"}]}

    def call_tool(self, name: str, _args: dict) -> dict:
        assert name == "evtx_query"
        return {**_evtx_output(1102), "_mcp_output_sha256": "a" * 64}


def test_agent_pools_recover_1102_when_model_does_not_record(
    monkeypatch,
) -> None:
    import findevil_agent.agentloop.factory as factory
    import findevil_agent.agentloop.loop as loop
    import findevil_agent.agentloop.mcp_tools as mcp_tools

    investigation = object.__new__(fea.Investigation)
    investigation.agent_provider = "stub"
    investigation.agent_model = "stub"
    investigation.agent_acknowledge_evidence_egress = False
    investigation.agent_max_steps = 2
    investigation.handle = {"id": "case-agent"}
    investigation.evidence = "/evidence/Security.evtx"
    investigation.tool_calls = []
    investigation.findings_pool_a = []
    investigation.findings_pool_b = []
    investigation._heartbeat = lambda *_args, **_kwargs: None
    investigation._record_tool = lambda _py, _name, _sha, **_kwargs: "tc-agent-1"
    audited: list[tuple[str, dict]] = []
    investigation._audit = lambda _py, kind, payload: audited.append((kind, payload))

    def run_agent_loop(*_args, **kwargs) -> LoopResult:
        result = kwargs["dispatch"]("evtx_query", {})
        return LoopResult(
            final_text="done without recording",
            stop="end_turn",
            steps=1,
            messages=[],
            tool_invocations=[
                ToolInvocation(id="query", name="evtx_query", arguments={}, result=result)
            ],
        )

    monkeypatch.setattr(factory, "build_provider", lambda **_kwargs: object())
    monkeypatch.setattr(loop, "run_agent_loop", run_agent_loop)
    monkeypatch.setattr(
        mcp_tools,
        "mcp_tools_to_openai",
        lambda _tools: [{"type": "function", "function": {"name": "evtx_query"}}],
    )

    investigation._run_agent_pools(_Rust(), SimpleNamespace(), "evtx")

    assert [f["mitre_technique"] for f in investigation.findings_pool_a] == ["T1070.001"]
    assert any(kind == "agent_high_signal_candidate" for kind, _payload in audited)
```

When implementing, make `_record_tool` return unique IDs in the real test helper (`tc-agent-1`, then `tc-agent-2`) so both observations remain attributable; assert the selected candidate cites one of those IDs.

- [ ] **Step 2: Run the integration test and verify RED**

Run:

```bash
uv run --directory services/agent pytest \
  tests/test_agent_high_signal_recall.py::test_agent_pools_recover_1102_when_model_does_not_record -q
```

Expected: FAIL because `_run_agent_pools` does not retain outputs or append recovered findings.

- [ ] **Step 3: Capture only successful `evtx_query` outputs**

In `_run_agent_pools`, initialize:

```python
agent_evtx_observations: list[tuple[str, dict[str, Any]]] = []
```

In `call_and_record`, after `_record_tool` assigns `tcid`, capture the display object only for a successful EVTX query:

```python
if name == "evtx_query" and isinstance(display, dict):
    agent_evtx_observations.append((tcid, display))
```

Do not capture error paths because they return before `tcid` is assigned.

- [ ] **Step 4: Recover, audit, and append after both pods**

After the `for pod in (POOL_A, POOL_B)` loop, add:

```python
existing_findings = [*self.findings_pool_a, *self.findings_pool_b]
recovered = recover_agent_high_signal_findings(
    agent_evtx_observations,
    existing_findings=existing_findings,
    case_id=case_id,
    artifact_path=self.evidence,
)
for finding in recovered:
    self._audit(
        py,
        "agent_high_signal_candidate",
        {
            "finding_id": finding["finding_id"],
            "tool_call_id": finding["tool_call_id"],
            "mitre_technique": finding["mitre_technique"],
            "rule_id": "evtx_eid_1102",
        },
    )
self.findings_pool_a.extend(recovered)
```

Keep recovery after both pods so an LLM-recorded equivalent from either pool suppresses it.

- [ ] **Step 5: Add malformed-output and fail-closed assertions**

Add this exact malformed-output test to `test_agent_high_signal_recall.py`:

```python
def test_error_shaped_agent_output_recovers_nothing() -> None:
    findings = fea.recover_agent_high_signal_findings(
        [("tc-agent-1", {"_error": {"message": "parse failed"}})],
        existing_findings=[],
        case_id="case-agent",
        artifact_path="/evidence/Security.evtx",
    )

    assert findings == []
```

The Task 1 `test_existing_1102_assertion_suppresses_duplicate` test pins duplicate suppression. The
existing `test_agent_pools_fail_closed_when_loop_has_no_successful_evidence_call` in
`test_agent_pool_evidence_gate.py` pins failed-tool behavior. Do not mock
`recover_agent_high_signal_findings` in the integration test.

- [ ] **Step 6: Run the agent integration regression set**

Run:

```bash
uv run --directory services/agent pytest \
  tests/test_agent_high_signal_recall.py \
  tests/test_agent_pool_evidence_gate.py \
  tests/test_agentloop_integration.py \
  tests/test_agent_tool_scope.py -q
```

Expected: all tests PASS.

- [ ] **Step 7: Commit the integration**

```bash
git add scripts/find_evil_auto.py services/agent/tests/test_agent_high_signal_recall.py
git commit -m "feat(agent): bind recovered findings to current queries"
```

### Task 3: Prompt And Runtime Contract Documentation

**Files:**
- Modify: `scripts/find_evil_auto.py:15482-15497`
- Modify: `services/agent/tests/test_agent_tool_scope.py:88-94`
- Modify: `docs/adr/0001-phase-4-native-agent-runtime.md:45-56`

- [ ] **Step 1: Write the failing prompt assertion**

Extend `test_agent_task_supplies_the_open_case_id`:

```python
assert "record every supported high-signal observation before ending" in task
```

- [ ] **Step 2: Run the prompt test and verify RED**

Run:

```bash
uv run --directory services/agent pytest \
  tests/test_agent_tool_scope.py::test_agent_task_supplies_the_open_case_id -q
```

Expected: FAIL because the task does not yet contain the instruction.

- [ ] **Step 3: Add the minimal EVTX prompt reinforcement**

Change the EVTX-specific suffix in `_agent_pod_task` to:

```python
task += (
    " For EVTX evidence, first call evtx_query without an eids filter to sample "
    "the records; only then target event IDs observed in that result. Record every "
    "supported high-signal observation before ending the investigation."
)
```

- [ ] **Step 4: Document the no-fallback boundary**

Append this consequence to ADR 0001:

```markdown
- Native agent mode may recover allowlisted high-signal candidates only from successful,
  current-run evidence calls made by the agent. This is not deterministic fallback: it issues no
  second investigation, cannot mask provider or tool failure, remains audit-visible, and every
  candidate still passes verifier replay and entailment before affecting the verdict.
```

- [ ] **Step 5: Run prompt, scope, and documentation checks**

Run:

```bash
uv run --directory services/agent pytest tests/test_agent_tool_scope.py -q
python3 scripts/verdict-policy-smoke.py
git diff --check
```

Expected: tests PASS, all policy-smoke cases PASS, and `git diff --check` emits no output.

- [ ] **Step 6: Commit the contract change**

```bash
git add scripts/find_evil_auto.py services/agent/tests/test_agent_tool_scope.py \
  docs/adr/0001-phase-4-native-agent-runtime.md
git commit -m "docs(agent): define current-query recall recovery"
```

### Task 4: Full Local Verification

**Files:**
- Verify all modified files

- [ ] **Step 1: Build the fresh worktree dependencies if needed**

```bash
/home/assessor/.cargo/bin/cargo build --release -p findevil-mcp
uv sync --directory services/agent_mcp
```

Expected: Rust release build and Python MCP environment complete successfully.

- [ ] **Step 2: Run the complete agent suite**

```bash
uv run --directory services/agent pytest -q
```

Expected: zero failures; the existing environment-dependent sample-run test may remain skipped.

- [ ] **Step 3: Run policy and report checks**

```bash
python3 scripts/verdict-policy-smoke.py
python3 scripts/report-policy-smoke.py
uv run --directory services/agent ruff check \
  tests/test_agent_high_signal_recall.py tests/test_agent_tool_scope.py
```

Expected: all policy checks PASS, Ruff reports no errors, and diff check emits no output.

- [ ] **Step 4: Review the branch diff**

```bash
git status --short
```

Expected: only the design/plan, agent recovery implementation, tests, prompt, and ADR changes.

### Task 5: Spark Fair-Fight Acceptance

**Files:**
- Deploy: `scripts/find_evil_auto.py` to `/home/raven/verdict-dfir-beta/scripts/find_evil_auto.py`
- Create in lab evidence branch: `$RECEIPT`, initialized from a UTC timestamp as shown below

- [ ] **Step 1: Sync the reviewed source to Spark**

```bash
scp -o ProxyJump=guac,desktop@192.168.122.198 scripts/find_evil_auto.py \
  raven@10.126.60.100:/home/raven/verdict-dfir-beta/scripts/find_evil_auto.py
```

Expected: exit 0.

- [ ] **Step 2: Verify source identity on both hosts**

```bash
sha256sum scripts/find_evil_auto.py
ssh -J guac,desktop@192.168.122.198 raven@10.126.60.100 \
  'sha256sum /home/raven/verdict-dfir-beta/scripts/find_evil_auto.py'
```

Expected: identical SHA-256 values.

- [ ] **Step 3: Run the pinned local-agent case**

```bash
ssh -J guac,desktop@192.168.122.198 raven@10.126.60.100 \
  'cd /home/raven/verdict-dfir-beta && PATH=/home/raven/.local/bin:$PATH \
   FINDEVIL_SKIP_GROUNDING=1 bash scripts/verdict \
   /home/raven/caseforge-core/evidence/real-evtx-20260708/attack-samples/DE_1102_security_log_cleared.evtx \
   --agent --agent-provider local --agent-model gpt-oss:120b --agent-max-steps 40 \
   --skip-build --no-dashboard --unattended --case-id native-agent-recall-1102-20260716'
```

Expected: completed agent run with manifest verification PASS.

- [ ] **Step 4: Score the remote case against the golden**

```bash
ssh -J guac,desktop@192.168.122.198 raven@10.126.60.100 \
  'cd /home/raven/verdict-dfir-beta && python3 scripts/score-recall.py \
   tmp/auto-runs/native-agent-recall-1102-20260716 \
   --golden goldens/security-log-cleared'
```

Expected: recall 100 percent, verdict match yes, no planted anti-fact, exit 0.

- [ ] **Step 5: Verify the acceptance fields**

Inspect the remote `verdict.json`, `manifest_verify.json`, and audit trail. Require:

```text
verdict = SUSPICIOUS
findings includes confidence=CONFIRMED and mitre_technique=T1070.001
finding tool_call_id resolves to a successful current-run evtx_query
audit includes agent_high_signal_candidate with rule_id=evtx_eid_1102
manifest_verify.overall = true
no deterministic whole-engine fallback marker
```

If any condition fails, do not publish a parity claim; return to the failing test or integration seam.

- [ ] **Step 6: Preserve a checksummed lab receipt**

Copy the remote case artifacts and run metadata into a timestamped directory under the existing
`dgx-spark-lab/.worktrees/full-residual-program/docs/receipts/` hierarchy. Include `SHA256SUMS`, the
source commit, source file SHA-256, command, model, evidence SHA-256, score output, and the five
acceptance fields above. Do not include credentials, model tokens, or classified case content beyond
the already-approved synthetic EID 1102 fixture.

Initialize the destination deterministically before copying:

```bash
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
RECEIPT="docs/receipts/native-agent-recall-1102-$STAMP"
mkdir -p "$RECEIPT"
```

- [ ] **Step 7: Commit the receipt in the lab evidence branch**

```bash
git add "$RECEIPT"
git commit -m "docs: record local agent 1102 recall acceptance"
```

### Task 6: Review, Push, And Merge

**Files:**
- Review all branch changes

- [ ] **Step 1: Request independent code review**

Review the complete diff against `origin/main` for custody regressions, accidental full-engine
fallback, duplicate findings, and unsupported product claims. Resolve every Critical or Important
finding before proceeding.

- [ ] **Step 2: Re-run fresh verification after review fixes**

```bash
uv run --directory services/agent pytest -q
python3 scripts/verdict-policy-smoke.py
python3 scripts/report-policy-smoke.py
```

Expected: zero failures and no diff errors.

- [ ] **Step 3: Push without bypassing hooks**

```bash
git push -u origin feat/local-agent-recall
```

Expected: pre-push checks pass and the remote branch is created.

- [ ] **Step 4: Open the pull request**

```bash
gh pr create --repo TimothyVang/verdict-dfir-beta --base main \
  --head feat/local-agent-recall \
  --title "feat(agent): recover high-signal EVTX findings" \
  --body "## Summary
- recover allowlisted high-signal findings only from successful current-run agent queries
- preserve verifier, report-QA, manifest, and no-whole-engine-fallback gates
- prove local-agent parity on the pinned synthetic EID 1102 case

## Verification
- include exact local test and policy-smoke counts from Task 4
- include Spark case ID, source/evidence SHA-256, recall score, and manifest result from Task 5

## Claim boundary
This establishes parity on the pinned EID 1102 case only; broader superiority requires the multi-case benchmark defined in the design."
```

The PR body must state the exact local test counts, Spark case ID, source/evidence hashes, golden
recall result, manifest result, and the boundary that this proves parity only on the pinned 1102
case.

- [ ] **Step 5: Wait for and inspect every CI check**

```bash
gh pr checks --repo TimothyVang/verdict-dfir-beta --watch --interval 10
```

Expected: every required Python and Rust check passes.

- [ ] **Step 6: Merge only when clean**

```bash
gh pr view --repo TimothyVang/verdict-dfir-beta --json mergeable,mergeStateStatus,statusCheckRollup
```

Expected: PR state becomes `MERGED`; verify the merge commit on `origin/main`.
