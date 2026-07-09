"""Bind the agent loop to find_evil_auto.py's custody spine.

``AgentToolBridge`` is the dispatch the host (find_evil_auto.py, agent mode) hands to
``run_agent_loop``. It does not own an MCP client; instead the host injects one
callable:

    call_and_record(name, arguments) -> (tcid | None, output_obj | None, error | None)

which routes the call to the right MCP server, hashes the output, and appends it to the
audit chain via the host's ``_record_tool`` — so the agent's tool calls land in the
SAME hash-chained ``audit.jsonl`` and ``tool_call_index`` the deterministic engine and
the verifier already use. The bridge surfaces each returned ``tcid`` to the model and
turns ``record_finding`` calls into gated finding DICTS in the pool schema ``reason()``
consumes. The default-on fact-fidelity gate fires here, before a finding is ever
recorded. No langgraph/fastapi (Amendment A2 content rule).
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Callable
from typing import Any

from findevil_agent.events import AssertedValue, Finding

from .pods import RECORD_FINDING_NAME

# (tcid, output_obj, error) — exactly one of tcid/error is set.
CallAndRecord = Callable[
    [str, dict[str, Any]], "tuple[str | None, dict[str, Any] | None, str | None]"
]

_CITE_HEADER = "tool_call_id: "


def finding_to_pool_dict(finding: Finding) -> dict[str, Any]:
    """Convert a validated :class:`Finding` to a find_evil_auto pool-finding dict.

    Only the keys the spine reads are emitted; ``None``/empty optionals are omitted so
    the dict matches the deterministic engine's hand-built findings.
    """
    out: dict[str, Any] = {
        "case_id": finding.case_id,
        "finding_id": finding.finding_id,
        "tool_call_id": finding.tool_call_id,
        "artifact_path": finding.artifact_path,
        "description": finding.description,
        "confidence": finding.confidence,
    }
    if finding.pool_origin is not None:
        out["pool_origin"] = finding.pool_origin
    if finding.mitre_technique is not None:
        out["mitre_technique"] = finding.mitre_technique
    if finding.derived_from:
        out["derived_from"] = list(finding.derived_from)
    if finding.asserted_values:
        out["asserted_values"] = [_asserted_value_to_dict(av) for av in finding.asserted_values]
    if finding.counter_hypothesis:
        out["counter_hypothesis"] = finding.counter_hypothesis
    return out


def _asserted_value_to_dict(av: AssertedValue) -> dict[str, Any]:
    d: dict[str, Any] = {"path": av.path, "expected": av.expected, "match": av.match}
    if av.count is not None:
        d["count"] = av.count
    return d


class AgentToolBridge:
    """Gate-enforcing dispatch that records via the host and emits pool-finding dicts."""

    def __init__(
        self,
        *,
        case_id: str,
        pool_origin: str,
        call_and_record: CallAndRecord,
    ) -> None:
        self.case_id = case_id
        self.pool_origin = pool_origin
        self._call_and_record = call_and_record
        self._seen_tcids: set[str] = set()
        self.findings: list[dict[str, Any]] = []

    def dispatch(self, name: str, arguments: dict[str, Any]) -> str:
        if name == RECORD_FINDING_NAME:
            return self._record_finding(arguments)
        tcid, output, error = self._call_and_record(name, arguments)
        if error is not None or tcid is None:
            return f"ERROR calling {name}: {error or 'no tool_call_id returned'}"
        self._seen_tcids.add(tcid)
        return f"{_CITE_HEADER}{tcid}\n{json.dumps(output, sort_keys=True)}"

    def _record_finding(self, args: dict[str, Any]) -> str:
        tool_call_id = str(args.get("tool_call_id", ""))
        if tool_call_id not in self._seen_tcids:
            return (
                f"ERROR: tool_call_id {tool_call_id!r} was not seen this case; cite the "
                "`tool_call_id:` header from a prior tool result."
            )
        try:
            asserted = [AssertedValue(**av) for av in args.get("asserted_values") or []]
        except (TypeError, ValueError) as exc:
            return f"ERROR: malformed asserted_values: {exc}"

        try:
            finding = Finding(
                case_id=self.case_id,
                finding_id=str(uuid.uuid4()),
                tool_call_id=tool_call_id,
                artifact_path=str(args["artifact_path"]),
                confidence=args["confidence"],
                description=str(args["description"]),
                mitre_technique=args.get("mitre_technique"),
                pool_origin=self.pool_origin,
                asserted_values=asserted,
                derived_from=args.get("derived_from"),
                counter_hypothesis=args.get("counter_hypothesis"),
            )
        except (KeyError, ValueError) as exc:
            return f"ERROR: finding rejected: {exc}"

        self.findings.append(finding_to_pool_dict(finding))
        return f"recorded finding {finding.finding_id} ({finding.confidence})"
