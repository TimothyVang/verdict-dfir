"""Pods (Pool A / Pool B) and the FindingSink — the model's only path to custody.

A *pod* is a biased investigator: Pool A leans persistence, Pool B leans exfil.
Each runs the same loop with a different system prompt (reused from
``findevil_agent.pools``), plus a citation contract that teaches the model to cite
the ``tool_call_id`` it saw in a prior tool result when it records a finding.

The *FindingSink* is the seam between the model and the custody spine. It:

* wraps the real ``McpClient`` and records every product tool call into a
  ``tool_call_index`` the verifier later replays (tool_call_id -> tool_name,
  arguments, output_sha256);
* surfaces each call's ``tool_call_id`` back to the model so it can cite it;
* turns a ``record_finding`` tool call into a :class:`Finding`, which must pass the
  default-on fact-fidelity gate. A CONFIRMED claim that declares no
  ``asserted_values`` is rejected HERE — mechanically, not by a prompt.

No langgraph/fastapi (Amendment A2 content rule); the read-only MCP boundary is
untouched (the sink only ever *reads* via ``call_tool``).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from findevil_agent.pools.exfil import EXFIL_SYSTEM_PROMPT
from findevil_agent.pools.persistence import PERSISTENCE_SYSTEM_PROMPT

RECORD_FINDING_NAME = "record_finding"

_CITATION_CONTRACT = """

== Recording findings (custody contract) ==
Every tool result you receive begins with a line `tool_call_id: <id>`. That id is
the citation handle for that tool's output. To record a finding you MUST call the
`record_finding` tool and set `tool_call_id` to the handle of the SINGLE tool result
you are citing.

A CONFIRMED finding MUST declare `asserted_values`: the specific value(s) you claim
are present in that cited output, as `{path, expected, match}` where `path` is a
dotted/wildcard path into the tool's output JSON (e.g. `rows[*].Image`). The verifier
re-runs the cited call and re-extracts each value; if a value is not actually there,
the finding is rejected. Do not assert a value you did not read. Use INFERRED (with
`derived_from` citing the confirmed facts) for cross-fact inferences, and HYPOTHESIS
for leads.

== Recording discipline ==
RECORD every finding the cited evidence DIRECTLY supports — never leave a clearly
reportable event unrecorded. An investigation that records nothing on evidence that
plainly shows a reportable event (e.g. an EID 1102 log-clear) is a failure, not
caution. A single record fully supports a CONFIRMED finding for what it literally
shows (declare its asserted_values), even when it is outside your pool's specialty —
your specialty guides what you HUNT for, not what you may report.

Assign only the MITRE technique the artifact DIRECTLY evidences. Do NOT assign
execution, exfiltration, command-and-control, or lateral-movement techniques (e.g.
T1059, T1053, T1543, T1547, T1041, T1048, T1567, T1071) without >=2 independent
current-case artifact classes — such a claim is set aside automatically, so do not
spend a finding on it.

Describe what you OBSERVE plainly and factually; do not add attack narrative or
speculation about attacker intent. You do not need to police exact wording — the
system composes the customer-visible text from your structured facts — so focus on
recording accurate findings with correct asserted_values and techniques.
"""

_RECORD_FINDING_DESCRIPTION = (
    "Record a forensic finding citing exactly one tool_call_id from a prior tool "
    "result. CONFIRMED/INFERRED findings must declare asserted_values (or, for "
    "INFERRED, derived_from). Values are re-extracted from the cited output by a "
    "non-LLM verifier; assert only what is actually present."
)

RECORD_FINDING_TOOL: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": RECORD_FINDING_NAME,
        "description": _RECORD_FINDING_DESCRIPTION,
        "parameters": {
            "type": "object",
            "properties": {
                "tool_call_id": {
                    "type": "string",
                    "description": "Handle from the cited tool result's `tool_call_id:` header.",
                },
                "confidence": {
                    "type": "string",
                    "enum": ["CONFIRMED", "INFERRED", "HYPOTHESIS"],
                },
                "artifact_path": {
                    "type": "string",
                    "description": "Path of the artifact the cited tool read.",
                },
                "description": {"type": "string"},
                "mitre_technique": {
                    "type": "string",
                    "description": "MITRE ATT&CK technique id, e.g. T1053.005 (optional).",
                },
                "asserted_values": {
                    "type": "array",
                    "description": "Values claimed present in the cited output (required for CONFIRMED).",
                    "items": {
                        "type": "object",
                        "properties": {
                            "path": {"type": "string"},
                            "expected": {"type": "string"},
                            "match": {
                                "type": "string",
                                "enum": ["exact", "contains", "iso_ts", "int", "record"],
                            },
                        },
                        "required": ["path", "expected"],
                    },
                },
                "derived_from": {
                    "type": "array",
                    "description": "tool_call_ids/finding_ids an INFERRED finding rests on.",
                    "items": {"type": "string"},
                },
            },
            "required": ["tool_call_id", "confidence", "artifact_path", "description"],
        },
    },
}


@dataclass(frozen=True)
class Pod:
    """A biased investigator: a name, its pool label, and its system prompt."""

    name: str
    pool_origin: str  # "A" | "B"
    system_prompt: str


POOL_A = Pod(
    name="pool_a",
    pool_origin="A",
    system_prompt=PERSISTENCE_SYSTEM_PROMPT + _CITATION_CONTRACT,
)
POOL_B = Pod(
    name="pool_b",
    pool_origin="B",
    system_prompt=EXFIL_SYSTEM_PROMPT + _CITATION_CONTRACT,
)
