"""Find Evil! agent runtime library for ACH and event primitives.

See:
  - ``docs/architecture.md`` — public architecture contract
  - ``CLAUDE.md`` — credential modes and investigation guardrails
"""

from findevil_agent.config import CredentialMode, resolve_credentials
from findevil_agent.events import (
    AgentEvent,
    AgentMessage,
    ChainUpdate,
    ContradictionFound,
    Finding,
    HypothesisUpdate,
    PlanApproved,
    PlanProposed,
    RunVerdict,
    ToolCallOutput,
    ToolCallStart,
    VerifierAction,
)

__version__ = "0.1.0"

__all__ = [
    "AgentEvent",
    "AgentMessage",
    "ChainUpdate",
    "ContradictionFound",
    "CredentialMode",
    "Finding",
    "HypothesisUpdate",
    "PlanApproved",
    "PlanProposed",
    "RunVerdict",
    "ToolCallOutput",
    "ToolCallStart",
    "VerifierAction",
    "__version__",
    "resolve_credentials",
]
