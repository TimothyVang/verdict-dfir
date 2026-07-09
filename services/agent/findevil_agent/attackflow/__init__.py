"""Deterministic, offline attack-flow + process-tree visualization.

Pure transform of a finished VERDICT case dir into visual artifacts.
Presentation only: never creates Findings, never mints tool_call_ids,
never reads raw evidence, makes no network/LLM calls.
"""

from .emit import EmitResult, emit  # noqa: F401
from .model import AttackFlowModel, load_case  # noqa: F401
