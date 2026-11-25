"""MCP tool registry.

Each tool module in this package exports a single :class:`ToolSpec`
named ``SPEC``. The :func:`all_specs` aggregator collects them in a
deterministic order so the server can register them at startup.

Adding a new tool: write the module, export ``SPEC``, and add it to
the import list in :data:`_MODULES`. No editing of ``server.py``
required.
"""

from __future__ import annotations

from importlib import import_module

from findevil_agent_mcp.tools._base import ToolSpec

_MODULES: tuple[str, ...] = (
    "audit_append",
    "audit_verify",
    "manifest_finalize",
    "manifest_verify",
    "verify_finding",
    "detect_contradictions",
    "judge_findings",
    "correlate_findings",
    "memory_remember",
    "memory_recall",
    "pool_handoff",
    "expert_miss_capture",
    "accuracy_compare",
)


def all_specs() -> list[ToolSpec]:
    """Return every registered :class:`ToolSpec`, in declaration order.

    Imports are deferred so test code can patch a single tool's
    handler before the registry is built.
    """
    out: list[ToolSpec] = []
    for mod_name in _MODULES:
        mod = import_module(f"findevil_agent_mcp.tools.{mod_name}")
        spec = getattr(mod, "SPEC", None)
        if not isinstance(spec, ToolSpec):
            raise RuntimeError(f"tools.{mod_name} does not export a ToolSpec named SPEC")
        out.append(spec)
    return out


__all__ = ["ToolSpec", "all_specs"]
