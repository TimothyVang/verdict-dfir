"""Provider-agnostic, agent-driven investigation loop (Stage B).

An opt-in alternative to the deterministic ``scripts/find_evil_auto.py`` engine:
a thin MCP-client loop driven by a pluggable LLM provider (Claude first, then any
OpenAI-compatible backend), with Pool A / Pool B pods whose findings are forced
through the default-on fact-fidelity gate + the existing verify/judge/correlate/
manifest custody spine. No LangGraph/FastAPI — a plain async loop.
"""
