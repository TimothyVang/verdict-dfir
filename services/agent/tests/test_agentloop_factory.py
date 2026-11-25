"""Increment 6a: the provider factory — select a ChatProvider, gate cloud egress.

Custody rule: a cloud provider ships evidence text off-host, so the factory refuses
to build one unless the caller explicitly acknowledges evidence egress. Unknown
providers fail before any network/key work. Selection comes from explicit args or
``FINDEVIL_AGENT_PROVIDER`` / ``FINDEVIL_AGENT_MODEL``.
"""

from __future__ import annotations

import pytest

from findevil_agent.agentloop.anthropic_provider import AnthropicProvider
from findevil_agent.agentloop.claude_cli import ClaudeCliProvider
from findevil_agent.agentloop.factory import (
    DEFAULT_MODEL,
    EvidenceEgressError,
    build_provider,
)
from findevil_agent.agentloop.openai_provider import OpenAIProvider


def test_local_provider_is_on_prem_no_egress_ack(monkeypatch: pytest.MonkeyPatch) -> None:
    # local (vLLM/Ollama) keeps evidence on-host: NO egress ack required.
    monkeypatch.delenv("FINDEVIL_AGENT_BASE_URL", raising=False)
    p = build_provider(provider="local", model="llama3.1", acknowledge_evidence_egress=False)
    assert isinstance(p, OpenAIProvider)
    assert p.base_url == "http://localhost:11434/v1"  # Ollama default


def test_openai_requires_egress_ack_and_model(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "sk-openai")
    with pytest.raises(EvidenceEgressError):
        build_provider(provider="openai", model="gpt-4o", acknowledge_evidence_egress=False)
    # model is required for the OpenAI-compatible family (no universal default)
    monkeypatch.delenv("FINDEVIL_AGENT_MODEL", raising=False)
    with pytest.raises(ValueError, match="needs a model"):
        build_provider(provider="openai", acknowledge_evidence_egress=True)


def test_openrouter_base_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("FINDEVIL_AGENT_BASE_URL", raising=False)
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or")
    p = build_provider(provider="openrouter", model="x/y", acknowledge_evidence_egress=True)
    assert isinstance(p, OpenAIProvider)
    assert p.base_url == "https://openrouter.ai/api/v1"


def test_dgx_requires_base_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("FINDEVIL_AGENT_BASE_URL", raising=False)
    with pytest.raises(ValueError, match="FINDEVIL_AGENT_BASE_URL"):
        build_provider(provider="dgx", model="m", acknowledge_evidence_egress=False)
    monkeypatch.setenv("FINDEVIL_AGENT_BASE_URL", "http://dgx.local:8000/v1")
    p = build_provider(provider="dgx", model="m", acknowledge_evidence_egress=False)
    assert p.base_url == "http://dgx.local:8000/v1"


def test_claude_cli_selected_with_default_model() -> None:
    p = build_provider(provider="claude_cli", acknowledge_evidence_egress=True)
    assert isinstance(p, ClaudeCliProvider)
    assert p.model == "claude-opus-4-8"  # CLI-appropriate per-provider default


def test_claude_cli_requires_egress_ack() -> None:
    with pytest.raises(EvidenceEgressError):
        build_provider(provider="claude_cli", acknowledge_evidence_egress=False)


def test_anthropic_requires_egress_ack(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-fake")
    with pytest.raises(EvidenceEgressError):
        build_provider(provider="anthropic", acknowledge_evidence_egress=False)


def test_anthropic_built_when_acked(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-fake")
    provider = build_provider(
        provider="anthropic", model="claude-x", acknowledge_evidence_egress=True
    )
    assert isinstance(provider, AnthropicProvider)
    assert provider.model == "claude-x"


def test_unknown_provider_rejected_before_egress_or_key() -> None:
    with pytest.raises(ValueError, match="unknown provider"):
        build_provider(provider="bogus", acknowledge_evidence_egress=True)


def test_provider_and_model_default_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-fake")
    monkeypatch.setenv("FINDEVIL_AGENT_PROVIDER", "anthropic")
    monkeypatch.delenv("FINDEVIL_AGENT_MODEL", raising=False)
    provider = build_provider(acknowledge_evidence_egress=True)
    assert isinstance(provider, AnthropicProvider)
    assert provider.model == DEFAULT_MODEL


def test_injected_transport_needs_no_credential() -> None:
    """A transport decouples construction from any key/OAuth (the no-credential raise
    is covered in test_agentloop_anthropic_auth::test_raises_when_no_credential)."""

    def fake_transport(_req):
        return {"content": [{"type": "text", "text": "ok"}], "stop_reason": "end_turn"}

    provider = build_provider(
        provider="anthropic",
        model="claude-x",
        acknowledge_evidence_egress=True,
        transport=fake_transport,
    )
    assert isinstance(provider, AnthropicProvider)
