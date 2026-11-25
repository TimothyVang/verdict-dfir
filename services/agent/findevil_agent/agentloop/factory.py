"""Provider factory: pick a ChatProvider, and gate evidence egress for custody.

Selection precedence: explicit args > ``FINDEVIL_AGENT_PROVIDER`` /
``FINDEVIL_AGENT_MODEL`` / ``FINDEVIL_AGENT_BASE_URL`` > defaults. A *cloud* provider
ships evidence text off-host, so the factory refuses to build one unless the caller
explicitly acknowledges evidence egress (``--acknowledge-evidence-egress``). The
*on-prem* OpenAI-compatible providers (``local`` vLLM/Ollama, ``dgx`` Spark) keep
evidence on the host/local network, so they are NOT gated — a custody win. Unknown
providers are rejected before any egress or key handling.

Backends: ``anthropic`` (Messages API), ``claude_cli`` (headless Claude Code, fine for
small cases but does not scale), and the OpenAI-compatible family ``openai`` /
``openrouter`` / ``local`` / ``dgx`` (one adapter, native tool-calling + prompt caching,
the scalable path).
"""

from __future__ import annotations

import os
from typing import Any

from .anthropic_provider import AnthropicProvider
from .claude_cli import ClaudeCliProvider
from .openai_provider import OpenAIProvider
from .types import ChatProvider

DEFAULT_PROVIDER = "anthropic"
# Workhorse default for a long tool-using investigation loop; operators can raise to
# a deeper-reasoning model via FINDEVIL_AGENT_MODEL / --model.
DEFAULT_MODEL = "claude-sonnet-4-6"
# Per-provider default model. The OpenAI-compatible family has no universal default —
# the operator names the model their endpoint serves via FINDEVIL_AGENT_MODEL.
_DEFAULT_MODEL_FOR = {"anthropic": DEFAULT_MODEL, "claude_cli": "claude-opus-4-8"}

# OpenAI-compatible /v1/chat/completions backends (one OpenAIProvider, config differs).
_OPENAI_COMPATIBLE = {"openai", "openrouter", "local", "dgx"}
# Default base_url per OpenAI-compatible provider (FINDEVIL_AGENT_BASE_URL overrides).
# openai -> the provider's own default; dgx -> must be supplied (the operator's endpoint).
_OPENAI_BASE_URLS = {
    "openrouter": "https://openrouter.ai/api/v1",
    "local": "http://localhost:11434/v1",  # Ollama default
}
# API-key env var per OpenAI-compatible provider (local needs none).
_OPENAI_KEY_ENV = {
    "openai": "OPENAI_API_KEY",
    "openrouter": "OPENROUTER_API_KEY",
    "dgx": "FINDEVIL_AGENT_API_KEY",
}

# Providers that transmit evidence text off-host (require egress ack). claude_cli routes
# through the local Claude Code CLI but evidence still reaches Anthropic, so it is gated.
# local/dgx are on-prem and deliberately absent.
_CLOUD_PROVIDERS = {"anthropic", "claude_cli", "openai", "openrouter"}
# Providers with a concrete adapter wired today.
_KNOWN_PROVIDERS = {"anthropic", "claude_cli", *_OPENAI_COMPATIBLE}


class EvidenceEgressError(RuntimeError):
    """Raised when a cloud provider is requested without an explicit egress ack."""


def build_provider(
    *,
    provider: str | None = None,
    model: str | None = None,
    acknowledge_evidence_egress: bool = False,
    api_key: str | None = None,
    transport: Any | None = None,
) -> ChatProvider:
    """Build the selected provider, enforcing the custody egress gate first."""
    provider = (provider or os.environ.get("FINDEVIL_AGENT_PROVIDER") or DEFAULT_PROVIDER).lower()

    if provider not in _KNOWN_PROVIDERS:
        raise ValueError(
            f"unknown provider {provider!r}; known providers: {sorted(_KNOWN_PROVIDERS)}"
        )
    if provider in _CLOUD_PROVIDERS and not acknowledge_evidence_egress:
        raise EvidenceEgressError(
            f"provider {provider!r} sends evidence text off-host; pass "
            "acknowledge_evidence_egress=True (CLI: --acknowledge-evidence-egress) to proceed"
        )

    model = model or os.environ.get("FINDEVIL_AGENT_MODEL") or _DEFAULT_MODEL_FOR.get(provider)
    if not model:
        raise ValueError(
            f"provider {provider!r} needs a model; set FINDEVIL_AGENT_MODEL or pass --agent-model "
            "(e.g. the model id your endpoint serves)"
        )

    if provider == "anthropic":
        return AnthropicProvider(model=model, api_key=api_key, transport=transport)
    if provider == "claude_cli":
        return ClaudeCliProvider(model=model)
    if provider in _OPENAI_COMPATIBLE:
        base_url = os.environ.get("FINDEVIL_AGENT_BASE_URL") or _OPENAI_BASE_URLS.get(provider)
        if provider == "dgx" and not base_url:
            raise ValueError(
                "provider 'dgx' needs FINDEVIL_AGENT_BASE_URL set to the DGX Spark endpoint"
            )
        key = api_key
        if key is None and provider in _OPENAI_KEY_ENV:
            key = os.environ.get(_OPENAI_KEY_ENV[provider])
        return OpenAIProvider(model=model, base_url=base_url, api_key=key, transport=transport)

    # Unreachable: _KNOWN_PROVIDERS is the guard above.
    raise ValueError(f"unknown provider {provider!r}")  # pragma: no cover
