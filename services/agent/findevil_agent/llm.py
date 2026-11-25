"""Provider-agnostic LLM and embedding factory backed by esperanto.

Usage:
    from findevil_agent.llm import get_language_model, get_embedding_model

    lm = get_language_model()          # uses FINDEVIL_LLM_PROVIDER + FINDEVIL_MODEL
    response = lm.chat_complete([{"role": "user", "content": "hello"}])

    em = get_embedding_model()         # uses FINDEVIL_EMBEDDING_PROVIDER + FINDEVIL_EMBEDDING_MODEL
    result = em.embed(["text to embed"])

Provider is selected from env vars at call time so tests can monkey-patch
os.environ without reloading the module. The returned objects are
esperanto LanguageModel / EmbeddingModel instances; callers use
``.chat_complete()`` / ``.achat_complete()`` / ``.embed()`` / ``.aembed()``
directly — no wrapper class needed.

Supported providers (non-exhaustive):
    ``anthropic``   — ANTHROPIC_API_KEY
    ``openrouter``  — OPENROUTER_API_KEY
    ``openai``      — OPENAI_API_KEY
    ``groq``        — GROQ_API_KEY
    ``ollama``      — no key needed (local)
    ``gemini``      — GOOGLE_API_KEY
"""

from __future__ import annotations

import os
from typing import Any

from esperanto.factory import AIFactory

from findevil_agent.config import (
    EMBEDDING_MODEL,
    EMBEDDING_PROVIDER,
    LLM_PROVIDER,
    MODEL,
)


def get_language_model(
    provider: str | None = None,
    model: str | None = None,
) -> Any:
    """Return an esperanto LanguageModel for the configured provider.

    Args:
        provider: Override ``FINDEVIL_LLM_PROVIDER``. Defaults to the env var.
        model: Override ``FINDEVIL_MODEL``. Defaults to the env var.

    Returns:
        An esperanto ``LanguageModel`` instance with ``.chat_complete()``
        and ``.achat_complete()`` methods.
    """
    resolved_provider = provider or os.environ.get("FINDEVIL_LLM_PROVIDER", LLM_PROVIDER)
    resolved_model = model or os.environ.get("FINDEVIL_MODEL", MODEL)
    return AIFactory.create_language(resolved_provider, resolved_model)


def get_embedding_model(
    provider: str | None = None,
    model: str | None = None,
) -> Any:
    """Return an esperanto EmbeddingModel for the configured provider.

    Args:
        provider: Override ``FINDEVIL_EMBEDDING_PROVIDER``. Defaults to the env var.
        model: Override ``FINDEVIL_EMBEDDING_MODEL``. Defaults to the env var.

    Returns:
        An esperanto ``EmbeddingModel`` instance with ``.embed()``
        and ``.aembed()`` methods.
    """
    resolved_provider = provider or os.environ.get(
        "FINDEVIL_EMBEDDING_PROVIDER", EMBEDDING_PROVIDER
    )
    resolved_model = model or os.environ.get("FINDEVIL_EMBEDDING_MODEL", EMBEDDING_MODEL)
    return AIFactory.create_embedding(resolved_provider, resolved_model)


__all__ = ["get_embedding_model", "get_language_model"]
