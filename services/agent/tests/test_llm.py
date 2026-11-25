"""Tests for ``findevil_agent.llm`` — multi-provider LLM factory.

No real API calls are made; AIFactory is patched at the call site.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from findevil_agent.llm import get_embedding_model, get_language_model


class TestGetLanguageModel:
    def test_uses_env_defaults(self) -> None:
        with patch("findevil_agent.llm.AIFactory.create_language") as mock_factory:
            mock_factory.return_value = MagicMock()
            get_language_model()
        mock_factory.assert_called_once_with("anthropic", "claude-sonnet-4-6")

    def test_explicit_provider_and_model_override_env(self) -> None:
        with patch("findevil_agent.llm.AIFactory.create_language") as mock_factory:
            mock_factory.return_value = MagicMock()
            get_language_model(provider="openrouter", model="openai/gpt-4o")
        mock_factory.assert_called_once_with("openrouter", "openai/gpt-4o")

    def test_env_var_overrides_module_defaults(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("FINDEVIL_LLM_PROVIDER", "groq")
        monkeypatch.setenv("FINDEVIL_MODEL", "llama3-70b-8192")
        with patch("findevil_agent.llm.AIFactory.create_language") as mock_factory:
            mock_factory.return_value = MagicMock()
            get_language_model()
        mock_factory.assert_called_once_with("groq", "llama3-70b-8192")

    def test_explicit_args_take_priority_over_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("FINDEVIL_LLM_PROVIDER", "groq")
        monkeypatch.setenv("FINDEVIL_MODEL", "llama3-70b-8192")
        with patch("findevil_agent.llm.AIFactory.create_language") as mock_factory:
            mock_factory.return_value = MagicMock()
            get_language_model(provider="openai", model="gpt-4o-mini")
        mock_factory.assert_called_once_with("openai", "gpt-4o-mini")

    def test_returns_factory_result(self) -> None:
        sentinel = MagicMock(name="language_model")
        with patch("findevil_agent.llm.AIFactory.create_language", return_value=sentinel):
            result = get_language_model()
        assert result is sentinel


class TestGetEmbeddingModel:
    def test_uses_env_defaults(self) -> None:
        with patch("findevil_agent.llm.AIFactory.create_embedding") as mock_factory:
            mock_factory.return_value = MagicMock()
            get_embedding_model()
        mock_factory.assert_called_once_with("anthropic", "voyage-3")

    def test_explicit_override(self) -> None:
        with patch("findevil_agent.llm.AIFactory.create_embedding") as mock_factory:
            mock_factory.return_value = MagicMock()
            get_embedding_model(provider="openai", model="text-embedding-3-small")
        mock_factory.assert_called_once_with("openai", "text-embedding-3-small")

    def test_env_var_overrides_defaults(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("FINDEVIL_EMBEDDING_PROVIDER", "ollama")
        monkeypatch.setenv("FINDEVIL_EMBEDDING_MODEL", "nomic-embed-text")
        with patch("findevil_agent.llm.AIFactory.create_embedding") as mock_factory:
            mock_factory.return_value = MagicMock()
            get_embedding_model()
        mock_factory.assert_called_once_with("ollama", "nomic-embed-text")

    def test_returns_factory_result(self) -> None:
        sentinel = MagicMock(name="embedding_model")
        with patch("findevil_agent.llm.AIFactory.create_embedding", return_value=sentinel):
            result = get_embedding_model()
        assert result is sentinel
