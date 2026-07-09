"""OAuth/key auth resolution + retry for the Anthropic transport (no network).

Two pure pieces unit-tested here: ``resolve_anthropic_auth`` picks x-api-key when an
API key is present, else falls back to the Claude Code OAuth token (Bearer + the oauth
beta header) read from the credentials file; and ``retry`` backs off on retryable
errors (HTTP 429/529) with an injectable sleeper so the live run survives the shared
rate limit.
"""

from __future__ import annotations

import json

import pytest

from findevil_agent.agentloop.anthropic_auth import (
    RetryableError,
    resolve_anthropic_auth,
    retry,
)


def test_api_key_takes_precedence() -> None:
    headers = resolve_anthropic_auth(api_key="sk-ant-key", credentials_path="/nonexistent")
    assert headers["x-api-key"] == "sk-ant-key"
    assert "authorization" not in headers


def test_oauth_fallback_when_no_key(tmp_path) -> None:
    cred = tmp_path / ".credentials.json"
    cred.write_text(
        json.dumps(
            {"claudeAiOauth": {"accessToken": "sk-ant-oat-xyz", "scopes": ["user:inference"]}}
        )
    )
    headers = resolve_anthropic_auth(api_key=None, credentials_path=str(cred))
    assert headers["authorization"] == "Bearer sk-ant-oat-xyz"
    assert "oauth" in headers["anthropic-beta"]
    assert "x-api-key" not in headers


def test_raises_when_no_credential(tmp_path) -> None:
    missing = tmp_path / "nope.json"
    with pytest.raises(ValueError, match="ANTHROPIC_API_KEY|OAuth|credential"):
        resolve_anthropic_auth(api_key=None, credentials_path=str(missing))


def test_oauth_requires_inference_scope(tmp_path) -> None:
    cred = tmp_path / ".credentials.json"
    cred.write_text(json.dumps({"claudeAiOauth": {"accessToken": "t", "scopes": ["user:profile"]}}))
    with pytest.raises(ValueError, match="inference"):
        resolve_anthropic_auth(api_key=None, credentials_path=str(cred))


def test_retry_succeeds_after_transient_429() -> None:
    calls = {"n": 0}
    slept: list[float] = []

    def flaky():
        calls["n"] += 1
        if calls["n"] < 3:
            raise RetryableError(429)
        return "ok"

    out = retry(flaky, max_retries=5, sleeper=slept.append, base_delay=0.01)
    assert out == "ok"
    assert calls["n"] == 3
    assert len(slept) == 2  # slept before each of the two retries


def test_retry_gives_up_after_max() -> None:
    def always_429():
        raise RetryableError(429)

    with pytest.raises(RetryableError):
        retry(always_429, max_retries=2, sleeper=lambda _d: None, base_delay=0.01)


def test_retry_does_not_swallow_non_retryable() -> None:
    def boom():
        raise ValueError("fatal")

    with pytest.raises(ValueError, match="fatal"):
        retry(boom, max_retries=3, sleeper=lambda _d: None)
