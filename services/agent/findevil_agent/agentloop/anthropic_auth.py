"""Anthropic auth resolution + retry, shared by the provider's default transport.

Auth precedence, custody-aware:

1. An explicit ``api_key`` or ``ANTHROPIC_API_KEY`` -> ``x-api-key`` header (a metered
   API key). Preferred for unattended/production use.
2. Otherwise the local Claude Code OAuth token from ``~/.claude/.credentials.json``
   (``claudeAiOauth.accessToken``, requires the ``user:inference`` scope) -> a Bearer
   token plus the ``anthropic-beta: oauth-...`` header. This is the same credential
   Claude Code itself presents to the Messages API, so a developer logged into Claude
   Code can drive the agent loop without minting a separate key.

``retry`` wraps a request thunk with exponential backoff on retryable status codes
(429 rate-limit, 529 overloaded) so a live run survives the shared session rate limit.
The sleeper is injectable so tests run instantly.
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, TypeVar

_OAUTH_BETA = "oauth-2025-04-20"
_INFERENCE_SCOPE = "user:inference"
_DEFAULT_CREDENTIALS = "~/.claude/.credentials.json"

# HTTP statuses worth retrying: rate limit and transient overload.
RETRYABLE_STATUSES = frozenset({429, 529})

T = TypeVar("T")


class RetryableError(Exception):
    """A transient HTTP failure (status in :data:`RETRYABLE_STATUSES`)."""

    def __init__(self, status: int, message: str = "") -> None:
        super().__init__(message or f"retryable HTTP {status}")
        self.status = status


def resolve_anthropic_auth(
    api_key: str | None = None,
    *,
    credentials_path: str | None = None,
) -> dict[str, str]:
    """Return the auth (and beta) headers for the Messages API.

    Raises ``ValueError`` when neither an API key nor a usable OAuth token is found.
    """
    key = api_key or os.environ.get("ANTHROPIC_API_KEY")
    if key:
        return {"x-api-key": key}

    path = Path(credentials_path or _DEFAULT_CREDENTIALS).expanduser()
    if not path.exists():
        raise ValueError(
            "no Anthropic credential: set ANTHROPIC_API_KEY, or log in to Claude Code so "
            f"an OAuth token exists at {path}"
        )

    try:
        data: dict[str, Any] = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"could not read Claude Code credentials at {path}: {exc}") from exc

    oauth = data.get("claudeAiOauth") or {}
    token = oauth.get("accessToken")
    scopes = oauth.get("scopes") or []
    if not token:
        raise ValueError(f"no OAuth accessToken in {path}; set ANTHROPIC_API_KEY instead")
    if _INFERENCE_SCOPE not in scopes:
        raise ValueError(
            f"Claude Code OAuth token lacks the {_INFERENCE_SCOPE!r} scope needed for the "
            "Messages API; set ANTHROPIC_API_KEY instead"
        )
    return {
        "authorization": f"Bearer {token}",
        "anthropic-beta": _OAUTH_BETA,
    }


def retry(
    fn: Callable[[], T],
    *,
    max_retries: int = 5,
    sleeper: Callable[[float], None] = time.sleep,
    base_delay: float = 1.0,
) -> T:
    """Call ``fn``; on :class:`RetryableError` back off and retry up to ``max_retries``."""
    attempt = 0
    while True:
        try:
            return fn()
        except RetryableError:
            if attempt >= max_retries:
                raise
            sleeper(base_delay * (2**attempt))
            attempt += 1
