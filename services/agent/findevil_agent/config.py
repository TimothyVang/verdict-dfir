"""Runtime configuration for the Find Evil! agent.

Amendment A1 (active): the Product accepts three credential modes
in priority order via ``resolve_credentials``. The full agent graph
routes every Claude invocation through the resolver so judges with
any of the three credential types can run the tool as-is.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Final


class CredentialMode(StrEnum):
    """Which credential path was detected at startup."""

    OAUTH_TOKEN = "oauth_token"
    """``CLAUDE_CODE_OAUTH_TOKEN`` env var from ``claude setup-token``."""

    CLAUDE_CODE_SESSION = "claude_code_session"
    """Interactive ``~/.claude/`` populated via ``claude auth login``."""

    API_KEY = "api_key"
    """Direct metered ``ANTHROPIC_API_KEY`` from console.anthropic.com."""


class CredentialsNotAvailableError(RuntimeError):
    """Raised by ``resolve_credentials`` when none of the three modes can be detected."""


@dataclass(frozen=True)
class CredentialResolution:
    """What ``resolve_credentials`` returns — the chosen mode plus
    whatever metadata the rest of the stack needs to wire up calls.
    """

    mode: CredentialMode
    """Which branch won the priority check."""

    # Only populated for API_KEY mode. Never log this value.
    api_key: str | None = None

    # Path to the ~/.claude/ dir when in session mode; informational only.
    claude_home: Path | None = None

    def api_key_fingerprint(self) -> str | None:
        """Return a safe-to-log fingerprint (first 5 / last 4 chars)."""
        if self.api_key is None:
            return None
        k = self.api_key
        if len(k) <= 12:
            return "sk-***"
        return f"{k[:5]}…{k[-4:]}"


# Model + LLM knobs. One MODEL constant per M4 ACH pool — Spec #2 §8.2
# explicitly requires homogeneous strength between Pool A and Pool B.
MODEL: Final[str] = os.environ.get("FINDEVIL_MODEL", "claude-sonnet-4-6")
"""Default Claude model for both ACH pools + specialists.

Overridable via ``FINDEVIL_MODEL`` env var. The value must be the
same for Pool A and Pool B; heterogeneous model strength triggers
the Estornell 2025 weak-agent-poisoning failure (see
``project_adversarial_agents_pattern.md``).
"""

# Multi-provider LLM knobs (esperanto-backed, see ``findevil_agent.llm``).
LLM_PROVIDER: Final[str] = os.environ.get("FINDEVIL_LLM_PROVIDER", "anthropic")
"""esperanto provider name for language-model calls.

Supported: ``anthropic``, ``openrouter``, ``openai``, ``groq``,
``ollama``, ``gemini``, and any other provider esperanto ships.
Requires the corresponding API key env var (e.g. ``OPENROUTER_API_KEY``).
"""

EMBEDDING_PROVIDER: Final[str] = os.environ.get("FINDEVIL_EMBEDDING_PROVIDER", "anthropic")
"""esperanto provider name for embedding calls (memory-store semantic search)."""

EMBEDDING_MODEL: Final[str] = os.environ.get("FINDEVIL_EMBEDDING_MODEL", "voyage-3")
"""Default embedding model. ``voyage-3`` works with the ``anthropic``
provider; swap to ``text-embedding-3-small`` for ``openai``, etc.
"""

# Judge hard-timeout. Spec #2 §8.1: the judge node commits a decision
# within 2 minutes of wall clock even if confidence is unresolved.
JUDGE_WALL_CLOCK_BUDGET_SECONDS: Final[int] = 120

# Per-tool wall clock per Spec #2 layer 2.
TOOL_SUBPROCESS_BUDGET_SECONDS: Final[int] = 120

# ACH single-round cap. Spec #2 §8.1 forbids iterative debate.
ACH_MAX_ROUNDS: Final[int] = 1


# ---------------------------------------------------------------------------
# Credential resolver.
# ---------------------------------------------------------------------------


def resolve_credentials(
    *, env: os._Environ[str] | dict[str, str] | None = None
) -> CredentialResolution:
    """Detect which credential mode is active.

    Priority (matches Amendment A1 §3.1):
      1. ``CLAUDE_CODE_OAUTH_TOKEN`` — non-interactive, judge-friendly
      2. ``~/.claude/`` session — developer / interactive
      3. ``ANTHROPIC_API_KEY`` — metered direct API

    Raises ``CredentialsNotAvailableError`` when none are detected.
    The CLI surface (``find-evil``) catches this and prints the
    three install instructions the user can follow.

    ``env`` is injectable for tests; production uses ``os.environ``.
    """
    env_src: dict[str, str] = dict(env) if env is not None else dict(os.environ)

    token = env_src.get("CLAUDE_CODE_OAUTH_TOKEN", "").strip()
    if token:
        return CredentialResolution(mode=CredentialMode.OAUTH_TOKEN, api_key=None)

    claude_home = _claude_home_from_env(env_src)
    # Valid session requires the dir to exist AND have at least one credential file.
    if claude_home is not None and claude_home.is_dir() and any(claude_home.iterdir()):
        return CredentialResolution(
            mode=CredentialMode.CLAUDE_CODE_SESSION,
            claude_home=claude_home,
        )

    api_key = env_src.get("ANTHROPIC_API_KEY", "").strip()
    if api_key:
        return CredentialResolution(mode=CredentialMode.API_KEY, api_key=api_key)

    raise CredentialsNotAvailableError(
        "No Claude credentials detected. Provide one of:\n"
        "  (1) CLAUDE_CODE_OAUTH_TOKEN env var (generate via `claude setup-token`).\n"
        "  (2) Claude Code interactive session (run `claude auth login`).\n"
        "  (3) ANTHROPIC_API_KEY env var (from https://console.anthropic.com).\n"
        "See scripts/install.sh for the full pre-flight check."
    )


def _claude_home_from_env(env: dict[str, str]) -> Path | None:
    """Resolve the Claude Code session dir — ``~/.claude/`` by convention."""
    home = env.get("HOME") or env.get("USERPROFILE")
    if not home:
        return None
    return Path(home) / ".claude"


# ---------------------------------------------------------------------------
# Case store root.
# ---------------------------------------------------------------------------


def resolve_case_home(*, env: os._Environ[str] | dict[str, str] | None = None) -> Path:
    """Return the root directory for per-case state.

    Matches the Rust ``case_open`` tool's resolver. Env var
    ``FINDEVIL_HOME`` takes precedence; otherwise ``$HOME/.findevil``.
    """
    env_src: dict[str, str] = dict(env) if env is not None else dict(os.environ)
    override = env_src.get("FINDEVIL_HOME", "").strip()
    if override:
        return Path(override)
    home = env_src.get("HOME") or env_src.get("USERPROFILE")
    if not home:
        raise RuntimeError(
            "cannot determine case-home directory (no FINDEVIL_HOME, HOME, or USERPROFILE)"
        )
    return Path(home) / ".findevil"


def resolve_memory_store_path(*, env: os._Environ[str] | dict[str, str] | None = None) -> Path:
    """Return the path to the Hermes cross-case memory SQLite database.

    Mirrors resolve_case_home precedence: ``FINDEVIL_MEMORY_STORE`` env var
    takes priority; otherwise ``<case_home>/memory/memory.sqlite``.
    """
    env_src: dict[str, str] = dict(env) if env is not None else dict(os.environ)
    override = env_src.get("FINDEVIL_MEMORY_STORE", "").strip()
    if override:
        return Path(override)
    return resolve_case_home(env=env_src) / "memory" / "memory.sqlite"


__all__ = [
    "ACH_MAX_ROUNDS",
    "EMBEDDING_MODEL",
    "EMBEDDING_PROVIDER",
    "JUDGE_WALL_CLOCK_BUDGET_SECONDS",
    "LLM_PROVIDER",
    "MODEL",
    "TOOL_SUBPROCESS_BUDGET_SECONDS",
    "CredentialMode",
    "CredentialResolution",
    "CredentialsNotAvailableError",
    "resolve_case_home",
    "resolve_credentials",
    "resolve_memory_store_path",
]
