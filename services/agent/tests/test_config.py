"""Tests for ``findevil_agent.config.resolve_credentials``.

Amendment A1 — three credential modes in priority order. These
tests never touch the real environment; they inject ``env=`` so
test parallelism is safe.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from findevil_agent.config import (
    ACH_MAX_ROUNDS,
    JUDGE_WALL_CLOCK_BUDGET_SECONDS,
    CredentialMode,
    CredentialResolution,
    CredentialsNotAvailableError,
    resolve_case_home,
    resolve_credentials,
    resolve_memory_store_path,
)


class TestResolveCredentials:
    def test_oauth_token_wins_over_everything(self, tmp_path: Path) -> None:
        (tmp_path / ".claude").mkdir()
        (tmp_path / ".claude" / "session").write_text("x")
        env = {
            "CLAUDE_CODE_OAUTH_TOKEN": "sk-ant-oat01-abc",
            "ANTHROPIC_API_KEY": "sk-ant-xyz",
            "HOME": str(tmp_path),
        }
        r = resolve_credentials(env=env)
        assert r.mode == CredentialMode.OAUTH_TOKEN
        assert r.api_key is None  # never surfaces raw token

    def test_interactive_session_wins_over_api_key(self, tmp_path: Path) -> None:
        (tmp_path / ".claude").mkdir()
        (tmp_path / ".claude" / "session").write_text("x")
        env = {
            "ANTHROPIC_API_KEY": "sk-ant-xyz",
            "HOME": str(tmp_path),
        }
        r = resolve_credentials(env=env)
        assert r.mode == CredentialMode.CLAUDE_CODE_SESSION
        assert r.claude_home == tmp_path / ".claude"

    def test_api_key_is_the_fallback(self, tmp_path: Path) -> None:
        # No ~/.claude, no oauth token.
        env = {
            "ANTHROPIC_API_KEY": "sk-ant-abc123",
            "HOME": str(tmp_path),
        }
        r = resolve_credentials(env=env)
        assert r.mode == CredentialMode.API_KEY
        assert r.api_key == "sk-ant-abc123"

    def test_empty_oauth_token_does_not_win(self, tmp_path: Path) -> None:
        env = {
            "CLAUDE_CODE_OAUTH_TOKEN": "   ",  # whitespace only
            "ANTHROPIC_API_KEY": "sk-ant-xyz",
            "HOME": str(tmp_path),
        }
        r = resolve_credentials(env=env)
        assert r.mode == CredentialMode.API_KEY

    def test_empty_claude_home_does_not_win(self, tmp_path: Path) -> None:
        # Directory exists but is empty → reject as invalid session.
        (tmp_path / ".claude").mkdir()
        env = {
            "ANTHROPIC_API_KEY": "sk-ant-xyz",
            "HOME": str(tmp_path),
        }
        r = resolve_credentials(env=env)
        assert r.mode == CredentialMode.API_KEY

    def test_raises_when_no_credentials(self, tmp_path: Path) -> None:
        env = {"HOME": str(tmp_path)}
        with pytest.raises(CredentialsNotAvailableError) as exc:
            resolve_credentials(env=env)
        msg = str(exc.value)
        assert "CLAUDE_CODE_OAUTH_TOKEN" in msg
        assert "claude auth login" in msg
        assert "ANTHROPIC_API_KEY" in msg

    def test_fingerprint_masks_api_key(self) -> None:
        r = CredentialResolution(mode=CredentialMode.API_KEY, api_key="sk-ant-abc123xyz456")
        fp = r.api_key_fingerprint()
        assert fp is not None
        # Fingerprint shows first 5 + last 4, never the middle.
        assert fp.startswith("sk-an")
        assert fp.endswith("z456")
        assert "abc123" not in fp

    def test_fingerprint_none_for_non_api_modes(self) -> None:
        r = CredentialResolution(mode=CredentialMode.OAUTH_TOKEN, api_key=None)
        assert r.api_key_fingerprint() is None


class TestResolveCaseHome:
    def test_findevil_home_override(self, tmp_path: Path) -> None:
        env = {"FINDEVIL_HOME": str(tmp_path)}
        assert resolve_case_home(env=env) == tmp_path

    def test_defaults_to_home_slash_findevil(self, tmp_path: Path) -> None:
        env = {"HOME": str(tmp_path)}
        assert resolve_case_home(env=env) == tmp_path / ".findevil"

    def test_falls_back_to_userprofile(self, tmp_path: Path) -> None:
        env = {"USERPROFILE": str(tmp_path)}
        assert resolve_case_home(env=env) == tmp_path / ".findevil"

    def test_raises_when_no_env(self) -> None:
        with pytest.raises(RuntimeError):
            resolve_case_home(env={})


class TestConstants:
    def test_ach_max_rounds_is_one(self) -> None:
        # Spec #2 §8.1 — multi-round debate amplifies sycophancy.
        assert ACH_MAX_ROUNDS == 1

    def test_judge_budget_is_two_minutes(self) -> None:
        # Spec #2 §8.1 — judge commits a decision within 2 min wall clock.
        assert JUDGE_WALL_CLOCK_BUDGET_SECONDS == 120


class TestResolveMemoryStorePath:
    def test_resolve_memory_store_path_precedence(
        self, tmp_path: pytest.TemporaryDirectory
    ) -> None:
        override = tmp_path / "custom_memory.sqlite"
        env = {"FINDEVIL_MEMORY_STORE": str(override), "HOME": str(tmp_path)}
        result = resolve_memory_store_path(env=env)
        assert result == override

    def test_defaults_under_case_home(self, tmp_path: pytest.TemporaryDirectory) -> None:
        env = {"HOME": str(tmp_path)}
        result = resolve_memory_store_path(env=env)
        assert result == tmp_path / ".findevil" / "memory" / "memory.sqlite"

    def test_respects_findevil_home_override(self, tmp_path: pytest.TemporaryDirectory) -> None:
        custom_home = tmp_path / "custom_findevil"
        env = {"FINDEVIL_HOME": str(custom_home), "HOME": str(tmp_path)}
        result = resolve_memory_store_path(env=env)
        assert result == custom_home / "memory" / "memory.sqlite"
