from __future__ import annotations

import sys
from pathlib import Path

import pytest

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402


@pytest.mark.parametrize("overall", [False, None], ids=["false", "missing"])
def test_native_run_is_incomplete_without_verified_manifest(overall: bool | None) -> None:
    result = {"verdict": "NO_EVIL", "manifest_verify_overall": overall}

    assert fea._run_completed(agent_mode=True, result=result) is False


def test_deterministic_run_preserves_existing_completion_contract() -> None:
    result = {"verdict": "NO_EVIL", "manifest_verify_overall": False}

    assert fea._run_completed(agent_mode=False, result=result) is True


def test_native_failed_manifest_prints_incomplete_instead_of_done(capsys) -> None:
    result = {"verdict": "NO_EVIL", "manifest_verify_overall": False}

    assert fea._print_completion_banner(agent_mode=True, result=result) is False

    captured = capsys.readouterr()
    assert "DONE" not in captured.out + captured.err
    assert "RUN INCOMPLETE / CUSTODY INVALID" in captured.err


def test_deterministic_error_preserves_existing_done_banner(capsys) -> None:
    result = {"verdict": "ERROR", "manifest_verify_overall": False}

    assert fea._print_completion_banner(agent_mode=False, result=result) is False

    captured = capsys.readouterr()
    assert "DONE — verdict: ERROR" in captured.out
    assert "RUN INCOMPLETE" not in captured.out + captured.err


def test_native_main_returns_nonzero_for_failed_manifest_verification(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    evidence = tmp_path / "sample.evtx"
    evidence.write_bytes(b"evtx")

    class FakeInvestigation:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def run(self) -> dict[str, object]:
            return {
                "verdict": "NO_EVIL",
                "manifest_verify_overall": False,
                "heartbeat_terminated": False,
                "packet_state": "EXPERT_REVIEW_REQUIRED",
            }

    monkeypatch.setattr(fea, "Investigation", FakeInvestigation)
    monkeypatch.setattr(fea, "preflight_check", lambda: None)
    monkeypatch.setattr(sys, "argv", ["find-evil-auto", str(evidence), "--agent"])

    assert fea.main() == 1
