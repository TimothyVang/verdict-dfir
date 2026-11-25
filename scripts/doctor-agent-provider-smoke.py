#!/usr/bin/env python3
"""Smoke the provider-aware doctor credential gate without network or models."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DOCTOR = REPO_ROOT / "scripts" / "doctor.sh"
VERDICT = REPO_ROOT / "scripts" / "verdict"
REQUIRED_COMMANDS = ("python3", "git", "unzip", "cargo", "uv", "npx")


def _fixture(root: Path) -> tuple[Path, dict[str, str]]:
    scripts = root / "scripts"
    scripts.mkdir()
    doctor = scripts / "doctor.sh"
    shutil.copy2(DOCTOR, doctor)

    (root / "target" / "release").mkdir(parents=True)
    (root / "target" / "release" / "findevil-mcp").write_text("", encoding="utf-8")
    (root / "target" / "release" / "findevil-mcp").chmod(0o755)
    (root / "services" / "agent_mcp" / ".venv").mkdir(parents=True)
    (root / "services" / "agent_mcp" / "findevil_agent_mcp").mkdir()
    (root / ".mcp.json").write_text(
        '{"mcpServers":{"findevil-mcp":{},"findevil-agent-mcp":{}}}\n',
        encoding="utf-8",
    )
    for name in ("run-mcp-rust.sh", "run-mcp-python.sh"):
        (scripts / name).write_text("#!/usr/bin/env bash\n", encoding="utf-8")

    fake_bin = root / "bin"
    fake_bin.mkdir()
    fake_command = fake_bin / "fake-command"
    fake_command.write_text(
        "#!/usr/bin/env bash\nprintf 'fixture tool 1.0\\n'\n", encoding="utf-8"
    )
    fake_command.chmod(0o755)
    for command in REQUIRED_COMMANDS:
        if command == "python3":
            (fake_bin / command).symlink_to(sys.executable)
            continue
        (fake_bin / command).symlink_to(fake_command)
    curl = fake_bin / "curl"
    curl.write_text("#!/usr/bin/env bash\nexit 1\n", encoding="utf-8")
    curl.chmod(0o755)

    home = root / "home"
    home.mkdir()
    env = {
        **os.environ,
        "HOME": str(home),
        "PATH": f"{fake_bin}:/usr/bin:/bin",
    }
    env.pop("CLAUDE_CODE_OAUTH_TOKEN", None)
    env.pop("ANTHROPIC_API_KEY", None)
    env.pop("FINDEVIL_DOCTOR_AGENT_PROVIDER", None)
    return doctor, env


def _write_fixture_credentials(home: Path) -> None:
    claude_dir = home / ".claude"
    claude_dir.mkdir(exist_ok=True)
    (claude_dir / ".credentials.json").write_text(
        json.dumps(
            {
                "claudeAiOauth": {
                    "accessToken": "fixture-token-not-real",
                    "scopes": ["user:inference"],
                }
            }
        ),
        encoding="utf-8",
    )


def _run(doctor: Path, env: dict[str, str], provider: str | None) -> dict[str, object]:
    run_env = dict(env)
    if provider is not None:
        run_env["FINDEVIL_DOCTOR_AGENT_PROVIDER"] = provider
    result = subprocess.run(
        ["bash", str(doctor), "--json"],
        capture_output=True,
        text=True,
        timeout=15,
        env=run_env,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def _check(report: dict[str, object], label: str) -> dict[str, str]:
    checks = report["checks"]
    assert isinstance(checks, list)
    return next(
        check
        for check in checks
        if isinstance(check, dict) and check.get("label") == label
    )


def _credential(report: dict[str, object]) -> dict[str, str]:
    return _check(report, "credential")


def _run_launcher_without_model(root: Path, provider: str) -> None:
    fake_bin = root / f"launcher-bin-{provider}"
    fake_bin.mkdir()
    fake_uv = fake_bin / "uv"
    fake_uv.write_text(
        """#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" != "run" ]]; then
  exec "${REAL_UV}" "$@"
fi
summary=""
while [[ $# -gt 0 ]]; do
  if [[ "$1" == "--run-summary" ]]; then
    summary="$2"
    break
  fi
  shift
done
mkdir -p "$(dirname "${summary}")"
printf '%s\n' '{"result":{"verdict":"NO_EVIL","manifest_verify_overall":true}}' >"${summary}"
printf '%s\n' '{"verdict":"NO_EVIL"}' >"$(dirname "$(dirname "${summary}")")/verdict.json"
""",
        encoding="utf-8",
    )
    fake_uv.chmod(0o755)
    fake_curl = fake_bin / "curl"
    fake_curl.write_text("#!/usr/bin/env bash\nexit 1\n", encoding="utf-8")
    fake_curl.chmod(0o755)
    fake_cargo = fake_bin / "cargo"
    fake_cargo.write_text(
        "#!/usr/bin/env bash\nprintf 'cargo fixture 1.0\\n'\n", encoding="utf-8"
    )
    fake_cargo.chmod(0o755)

    evidence = root / f"{provider}.evtx"
    evidence.write_bytes(b"fixture")
    home = root / f"launcher-home-{provider}"
    home.mkdir()
    case_id = f"provider-preflight-{provider}-{uuid.uuid4().hex}"
    case_dir = REPO_ROOT / "tmp" / "auto-runs" / case_id
    env = {
        **os.environ,
        "HOME": str(home),
        "PATH": f"{fake_bin}:/usr/bin:/bin",
        "REAL_UV": shutil.which("uv") or "uv",
        "FINDEVIL_SKIP_GROUNDING": "1",
    }
    env.pop("CLAUDE_CODE_OAUTH_TOKEN", None)
    env.pop("ANTHROPIC_API_KEY", None)
    assert shutil.which("claude", path=env["PATH"]) is None

    try:
        result = subprocess.run(
            [
                "bash",
                str(VERDICT),
                str(evidence),
                "--agent",
                "--agent-provider",
                provider,
                "--agent-model",
                "fixture-model",
                "--skip-build",
                "--no-dashboard",
                "--case-id",
                case_id,
            ],
            capture_output=True,
            text=True,
            timeout=30,
            env=env,
        )
    finally:
        shutil.rmtree(case_dir, ignore_errors=True)
    combined = result.stdout + result.stderr
    assert result.returncode == 0, combined
    assert f"not required for {provider} execution" in combined, combined


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        doctor, env = _fixture(Path(tmp))

        for provider in ("local", "dgx", "openai", "openrouter", "deterministic"):
            report = _run(doctor, env, provider)
            credential = _credential(report)
            claude = _check(report, "claude")
            assert report["ready"] is True, report
            assert credential["status"] == "ok", credential
            assert provider in credential["detail"], credential
            assert "not required" in credential["detail"], credential
            assert claude["status"] == "ok", claude
            assert provider in claude["detail"], claude
            assert "not required" in claude["detail"], claude
            print(f"  [PASS] {provider} needs no Claude credential or CLI")

        for provider in ("local", "dgx"):
            _run_launcher_without_model(Path(tmp), provider)
            print(
                f"  [PASS] canonical {provider} launcher runs without a model or credential"
            )

        _write_fixture_credentials(Path(env["HOME"]))
        report = _run(doctor, env, "anthropic")
        credential = _credential(report)
        claude = _check(report, "claude")
        assert report["ready"] is True, report
        assert credential["status"] == "ok", credential
        assert "credentials" in credential["detail"], credential
        assert claude["status"] == "ok", claude
        assert "not required" in claude["detail"], claude
        print(
            "  [PASS] direct anthropic accepts fixture credentials without Claude CLI"
        )

        report = _run(doctor, env, "claude_cli")
        credential = _credential(report)
        claude = _check(report, "claude")
        assert report["ready"] is False, report
        assert credential["status"] == "ok", credential
        assert claude["status"] == "err", claude
        print(
            "  [PASS] claude_cli fails without Claude CLI despite fixture authentication"
        )

        report = _run(doctor, env, "unknown-provider")
        assert report["ready"] is False, report
        provider_check = _check(report, "agent provider")
        assert provider_check["status"] == "err", provider_check
        print("  [PASS] unknown provider fails closed")

    print("\ndoctor-agent-provider-smoke: 10 passed, 0 failed")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print(f"  [FAIL] {exc}", file=sys.stderr)
        sys.exit(1)
