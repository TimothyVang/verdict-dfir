#!/usr/bin/env python3
"""Resumable local build runner and checker.

This tool owns the state format for ``scripts/build-local.sh``. The local
build lane is intentionally narrower than submission readiness: it proves the
repo builds and fast local checks run, while SIFT, Docker L1, real evidence,
Devpost assets, and L3 goldens remain external readiness checks.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any

REPO = Path(__file__).resolve().parent.parent
RUN_ROOT = REPO / "tmp" / "build-runs"

LOCAL_PASS = "LOCAL_BUILD_PASS"
LOCAL_FAST_PASS = "LOCAL_BUILD_FAST_PASS"
LOCAL_FAIL = "LOCAL_BUILD_FAIL"
LOCAL_INCOMPLETE = "LOCAL_BUILD_INCOMPLETE"
STATE_VERSION = 1
MAX_UNTRACKED_HASH_BYTES = 5_000_000

EXTERNAL_READINESS_CHECKS = (
    "Docker L1 CI-equivalent gate",
    "SIFT VM / real evidence execution",
    "L3 goldens / benchmark evidence",
    "Devpost demo URL and package assets",
)


@dataclass(frozen=True)
class BuildStep:
    name: str
    label: str
    command: tuple[str, ...]
    log_name: str
    env: dict[str, str] | None = None
    fast_skip: bool = False


STEPS: tuple[BuildStep, ...] = (
    BuildStep(
        name="cargo-build-release",
        label="Build Rust MCP release binary",
        command=("cargo", "build", "--release", "-p", "findevil-mcp", "--locked"),
        log_name="01-cargo-build-release.log",
    ),
    BuildStep(
        name="uv-sync-agent-mcp",
        label="Sync Python agent MCP dev env",
        command=("uv", "sync", "--directory", "services/agent_mcp", "--extra", "dev"),
        log_name="02-uv-sync-agent-mcp.log",
    ),
    BuildStep(
        name="local-smokes",
        label="Run local smoke gate",
        command=("bash", "scripts/run-all-smokes.sh"),
        log_name="03-run-all-smokes.log",
    ),
    BuildStep(
        name="ruff-check",
        label="Run Python lint",
        command=("ruff", "check", "."),
        log_name="04-ruff-check.log",
    ),
    BuildStep(
        name="ruff-format-check",
        label="Run Python format check",
        command=("ruff", "format", "--check", "."),
        log_name="05-ruff-format-check.log",
    ),
    BuildStep(
        name="pnpm-install",
        label="Install web dependencies",
        command=("pnpm", "install", "--frozen-lockfile"),
        log_name="06-pnpm-install.log",
    ),
    BuildStep(
        name="web-typecheck",
        label="Typecheck web app",
        command=("pnpm", "--filter", "@findevil/web", "typecheck"),
        log_name="07-web-typecheck.log",
    ),
    BuildStep(
        name="web-build",
        label="Build web app",
        command=("pnpm", "--filter", "@findevil/web", "build"),
        log_name="08-web-build.log",
    ),
    BuildStep(
        name="web-test",
        label="Run web tests",
        command=("pnpm", "--filter", "@findevil/web", "test"),
        log_name="09-web-test.log",
        fast_skip=True,
    ),
)


def utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def make_run_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"build-{stamp}"


def format_command(command: tuple[str, ...]) -> str:
    return " ".join(shlex.quote(part) for part in command)


def build_env() -> dict[str, str]:
    """Return an environment with common per-user tool bins on PATH.

    OpenCode may launch Git Bash with a reduced PATH even when Windows
    itself can find tools such as ``cargo.exe``. Prepending these standard
    locations keeps the local build lane resumable across terminal sessions.
    """
    env = os.environ.copy()
    candidates = [
        Path.home() / ".cargo" / "bin",
        Path.home() / ".local" / "bin",
    ]
    windows_home = windows_home_from_repo()
    if windows_home is not None:
        candidates.extend(
            [
                windows_home / ".cargo" / "bin",
                windows_home / ".local" / "bin",
                windows_home / "AppData" / "Local" / "pnpm",
                windows_home / "AppData" / "Roaming" / "npm",
            ]
        )
    appdata = env.get("APPDATA")
    if appdata:
        candidates.append(Path(appdata) / "npm")
    localappdata = env.get("LOCALAPPDATA")
    if localappdata:
        candidates.append(Path(localappdata) / "pnpm")
    extras = [str(path) for path in candidates if path.is_dir()]
    if extras:
        env["PATH"] = os.pathsep.join(extras + [env.get("PATH", "")])
    return env


def windows_home_from_repo() -> Path | None:
    """Infer the Windows home directory when running from WSL.

    Example repo path: ``/mnt/c/Users/newbi/Desktop/...``.
    """
    parts = REPO.parts
    if len(parts) >= 5 and parts[1:4] == ("mnt", "c", "Users"):
        return Path("/") / "mnt" / "c" / "Users" / parts[4]
    return None


def resolve_command(command: tuple[str, ...], env: dict[str, str]) -> tuple[str, ...]:
    """Resolve Windows .exe tools when running under WSL/MSYS Python."""
    if os.name == "nt" and command[0] == "bash":
        git_bash = find_git_bash()
        if git_bash is not None:
            return (str(git_bash), *command[1:])
    path = env.get("PATH")
    executable = shutil.which(command[0], path=path)
    if executable is None and not command[0].lower().endswith(".exe"):
        executable = shutil.which(f"{command[0]}.exe", path=path)
    if executable is None:
        return command
    return (executable, *command[1:])


def find_git_bash() -> Path | None:
    candidates: list[Path] = []
    for env_name in ("ProgramW6432", "ProgramFiles", "ProgramFiles(x86)"):
        root = os.environ.get(env_name)
        if root:
            candidates.extend(
                [
                    Path(root) / "Git" / "bin" / "bash.exe",
                    Path(root) / "Git" / "usr" / "bin" / "bash.exe",
                ]
            )
    candidates.extend(
        [
            Path("C:/Program Files/Git/bin/bash.exe"),
            Path("C:/Program Files/Git/usr/bin/bash.exe"),
            Path("C:/Program Files (x86)/Git/bin/bash.exe"),
            Path("C:/Program Files (x86)/Git/usr/bin/bash.exe"),
        ]
    )
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def atomic_write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
        fh.write("\n")
        tmp_name = fh.name
    Path(tmp_name).replace(path)


def initial_state(run_id: str, run_dir: Path, *, fast: bool) -> dict[str, Any]:
    return {
        "state_version": STATE_VERSION,
        "run_id": run_id,
        "mode": "local",
        "status": LOCAL_INCOMPLETE,
        "started_at": utc_now(),
        "finished_at": None,
        "fast": fast,
        "repo": str(REPO),
        "run_dir": str(run_dir),
        "fingerprint": build_fingerprint(),
        "step_schema": step_schema(),
        "external_readiness_checks": [
            {
                "name": name,
                "status": "not_run",
                "reason": "external readiness only; not a local build blocker",
            }
            for name in EXTERNAL_READINESS_CHECKS
        ],
        "steps": [step_record(step) for step in STEPS],
    }


def step_record(step: BuildStep) -> dict[str, Any]:
    return {
        "name": step.name,
        "label": step.label,
        "status": "pending",
        "command": format_command(step.command),
        "log": f"logs/{step.log_name}",
        "started_at": None,
        "finished_at": None,
        "duration_seconds": None,
        "exit_code": None,
    }


def step_schema() -> list[dict[str, str]]:
    return [
        {"name": step.name, "command": format_command(step.command)} for step in STEPS
    ]


def git_bytes(*args: str, check: bool = False) -> bytes:
    result = subprocess.run(
        ("git", *args),
        cwd=REPO,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=60,
    )
    if check and result.returncode != 0:
        raise RuntimeError(result.stderr.decode("utf-8", errors="replace"))
    return result.stdout


def is_non_code_runtime_path(path: bytes) -> bool:
    normalized = path.replace(b"\\", b"/")
    return normalized.startswith(
        (b".omx/", b"tmp/", b"release-assets/", b"apps/web/dist/")
    ) or normalized in {
        b"benchmark-results.csv",
        b"find-evil-submission.zip",
    }


def build_fingerprint() -> dict[str, str]:
    """Hash git HEAD plus non-runtime dirty state.

    Ignored runtime dirs such as ``tmp/`` and ``.omx/`` are deliberately
    excluded so log/checkpoint churn does not invalidate resumes.
    """
    sha = hashlib.sha256()
    try:
        head = git_bytes("rev-parse", "HEAD", check=True).strip()
        sha.update(b"HEAD\0" + head + b"\0")
        sha.update(b"DIFF\0" + git_bytes("diff", "--binary") + b"\0")
        sha.update(b"CACHED\0" + git_bytes("diff", "--cached", "--binary") + b"\0")
        status = git_bytes("status", "--porcelain=v1", "--untracked-files=all")
        filtered_status = []
        for line in status.splitlines():
            path = line[3:] if len(line) > 3 else line
            if is_non_code_runtime_path(path):
                continue
            filtered_status.append(line)
        for line in sorted(filtered_status):
            sha.update(b"STATUS\0" + line + b"\0")
        untracked = git_bytes("ls-files", "--others", "--exclude-standard", "-z")
        for raw in sorted(path for path in untracked.split(b"\0") if path):
            if is_non_code_runtime_path(raw):
                continue
            rel = raw.decode("utf-8", errors="surrogateescape")
            path = REPO / rel
            sha.update(b"UNTRACKED\0" + raw + b"\0")
            if path.is_file():
                size = path.stat().st_size
                sha.update(str(size).encode() + b"\0")
                if size <= MAX_UNTRACKED_HASH_BYTES:
                    sha.update(path.read_bytes())
        return {
            "kind": "git",
            "head": head.decode("utf-8", errors="replace"),
            "digest": sha.hexdigest(),
        }
    except Exception as exc:  # pragma: no cover - defensive for broken git envs
        # Make resumes fail closed if git fingerprinting is unavailable.
        return {
            "kind": "unavailable",
            "error": str(exc),
            "digest": f"unavailable:{utc_now()}",
        }


def load_state(run_dir: Path) -> dict[str, Any]:
    state_path = run_dir / "state.json"
    if not state_path.is_file():
        raise SystemExit(f"state file not found: {state_path}")
    return json.loads(state_path.read_text(encoding="utf-8"))


def save_state(run_dir: Path, state: dict[str, Any]) -> None:
    atomic_write_json(run_dir / "state.json", state)


def latest_run_dir() -> Path | None:
    if not RUN_ROOT.is_dir():
        return None
    candidates = [p for p in RUN_ROOT.iterdir() if (p / "state.json").is_file()]
    if not candidates:
        return None
    return max(candidates, key=lambda p: (p / "state.json").stat().st_mtime)


def resolve_run_dir(value: str | None) -> Path | None:
    if value is None:
        return latest_run_dir()
    raw = Path(value)
    if raw.is_absolute() or raw.parts[:1] == ("tmp",):
        return (REPO / raw).resolve() if not raw.is_absolute() else raw
    candidate = RUN_ROOT / value
    if candidate.exists():
        return candidate
    return (REPO / raw).resolve()


def step_index(state: dict[str, Any], name: str) -> int:
    for idx, record in enumerate(state["steps"]):
        if record["name"] == name:
            return idx
    raise KeyError(name)


def summarize_status(state: dict[str, Any]) -> str:
    statuses = [record.get("status") for record in state.get("steps", [])]
    if any(status == "failed" for status in statuses):
        return LOCAL_FAIL
    if statuses and all(status in {"passed", "skipped"} for status in statuses):
        if state.get("fast") or any(status == "skipped" for status in statuses):
            return LOCAL_FAST_PASS
        return LOCAL_PASS
    return LOCAL_INCOMPLETE


def run_step(run_dir: Path, state: dict[str, Any], step: BuildStep) -> int:
    idx = step_index(state, step.name)
    record = state["steps"][idx]
    log_path = run_dir / record["log"]
    log_path.parent.mkdir(parents=True, exist_ok=True)

    record.update(
        {
            "status": "running",
            "started_at": utc_now(),
            "finished_at": None,
            "duration_seconds": None,
            "exit_code": None,
        }
    )
    state["status"] = LOCAL_INCOMPLETE
    save_state(run_dir, state)

    env = build_env()
    if step.env:
        env.update(step.env)
    if state.get("fast") and step.name == "local-smokes":
        env["SKIP_SLOW_RUST"] = "1"
    resolved_command = resolve_command(step.command, env)

    print(f"\n[build-local] {step.label}")
    print(f"[build-local] command: {record['command']}")
    print(f"[build-local] log: {log_path.relative_to(REPO)}")
    started = time.monotonic()
    with log_path.open("w", encoding="utf-8", errors="replace") as log:
        log.write(f"# {step.label}\n")
        log.write(f"# command: {record['command']}\n")
        log.write(f"# started_at: {record['started_at']}\n\n")
        try:
            proc = subprocess.Popen(
                resolved_command,
                cwd=REPO,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
            )
        except FileNotFoundError as exc:
            message = f"command not found: {step.command[0]} ({exc})\n"
            print(message, end="")
            log.write(message)
            exit_code = 127
        else:
            assert proc.stdout is not None
            for line in proc.stdout:
                print(line, end="")
                log.write(line)
            exit_code = proc.wait()

        duration = int(time.monotonic() - started)
        record.update(
            {
                "status": "passed" if exit_code == 0 else "failed",
                "finished_at": utc_now(),
                "duration_seconds": duration,
                "exit_code": exit_code,
            }
        )
        log.write(f"\n# finished_at: {record['finished_at']}\n")
        log.write(f"# duration_seconds: {duration}\n")
        log.write(f"# exit_code: {exit_code}\n")

    state["status"] = summarize_status(state)
    if state["status"] != LOCAL_INCOMPLETE:
        state["finished_at"] = utc_now()
    save_state(run_dir, state)
    return exit_code


def skipped_fast_step(run_dir: Path, state: dict[str, Any], step: BuildStep) -> None:
    idx = step_index(state, step.name)
    record = state["steps"][idx]
    record.update(
        {
            "status": "skipped",
            "started_at": utc_now(),
            "finished_at": utc_now(),
            "duration_seconds": 0,
            "exit_code": 0,
            "reason": "--fast requested",
        }
    )
    save_state(run_dir, state)


def ensure_state(args: argparse.Namespace) -> tuple[Path, dict[str, Any]]:
    if args.resume:
        run_dir = resolve_run_dir(args.run_id)
        if run_dir is not None and (run_dir / "state.json").is_file():
            state = load_state(run_dir)
            if state.get("state_version") != STATE_VERSION:
                raise SystemExit(
                    "build state schema changed; start a new run instead of resuming"
                )
            if state.get("step_schema") != step_schema():
                raise SystemExit(
                    "build step list changed; start a new run instead of resuming"
                )
            current_fingerprint = build_fingerprint()
            if state.get("fingerprint") != current_fingerprint:
                raise SystemExit(
                    "working tree changed since this build run started; "
                    "start a new run instead of resuming"
                )
            state["repo"] = str(REPO)
            state["run_dir"] = str(run_dir)
            state["resumed_at"] = utc_now()
            if args.fast:
                state["fast"] = True
            if state.get("status") != LOCAL_PASS:
                state["status"] = LOCAL_INCOMPLETE
                state["finished_at"] = None
            save_state(run_dir, state)
            return run_dir, state

    run_id = args.run_id or make_run_id()
    run_dir = RUN_ROOT / run_id
    if (run_dir / "state.json").exists():
        raise SystemExit(f"run already exists, use --resume: {run_id}")
    run_dir.mkdir(parents=True, exist_ok=True)
    state = initial_state(run_id, run_dir, fast=args.fast)
    save_state(run_dir, state)
    return run_dir, state


def run_local_build(args: argparse.Namespace) -> int:
    if wsl_without_linux_cargo():
        print(
            "[build-local] ERROR: WSL Python detected without a Linux Rust "
            "toolchain. Run from PowerShell/OpenCode with Windows python, use "
            "Git Bash, or install Rust inside WSL.",
            file=sys.stderr,
        )
        return 2
    run_dir, state = ensure_state(args)
    print(f"[build-local] run: {run_dir.relative_to(REPO)}")
    print("[build-local] scope: local build only; external readiness checks skipped")

    for step in STEPS:
        idx = step_index(state, step.name)
        record = state["steps"][idx]
        if record.get("status") == "passed":
            print(f"[build-local] skip passed step: {step.name}")
            continue
        if record.get("status") == "skipped" and state.get("fast"):
            print(f"[build-local] skip fast step: {step.name}")
            continue
        if (args.fast or state.get("fast")) and step.fast_skip:
            print(f"[build-local] skip fast step: {step.name}")
            skipped_fast_step(run_dir, state, step)
            continue
        exit_code = run_step(run_dir, state, step)
        if exit_code != 0:
            print_status(state, run_dir=run_dir)
            return exit_code

    state["status"] = summarize_status(state)
    state["finished_at"] = utc_now()
    save_state(run_dir, state)
    print_status(state, run_dir=run_dir)
    return 0 if state["status"] in {LOCAL_PASS, LOCAL_FAST_PASS} else 1


def wsl_without_linux_cargo() -> bool:
    if os.name != "posix":
        return False
    proc_version = Path("/proc/version")
    if not proc_version.is_file():
        return False
    text = proc_version.read_text(encoding="utf-8", errors="ignore").lower()
    return "microsoft" in text and shutil.which("cargo") is None


def read_status(args: argparse.Namespace) -> tuple[Path | None, dict[str, Any] | None]:
    run_dir = resolve_run_dir(args.run)
    if run_dir is None:
        return None, None
    return run_dir, load_state(run_dir)


def print_status(
    state: dict[str, Any], *, run_dir: Path, status_override: str | None = None
) -> None:
    status = status_override or summarize_status(state)
    passed = [s["name"] for s in state["steps"] if s.get("status") == "passed"]
    failed = [s["name"] for s in state["steps"] if s.get("status") == "failed"]
    skipped = [s["name"] for s in state["steps"] if s.get("status") == "skipped"]
    pending = [
        s["name"] for s in state["steps"] if s.get("status") in {"pending", "running"}
    ]

    print("\n==========================================")
    print(f"Local build: {status}")
    print(f"Run: {run_dir.relative_to(REPO)}")
    print(f"Passed: {', '.join(passed) if passed else '-'}")
    print(f"Failed: {', '.join(failed) if failed else '-'}")
    print(f"Skipped local steps: {', '.join(skipped) if skipped else '-'}")
    print(f"Pending/resumable: {', '.join(pending) if pending else '-'}")
    print(
        "Skipped external blockers: Docker L1, SIFT evidence, "
        "L3 goldens, Devpost package"
    )
    print("Resume:")
    print(f"  bash scripts/build-local.sh --resume --run-id {state['run_id']}")
    print("Checker:")
    print(f"  python scripts/build-checker.py --run {state['run_id']}")
    print("==========================================")
    if status == LOCAL_PASS:
        print("LOCAL_BUILD_PASS is not SUBMISSION_READY.")
    if status == LOCAL_FAST_PASS:
        print(
            "LOCAL_BUILD_FAST_PASS is partial: rerun without --fast for full local coverage."
        )


def fingerprint_blocker(state: dict[str, Any]) -> tuple[str | None, dict[str, str]]:
    stored = state.get("fingerprint")
    current = build_fingerprint()
    if not isinstance(stored, dict):
        return "build state is missing a source fingerprint", current
    if stored.get("kind") == "unavailable":
        return "build state fingerprint was unavailable when the run started", current
    if current.get("kind") == "unavailable":
        return "current source fingerprint is unavailable", current
    if stored != current:
        return "working tree changed since this build run completed", current
    return None, current


def status_exit_code(status: str) -> int:
    if status == LOCAL_PASS:
        return 0
    if status == LOCAL_FAST_PASS:
        return 3
    if status == LOCAL_FAIL:
        return 1
    return 2


def status_command(args: argparse.Namespace) -> int:
    run_dir, state = read_status(args)
    if run_dir is None or state is None:
        payload = {
            "status": LOCAL_INCOMPLETE,
            "message": "no local build runs found",
            "run_root": str(RUN_ROOT),
        }
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print("Local build: LOCAL_BUILD_INCOMPLETE")
            print("No local build runs found.")
            print("Start one with: bash scripts/build-local.sh")
        return 2

    state["status"] = summarize_status(state)
    fingerprint_error, current_fingerprint = fingerprint_blocker(state)
    if fingerprint_error is not None:
        state["status"] = LOCAL_INCOMPLETE
        state["fingerprint_status"] = {
            "status": "blocked",
            "reason": fingerprint_error,
            "stored": state.get("fingerprint"),
            "current": current_fingerprint,
        }
    if args.json:
        print(json.dumps(state, indent=2, sort_keys=True))
    else:
        print_status(state, run_dir=run_dir, status_override=state["status"])
        if fingerprint_error is not None:
            print(f"Source fingerprint: BLOCKED ({fingerprint_error})")
            print("Start a new run with: bash scripts/build-local.sh")
    return status_exit_code(state["status"])


def build_run_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the resumable local build lane.",
    )
    parser.add_argument(
        "--resume", action="store_true", help="resume latest or named run"
    )
    parser.add_argument("--run-id", help="run id to create or resume")
    parser.add_argument(
        "--fast",
        action="store_true",
        help="skip optional web tests and slow Rust smoke test",
    )
    return parser


def build_status_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Check the latest or named local build run.",
    )
    parser.add_argument("--run", help="run id or tmp/build-runs/<id> path")
    parser.add_argument("--json", action="store_true", help="print raw state JSON")
    return parser


def main(argv: list[str]) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    if argv and argv[0] == "run":
        parser = build_run_parser()
        args = parser.parse_args(argv[1:])
        return run_local_build(args)
    parser = build_status_parser()
    args = parser.parse_args(argv)
    return status_command(args)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
