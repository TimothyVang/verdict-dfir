#!/usr/bin/env python3
"""Cross-repo smoke proving CaseForge can consume this Dev VERDICT checkout.

The contract is intentionally mechanical and cheap:

* the release Rust MCP server exists;
* both MCP launch scripts work from an arbitrary CWD;
* a real case_open lands in this checkout's .project-local/findevil/cases;
* CaseForge can verify the committed public sample run;
* the committed sample run has no host-machine absolute path leak.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from queue import Empty, Queue
from typing import Any

REPO = Path(__file__).resolve().parent.parent
SAMPLE_RUN = REPO / "docs" / "release-evidence" / "sample-run"
REQUIRED_SAMPLE_FILES = (
    "audit.jsonl",
    "verdict.json",
    "run.manifest.json",
    "manifest_verify.json",
    "README.md",
)
HOST_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?:(?:/home|/Users)/[^/\s\"']+(?:/[^\s\"']*)?|/(?:tmp|private/var|var/folders|mnt|media|Volumes)/[^\s\"']+)"
)
WINDOWS_HOST_PATH_RE = re.compile(
    r"(?i)\b[A-Z]:\\(?:Users|Temp|Windows\\Temp|tmp)\\[^\s\"']+"
)


def fatal(message: str) -> None:
    print(f"\n[FAIL] {message}", file=sys.stderr)
    raise SystemExit(1)


def log(message: str) -> None:
    print(f"  {message}")


def _caseforge_candidates() -> list[Path]:
    env_root = os.environ.get("CASEFORGE_HOME") or os.environ.get("CASEFORGE_ROOT")
    candidates: list[Path] = []
    if env_root:
        candidates.append(Path(env_root).expanduser())
    candidates.extend(
        [
            REPO.parent / "caseforge-cloud",
            REPO.parent / "caseforge",
            REPO.parent / "caseforge-core",
            REPO.parent.parent / "verdict" / "caseforge",
        ]
    )
    return candidates


def resolve_caseforge_root() -> Path:
    for candidate in _caseforge_candidates():
        cli = candidate / "packages" / "caseforge-cli" / "dist" / "src" / "cli.js"
        launcher = candidate / "bin" / "verdict"
        if cli.is_file() and launcher.is_file():
            return candidate.resolve()
    tried = "\n".join(f"  - {path}" for path in _caseforge_candidates())
    fatal(
        "CaseForge CLI is not built or not discoverable; set CASEFORGE_HOME "
        "or run npm run build in the CaseForge checkout.\n"
        f"Tried:\n{tried}"
    )


def release_binary() -> Path:
    target_root = Path(os.environ.get("CARGO_TARGET_DIR", REPO / "target"))
    if not target_root.is_absolute():
        target_root = REPO / target_root
    name = "findevil-mcp.exe" if sys.platform == "win32" else "findevil-mcp"
    binary = target_root / "release" / name
    if not binary.is_file() and sys.platform != "win32":
        exe = binary.with_name("findevil-mcp.exe")
        if exe.is_file():
            binary = exe
    return binary


def contract_env() -> dict[str, str]:
    script = REPO / "scripts" / "lib" / "project-env.sh"
    proc = subprocess.run(
        [
            "bash",
            "-c",
            'source "$1"; "$2" -c \'import json, os; print(json.dumps(dict(os.environ)))\'',
            "bash",
            str(script),
            sys.executable,
        ],
        cwd=REPO,
        env=os.environ.copy(),
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        print(proc.stdout, file=sys.stderr)
        print(proc.stderr, file=sys.stderr)
        fatal(f"could not source containment environment: {script}")
    env = json.loads(proc.stdout)
    env["FINDEVIL_LOG_LEVEL"] = "WARNING"
    env["PYTHONUNBUFFERED"] = "1"
    for key in (
        "PROJECT_LOCAL",
        "TMPDIR",
        "XDG_DATA_HOME",
        "XDG_STATE_HOME",
        "XDG_CACHE_HOME",
        "FINDEVIL_HOME",
    ):
        env[key] = str(Path(env[key]).expanduser().resolve())
        Path(env[key]).mkdir(parents=True, exist_ok=True)
    expected_project_local = (REPO / ".project-local").resolve()
    expected_findevil = expected_project_local / "findevil"
    if (
        Path(env["PROJECT_LOCAL"]) != expected_project_local
        or Path(env["FINDEVIL_HOME"]) != expected_findevil
    ):
        fatal(
            "caseforge contract smoke proves the default Dev VERDICT containment store; "
            "unset PROJECT_LOCAL and FINDEVIL_HOME before running it"
        )
    return env


def case_store(env: dict[str, str]) -> Path:
    return Path(env["FINDEVIL_HOME"]) / "cases"


def project_local(env: dict[str, str]) -> Path:
    return Path(env["PROJECT_LOCAL"])


class StdioClient:
    def __init__(self, cmd: list[str], *, cwd: Path, env: dict[str, str]) -> None:
        self.proc = subprocess.Popen(
            cmd,
            cwd=cwd,
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            bufsize=1,
        )
        self._next_id = 1
        self._stdout: Queue[str | None] = Queue()
        self._stderr: Queue[str | None] = Queue()
        threading.Thread(
            target=self._reader, args=(self.proc.stdout, self._stdout), daemon=True
        ).start()
        threading.Thread(
            target=self._reader, args=(self.proc.stderr, self._stderr), daemon=True
        ).start()

    @staticmethod
    def _reader(stream: Any, out: Queue[str | None]) -> None:
        try:
            if stream is None:
                return
            for line in iter(stream.readline, ""):
                out.put(line)
        finally:
            out.put(None)

    def _stderr_tail(self) -> str:
        lines: list[str] = []
        while True:
            try:
                line = self._stderr.get_nowait()
            except Empty:
                break
            if line:
                lines.append(line.rstrip())
        return "\n".join(lines[-20:])

    def send(self, message: dict[str, Any]) -> None:
        if self.proc.stdin is None:
            fatal("server stdin is unavailable")
        self.proc.stdin.write(json.dumps(message, separators=(",", ":")) + "\n")
        self.proc.stdin.flush()

    def read(self, timeout_s: float = 45.0) -> dict[str, Any]:
        deadline = time.monotonic() + timeout_s
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                fatal(f"timed out waiting for MCP response\n{self._stderr_tail()}")
            try:
                line = self._stdout.get(timeout=remaining)
            except Empty:
                continue
            if line is None:
                fatal(f"MCP server closed stdout\n{self._stderr_tail()}")
            line = line.strip()
            if not line:
                continue
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                continue

    def call(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        msg_id = self._next_id
        self._next_id += 1
        self.send(
            {"jsonrpc": "2.0", "id": msg_id, "method": method, "params": params or {}}
        )
        response = self.read()
        if response.get("id") != msg_id:
            fatal(f"MCP id mismatch for {method}: {response}")
        if "error" in response:
            fatal(f"MCP error from {method}: {response['error']}")
        result = response.get("result")
        if not isinstance(result, dict):
            fatal(f"MCP result from {method} is not an object: {response}")
        return result

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        self.send({"jsonrpc": "2.0", "method": method, "params": params or {}})

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        result = self.call("tools/call", {"name": name, "arguments": arguments})
        content = result.get("content")
        if not isinstance(content, list) or not content:
            fatal(f"{name} returned empty MCP content")
        body = json.loads(content[0]["text"])
        if not isinstance(body, dict):
            fatal(f"{name} returned non-object body: {body!r}")
        return body

    def close(self) -> None:
        if self.proc.stdin is not None and not self.proc.stdin.closed:
            self.proc.stdin.close()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()


def initialize_and_list(client: StdioClient, expected: set[str]) -> set[str]:
    init = client.call(
        "initialize",
        {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "caseforge-contract-smoke", "version": "1.0"},
        },
    )
    if "capabilities" not in init:
        fatal(f"initialize response missing capabilities: {init}")
    client.notify("notifications/initialized")
    tools = client.call("tools/list").get("tools")
    if not isinstance(tools, list):
        fatal(f"tools/list returned malformed tools: {tools!r}")
    names = {tool.get("name") for tool in tools if isinstance(tool, dict)}
    missing = expected - names
    if missing:
        fatal(f"MCP tools/list missing expected tools: {sorted(missing)}")
    return {name for name in names if isinstance(name, str)}


def check_release_binary_and_launchers() -> None:
    binary = release_binary()
    if not binary.is_file():
        fatal(f"release findevil-mcp missing: {binary}")
    if not os.access(binary, os.X_OK):
        fatal(f"release findevil-mcp is not executable: {binary}")
    for launcher in ("run-mcp-rust.sh", "run-mcp-python.sh"):
        path = REPO / "scripts" / launcher
        if not path.is_file() or not os.access(path, os.X_OK):
            fatal(f"MCP launcher missing or not executable: {path}")
    log(f"release findevil-mcp present: {binary}")


def rust_mcp_contract() -> None:
    env = contract_env()
    cases_root = case_store(env)
    cases_root.mkdir(parents=True, exist_ok=True)
    before = (
        {path.name for path in cases_root.iterdir() if path.is_dir()}
        if cases_root.is_dir()
        else set()
    )
    with tempfile.TemporaryDirectory(
        prefix="caseforge-contract-", dir=env["TMPDIR"]
    ) as td:
        temp = Path(td)
        evidence = temp / "contract.E01"
        evidence.write_bytes(b"CASEFORGE CONTRACT SYNTHETIC EVIDENCE\n")
        client = StdioClient(
            [str(REPO / "scripts" / "run-mcp-rust.sh")],
            cwd=temp,
            env=env,
        )
        try:
            names = initialize_and_list(client, {"case_open", "evtx_query"})
            handle = client.call_tool(
                "case_open",
                {"image_path": str(evidence), "label": "caseforge-contract-smoke"},
            )
        finally:
            client.close()
    case_id = handle.get("id")
    if not isinstance(case_id, str) or not case_id:
        fatal(f"case_open returned malformed handle: {handle}")
    case_dir = cases_root / case_id
    after = (
        {path.name for path in cases_root.iterdir() if path.is_dir()}
        if cases_root.is_dir()
        else set()
    )
    if not case_dir.is_dir() or case_id not in after - before:
        fatal(f"case_open did not create a fresh contained case dir: {case_dir}")
    check_runtime_case_no_external_path_leak(case_dir, handle, env)
    log(
        f"rust MCP launcher advertised {len(names)} tools and created .project-local case {case_id[:8]}..."
    )


def python_mcp_contract() -> None:
    if shutil.which("uv") is None:
        fatal("uv is required for scripts/run-mcp-python.sh")
    env = contract_env()
    with tempfile.TemporaryDirectory(
        prefix="caseforge-agent-contract-", dir=env["TMPDIR"]
    ) as td:
        temp = Path(td)
        client = StdioClient(
            [str(REPO / "scripts" / "run-mcp-python.sh")],
            cwd=temp,
            env=env,
        )
        try:
            names = initialize_and_list(client, {"audit_verify", "manifest_verify"})
            body = client.call_tool(
                "audit_verify", {"path": str(temp / "missing-audit.jsonl")}
            )
        finally:
            client.close()
    if body.get("ok") is not True or body.get("record_count") != 0:
        fatal(f"agent MCP audit_verify returned unexpected body: {body}")
    log(f"python MCP launcher advertised {len(names)} tools and audit_verify works")


def caseforge_verify_sample_run(caseforge_root: Path) -> None:
    cli = caseforge_root / "packages" / "caseforge-cli" / "dist" / "src" / "cli.js"
    if shutil.which("node") is None:
        fatal("node is required to run the CaseForge CLI")
    env = contract_env()
    with tempfile.TemporaryDirectory(
        prefix="caseforge-verify-contract-", dir=env["TMPDIR"]
    ) as td:
        env["VERDICT_DFIR_HOME"] = str(REPO)
        proc = subprocess.run(
            ["node", str(cli), "verify", str(SAMPLE_RUN)],
            cwd=td,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
    if proc.returncode != 0:
        print(proc.stdout, file=sys.stderr)
        print(proc.stderr, file=sys.stderr)
        fatal(f"CaseForge verify failed for {SAMPLE_RUN}")
    log("CaseForge CLI verifies docs/release-evidence/sample-run from an arbitrary CWD")


def external_host_paths(text: str, allowed_prefixes: tuple[str, ...] = ()) -> list[str]:
    matches = HOST_PATH_RE.findall(text) + WINDOWS_HOST_PATH_RE.findall(text)
    offenders: list[str] = []
    for match in matches:
        normalized = match.rstrip(".,);]")
        if "..." in normalized:
            continue
        if any(normalized.startswith(prefix) for prefix in allowed_prefixes):
            continue
        offenders.append(normalized)
    return sorted(set(offenders))


def sample_run_text_files() -> list[Path]:
    files: list[Path] = []
    for path in sorted(SAMPLE_RUN.rglob("*")):
        if path.is_file() and path.stat().st_size <= 1_000_000:
            files.append(path)
    return files


def check_sample_run_no_host_path_leak() -> None:
    missing = [
        name for name in REQUIRED_SAMPLE_FILES if not (SAMPLE_RUN / name).is_file()
    ]
    if missing:
        fatal(f"sample-run missing required files: {', '.join(missing)}")
    offenders: list[str] = []
    repo_abs = str(REPO)
    for path in sample_run_text_files():
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        if external_host_paths(text) or repo_abs in text:
            offenders.append(str(path.relative_to(SAMPLE_RUN)))
    if offenders:
        fatal(f"host machine path leaked into sample-run: {', '.join(offenders)}")
    log("sample-run has no /home, /Users, or current checkout absolute path leak")


def check_runtime_case_no_external_path_leak(
    case_dir: Path, handle: dict[str, Any], env: dict[str, str]
) -> None:
    allowed = (
        str(project_local(env)),
        str(case_dir),
    )
    offenders: list[str] = []
    handle_text = json.dumps(handle, sort_keys=True)
    offenders.extend(external_host_paths(handle_text, allowed))
    for path in case_dir.rglob("*"):
        if not path.is_file() or path.stat().st_size > 1_000_000:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        offenders.extend(external_host_paths(text, allowed))
    if offenders:
        fatal(f"fresh runtime case leaked external host paths: {', '.join(offenders)}")


def main() -> int:
    print("=" * 64)
    print("CaseForge <-> Dev VERDICT contract smoke")
    print("=" * 64)
    caseforge_root = resolve_caseforge_root()
    log(f"CaseForge root: {caseforge_root}")
    check_release_binary_and_launchers()
    rust_mcp_contract()
    python_mcp_contract()
    caseforge_verify_sample_run(caseforge_root)
    check_sample_run_no_host_path_leak()
    print("caseforge-contract-smoke: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
