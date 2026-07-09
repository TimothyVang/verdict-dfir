"""The deterministic engine's docker-exec MCP transport (scripts/verdict
--docker). This is the container analog of the SIFT ssh transport: the two MCP
servers run INSIDE the findevil-dfir container over ``docker exec -i`` instead
of ``ssh -i key GUEST``, with container paths (/workspace, /evidence).

These tests pin the transport selection + path mapping that make a deterministic
``scripts/verdict --docker`` run reach its MCP through the container rather than
degrading to an SSH-to-a-dead-host tool error.
"""

from __future__ import annotations

import importlib.util
import sys
import textwrap
import time
from pathlib import Path

import pytest

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402


def _load_docker_engine(monkeypatch: pytest.MonkeyPatch):
    """Load a FRESH copy of find_evil_auto with FIND_EVIL_DOCKER=1 so its
    import-time constants (GUEST_REPO, RUST_BIN, the docker argvs) resolve for
    the container backend, without mutating the already-imported module."""
    monkeypatch.setenv("FIND_EVIL_DOCKER", "1")
    monkeypatch.delenv("FIND_EVIL_LOCAL", raising=False)
    monkeypatch.delenv("FIND_EVIL_GUEST_REPO", raising=False)
    spec = importlib.util.spec_from_file_location(
        "find_evil_auto_docker", _SCRIPTS / "find_evil_auto.py"
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_docker_mode_selects_container_paths(monkeypatch) -> None:
    m = _load_docker_engine(monkeypatch)
    assert m.DOCKER_MODE is True
    assert m.LOCAL_MODE is False
    # /workspace is the repo bind mount; the Rust MCP binary lives under it.
    assert m.GUEST_REPO == "/workspace"
    assert m.RUST_BIN == "/workspace/target/release/findevil-mcp"


def test_docker_mcp_argv_mirrors_mcp_json_docker(monkeypatch) -> None:
    m = _load_docker_engine(monkeypatch)
    # Rust: launched directly (tool env baked into the image), matching
    # .mcp.json.docker's findevil-mcp args.
    assert m.DOCKER_RUST_ARGV == [
        "docker",
        "exec",
        "-i",
        "findevil-dfir",
        "/workspace/target/release/findevil-mcp",
    ]
    # Python: run under uv with cwd services/agent_mcp, matching
    # .mcp.json.docker's findevil-agent-mcp args.
    assert m.DOCKER_PY_ARGV == [
        "docker",
        "exec",
        "-i",
        "-w",
        "/workspace/services/agent_mcp",
        "findevil-dfir",
        "uv",
        "run",
        "python",
        "-m",
        "findevil_agent_mcp.server",
    ]


def test_docker_replay_command_is_container_binary(monkeypatch) -> None:
    # verify_finding re-runs this argv INSIDE the container to reproduce
    # output_sha256; it must be the container binary with no host/guest
    # sansforensics tool-path prefix (those paths do not exist in the container).
    m = _load_docker_engine(monkeypatch)
    assert m.rust_replay_command() == ["/workspace/target/release/findevil-mcp"]


def test_docker_container_name_is_overridable(monkeypatch) -> None:
    monkeypatch.setenv("FIND_EVIL_DOCKER_CONTAINER", "custom-ctr")
    m = _load_docker_engine(monkeypatch)
    assert m.DOCKER_CONTAINER == "custom-ctr"
    assert m.DOCKER_RUST_ARGV[3] == "custom-ctr"


def test_ssh_run_uses_docker_exec_in_docker_mode(monkeypatch) -> None:
    # ssh_run (guest-side mkdir/test/cat) must route through `docker exec -i
    # <ctr> bash -lc <cmd>` in docker mode — the container analog of ssh GUEST.
    captured: dict[str, list[str]] = {}

    class _Res:
        returncode = 0
        stdout = "ok\n"
        stderr = ""

    def _fake_run(argv, **kwargs):
        captured["argv"] = argv
        return _Res()

    monkeypatch.setattr(fea, "DOCKER_MODE", True)
    monkeypatch.setattr(fea, "LOCAL_MODE", False)
    monkeypatch.setattr(fea, "DOCKER_CONTAINER", "findevil-dfir")
    monkeypatch.setattr(fea.subprocess, "run", _fake_run)

    code, out, _ = fea.ssh_run("mkdir -p /workspace/tmp/auto-runs/case")
    assert code == 0
    assert captured["argv"][:5] == [
        "docker",
        "exec",
        "-i",
        "findevil-dfir",
        "bash",
    ]
    assert captured["argv"][-1] == "mkdir -p /workspace/tmp/auto-runs/case"


def test_missing_docker_binary_degrades_not_crashes(monkeypatch) -> None:
    # A host with no docker client must degrade to the same fast tool error as
    # an unreachable SIFT VM, not crash the engine at client construction.
    def _no_docker(*args, **kwargs):
        raise FileNotFoundError(2, "No such file or directory", "docker")

    monkeypatch.setattr(fea.subprocess, "Popen", _no_docker)

    client = fea.DockerMcpClient(["docker", "exec", "-i", "findevil-dfir", "x"], "rust-mcp")
    try:
        result = client.call_tool("case_open", {}, timeout=5.0)
        assert "_error" in result
        assert "docker" in result["_error"]["message"]
    finally:
        client.close()


# Responder for the large-response deadlock repro below. It reproduces the
# ROOT-CAUSE trigger deterministically without needing a real container:
#   1. emit one non-utf-8 byte on stderr — under strict decode this raised
#      UnicodeDecodeError (a ValueError) inside _drain_stderr, whose ``except``
#      swallowed it and KILLED the drain thread;
#   2. with the drain dead, flood stderr past the 64 KB pipe buffer;
#   3. only THEN read the JSON-RPC request and answer on stdout.
# With the drain dead (pre-fix) the flood fills the stderr pipe and the producer
# blocks on write(stderr) forever, so the response in step 3 never ships and the
# ``call`` times out — the same stall that, over ``docker exec``, is aggravated
# by stdcopy's single-goroutine stdout/stderr demux. With errors="replace" the
# drain survives step 1, keeps stderr drained, and the response ships promptly.
_DEADLOCK_RESPONDER = textwrap.dedent(
    """
    import sys, os, time, json
    os.write(2, b"\\xff\\n")          # non-utf-8 byte: kills a strict-decode drain
    time.sleep(0.3)                    # let the drain thread hit it
    os.write(2, b"E" * (1024 * 1024))  # flood the (now undrained) stderr pipe
    line = sys.stdin.readline()        # only reached if the drain kept up
    req = json.loads(line)
    resp = {"jsonrpc": "2.0", "id": req["id"], "result": {"ok": True, "rows": 2500}}
    os.write(1, (json.dumps(resp, separators=(",", ":")) + "\\n").encode())
    sys.stdout.flush()
    time.sleep(0.5)
    """
)


def test_docker_large_response_survives_stderr_backpressure() -> None:
    """A large response must ship even when the container floods stderr with a
    stray non-utf-8 byte in it. Pre-fix (strict decode) the drain thread died on
    that byte, stderr backed up, and the response never arrived — the run hung.
    errors="replace" keeps the drain alive so the response ships.

    Docker-free by design: DockerMcpClient just spawns whatever argv it is given,
    so a plain ``python3 -c`` producer exercises the exact reader/drain code the
    fix touches, deterministically and without a running container.
    """
    argv = [sys.executable, "-c", _DEADLOCK_RESPONDER]
    client = fea.DockerMcpClient(argv, "py-mcp")
    try:
        t0 = time.time()
        # Pre-fix this call blocks until the timeout; post-fix it returns in ~1s.
        result = client.call("tools/call", {"name": "x", "arguments": {}}, timeout=20.0)
        elapsed = time.time() - t0
        assert result == {"ok": True, "rows": 2500}
        # Comfortably under the timeout: proves the response shipped rather than
        # the caller being woken by a closing pipe near the deadline.
        assert elapsed < 15.0
    finally:
        client.close()


def test_ssh_client_keeps_strict_decode() -> None:
    """The fix is scoped to the docker path: the ssh/local clients keep strict
    utf-8 decode (errors defaults to None/"strict"), so their behavior is
    unchanged. Guards against the fix silently leaking onto the other spawns."""
    # DockerMcpClient opts into replacement …
    docker = fea.DockerMcpClient([sys.executable, "-c", "pass"], "probe")
    try:
        assert docker.proc is not None
        assert docker.proc.stdout.errors == "replace"
        assert docker.proc.stderr.errors == "replace"
    finally:
        docker.close()
    # … the local stdio client (same reader/drain, different spawn) does not.
    local = fea.StdioMcpClient("true", "probe")
    try:
        assert local.proc is not None
        assert local.proc.stdout.errors == "strict"
        assert local.proc.stderr.errors == "strict"
    finally:
        local.close()
