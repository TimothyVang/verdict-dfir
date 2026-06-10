"""Concurrency tests for the stdio MCP client in ``scripts/find_evil_auto.py``.

Parallel investigation/verification multiplexes many tool calls over a single
stdio connection, so the client MUST be thread-safe and route each JSON-RPC
response to the caller whose request id it answers. These tests import the engine
module (the same pattern as ``test_memory_hooks.py``) and exercise the actual
``StdioMcpClient`` with a fake stdio server:

- C1: N concurrent ``call()``s each receive the response for their OWN request
      id, even when the server emits responses OUT OF ORDER.
- C2: server EOF (stdout closed) mid-wait raises in every blocked caller (no hang).
- C3: a single sequential ``call()`` still returns its result (no regression).
"""

from __future__ import annotations

import json
import sys
import threading
import time
from pathlib import Path
from queue import Queue

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402


class _FakeStdin:
    """Captures whole-request writes from the client (one JSON line per write)."""

    def __init__(self, on_request) -> None:
        self._on_request = on_request
        self._lock = threading.Lock()
        self.closed = False

    def write(self, data: str) -> int:
        with self._lock:
            self._on_request(data)
        return len(data)

    def flush(self) -> None:
        pass

    def close(self) -> None:
        self.closed = True


class _FakeStdout:
    """Blocking line source fed by the test server; ``""`` signals EOF."""

    def __init__(self) -> None:
        self._q: Queue[str] = Queue()

    def feed(self, line: str) -> None:
        self._q.put(line)

    def readline(self) -> str:
        return self._q.get()


class _FakeProc:
    def __init__(self, stdin: _FakeStdin, stdout: _FakeStdout) -> None:
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = _FakeStdout()

    def wait(self, timeout: float | None = None) -> int:
        return 0

    def kill(self) -> None:
        pass

    def poll(self) -> int | None:
        return None


class _Server:
    """Records incoming requests; lets the test feed responses on demand."""

    def __init__(self) -> None:
        self.requests: list[dict] = []
        self._lock = threading.Lock()
        self.stdout = _FakeStdout()
        self.stdin = _FakeStdin(self._on_request)
        self.proc = _FakeProc(self.stdin, self.stdout)

    def _on_request(self, data: str) -> None:
        for line in data.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            with self._lock:
                self.requests.append(msg)

    def wait_for(self, n: int, timeout: float = 5.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                if len(self.requests) >= n:
                    return True
            time.sleep(0.01)
        with self._lock:
            return len(self.requests) >= n

    def respond(self, msg_id: object, result: dict) -> None:
        self.stdout.feed(json.dumps({"jsonrpc": "2.0", "id": msg_id, "result": result}) + "\n")

    def close_stdout(self) -> None:
        self.stdout.feed("")


def _make_client(monkeypatch, server: _Server) -> fea.StdioMcpClient:
    monkeypatch.setattr(fea.subprocess, "Popen", lambda *a, **k: server.proc)
    return fea.StdioMcpClient("ignored-command", "test")


def test_concurrent_calls_match_by_id(monkeypatch) -> None:
    server = _Server()
    client = _make_client(monkeypatch, server)
    n = 8
    results: dict[int, dict] = {}
    errors: list[Exception] = []
    start = threading.Barrier(n)

    def worker(v: int) -> None:
        try:
            start.wait()
            results[v] = client.call("echo", {"n": v}, timeout=5.0)
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(v,)) for v in range(n)]
    for t in threads:
        t.start()

    assert server.wait_for(n), f"only {len(server.requests)} requests arrived"
    # Respond OUT OF ORDER (reverse id) — only id-matching can stay correct.
    for msg in sorted(server.requests, key=lambda m: m["id"], reverse=True):
        server.respond(msg["id"], {"n": msg["params"]["n"]})

    for t in threads:
        t.join(timeout=10)
    assert not errors, f"unexpected errors: {errors}"
    for v in range(n):
        assert results.get(v) == {"n": v}, f"worker {v} got {results.get(v)!r}"


def test_server_eof_wakes_every_waiter(monkeypatch) -> None:
    server = _Server()
    client = _make_client(monkeypatch, server)
    n = 4
    errors: list[Exception] = []
    start = threading.Barrier(n)

    def worker(v: int) -> None:
        try:
            start.wait()
            client.call("echo", {"n": v}, timeout=5.0)
        except RuntimeError as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(v,)) for v in range(n)]
    for t in threads:
        t.start()

    assert server.wait_for(n)
    server.close_stdout()
    for t in threads:
        t.join(timeout=10)
    assert len(errors) == n, f"expected {n} errors, got {len(errors)}: {errors}"


def test_sequential_call_returns_result(monkeypatch) -> None:
    server = _Server()
    client = _make_client(monkeypatch, server)
    done = threading.Event()
    box: dict[str, dict] = {}

    def caller() -> None:
        box["r"] = client.call("ping", {"n": 42}, timeout=5.0)
        done.set()

    t = threading.Thread(target=caller)
    t.start()
    assert server.wait_for(1)
    server.respond(server.requests[0]["id"], {"n": 42})
    assert done.wait(10)
    assert box["r"] == {"n": 42}
