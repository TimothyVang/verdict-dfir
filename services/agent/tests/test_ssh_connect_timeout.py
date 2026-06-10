"""Regression: an unreachable SIFT VM must fail fast, not hang forever.

A disk run reached the SIFT-backed phase while the VM was down; ssh had no
ConnectTimeout, so it blocked on connect() with no upper bound and deadlocked
the whole investigation. SSH_CONNECT_OPTS now bounds the connect (and tears a
session down after missed keepalives) on every ssh invocation.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402


def test_connect_opts_bound_the_connection() -> None:
    # Guard against anyone dropping the connect bound back to an unbounded ssh.
    assert "ConnectTimeout=10" in fea.SSH_CONNECT_OPTS
    assert "ServerAliveCountMax=3" in fea.SSH_CONNECT_OPTS


def test_missing_ssh_binary_degrades_not_crashes(monkeypatch) -> None:
    # The L1 devbase has no ssh client. Spawning the tunnel must degrade to
    # the same fast tool error as an unreachable VM — not crash the engine
    # with an unhandled FileNotFoundError at client construction.
    def _no_ssh(*args, **kwargs):
        raise FileNotFoundError(2, "No such file or directory", "ssh")

    monkeypatch.setattr(fea.subprocess, "Popen", _no_ssh)

    client = fea.SshMcpClient("true", "rust-mcp")
    try:
        result = client.call_tool("case_open", {}, timeout=5.0)
        assert "_error" in result
        assert "ssh" in result["_error"]["message"]
    finally:
        client.close()


def test_unreachable_sift_returns_fast_not_hang(monkeypatch) -> None:
    # TEST-NET-1 (RFC 5737) is guaranteed unroutable, so ssh exercises the
    # ConnectTimeout path. With the bound, the client gives up in ~10s and the
    # call surfaces an error; without it, ssh would block far past this window.
    monkeypatch.setattr(fea, "GUEST_IP", "192.0.2.1")
    monkeypatch.setattr(fea, "GUEST_USER", "nobody")

    start = time.monotonic()
    client = fea.SshMcpClient("true", "rust-mcp")
    try:
        # call_tool swallows the RuntimeError and returns an _error dict; the
        # point is that it RETURNS (doesn't hang) well within the 90s timeout.
        result = client.call_tool("case_open", {}, timeout=90.0)
        assert "_error" in result
    finally:
        client.close()
    elapsed = time.monotonic() - start
    assert elapsed < 45, f"took {elapsed:.0f}s — ssh connect was not bounded"
