#!/usr/bin/env python3
"""End-to-end smoke for the findevil-mcp Rust MCP server.

Spawns the Rust binary as a subprocess, completes the MCP initialize
handshake, lists tools, and calls each one. Mirrors the Python
agent-mcp-smoke.py pattern.

Under Amendment A2 this is the missing piece — without the stdio
server, Claude Code can't reach case_open / evtx_query / prefetch_parse
through the typed MCP surface. This script proves the wire works.

Usage::

    python scripts/rust-mcp-smoke.py [--release]

The default uses the debug binary under ``target/``;
``--release`` switches to the release binary. If ``CARGO_TARGET_DIR`` is set,
the binary is resolved from that directory instead of the repository ``target/``.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from queue import Empty, Queue
from typing import Any

REPO = Path(__file__).resolve().parent.parent


def fatal(msg: str) -> None:
    print(f"\n[FAIL] {msg}", file=sys.stderr)
    sys.exit(1)


def log(msg: str) -> None:
    print(f"  {msg}")


class StdioClient:
    def __init__(self, cmd: list[str]) -> None:
        env = os.environ.copy()
        # Quiet mode — keep stderr from cluttering terminal during smoke.
        env.setdefault("RUST_LOG", "warn")
        self.proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            text=True,
            encoding="utf-8",
            bufsize=1,
        )
        self._next_id = 1
        self._queue: Queue[str | None] = Queue()
        threading.Thread(target=self._reader, daemon=True).start()

    def _reader(self) -> None:
        try:
            assert self.proc.stdout is not None
            for line in iter(self.proc.stdout.readline, ""):
                if not line:
                    break
                self._queue.put(line)
        finally:
            self._queue.put(None)

    def send(self, message: dict[str, Any]) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.write(json.dumps(message, separators=(",", ":")) + "\n")
        self.proc.stdin.flush()

    def read(self, timeout_s: float = 30.0) -> dict[str, Any]:
        deadline = time.monotonic() + timeout_s
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("read timed out")
            try:
                line = self._queue.get(timeout=remaining)
            except Empty:
                continue
            if line is None:
                raise RuntimeError("server closed stdout")
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
            {
                "jsonrpc": "2.0",
                "id": msg_id,
                "method": method,
                "params": params or {},
            }
        )
        resp = self.read()
        if resp.get("id") != msg_id:
            fatal(f"id mismatch: sent {msg_id}, got {resp.get('id')}")
        if "error" in resp:
            fatal(f"server error on {method}: {resp['error']}")
        return resp["result"]

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        result = self.call("tools/call", {"name": name, "arguments": arguments})
        content = result.get("content") or []
        if not content:
            fatal(f"empty content from {name}")
        body = json.loads(content[0]["text"])
        meta = result.get("_meta", {})
        # Tools should attach SHA-256 of canonical output to _meta.
        if "output_sha256" not in meta or len(meta["output_sha256"]) != 64:
            fatal(f"{name} missing _meta.output_sha256")
        return body

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        self.send({"jsonrpc": "2.0", "method": method, "params": params or {}})

    def close(self) -> None:
        if self.proc.stdin is not None and not self.proc.stdin.closed:
            self.proc.stdin.close()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--release", action="store_true")
    p.add_argument(
        "--real-evidence",
        action="store_true",
        help=(
            "After the standard error-path tests, drive evtx_query against "
            "fixtures/single-evtx/Security.evtx (run scripts/fetch-nist-fixture.sh "
            "to populate). Skipped silently when the fixture is absent so the "
            "smoke harness keeps working offline."
        ),
    )
    args = p.parse_args()

    bin_dir = "release" if args.release else "debug"
    bin_name = "findevil-mcp.exe" if sys.platform == "win32" else "findevil-mcp"
    target_root = Path(os.environ.get("CARGO_TARGET_DIR", REPO / "target"))
    if not target_root.is_absolute():
        target_root = REPO / target_root
    binary = target_root / bin_dir / bin_name
    if not binary.is_file() and sys.platform != "win32":
        windows_binary = binary.with_name("findevil-mcp.exe")
        if windows_binary.is_file():
            binary = windows_binary

    if not binary.is_file():
        fatal(
            f"binary not built: {binary}\n"
            f"  build: cargo build {'--release' if args.release else ''} -p findevil-mcp"
        )

    print("=" * 60)
    print("Find Evil! — findevil-mcp (Rust) end-to-end smoke")
    print("=" * 60)
    log(f"binary: {binary}")

    client = StdioClient([str(binary)])
    try:
        # ---- 1. initialize handshake ------------------------------------
        log("initialize handshake...")
        init = client.call(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "rust-mcp-smoke", "version": "1.0"},
            },
        )
        if init.get("protocolVersion") != "2024-11-05":
            fatal(f"unexpected protocol version: {init}")
        if init.get("serverInfo", {}).get("name") != "findevil-mcp":
            fatal(f"unexpected serverInfo: {init}")
        client.notify("notifications/initialized")
        log(
            f"  -> protocol={init['protocolVersion']} server={init['serverInfo']['name']}"
        )

        # ---- 2. tools/list -----------------------------------------------
        log("tools/list...")
        tools_resp = client.call("tools/list")
        names = sorted(t["name"] for t in tools_resp["tools"])
        expected = sorted(
            [
                "case_open",
                "disk_mount",
                "disk_extract_artifacts",
                "disk_unmount",
                "evtx_query",
                "prefetch_parse",
                "mft_timeline",
                "registry_query",
                "yara_scan",
                "usnjrnl_query",
                "hayabusa_scan",
                "sysmon_network_query",
                "zeek_summary",
                "pcap_triage",
                "vol_pslist",
                "vol_malfind",
                "vol_psscan",
                "vol_psxview",
                "vol_run",
                "ez_parse",
                "plaso_parse",
                "mac_triage",
                "cloud_audit",
                "journalctl_query",
                "login_accounting",
                "ausearch",
                "nfdump_query",
                "suricata_eve",
                "indx_parse",
                "vel_collect",
                "browser_history",
            ]
        )
        if names != expected:
            fatal(f"tool mismatch: {names} != {expected}")
        # Each tool must advertise an inputSchema dict and annotations.
        for tool in tools_resp["tools"]:
            schema = tool["inputSchema"]
            if not isinstance(schema, dict) or "type" not in schema:
                fatal(f"{tool['name']} schema malformed: {schema}")
            ann = tool.get("annotations")
            if not isinstance(ann, dict):
                fatal(f"{tool['name']} annotations missing or malformed: {ann}")
            if not isinstance(ann.get("title"), str) or not ann["title"]:
                fatal(f"{tool['name']} annotations.title missing or empty")
            for hint in (
                "readOnlyHint",
                "destructiveHint",
                "idempotentHint",
                "openWorldHint",
            ):
                if not isinstance(ann.get(hint), bool):
                    fatal(f"{tool['name']} annotations.{hint} missing or non-bool")
        log(f"  -> {len(names)} tools advertised with JSON Schema + annotations")

        # ---- 3. case_open -----------------------------------------------
        log("case_open: register synthetic evidence...")
        workdir = REPO / "tmp" / "rust-smoke"
        workdir.mkdir(parents=True, exist_ok=True)
        evidence = workdir / "evidence.E01"
        evidence.write_bytes(
            b"FAKE EVIDENCE BYTES for the rust-mcp-smoke harness. "
            b"Real .e01 round-trip would land in tmp/rust-smoke/."
        )
        case_home = workdir / "home"
        case_home.mkdir(exist_ok=True)
        os.environ["FINDEVIL_HOME"] = str(case_home)

        handle = client.call_tool(
            "case_open",
            {"image_path": str(evidence), "label": "rust-mcp-smoke"},
        )
        if not (
            isinstance(handle.get("id"), str)
            and len(handle.get("image_hash", "")) == 64
        ):
            fatal(f"case_open returned malformed handle: {handle}")
        log(
            f"  -> case_id={handle['id'][:8]}... "
            f"image_hash={handle['image_hash'][:12]}... "
            f"size={handle['image_size_bytes']}B"
        )

        def expect_error_response(
            method: str,
            params: dict[str, Any],
            substr: str,
            expected_code: int = -32603,
        ) -> None:
            """Call the server raw and assert the response is a JSON-RPC error
            with the expected code (default -32603 internal). Pass
            expected_code=-32602 for user-input (invalid_params) errors.
            """
            msg_id = client._next_id  # noqa: SLF001 — test-only access
            client._next_id += 1  # noqa: SLF001
            client.send(
                {"jsonrpc": "2.0", "id": msg_id, "method": method, "params": params}
            )
            resp = client.read()
            if resp.get("id") != msg_id:
                fatal(f"id mismatch: {resp}")
            if "error" not in resp:
                fatal(f"expected error, got success: {resp}")
            actual_code = resp["error"].get("code")
            if actual_code != expected_code:
                fatal(f"expected error code {expected_code}, got {actual_code}: {resp}")
            if substr not in resp["error"].get("message", ""):
                fatal(f"error message missing {substr!r}: {resp}")

        # ---- 4. disk_* mock path ----------------------------------------
        log("disk_mount/extract/unmount: mock session-resource path...")
        mount_root = workdir / "mock-mounted-disk"
        (mount_root / "Windows" / "Prefetch").mkdir(parents=True, exist_ok=True)
        (mount_root / "Windows" / "System32" / "config").mkdir(
            parents=True, exist_ok=True
        )
        (mount_root / "$MFT").write_bytes(b"mft smoke bytes")
        (mount_root / "Windows" / "Prefetch" / "CMD.EXE-12345678.pf").write_bytes(b"pf")
        (mount_root / "Windows" / "System32" / "config" / "SOFTWARE").write_bytes(
            b"hive"
        )
        mounted = client.call_tool(
            "disk_mount",
            {
                "case_id": handle["id"],
                "image_path": str(evidence),
                "mount_point": str(mount_root),
                "mode": "mock",
            },
        )
        if mounted.get("status") != "mounted" or not mounted.get("mount_id"):
            fatal(f"disk_mount mock returned malformed output: {mounted}")
        extracted = client.call_tool(
            "disk_extract_artifacts",
            {
                "case_id": handle["id"],
                "mount_id": mounted["mount_id"],
                "limit": 20,
            },
        )
        classes = {a.get("artifact_class") for a in extracted.get("artifacts", [])}
        if not {"mft", "prefetch", "registry"}.issubset(classes):
            fatal(f"disk_extract_artifacts missed expected classes: {extracted}")
        unmounted = client.call_tool(
            "disk_unmount",
            {"case_id": handle["id"], "mount_id": mounted["mount_id"], "mode": "mock"},
        )
        if unmounted.get("status") != "unmounted":
            fatal(f"disk_unmount mock returned malformed output: {unmounted}")
        log(
            f"  -> extracted {len(extracted.get('artifacts', []))} artifacts; "
            "ledger updated"
        )

        # ---- 5. evtx_query (error path) ---------------------------------
        log("evtx_query: missing-file error path (-32602)...")
        expect_error_response(
            "tools/call",
            {
                "name": "evtx_query",
                "arguments": {
                    "case_id": handle["id"],
                    "evtx_path": str(workdir / "nope.evtx"),
                },
            },
            "evtx file not found",
            expected_code=-32602,
        )
        log("  -> -32602 invalid_params with 'evtx file not found' as expected")

        # ---- 5. prefetch_parse (error path) -----------------------------
        log("prefetch_parse: missing-file error path (-32602)...")
        expect_error_response(
            "tools/call",
            {
                "name": "prefetch_parse",
                "arguments": {
                    "case_id": handle["id"],
                    "prefetch_path": str(workdir / "nope.pf"),
                },
            },
            "prefetch file not found",
            expected_code=-32602,
        )
        log("  -> -32602 invalid_params with 'prefetch file not found' as expected")

        # ---- 6. mft_timeline (error path) -------------------------------
        log("mft_timeline: missing-file error path (-32602)...")
        expect_error_response(
            "tools/call",
            {
                "name": "mft_timeline",
                "arguments": {
                    "case_id": handle["id"],
                    "mft_path": str(workdir / "nope.mft"),
                },
            },
            "MFT file not found",
            expected_code=-32602,
        )
        log("  -> -32602 invalid_params with 'MFT file not found' as expected")

        # ---- 7. mft_timeline invalid-time-filter (-32602) ---------------
        log("mft_timeline: invalid time filter (-32602)...")
        # Use the temp evidence file as the mft_path — the parser will try
        # to open it and may fail later, but the time-filter validation
        # runs FIRST and returns -32602 before any parsing happens.
        expect_error_response(
            "tools/call",
            {
                "name": "mft_timeline",
                "arguments": {
                    "case_id": handle["id"],
                    "mft_path": str(evidence),
                    "since_iso": "not-a-real-time",
                },
            },
            "invalid time filter",
            expected_code=-32602,
        )
        log("  -> -32602 invalid_params with 'invalid time filter' as expected")

        # ---- 8. registry_query (error path) -----------------------------
        log("registry_query: missing-file error path (-32602)...")
        expect_error_response(
            "tools/call",
            {
                "name": "registry_query",
                "arguments": {
                    "case_id": handle["id"],
                    "hive_path": str(workdir / "nope.dat"),
                    "key_path": "",
                },
            },
            "registry hive not found",
            expected_code=-32602,
        )
        log("  -> -32602 invalid_params with 'registry hive not found' as expected")

        # ---- 9. yara_scan (error path) ----------------------------------
        log("yara_scan: missing-target error path (-32602)...")
        expect_error_response(
            "tools/call",
            {
                "name": "yara_scan",
                "arguments": {
                    "case_id": handle["id"],
                    "target_path": str(workdir / "nope.bin"),
                    "rules_path": str(workdir / "nope.yar"),
                },
            },
            "YARA target not found",
            expected_code=-32602,
        )
        log("  -> -32602 invalid_params with 'YARA target not found' as expected")

        # ---- 10. usnjrnl_query (error path) -----------------------------
        log("usnjrnl_query: missing-file error path (-32602)...")
        expect_error_response(
            "tools/call",
            {
                "name": "usnjrnl_query",
                "arguments": {
                    "case_id": handle["id"],
                    "usnjrnl_path": str(workdir / "nope.j"),
                },
            },
            "UsnJrnl file not found",
            expected_code=-32602,
        )
        log("  -> -32602 invalid_params with 'UsnJrnl file not found' as expected")

        # ---- 11. hayabusa_scan (error path) -----------------------------
        log("hayabusa_scan: missing-evtx-dir error path (-32602)...")
        expect_error_response(
            "tools/call",
            {
                "name": "hayabusa_scan",
                "arguments": {
                    "case_id": handle["id"],
                    "evtx_dir": str(workdir / "nope-evtx-dir"),
                },
            },
            "evtx_dir not found",
            expected_code=-32602,
        )
        log("  -> -32602 invalid_params with 'evtx_dir not found' as expected")

        log("sysmon_network_query: missing-file error path (-32602)...")
        expect_error_response(
            "tools/call",
            {
                "name": "sysmon_network_query",
                "arguments": {
                    "case_id": handle["id"],
                    "evtx_path": str(workdir / "missing-sysmon.evtx"),
                },
            },
            "sysmon evtx file not found",
            expected_code=-32602,
        )
        log("  -> -32602 invalid_params with 'sysmon evtx file not found' as expected")

        log("zeek_summary: missing-path error path (-32602)...")
        expect_error_response(
            "tools/call",
            {
                "name": "zeek_summary",
                "arguments": {
                    "case_id": handle["id"],
                    "zeek_path": str(workdir / "missing-zeek"),
                },
            },
            "zeek path not found",
            expected_code=-32602,
        )
        log("  -> -32602 invalid_params with 'zeek path not found' as expected")

        log("pcap_triage: missing-file error path (-32602)...")
        expect_error_response(
            "tools/call",
            {
                "name": "pcap_triage",
                "arguments": {
                    "case_id": handle["id"],
                    "pcap_path": str(workdir / "missing.pcap"),
                },
            },
            "pcap file not found",
            expected_code=-32602,
        )
        log("  -> -32602 invalid_params with 'pcap file not found' as expected")

        # ---- 12. vol_pslist (error path) --------------------------------
        log("vol_pslist: missing-image error path (-32602)...")
        expect_error_response(
            "tools/call",
            {
                "name": "vol_pslist",
                "arguments": {
                    "case_id": handle["id"],
                    "memory_path": str(workdir / "nope.mem"),
                },
            },
            "memory image not found",
            expected_code=-32602,
        )
        log("  -> -32602 invalid_params with 'memory image not found' as expected")

        # ---- 13. vol_malfind (error path) -------------------------------
        log("vol_malfind: missing-image error path (-32602)...")
        expect_error_response(
            "tools/call",
            {
                "name": "vol_malfind",
                "arguments": {
                    "case_id": handle["id"],
                    "memory_path": str(workdir / "nope.mem"),
                },
            },
            "memory image not found",
            expected_code=-32602,
        )
        log("  -> -32602 invalid_params with 'memory image not found' as expected")

        # ---- 14a. vol_psscan (error path -32602) ------------------------
        log("vol_psscan: missing-image error path (-32602)...")
        expect_error_response(
            "tools/call",
            {
                "name": "vol_psscan",
                "arguments": {
                    "case_id": handle["id"],
                    "memory_path": str(workdir / "nope.mem"),
                },
            },
            "memory image not found",
            expected_code=-32602,
        )
        log("  -> -32602 invalid_params with 'memory image not found' as expected")

        # ---- 14b. vol_psxview (error path -32602) ------------------------
        log("vol_psxview: missing-image error path (-32602)...")
        expect_error_response(
            "tools/call",
            {
                "name": "vol_psxview",
                "arguments": {
                    "case_id": handle["id"],
                    "memory_path": str(workdir / "nope.mem"),
                },
            },
            "memory image not found",
            expected_code=-32602,
        )
        log("  -> -32602 invalid_params with 'memory image not found' as expected")

        # ---- 14c. vel_collect invalid-artifact-name (-32602) -------------
        log("vel_collect: invalid artifact name (-32602)...")
        expect_error_response(
            "tools/call",
            {
                "name": "vel_collect",
                "arguments": {
                    "case_id": handle["id"],
                    "artifact": "Has Spaces",
                },
            },
            "invalid artifact name",
            expected_code=-32602,
        )
        log("  -> -32602 invalid_params with 'invalid artifact name' as expected")

        # ---- 15. real-evidence smoke (opt-in via --real-evidence) -------
        if args.real_evidence:
            log("real-evidence: looking for fixtures/single-evtx/Security.evtx...")
            fixture = REPO / "fixtures" / "single-evtx" / "Security.evtx"
            if not fixture.is_file():
                log(
                    f"  -> fixture absent at {fixture} — skipping. "
                    "Run scripts/fetch-nist-fixture.sh to populate."
                )
            else:
                size_kb = fixture.stat().st_size / 1024
                log(f"  -> fixture present ({size_kb:.1f} KiB); driving evtx_query...")
                body = client.call_tool(
                    "evtx_query",
                    {
                        "case_id": handle["id"],
                        "evtx_path": str(fixture),
                        "limit": 25,
                    },
                )
                rows = body.get("rows") or []
                seen = body.get("records_seen", 0)
                if not isinstance(rows, list):
                    fatal(f"evtx_query rows not a list: {body!r}")
                if seen <= 0:
                    fatal(
                        f"evtx_query saw no records on a real fixture — "
                        f"the file is probably empty or not a real EVTX: {body!r}"
                    )
                log(
                    f"  -> evtx_query returned {len(rows)} rows "
                    f"(of {seen} seen); parse_errors={body.get('parse_errors', 0)}"
                )

        # ---- 16. unknown tool dispatch is rejected ----------------------
        log("unknown tool: expect JSON-RPC error...")
        client.send(
            {
                "jsonrpc": "2.0",
                "id": 9999,
                "method": "tools/call",
                "params": {"name": "no_such_tool", "arguments": {}},
            }
        )
        resp = client.read()
        if "error" not in resp or resp["error"]["code"] != -32602:
            fatal(f"expected -32602 invalid_params, got: {resp}")
        log(f"  -> rejected with -32602: {resp['error']['message'][:60]}...")

        print()
        print("=" * 60)
        print("OK — Rust MCP server speaks 2024-11-05 over stdio.")
        print(f"  All {len(expected)} tools advertised; core error paths well-formed.")
        print("=" * 60)
        return 0
    finally:
        client.close()
        os.environ.pop("FINDEVIL_HOME", None)


if __name__ == "__main__":
    sys.exit(main())
