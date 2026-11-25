#!/usr/bin/env python3
"""Query Event ID 1102 rows from an EVTX via findevil-mcp (JSON lines stdout).

Usage:
  VERDICT_DFIR_HOME=/path/to/dev python3 scripts/evtx-1102-probe.py \\
    --evtx /path/to/file.evtx [--case-id UUID]

Prints a JSON object: {"ok": true, "rows": [...], "records_seen": N}
Never invents rows. Exit 0 on ok (including zero rows); exit 1 on transport/tool error.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import threading
import uuid
from pathlib import Path
from typing import Any


class _Mcp:
    def __init__(self, cmd: list[str], env: dict[str, str]) -> None:
        self.proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
            bufsize=1,
        )
        assert self.proc.stdin and self.proc.stdout
        self._id = 0
        self._lock = threading.Lock()
        # MCP initialize handshake
        self.call("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "caseforge-evtx-1102-probe", "version": "0.1"},
        })
        self.notify("notifications/initialized", {})

    def notify(self, method: str, params: dict[str, Any]) -> None:
        assert self.proc.stdin
        self.proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": method, "params": params}) + "\n")
        self.proc.stdin.flush()

    def call(self, method: str, params: dict[str, Any]) -> Any:
        with self._lock:
            self._id += 1
            req_id = self._id
            assert self.proc.stdin and self.proc.stdout
            self.proc.stdin.write(
                json.dumps({"jsonrpc": "2.0", "id": req_id, "method": method, "params": params}) + "\n"
            )
            self.proc.stdin.flush()
            while True:
                line = self.proc.stdout.readline()
                if not line:
                    raise RuntimeError("MCP server closed stdout")
                msg = json.loads(line)
                if msg.get("id") != req_id:
                    continue
                if "error" in msg:
                    raise RuntimeError(json.dumps(msg["error"]))
                return msg.get("result")

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        result = self.call("tools/call", {"name": name, "arguments": arguments})
        content = result.get("content") if isinstance(result, dict) else None
        if not isinstance(content, list) or not content:
            return result if isinstance(result, dict) else {"raw": result}
        text = content[0].get("text") if isinstance(content[0], dict) else None
        if isinstance(text, str):
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return {"text": text}
        return result if isinstance(result, dict) else {}

    def close(self) -> None:
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.proc.kill()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--evtx", required=True)
    ap.add_argument("--case-id", default="")
    args = ap.parse_args()
    evtx = Path(args.evtx).expanduser().resolve()
    if not evtx.is_file():
        print(json.dumps({"ok": False, "error": f"evtx not found: {evtx}"}))
        return 1

    dfir = os.environ.get("VERDICT_DFIR_HOME", "")
    if not dfir or not Path(dfir, "scripts", "run-mcp-rust.sh").is_file():
        print(json.dumps({"ok": False, "error": "set VERDICT_DFIR_HOME to toolkit with scripts/run-mcp-rust.sh"}))
        return 1

    launcher = str(Path(dfir) / "scripts" / "run-mcp-rust.sh")
    env = os.environ.copy()
    env["VERDICT_DFIR_HOME"] = dfir
    client = _Mcp(["bash", launcher], env)
    try:
        case_id = args.case_id.strip()
        if not case_id:
            opened = client.call_tool("case_open", {"image_path": str(evtx)})
            case_id = str(opened.get("id") or opened.get("case_id") or "")
            if not case_id:
                print(json.dumps({"ok": False, "error": "case_open missing id", "opened": opened}))
                return 1
        out = client.call_tool(
            "evtx_query",
            {"case_id": case_id, "evtx_path": str(evtx), "eids": [1102], "limit": 100},
        )
        rows_in = out.get("rows") if isinstance(out, dict) else None
        rows: list[dict[str, Any]] = []
        if isinstance(rows_in, list):
            for r in rows_in:
                if not isinstance(r, dict):
                    continue
                eid = r.get("event_id") if "event_id" in r else r.get("EventID")
                try:
                    eid_n = int(eid)  # type: ignore[arg-type]
                except (TypeError, ValueError):
                    continue
                if eid_n != 1102:
                    continue
                rows.append(
                    {
                        "event_id": 1102,
                        "record_id": r.get("record_id", r.get("RecordID")),
                        "channel": r.get("channel", r.get("Channel", "Security")),
                        "ts": r.get("ts", r.get("timestamp")),
                    }
                )
        records_seen = out.get("records_seen") if isinstance(out, dict) else None
        print(
            json.dumps(
                {
                    "ok": True,
                    "case_id": case_id,
                    "records_seen": records_seen,
                    "row_count": len(rows),
                    "rows": rows,
                }
            )
        )
        return 0
    except Exception as exc:  # noqa: BLE001 — surface to caseforge as JSON
        print(json.dumps({"ok": False, "error": str(exc)}))
        return 1
    finally:
        client.close()


if __name__ == "__main__":
    raise SystemExit(main())
