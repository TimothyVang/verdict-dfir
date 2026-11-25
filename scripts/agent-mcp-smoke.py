#!/usr/bin/env python3
"""End-to-end smoke for the findevil-agent-mcp Python MCP server.

Two modes:

**Synthetic** (default): spawns the server as a subprocess (matching
the ``.mcp.json`` boot recipe) and drives a full investigation
through 11 of 12 MCP tools with hand-crafted Findings. This is the
demo flow under Amendment A2/A3 minus an actual disk image —
exercises the same crypto/ACH/memory/ACP paths the live demo
will. Skipped: ``verify_finding`` (needs the Rust DFIR MCP server).
The A3 additions (``memory_remember`` + ``memory_recall`` cold→warm
transition, ``pool_handoff`` IBM-ACP envelope) and the expert-miss
ledger capture are exercised in steps 4a-4g.

**Real-evidence** (``--real-evidence [<auto-run-dir>]``): replays a
real ``find-evil-auto`` case directory through the agent_mcp surface.
Loads its ``verdict.json`` + ``audit.jsonl`` + ``run.manifest.json``,
splits findings by ``pool_origin``, and pushes them through the
ACH stack (audit_verify → manifest_verify → detect_contradictions
→ judge_findings → correlate_findings). The point is regression
coverage: prove the agent_mcp tools still parse production output
shape after any schema change. ``verify_finding`` is skipped — it
needs the Rust DFIR server. If no path is given, the latest dir
under ``tmp/auto-runs/`` is used.

Usage::

    uv run --directory services/agent_mcp python ../../scripts/agent-mcp-smoke.py
    uv run --directory services/agent_mcp python ../../scripts/agent-mcp-smoke.py --real-evidence
    uv run --directory services/agent_mcp python ../../scripts/agent-mcp-smoke.py --real-evidence tmp/auto-runs/auto-<uuid>

Exit code: 0 on full success, 1 on the first assertion failure.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from queue import Empty, Queue
from typing import Any

REPO = Path(__file__).resolve().parent.parent
AGENT_MCP_DIR = REPO / "services" / "agent_mcp"

# The fact-fidelity gate is production-default-ON (Stage A). This smoke exercises
# the audit/crypto chain over hand-crafted synthetic Findings, not the gate, so
# disable it here — also propagated to the spawned MCP server via os.environ.copy().
os.environ.setdefault("FIND_EVIL_REQUIRE_ASSERTED_VALUES", "0")


def fatal(msg: str) -> None:
    print(f"\n[FAIL] {msg}", file=sys.stderr)
    sys.exit(1)


def log(msg: str) -> None:
    print(f"  {msg}")


# ---------------------------------------------------------------------------
# Stdio JSON-RPC harness — line-delimited JSON, NOT LSP framing.
# ---------------------------------------------------------------------------


class StdioClient:
    def __init__(self, cmd: list[str]) -> None:
        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"
        env["FINDEVIL_LOG_LEVEL"] = "WARNING"
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
        self._t = threading.Thread(target=self._reader, daemon=True)
        self._t.start()

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
        if (
            isinstance(body, dict)
            and "error" in body
            and isinstance(body["error"], dict)
        ):
            fatal(f"{name} returned error: {body['error']}")
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


# ---------------------------------------------------------------------------
# The smoke flow.
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    from datetime import UTC, datetime

    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _finding(
    *,
    case_id: str,
    finding_id: str,
    tool_call_id: str,
    artifact: str,
    description: str,
    confidence: str,
    pool: str,
    mitre: str | None = None,
) -> dict[str, Any]:
    return {
        "case_id": case_id,
        "finding_id": finding_id,
        "tool_call_id": tool_call_id,
        "artifact_path": artifact,
        "confidence": confidence,
        "description": description,
        "mitre_technique": mitre,
        "pool_origin": pool,
    }


def _verifier_actions(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    actions: list[dict[str, Any]] = []
    for finding in findings:
        action = str(finding.get("verifier_action") or "approved")
        actions.append(
            {
                "case_id": str(finding.get("case_id") or "smoke-case"),
                "finding_id": str(finding["finding_id"]),
                "action": action,
                "reason": "smoke verifier action supplied before judge_findings",
            }
        )
    return actions


def latest_auto_run() -> Path | None:
    base = REPO / "tmp" / "auto-runs"
    if not base.is_dir():
        return None
    candidates = sorted(
        (p for p in base.glob("auto-*") if (p / "verdict.json").is_file()),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return candidates[0] if candidates else None


def real_evidence_flow(client: StdioClient, case_dir: Path) -> int:
    """Drive the agent_mcp surface against a real find-evil-auto case dir.

    Skips verify_finding (needs Rust DFIR server) — demonstrated in
    the synthetic flow's siblings.
    """
    audit_path = case_dir / "audit.jsonl"
    manifest_path = case_dir / "run.manifest.json"
    verdict_path = case_dir / "verdict.json"
    for required in (audit_path, manifest_path, verdict_path):
        if not required.is_file():
            fatal(f"missing required file in case_dir: {required}")

    verdict = json.loads(verdict_path.read_text(encoding="utf-8"))
    findings = verdict.get("findings", [])
    case_id = verdict.get("case_id") or "real-evidence-case"
    log(f"loaded {len(findings)} findings from {verdict_path}")
    log(f"  case_id      = {case_id}")
    log(f"  verdict      = {verdict.get('verdict')}")
    log(f"  evidence     = {verdict.get('evidence_path')}")

    # ---- 1. audit_verify on the recorded chain ------------------------
    log("audit_verify: replay the recorded chain...")
    av = client.call_tool("audit_verify", {"path": str(audit_path)})
    if not av["ok"]:
        fatal(f"recorded audit chain did NOT verify: {av}")
    log(f"  -> chain verifies, {av['record_count']} records")

    # ---- 2. manifest_verify on the recorded manifest ------------------
    # The manifest's `audit_log_path` is the path AS SEEN by the agent
    # at investigation time. find-evil-auto runs the agent inside the
    # SIFT VM; the path is /home/sansforensics/.../audit.jsonl over
    # there. Locally the same audit.jsonl is mirrored at <case_dir>/
    # audit.jsonl. Rewrite the manifest in-place to the local path,
    # verify, then restore — surgical, doesn't mutate the on-disk
    # cryptographic record long-term.
    log("manifest_verify: replay the recorded manifest...")
    original = manifest_path.read_text(encoding="utf-8")
    loaded = json.loads(original)
    saved_audit_log_path = loaded.get("audit_log_path")
    loaded["audit_log_path"] = str(audit_path)
    manifest_path.write_text(
        json.dumps(loaded, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    try:
        mv = client.call_tool("manifest_verify", {"manifest_path": str(manifest_path)})
    finally:
        manifest_path.write_text(original, encoding="utf-8")

    if not mv["overall"]:
        fatal(f"recorded manifest did NOT verify (after path rewrite): {mv}")
    log(
        "  -> overall=True  audit_chain={a}  merkle={m}  sig_present={s} "
        "(audit_log_path rewritten {orig!r} -> local copy)".format(
            a=mv["audit_chain_ok"],
            m=mv["merkle_root_ok"],
            s=mv["signature_present"],
            orig=saved_audit_log_path,
        )
    )

    # ---- 3. split findings by pool_origin -----------------------------
    pool_a = [f for f in findings if f.get("pool_origin") == "A"]
    pool_b = [f for f in findings if f.get("pool_origin") == "B"]
    if not (pool_a or pool_b):
        log("no pool-tagged findings — synthesizing by index for A/B split")
        # detect_contradictions / judge_findings still need *some* split;
        # spread findings round-robin across pools so the shape assertions
        # exercise both branches.
        for i, f in enumerate(findings):
            (pool_a if i % 2 == 0 else pool_b).append(f)

    log(f"split: pool_a={len(pool_a)}  pool_b={len(pool_b)}")

    # ---- 4. detect_contradictions -------------------------------------
    log("detect_contradictions: replay against real findings...")
    cs = client.call_tool(
        "detect_contradictions",
        {
            "case_id": case_id,
            "pool_a": pool_a,
            "pool_b": pool_b,
            "resolution_required": False,
        },
    )
    if cs["pool_a_count"] != len(pool_a) or cs["pool_b_count"] != len(pool_b):
        fatal(f"pool counts mismatch: {cs}")
    log(f"  -> {len(cs['contradictions'])} contradictions surfaced")

    # ---- 5. judge_findings --------------------------------------------
    log("judge_findings: replay against real findings...")
    j = client.call_tool(
        "judge_findings",
        {
            "pool_a_findings": pool_a,
            "pool_b_findings": pool_b,
            "pool_a_verifier_actions": _verifier_actions(pool_a),
            "pool_b_verifier_actions": _verifier_actions(pool_b),
        },
    )
    if "merged" not in j:
        fatal(f"judge response missing 'merged' key: {j}")
    log(
        f"  -> {len(j['merged'])} merged findings (budget_exceeded={j['budget_exceeded']})"
    )

    # ---- 6. correlate_findings ----------------------------------------
    log("correlate_findings: replay against real findings...")
    merged_only = [m["finding"] for m in j["merged"]]
    if merged_only:
        c = client.call_tool("correlate_findings", {"findings": merged_only})
        kept = sum(1 for o in c["outcomes"] if o["action"] == "kept")
        downgraded = sum(1 for o in c["outcomes"] if o["action"] == "downgraded")
        log(f"  -> {kept} kept, {downgraded} downgraded by SOUL.md rules")
    else:
        log("  -> skipped (judge produced no merged findings)")

    print()
    print("=" * 60)
    print("OK — agent_mcp surface still parses real production output.")
    print(f"  case_dir       : {case_dir}")
    print(f"  case_id        : {case_id}")
    print(f"  audit records  : {av['record_count']}")
    print(f"  findings       : {len(findings)} ({len(pool_a)} A + {len(pool_b)} B)")
    print(f"  contradictions : {len(cs['contradictions'])}")
    print(f"  merged         : {len(j['merged'])}")
    print("=" * 60)
    return 0


def synthetic_flow(client: StdioClient) -> int:
    case_id = f"smoke-{uuid.uuid4()}"
    run_id = f"run-{int(time.time())}"
    workdir = REPO / "tmp" / "smoke" / case_id
    workdir.mkdir(parents=True, exist_ok=True)
    audit_path = workdir / "audit.jsonl"
    manifest_path = workdir / "run.manifest.json"
    started_at = _now_iso()

    try:
        # ---- 1. audit_append a representative tool-call sequence -------
        # (initialize + tools/list happened in main() before dispatch.)
        log("audit_append: chaining 12 records...")
        records = [
            (
                "agent_message",
                {"role": "supervisor", "content": "starting investigation"},
            ),
            ("tool_call_start", {"tool_call_id": "tc-1", "tool": "case_open"}),
            ("tool_call_output", {"tool_call_id": "tc-1", "output_hash": "a" * 64}),
            ("tool_call_start", {"tool_call_id": "tc-2", "tool": "evtx_query"}),
            (
                "tool_call_output",
                {"tool_call_id": "tc-2", "output_hash": "b" * 64, "row_count": 42},
            ),
            ("tool_call_start", {"tool_call_id": "tc-3", "tool": "prefetch_parse"}),
            ("tool_call_output", {"tool_call_id": "tc-3", "output_hash": "c" * 64}),
            ("tool_call_start", {"tool_call_id": "tc-4", "tool": "mft_timeline"}),
            ("tool_call_output", {"tool_call_id": "tc-4", "output_hash": "d" * 64}),
            (
                "finding_approved",
                {
                    "finding_id": "f-A-1",
                    "tool_call_id": "tc-2",
                    "confidence": "CONFIRMED",
                },
            ),
            (
                "finding_approved",
                {
                    "finding_id": "f-B-1",
                    "tool_call_id": "tc-3",
                    "confidence": "INFERRED",
                },
            ),
            ("agent_message", {"role": "judge", "content": "merge complete"}),
        ]
        for kind, payload in records:
            client.call_tool(
                "audit_append",
                {"path": str(audit_path), "kind": kind, "payload": payload},
            )

        # ---- 4. audit_verify replay ------------------------------------
        log("audit_verify: replay the chain...")
        v = client.call_tool("audit_verify", {"path": str(audit_path)})
        if not (v["ok"] and v["record_count"] == len(records)):
            fatal(f"audit chain replay failed: {v}")
        log(f"  -> chain verifies, {v['record_count']} records")

        # ---- 4a. pool_handoff: verifier -> judge (IBM-ACP, A3 §2.3) ---
        # Writes a kind="acp_handoff" line into the same chain. Proves
        # the new envelope shape lands without breaking audit_verify.
        log("pool_handoff: verifier -> judge structured handoff (A3 §2.3)...")
        ph = client.call_tool(
            "pool_handoff",
            {
                "audit_path": str(audit_path),
                "from_role": "verifier",
                "to_role": "judge",
                "payload": {
                    "finding_id": "f-A-1",
                    "action": "approved",
                    "replay_record_sha256": "a" * 64,
                },
            },
        )
        if ph["acp_version"] != "1.0" or ph["from_role"] != "verifier":
            fatal(f"pool_handoff returned unexpected envelope: {ph}")
        log(
            f"  -> acp v{ph['acp_version']} from={ph['from_role']} to={ph['to_role']} "
            f"corr={ph['correlation_id'][:8]}..."
        )

        # ---- 4b. audit_verify (post-handoff): chain still verifies ---
        # Proves kind="acp_handoff" doesn't break the prev_hash chain.
        log(
            "audit_verify (post-handoff): chain still verifies with acp_handoff line..."
        )
        v_post = client.call_tool("audit_verify", {"path": str(audit_path)})
        if not (v_post["ok"] and v_post["record_count"] == len(records) + 1):
            fatal(f"audit chain replay failed after acp_handoff: {v_post}")
        log(f"  -> chain verifies, {v_post['record_count']} records (+1 acp_handoff)")

        # ---- 4c. memory_recall (cold): empty store returns no hits ---
        # Demonstrates the cold-start case Pool A/B sees on the first
        # investigation against a fresh memory store.
        memory_path = workdir / "memory.sqlite"
        log("memory_recall (cold): empty store returns no hits...")
        rc_cold = client.call_tool(
            "memory_recall",
            {"store_path": str(memory_path), "query": "evil.example.com", "limit": 5},
        )
        if rc_cold["hits"]:
            fatal(f"cold recall expected 0 hits, got {len(rc_cold['hits'])}: {rc_cold}")
        log("  -> 0 hits (expected on first run)")

        # ---- 4d. memory_remember: seed an IOC the next case should see ---
        log("memory_remember: seed a Pool B IOC (A3 §2.2)...")
        mr = client.call_tool(
            "memory_remember",
            {
                "store_path": str(memory_path),
                "case_id": case_id,
                "kind": "ioc",
                "key": "evil.example.com",
                "value": "evil.example.com C2 from Pool B exfil finding",
                "sha256": "sha256:" + "f" * 64,
            },
        )
        if mr["case_id"] != case_id or mr["kind"] != "ioc":
            fatal(f"memory_remember returned unexpected echo: {mr}")
        log(
            f"  -> remembered case_id={mr['case_id'][:12]}... kind={mr['kind']} key={mr['key']!r}"
        )

        # ---- 4e. memory_recall (warm): same key now returns the hit ---
        # The cold/warm transition is what makes this a "cross-case
        # memory" tool — a future case investigating evil.example.com
        # gets this hit back as prior context. Memory recall is
        # context only; it does NOT count toward the SOUL.md
        # ≥2-artifact-class corroboration rule.
        log("memory_recall (warm): expect 1 hit with confidence > 0...")
        rc_warm = client.call_tool(
            "memory_recall",
            {"store_path": str(memory_path), "query": "evil.example.com", "limit": 5},
        )
        if len(rc_warm["hits"]) != 1:
            fatal(f"warm recall expected 1 hit, got {len(rc_warm['hits'])}: {rc_warm}")
        hit = rc_warm["hits"][0]
        if hit["case_id"] != case_id or hit["kind"] != "ioc" or hit["confidence"] <= 0:
            fatal(f"warm recall hit shape unexpected: {hit}")
        log(
            f"  -> hit case_id={hit['case_id'][:12]}... kind={hit['kind']} "
            f"confidence={hit['confidence']:.3f}"
        )

        # ---- 4f. memory_recall (kind-filtered): only the wrong kind --
        # Proves the optional kind filter actually filters. We seeded
        # an "ioc"; ask for "hash" — should be empty.
        log("memory_recall (kind=hash): expect 0 hits (we seeded only ioc)...")
        rc_kf = client.call_tool(
            "memory_recall",
            {
                "store_path": str(memory_path),
                "query": "evil.example.com",
                "kind": "hash",
            },
        )
        if rc_kf["hits"]:
            fatal(f"kind-filtered recall expected 0 hits, got {len(rc_kf['hits'])}")
        log("  -> 0 hits (kind filter correctly excluded the ioc seed)")

        # ---- 4g. expert_miss_capture: expert correction ledger -------
        miss_ledger = workdir / "expert_misses.jsonl"
        log("expert_miss_capture: record one expert correction...")
        miss = client.call_tool(
            "expert_miss_capture",
            {
                "case_id": case_id,
                "finding_id": "f-A-1",
                "edit_type": "qa",
                "edit_text": "Expert requested a stronger replay caveat before release.",
                "expert_name": "smoke-test",
                "ledger_path": str(miss_ledger),
            },
        )
        if miss["seq"] != 0 or not miss["line_hash"] or miss["github_issue_url"]:
            fatal(f"expert_miss_capture returned unexpected payload: {miss}")
        miss_verify = client.call_tool("audit_verify", {"path": str(miss_ledger)})
        if not (miss_verify["ok"] and miss_verify["record_count"] == 1):
            fatal(f"expert miss ledger failed audit_verify: {miss_verify}")
        log(f"  -> ledger verifies, line_hash={miss['line_hash'][:12]}...")

        # ---- 5. detect_contradictions ----------------------------------
        log("detect_contradictions: Pool A persistence vs Pool B exfil...")
        a_findings = [
            _finding(
                case_id=case_id,
                finding_id="f-A-1",
                tool_call_id="tc-2",
                artifact="C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
                description="Type 10 RDP logon at 02:14 UTC from external IP",
                confidence="CONFIRMED",
                pool="A",
                mitre="T1078",
            ),
            _finding(
                case_id=case_id,
                finding_id="f-A-2",
                tool_call_id="tc-3",
                artifact="C:\\Windows\\Prefetch\\STAGER.EXE-D269B812.pf",
                description="Prefetch shows STAGER.EXE ran 3 times, last 03:08 UTC",
                confidence="CONFIRMED",
                pool="A",
                mitre="T1547.001",
            ),
        ]
        b_findings = [
            _finding(
                case_id=case_id,
                finding_id="f-B-1",
                tool_call_id="tc-2",
                artifact="C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
                description="Possible RDP brute-force; not a successful logon",
                confidence="HYPOTHESIS",
                pool="B",
                mitre="T1110.001",
            ),
        ]
        cs = client.call_tool(
            "detect_contradictions",
            {
                "case_id": case_id,
                "pool_a": a_findings,
                "pool_b": b_findings,
                "resolution_required": True,
            },
        )
        if cs["pool_a_count"] != 2 or cs["pool_b_count"] != 1:
            fatal(f"unexpected pool counts: {cs}")
        if not cs["contradictions"]:
            fatal(
                "expected at least one contradiction (CONFIRMED vs HYPOTHESIS on tc-2)"
            )
        log(f"  -> {len(cs['contradictions'])} contradictions surfaced")

        # ---- 6. judge_findings -----------------------------------------
        log("judge_findings: credibility-weighted merge...")
        j = client.call_tool(
            "judge_findings",
            {
                "pool_a_findings": a_findings,
                "pool_b_findings": b_findings,
                "pool_a_verifier_actions": _verifier_actions(a_findings),
                "pool_b_verifier_actions": _verifier_actions(b_findings),
            },
        )
        if not j["merged"] or j["budget_exceeded"]:
            fatal(f"judge produced no merged findings: {j}")
        log(f"  -> {len(j['merged'])} merged findings; budget OK")

        # ---- 7. correlate_findings -------------------------------------
        log("correlate_findings: SOUL.md cross-artifact rules...")
        merged_only = [m["finding"] for m in j["merged"]]
        c = client.call_tool("correlate_findings", {"findings": merged_only})
        kept = sum(1 for o in c["outcomes"] if o["action"] == "kept")
        downgraded = sum(1 for o in c["outcomes"] if o["action"] == "downgraded")
        log(f"  -> {kept} kept, {downgraded} downgraded by SOUL.md rules")

        # ---- 8. manifest_finalize --------------------------------------
        log("manifest_finalize: build + sign run.manifest.json...")
        mf = client.call_tool(
            "manifest_finalize",
            {
                "case_id": case_id,
                "run_id": run_id,
                "started_at": started_at,
                "audit_log_path": str(audit_path),
                "output_path": str(manifest_path),
                "signer": "stub",
                "extra": {
                    "image_path": "/fixtures/sample-case/sample-disk.001",
                    "model": "claude-opus-4-7",
                },
            },
        )
        if not (mf["leaf_count"] >= 4 and len(mf["merkle_root_hex"]) == 64):
            fatal(f"manifest finalize unexpected: {mf}")
        log(
            f"  -> {mf['leaf_count']} Merkle leaves, root={mf['merkle_root_hex'][:12]}..., "
            f"sig sha256={mf['signature_payload_sha256'][:12]}..."
        )

        # ---- 9. manifest_verify (offline) ------------------------------
        log("manifest_verify: offline replay...")
        mv = client.call_tool("manifest_verify", {"manifest_path": str(manifest_path)})
        if not mv["overall"]:
            fatal(f"manifest verification failed: {mv}")
        log(
            "  -> overall=True, audit_chain_ok={a}, merkle_root_ok={m}, sig_present={s}".format(
                a=mv["audit_chain_ok"],
                m=mv["merkle_root_ok"],
                s=mv["signature_present"],
            )
        )

        # ---- 10. tampered manifest is rejected -------------------------
        log("manifest_verify (tampered): expect failure...")
        loaded = json.loads(manifest_path.read_text(encoding="utf-8"))
        loaded["merkle_root_hex"] = "ff" * 32
        manifest_path.write_text(
            json.dumps(loaded, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        mv2 = client.call_tool("manifest_verify", {"manifest_path": str(manifest_path)})
        if mv2["overall"]:
            fatal("tampered manifest must NOT verify, but it did")
        log(f"  -> tampered manifest correctly rejected: {mv2['merkle_root_detail']!r}")

        print()
        print("=" * 60)
        print("OK — full A2+A3 demo flow round-trips clean.")
        print(f"  case_id        : {case_id}")
        print(f"  run_id         : {run_id}")
        print(
            f"  audit log      : {audit_path} ({v_post['record_count']} records, "
            f"includes 1 acp_handoff)"
        )
        print(f"  memory store   : {memory_path} (1 ioc seeded)")
        print(f"  manifest       : {manifest_path}")
        print("=" * 60)
        return 0
    finally:
        # Client lifecycle is owned by the caller (main); leaving the
        # try/finally as a structural placeholder so the flow's nested
        # exits (`fatal`) still unwind cleanly even when extended later.
        pass


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--real-evidence",
        nargs="?",
        const="<latest>",
        default=None,
        metavar="AUTO_RUN_DIR",
        help=(
            "Replay a real find-evil-auto case dir through the agent_mcp "
            "surface. Pass a path, or omit to use the latest dir under "
            "tmp/auto-runs/."
        ),
    )
    args = parser.parse_args()

    print("=" * 60)
    if args.real_evidence is not None:
        print("Find Evil! — agent_mcp real-evidence regression smoke")
    else:
        print("Find Evil! — agent_mcp end-to-end smoke (Amendment A2)")
    print("=" * 60)

    cmd = [
        "uv",
        "run",
        "--directory",
        str(AGENT_MCP_DIR),
        "python",
        "-m",
        "findevil_agent_mcp.server",
    ]
    log(f"spawning: {' '.join(cmd)}")
    client = StdioClient(cmd)
    try:
        log("initialize handshake...")
        init = client.call(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "agent-mcp-smoke", "version": "1.0"},
            },
        )
        assert "capabilities" in init, f"no capabilities in init result: {init}"
        client.notify("notifications/initialized")

        log("tools/list...")
        tools_resp = client.call("tools/list")
        names = sorted(t["name"] for t in tools_resp["tools"])
        expected = sorted(
            [
                # A2 baseline minus the OTS pair removed under A5 (8 tools)
                "audit_append",
                "audit_verify",
                "manifest_finalize",
                "manifest_verify",
                "verify_finding",
                "detect_contradictions",
                "judge_findings",
                "correlate_findings",
                # A3 additions (cross-case memory + IBM-ACP handoff)
                "memory_remember",
                "memory_recall",
                "pool_handoff",
                "expert_miss_capture",
                # read-only accuracy diagnostic (13th Python tool)
                "accuracy_compare",
            ]
        )
        if names != expected:
            fatal(f"tools mismatch: got {names}, expected {expected}")
        log(f"  -> {len(names)} tools registered")

        if args.real_evidence is not None:
            if args.real_evidence == "<latest>":
                case_dir = latest_auto_run()
                if case_dir is None:
                    fatal(
                        "no auto-run dir found under tmp/auto-runs/ — "
                        "run scripts/find-evil-auto first"
                    )
            else:
                # `uv run --directory services/agent_mcp` runs the
                # interpreter with cwd=services/agent_mcp, so a path
                # like `tmp/auto-runs/auto-<uuid>` is relative to the
                # repo root the user typed it from, not to the new cwd.
                # Resolve relative paths against REPO before falling
                # back to as-given (lets users still pass absolute
                # paths or paths relative to any cwd that contains the
                # target).
                raw = Path(args.real_evidence)
                case_dir = raw if raw.is_absolute() and raw.is_dir() else (REPO / raw)
                if not case_dir.is_dir():
                    case_dir = raw
                if not case_dir.is_dir():
                    fatal(
                        f"--real-evidence path is not a directory: "
                        f"{args.real_evidence} (also tried {REPO / raw})"
                    )
            return real_evidence_flow(client, case_dir)
        return synthetic_flow(client)
    finally:
        client.close()


if __name__ == "__main__":
    sys.exit(main())
