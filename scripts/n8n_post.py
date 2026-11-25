#!/usr/bin/env python3
"""n8n_post — fire a completed case's verdict at the optional n8n
finding-to-action workflow and record the outcome as automation.json.

n8n is operator tooling that lives OUTSIDE the evidentiary chain. This script
deliberately:
  - reads the SIGNED verdict.json (read-only),
  - POSTs a summary to the n8n webhook,
  - writes the result to <case>/automation.json — a separate file, NOT the
    hash-chained audit.jsonl (appending there would invalidate the manifest's
    audit_log_final_hash), and never cited as a Finding.

Graceful: if n8n is unreachable it still writes automation.json with
n8n_reachable=false so the dashboard can say so honestly.

Usage: n8n_post.py <case-dir>
Env:   FINDEVIL_N8N_WEBHOOK  (default http://localhost:5678/webhook/findevil-finding-to-action)
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

WEBHOOK = os.environ.get(
    "FINDEVIL_N8N_WEBHOOK",
    "http://localhost:5678/webhook/findevil-finding-to-action",
)
NODES = ("trigger", "route", "ticket")
SOURCE = "n8n finding-to-action (operator harness; not evidence, not in audit chain)"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _summarize_findings(verdict: dict) -> list[dict]:
    out = []
    for f in verdict.get("findings", []):
        out.append(
            {
                "title": f.get("description") or f.get("title") or "finding",
                "mitre": f.get("mitre_technique") or f.get("mitre"),
                "confidence": f.get("confidence"),
            }
        )
    return out


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: n8n_post.py <case-dir>", file=sys.stderr)
        return 2
    case_dir = Path(sys.argv[1])
    verdict_file = case_dir / "verdict.json"
    out_file = case_dir / "automation.json"
    case_dir.mkdir(parents=True, exist_ok=True)

    if not verdict_file.is_file():
        out_file.write_text(
            json.dumps(
                {"ran": False, "reason": "no verdict.json", "source": SOURCE}, indent=2
            )
        )
        return 0

    verdict = json.loads(verdict_file.read_text())
    findings = _summarize_findings(verdict)
    payload = {
        "case_id": verdict.get("case_id"),
        "verdict": verdict.get("verdict"),
        "findings": findings,
    }
    record: dict = {
        "ran": True,
        "posted_at": _now(),
        "webhook": WEBHOOK,
        "verdict": verdict.get("verdict"),
        "finding_count": len(findings),
        "source": SOURCE,
    }

    try:
        req = urllib.request.Request(
            WEBHOOK,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310 (fixed localhost webhook)
            body = resp.read().decode("utf-8", errors="replace")
        try:
            rj = json.loads(body)
        except json.JSONDecodeError:
            rj = {}
        action_plan = rj.get("action_plan", [])
        ticket_file = rj.get("ticket_file")
        # The workflow is a linear chain (Webhook->Router->Ticket->Respond);
        # a valid response means every node before Respond executed.
        record.update(
            {
                "n8n_reachable": True,
                "steps": [{"node": n, "status": "ok"} for n in NODES],
                "action_plan": action_plan,
                "ticket_file": ticket_file,
            }
        )
    except (urllib.error.URLError, OSError, TimeoutError, ValueError) as exc:
        record.update(
            {
                "n8n_reachable": False,
                "error": str(exc),
                "steps": [{"node": n, "status": "idle"} for n in NODES],
                "ticket_file": None,
                "action_plan": [],
            }
        )

    out_file.write_text(json.dumps(record, indent=2))
    state = "n8n routed" if record.get("n8n_reachable") else "n8n unreachable (skipped)"
    print(f"[n8n_post] {state} -> {out_file}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
