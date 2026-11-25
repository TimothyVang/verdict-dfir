#!/usr/bin/env python3
"""fleet_investigate — run find-evil-auto across an entire evidence corpus.

Walks /mnt/hgfs/evidence/extracted/<host>/*.img inside the SIFT VM
(via SSH `find`), invokes find-evil-auto for each, captures verdicts.
Sequential by default to avoid VM RAM contention; vol3 keeps a symbol
cache so the per-image overhead drops after the first run.

Output:
  tmp/fleet-runs/fleet-<timestamp>/
    fleet.json           — per-host verdict summary
    fleet-summary.md     — human-readable report
    hosts/<host>/...     — symlinks to each per-host case dir

Usage:
  python scripts/fleet_investigate.py [--dry-run] [--limit N] [--skip-existing]
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

GUEST_IP = os.environ.get("FIND_EVIL_GUEST_IP", "192.168.197.143")
GUEST_USER = os.environ.get("FIND_EVIL_GUEST_USER", "sansforensics")
SSH_KEY = os.environ.get("FIND_EVIL_SSH_KEY", str(Path.home() / ".ssh" / "sift_key"))
EVIDENCE_ROOT = "/mnt/hgfs/evidence/extracted"


def ssh_run(cmd: str, timeout: int = 60) -> tuple[int, str, str]:
    r = subprocess.run(
        [
            "ssh",
            "-i",
            SSH_KEY,
            "-o",
            "BatchMode=yes",
            f"{GUEST_USER}@{GUEST_IP}",
            cmd,
        ],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return r.returncode, r.stdout, r.stderr


def list_evidence() -> list[tuple[str, int]]:
    """Returns [(path, size_bytes)] for every .img under EVIDENCE_ROOT."""
    code, stdout, _ = ssh_run(
        f"find {EVIDENCE_ROOT} -type f -name '*.img' "
        "-printf '%s\\t%p\\n' 2>/dev/null | sort -n"
    )
    if code != 0:
        return []
    out: list[tuple[str, int]] = []
    for line in stdout.splitlines():
        if "\t" not in line:
            continue
        size, path = line.split("\t", 1)
        out.append((path, int(size)))
    return out


def run_find_evil_auto(evidence_path: str) -> dict:
    """Spawns scripts/find-evil-auto, returns the resulting verdict dict
    (or a synthetic error dict if anything went wrong)."""
    started = time.monotonic()
    proc = subprocess.run(
        [
            "bash",
            str(REPO_ROOT / "scripts" / "find-evil-auto"),
            evidence_path,
            "--unattended",
            "--no-report",
            # Fleet investigate already verified the VM is reachable
            # via list_evidence(); skip the per-host SSH preflight to
            # save ~50ms × 22 hosts on a fleet run.
            "--skip-preflight",
        ],
        capture_output=True,
        text=True,
        timeout=1800,
        cwd=str(REPO_ROOT),
    )
    elapsed = time.monotonic() - started
    last_line_with_local = None
    for line in proc.stdout.splitlines():
        if "On host (local)" in line:
            last_line_with_local = line
            break
    if not last_line_with_local:
        return {
            "status": "error",
            "elapsed_sec": elapsed,
            "stderr_tail": proc.stderr[-500:],
            "stdout_tail": proc.stdout[-500:],
        }
    case_dir = last_line_with_local.split(":", 1)[1].strip()
    verdict_path = Path(case_dir) / "verdict.json"
    if not verdict_path.exists():
        return {
            "status": "no_verdict",
            "elapsed_sec": elapsed,
            "case_dir": case_dir,
        }
    try:
        v = json.loads(verdict_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        return {
            "status": "verdict_unreadable",
            "elapsed_sec": elapsed,
            "case_dir": case_dir,
            "error": str(e),
        }
    return {
        "status": "ok",
        "elapsed_sec": elapsed,
        "case_dir": case_dir,
        "verdict": v.get("verdict"),
        "case_id": v.get("case_id"),
        "findings_summary": v.get("findings_summary", {}),
        "manifest_path": v.get("cryptographic_attestation", {}).get("manifest_path"),
        "merkle_root": v.get("cryptographic_attestation", {}).get("merkle_root_hex"),
    }


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--dry-run", action="store_true")
    p.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Investigate only the first N hosts (smallest first).",
    )
    p.add_argument(
        "--skip",
        default="",
        help="Comma-separated host basenames to skip "
        "(e.g., 'base-mail,base-av' for big ones).",
    )
    args = p.parse_args()

    fleet_id = datetime.now(timezone.utc).strftime("fleet-%Y%m%dT%H%M%SZ")
    fleet_dir = REPO_ROOT / "tmp" / "fleet-runs" / fleet_id
    fleet_dir.mkdir(parents=True, exist_ok=True)
    print(f"=== fleet investigation {fleet_id} ===")
    print(f"  output: {fleet_dir}")

    evidence = list_evidence()
    if not evidence:
        print("  no .img evidence found in VM")
        return 1
    print(
        f"  found {len(evidence)} memory images, total "
        f"{sum(s for _, s in evidence) / 1024**3:.1f} GiB"
    )

    # Filter
    skip_basenames = {s.strip() for s in args.skip.split(",") if s.strip()}
    if skip_basenames:
        before = len(evidence)
        evidence = [
            (p, s) for p, s in evidence if Path(p).parent.name not in skip_basenames
        ]
        print(f"  skipping {before - len(evidence)} ({skip_basenames})")
    if args.limit:
        evidence = evidence[: args.limit]
        print(f"  limit {args.limit}")

    if args.dry_run:
        for path, size in evidence:
            print(
                f"  WOULD: {Path(path).parent.name:25s} "
                f"{size / 1024**3:6.2f} GiB  {path}"
            )
        return 0

    results: list[dict] = []
    started_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    for i, (path, size) in enumerate(evidence, 1):
        host = Path(path).parent.name
        print(f"\n[{i}/{len(evidence)}] {host}  ({size / 1024**3:.2f} GiB)")
        try:
            r = run_find_evil_auto(path)
        except subprocess.TimeoutExpired:
            r = {"status": "timeout", "elapsed_sec": 1800}
        except Exception as e:
            r = {"status": "exception", "error": str(e)}
        r["host"] = host
        r["evidence_path"] = path
        r["size_bytes"] = size
        verdict_str = r.get("verdict") or r.get("status", "?")
        elapsed = r.get("elapsed_sec", 0)
        print(f"  -> {verdict_str:14s} in {elapsed:.0f}s")
        results.append(r)

        # Persist after each host so a crash doesn't lose everything
        (fleet_dir / "fleet.json").write_text(
            json.dumps(
                {
                    "fleet_id": fleet_id,
                    "started_at": started_at,
                    "current": i,
                    "total": len(evidence),
                    "results": results,
                },
                indent=2,
                sort_keys=True,
            ),
            encoding="utf-8",
        )

    finalize_summary(fleet_dir, results, fleet_id, started_at)
    return 0


def finalize_summary(
    fleet_dir: Path, results: list[dict], fleet_id: str, started_at: str
) -> None:
    finalized_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    by_verdict: dict[str, list[str]] = {}
    for r in results:
        v = r.get("verdict") or r.get("status", "?")
        by_verdict.setdefault(v, []).append(r["host"])

    md = ["# Fleet investigation summary", ""]
    md.append(f"**Fleet ID:** `{fleet_id}`")
    md.append(f"**Started:** {started_at}")
    md.append(f"**Finalized:** {finalized_at}")
    md.append(f"**Total hosts:** {len(results)}")
    md.append("")
    md.append("## Verdict distribution")
    md.append("")
    md.append("| Verdict | Count | Hosts |")
    md.append("|---|---:|---|")
    for verdict, hosts in sorted(by_verdict.items(), key=lambda kv: -len(kv[1])):
        hosts_str = ", ".join(sorted(hosts))
        md.append(f"| **{verdict}** | {len(hosts)} | {hosts_str} |")
    md.append("")
    md.append("## Per-host detail")
    md.append("")
    md.append("| Host | Verdict | Findings (C/I/H) | Contras | Time |")
    md.append("|---|---|---:|---:|---:|")
    for r in results:
        v = r.get("verdict") or r.get("status", "?")
        fs = r.get("findings_summary", {})
        bc = fs.get("by_confidence", {})
        c = bc.get("CONFIRMED", 0)
        i = bc.get("INFERRED", 0)
        h = bc.get("HYPOTHESIS", 0)
        contras = fs.get("contradictions_surfaced", 0)
        elapsed = r.get("elapsed_sec", 0)
        md.append(f"| `{r['host']}` | {v} | {c}/{i}/{h} | {contras} | {elapsed:.0f}s |")
    md.append("")
    md.append("## Cryptographic attestation per host")
    md.append("")
    md.append("| Host | case_id | Merkle root |")
    md.append("|---|---|---|")
    for r in results:
        cid = r.get("case_id", "—")
        mr = r.get("merkle_root", "—")
        if mr and mr != "—":
            mr = mr[:24] + "…"
        md.append(f"| `{r['host']}` | `{cid[:8]}…` | `{mr}` |")
    md.append("")
    md.append("---")
    md.append("")
    md.append(
        "*Each per-host case dir under `tmp/auto-runs/auto-<uuid>/` "
        "contains its own `audit.jsonl`, `run.manifest.json`, "
        "`verdict.json`, and `REPORT.{md,html,pdf}`. The "
        "`fleet.json` in this directory aggregates everything.*"
    )

    (fleet_dir / "fleet-summary.md").write_text("\n".join(md), encoding="utf-8")
    print(f"\n=== fleet summary written to {fleet_dir / 'fleet-summary.md'} ===")


if __name__ == "__main__":
    sys.exit(main())
