#!/usr/bin/env python3
"""fleet_local — adapt a local whole-case run into a correlate-ready fleet dir.

run-whole-case-local.sh writes per-target ``results.jsonl`` rows
(``{host, verdict, manifest_ok, packet, case_dir}``); the fleet pipeline's
stage 2 (``fleet_correlate.py``) reads ``fleet.json``
(``{fleet_id, started_at, total, results: [{host, case_dir, verdict, status}]}``).
This ~60-line stdlib adapter bridges the two so the one-command fleet path
(``scripts/verdict <case-root> --fleet``) can chain
run-whole-case-local → fleet_local → fleet_correlate → render_fleet_report.

Usage: python3 scripts/fleet_local.py <fleet-dir>
"""

from __future__ import annotations

import json
import sys
from datetime import (
    datetime,
    timezone,
)  # timezone.utc: scripts/ run on system python3 (3.10)
from pathlib import Path

_LABEL_PREFIXES = ("mem:", "disk:", "xart:")


def _host_from_label(label: str) -> str:
    """Strip the run-whole-case-local target-kind prefix from a label."""
    for prefix in _LABEL_PREFIXES:
        if label.startswith(prefix):
            return label[len(prefix) :]
    return label


def results_to_fleet(fleet_dir: Path) -> Path:
    """Write ``fleet.json`` next to ``results.jsonl``. Returns its path."""
    fleet_dir = Path(fleet_dir)
    results_path = fleet_dir / "results.jsonl"
    if not results_path.is_file():
        raise SystemExit(f"fleet_local: no results.jsonl under {fleet_dir}")
    results: list[dict] = []
    for line in results_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        row = json.loads(line)
        case_dir = row.get("case_dir") or ""
        results.append(
            {
                "host": _host_from_label(str(row.get("host") or "?")),
                "case_dir": case_dir,
                "verdict": row.get("verdict"),
                "manifest_ok": row.get("manifest_ok"),
                "status": "ok" if case_dir else "error",
            }
        )
    started_at = datetime.fromtimestamp(
        results_path.stat().st_mtime, tz=timezone.utc
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    fleet = {
        "fleet_id": fleet_dir.name,
        "started_at": started_at,
        "total": len(results),
        "current": len(results),
        "results": results,
    }
    out = fleet_dir / "fleet.json"
    out.write_text(json.dumps(fleet, indent=1), encoding="utf-8")
    return out


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: fleet_local.py <fleet-dir>", file=sys.stderr)
        return 2
    out = results_to_fleet(Path(argv[1]))
    print(f"fleet_local: wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
