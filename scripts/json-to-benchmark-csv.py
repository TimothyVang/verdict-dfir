#!/usr/bin/env python3
"""Convert L3 run verdict JSON files into a flat benchmark-results.csv.

Glue Spec #4 §9. Used by devpost-submit.yml — the CSV goes in the
Devpost submission zip as the machine-readable accuracy artifact.

Usage:
    scripts/json-to-benchmark-csv.py logs/l3 > benchmark-results.csv

Or per-file:
    scripts/json-to-benchmark-csv.py logs/l3/nist-verdict.json > row.csv
"""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

CSV_COLUMNS = [
    "fixture",
    "findings_matched",
    "findings_expected",
    "verdict",
    "verdict_correct",
    "wall_clock_seconds",
    "manifest_verify_overall",
    "run_duration_seconds",
    "contradictions_found",
    "contradictions_auto_resolved",
    "source_file",
]


def load_records(path: Path) -> list[dict]:
    """Yield one row dict per verdict JSON found at ``path``.

    ``path`` can be a file or a directory; directories are scanned
    recursively for ``*-verdict.json`` (the L3 driver's naming convention).
    """
    if path.is_file():
        return [_record_from_file(path)]
    if path.is_dir():
        return [_record_from_file(p) for p in sorted(path.glob("**/*-verdict.json"))]
    raise SystemExit(f"input path not found: {path}")


def _record_from_file(p: Path) -> dict:
    try:
        data = json.loads(p.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError:
        return {c: "" for c in CSV_COLUMNS} | {"source_file": str(p)}
    recall = data.get("recall") if isinstance(data.get("recall"), dict) else {}
    return {
        "fixture": fixture_name(data, p),
        "findings_matched": data.get("findings_matched")
        or recall.get("recalled_n")
        or data.get("finding_count")
        or len(data.get("findings", []) or []),
        "findings_expected": data.get("findings_expected")
        or recall.get("expected_n")
        or "",
        "verdict": data.get("verdict", ""),
        "verdict_correct": data.get("verdict_correct", ""),
        "wall_clock_seconds": data.get("wall_clock_seconds")
        or data.get("run_duration_seconds", ""),
        "manifest_verify_overall": data.get("manifest_verify_overall", ""),
        "run_duration_seconds": data.get("run_duration_seconds", ""),
        "contradictions_found": data.get("contradictions_found", ""),
        "contradictions_auto_resolved": data.get("contradictions_auto_resolved", ""),
        "source_file": str(p),
    }


def fixture_name(data: dict, p: Path) -> str:
    explicit = data.get("fixture")
    if explicit:
        return explicit
    filename_fixture = p.stem.removesuffix("-verdict")
    if filename_fixture and filename_fixture != "verdict":
        return filename_fixture
    return data.get("case_id") or filename_fixture


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(
            "usage: json-to-benchmark-csv.py <logs/l3 | foo-verdict.json>",
            file=sys.stderr,
        )
        return 2
    records = load_records(Path(argv[1]))
    writer = csv.DictWriter(sys.stdout, fieldnames=CSV_COLUMNS)
    writer.writeheader()
    for r in records:
        writer.writerow(r)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
