#!/usr/bin/env python3
"""Summarize expert-miss ledger volume over a rolling window."""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import UTC, datetime, timedelta
import json
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent
DEFAULT_LEDGER = REPO / "state" / "expert_misses.jsonl"


def _parse_ts(value: str) -> datetime | None:
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError:
        return None


def load_rows(ledger: Path, days: int) -> list[dict[str, Any]]:
    if not ledger.is_file():
        return []
    cutoff = datetime.now(UTC) - timedelta(days=days)
    rows: list[dict[str, Any]] = []
    for raw in ledger.read_text(encoding="utf-8").splitlines():
        try:
            record = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if record.get("kind") != "expert_miss":
            continue
        ts = _parse_ts(str(record.get("ts") or ""))
        if ts is None or ts < cutoff:
            continue
        payload = record.get("payload") or {}
        if not isinstance(payload, dict):
            continue
        rows.append(payload)
    return rows


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_type = Counter(str(row.get("edit_type") or "unknown") for row in rows)
    case_ids = {str(row.get("case_id")) for row in rows if row.get("case_id")}
    total = sum(by_type.values())
    denominator = len(case_ids) or 1
    return {
        "total": total,
        "cases": len(case_ids),
        "rate_per_case": total / denominator,
        "by_type": dict(sorted(by_type.items())),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ledger", type=Path, default=DEFAULT_LEDGER)
    parser.add_argument("--days", type=int, default=30)
    parser.add_argument("--by-type", action="store_true")
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args()

    result = summarize(load_rows(args.ledger, args.days))
    if args.as_json:
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0

    print(f"Expert misses in last {args.days} day(s): {result['total']}")
    print(f"Cases with captured misses: {result['cases']}")
    print(f"Rate per case: {result['rate_per_case']:.2f}")
    if args.by_type:
        for edit_type, count in result["by_type"].items():
            print(f"{edit_type}: {count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
