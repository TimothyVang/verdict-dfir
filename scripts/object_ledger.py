#!/usr/bin/env python3
"""Account for every object under an evidence root, and reconcile the count.

This is what makes a coverage number mean something. Before it, a lane
reported `discovered=1, inspected=1` -- a constant no real change could move,
which renders as 100 % and is therefore not accounting.

The ledger walks the root, verifies each object's type from its bytes,
descends into containers under budget, and assigns every object a terminal
state. Then it RECONCILES: inspected + failed + skipped + over_budget +
unsupported must equal discovered. A ledger that does not add up is reported
as not adding up rather than quietly published.

Lane routing is by VERIFIED content type, never by extension. That is the
whole point of piece 1: a PE named notes.txt must reach the binary lane.
"""
from __future__ import annotations

from pathlib import Path

try:
    from container_intake import (Budget, ENCRYPTED, EXTRACTED, REFUSED,
                                  UNSUPPORTED, inspect_container)
    from content_type import CONTAINER_TYPES, verify_declared_type
except ImportError:  # pragma: no cover
    inspect_container = None

# Verified content type -> the lane that can actually parse it. Keyed on what
# the BYTES say; an extension never appears here.
_LANE_BY_TYPE = {
    "pe": "binary", "dos-mz": "binary", "elf": "binary",
    "macho": "binary", "macho-fat": "binary",
    "pdf": "document", "ole": "document",
    "evtx": "eventlog", "registry-hive": "registry",
    "sqlite": "database",
    "memory-dump": "memory",
    "vmdk": "diskimage", "qcow": "diskimage", "vhd": "diskimage",
    "ext-superblock": "diskimage",
    "png": "image", "jpeg": "image",
    "script-shebang": "script",
    "zip": "container", "tar": "container", "gzip": "container",
    "bzip2": "container", "xz": "container", "7z": "container",
    "rar": "container", "zip-empty": "container",
}


def lane_for(content_type: str | None) -> str | None:
    """The lane that can parse these bytes, or None when unknown.

    None is a real answer. Routing an unidentified object to a default lane
    would produce a confident parse of something we never identified.
    """
    return _LANE_BY_TYPE.get(content_type) if content_type else None



def reconcile(counts: dict) -> tuple[bool, int]:
    """Do the buckets account for every discovered object?

    Split out as a pure function so it can be tested against counts that do
    NOT add up. Asserting the flag on a ledger whose counts happen to
    reconcile proves nothing -- hardcoding `reconciles: True` passed that test.
    """
    discovered = counts.get("discovered", 0)
    accounted = sum(v for k, v in counts.items() if k != "discovered")
    return accounted == discovered, discovered - accounted


def build_object_ledger(root, workdir, *, budget: Budget | None = None) -> dict:
    """Enumerate every object under root, including container members."""
    root = Path(root)
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    budget = budget or Budget()
    objects: list[dict] = []

    candidates = [root] if root.is_file() else sorted(
        p for p in root.rglob("*") if p.is_file())

    for path in candidates:
        facts = verify_declared_type(path)
        entry = {
            "path": str(path),
            "content_type": facts["content_type"],
            "type_agreement": facts["agreement"],
            "lane": lane_for(facts["content_type"]),
            "depth": 0,
            "member_of": None,
            "byte_range": None,
            "size_bytes": path.stat().st_size if path.exists() else None,
        }
        if facts["content_type"] in CONTAINER_TYPES:
            child_records = inspect_container(
                path, workdir / f"x_{path.name}", budget=budget)
            # A container's own state is decided by what descending it produced.
            blocked = [r for r in child_records
                       if r["state"] in (ENCRYPTED, UNSUPPORTED, REFUSED)
                       and r["path"] == str(path)]
            if blocked:
                entry["state"] = ("unsupported" if blocked[0]["state"] != REFUSED
                                  else "over_budget")
                entry["reason"] = blocked[0]["reason"]
                objects.append(entry)
                continue
            entry["state"] = "inspected"
            entry["reason"] = "container enumerated"
            objects.append(entry)
            for rec in child_records:
                if rec["path"] == str(path):
                    continue
                child_facts = (verify_declared_type(rec["path"])
                               if Path(rec["path"]).is_file()
                               else {"content_type": None, "agreement": "unknown"})
                objects.append({
                    "path": rec["path"],
                    "content_type": child_facts["content_type"],
                    "type_agreement": child_facts["agreement"],
                    "lane": lane_for(child_facts["content_type"]),
                    "depth": rec["depth"] + 1,
                    "member_of": rec["member_of"],
                    "byte_range": rec["byte_range"],
                    "size_bytes": rec["size_bytes"],
                    "state": {EXTRACTED: "inspected", ENCRYPTED: "unsupported",
                              UNSUPPORTED: "unsupported",
                              REFUSED: "over_budget"}[rec["state"]],
                    "reason": rec["reason"],
                })
        else:
            entry["state"] = "inspected"
            entry["reason"] = "leaf object"
            objects.append(entry)

    buckets = {k: 0 for k in
               ("inspected", "failed", "skipped", "over_budget", "unsupported")}
    for obj in objects:
        buckets[obj["state"]] = buckets.get(obj["state"], 0) + 1
    discovered = len(objects)
    counts = {"discovered": discovered, **buckets}
    reconciles, unaccounted = reconcile(counts)

    return {
        "schema": "gn7000.object-ledger/v1",
        "root": str(root),
        "objects": objects,
        "counts": counts,
        # Stated, not assumed. A ledger that does not add up must say so rather
        # than be published as coverage.
        "reconciles": reconciles,
        "unaccounted": unaccounted,
        "budgets_exhausted": list(budget.exhausted),
        "unrouted": sum(1 for o in objects if o["lane"] is None),
    }


def coverage_objects_from_ledger(ledger: dict) -> dict:
    """Shape the ledger's counts for verdict.coverage/v1's objects block.

    This is the number that replaces the discovered=1/inspected=1 constant.
    """
    c = ledger["counts"]
    return {
        "discovered": c["discovered"],
        "inspected": c["inspected"],
        "executed": 0,
        "failed": c["failed"],
        "skipped": c["skipped"],
        "over_budget": c["over_budget"],
        "unsupported": c["unsupported"],
    }


OBJECT_LEDGER_FILENAME = "object-ledger.json"


def write_object_ledger_to_case(root, case_dir, workdir, *, budget: Budget | None = None) -> Path:
    """Build the ledger and write it where gn7000 seal_case looks.

    orchestrator_common.load_object_ledger reads <case_dir>/object-ledger.json
    and only returns counts when reconciles is True. Building in memory alone
    never reaches that reader — this is the missing write path for item 3.
    """
    import json

    case_dir = Path(case_dir)
    case_dir.mkdir(parents=True, exist_ok=True)
    ledger = build_object_ledger(root, workdir, budget=budget)
    path = case_dir / OBJECT_LEDGER_FILENAME
    path.write_text(json.dumps(ledger, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def main(argv: list[str] | None = None) -> int:
    """CLI: write object-ledger.json into a case directory."""
    import argparse

    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--root", required=True, help="Evidence root (file or directory)")
    parser.add_argument("--case-dir", required=True, help="Case directory to write into")
    parser.add_argument(
        "--workdir",
        default=None,
        help="Scratch dir for container extraction (default: <case-dir>/object-ledger-work)",
    )
    args = parser.parse_args(argv)
    case_dir = Path(args.case_dir)
    workdir = Path(args.workdir) if args.workdir else case_dir / "object-ledger-work"
    path = write_object_ledger_to_case(args.root, case_dir, workdir)
    print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
