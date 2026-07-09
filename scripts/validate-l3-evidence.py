#!/usr/bin/env python3
"""Validate local L3 fallback evidence and emit benchmark verdict JSON.

The normal L3 path runs SIFT goldens under KVM. GitHub-hosted KVM runners are
not always available, so release workflows may use this script to validate an
explicit local evidence summary instead of silently treating a skipped KVM run
as green.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
from typing import Any


EXPECTED_NIST_SHA256 = (
    "65e2002fed0b286f49541c7e97dcec0dda913d51a063ceeed86782bdacda2312"
)
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")


def positive_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def nested(data: dict[str, Any], *keys: str) -> Any:
    current: Any = data
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def validate_evidence(
    data: dict[str, Any], expected_commit: str | None = None
) -> list[str]:
    errors: list[str] = []

    if data.get("version") != 1:
        errors.append("version must be 1")
    if data.get("evidence_kind") not in {
        "local-sift-vmware-l3-fallback",
        "committed-local-l3-fallback",
    }:
        errors.append("evidence_kind must be a supported local L3 fallback kind")
    if data.get("fixture") != "nist-hacking-case":
        errors.append("fixture must be nist-hacking-case")
    if data.get("findings_expected") != 14:
        errors.append("findings_expected must be 14 for nist-hacking-case")
    product_commit = str(data.get("product_commit") or "")
    if not HEX40.fullmatch(product_commit):
        errors.append("product_commit must be a 40-character lowercase hex SHA")
    if expected_commit is not None:
        expected = expected_commit.strip().lower()
        if not HEX40.fullmatch(expected):
            errors.append("expected_commit must be a 40-character hex SHA")
        elif product_commit != expected:
            errors.append("product_commit must match expected commit")

    image_sha = nested(data, "nist_image", "sha256")
    if image_sha != EXPECTED_NIST_SHA256:
        errors.append(
            "nist_image.sha256 does not match the expected fixture disk image"
        )
    if positive_int(nested(data, "nist_image", "size_bytes")) is None:
        errors.append("nist_image.size_bytes must be positive")

    finding_count = positive_int(nested(data, "run", "finding_count"))
    if finding_count is None:
        errors.append("run.finding_count must be positive")
    if nested(data, "run", "verifier", "approved") != finding_count:
        errors.append("run.verifier.approved must equal run.finding_count")
    if nested(data, "run", "verifier", "rejected") != 0:
        errors.append("run.verifier.rejected must be 0")
    if nested(data, "run", "failed_checks") not in ([], None):
        errors.append("run.failed_checks must be empty")
    if nested(data, "run", "report_qa_status") not in {"PASS", "WARN"}:
        errors.append("run.report_qa_status must be PASS or WARN")
    if nested(data, "run", "ready_for_expert_signoff") is not True:
        errors.append("run.ready_for_expert_signoff must be true")
    if nested(data, "run", "customer_releasable") is not False:
        errors.append("run.customer_releasable must be false")
    if nested(data, "run", "verdict") != "SUSPICIOUS":
        errors.append("run.verdict must be SUSPICIOUS for the current NIST fallback")

    recall = data.get("recall")
    if not isinstance(recall, dict):
        errors.append("recall must be an object")
        recall = {}
    expected_n = positive_int(recall.get("expected_n"))
    recalled_n = positive_int(recall.get("recalled_n"))
    recall_percent = positive_int(recall.get("recall_percent"))
    min_recall_percent = positive_int(recall.get("min_recall_percent"))
    if expected_n != 14:
        errors.append("recall.expected_n must be 14")
    if recalled_n is None:
        errors.append("recall.recalled_n must be positive")
    elif expected_n is not None and recalled_n > expected_n:
        errors.append("recall.recalled_n must not exceed recall.expected_n")
    computed_recall_percent = None
    if expected_n is not None and recalled_n is not None:
        computed_recall_percent = round(recalled_n * 100 / expected_n)
        if recall_percent is not None and recall_percent != computed_recall_percent:
            errors.append("recall.recall_percent must match recalled_n / expected_n")
    threshold_recall_percent = (
        computed_recall_percent
        if computed_recall_percent is not None
        else recall_percent
    )
    if recall.get("pass") is not True:
        errors.append("recall.pass must be true")
    if recall_percent is None:
        errors.append("recall.recall_percent must be positive")
    if min_recall_percent is None:
        errors.append("recall.min_recall_percent must be positive")
    if (
        threshold_recall_percent is not None
        and min_recall_percent is not None
        and threshold_recall_percent < min_recall_percent
    ):
        errors.append("recall.recall_percent must be >= recall.min_recall_percent")
    matched_ids = recall.get("matched_ids")
    if not isinstance(matched_ids, list):
        errors.append("recall.matched_ids must be a list")
    elif recalled_n is not None and len(matched_ids) != recalled_n:
        errors.append("recall.matched_ids length must equal recall.recalled_n")
    unmatched_ids = recall.get("unmatched_ids")
    if not isinstance(unmatched_ids, list):
        errors.append("recall.unmatched_ids must be a list")
    elif (
        expected_n is not None
        and recalled_n is not None
        and len(unmatched_ids) != expected_n - recalled_n
    ):
        errors.append("recall.unmatched_ids length must equal expected_n - recalled_n")
    if (
        finding_count is not None
        and recalled_n is not None
        and finding_count < recalled_n
    ):
        errors.append("run.finding_count must be >= recall.recalled_n")

    if nested(data, "readiness", "readiness_state") != "READY_FOR_EXPERT_REVIEW":
        errors.append("readiness.readiness_state must be READY_FOR_EXPERT_REVIEW")
    if nested(data, "readiness", "blockers") != []:
        errors.append("readiness.blockers must be empty")
    if nested(data, "readiness", "customer_releasable") is not False:
        errors.append("readiness.customer_releasable must be false")

    artifacts = data.get("artifacts")
    if not isinstance(artifacts, dict):
        errors.append("artifacts must be an object")
        artifacts = {}
    for key in (
        "verdict_sha256",
        "run_manifest_sha256",
        "manifest_verify_sha256",
        "recall_score_sha256",
        "merkle_root_hex",
    ):
        value = str(artifacts.get(key) or "")
        if not HEX64.fullmatch(value):
            errors.append(f"artifacts.{key} must be a lowercase sha256/merkle hex")
    for key in ("readiness_summary_sha256", "readiness_packet_zip_sha256"):
        value = artifacts.get(key)
        if value is not None and not HEX64.fullmatch(str(value)):
            errors.append(f"artifacts.{key} must be a lowercase sha256 when present")
    if artifacts.get("manifest_verify_overall") is not True:
        errors.append("artifacts.manifest_verify_overall must be true")
    if positive_int(artifacts.get("manifest_leaf_count")) is None:
        errors.append("artifacts.manifest_leaf_count must be positive")

    commands = data.get("verification_commands")
    if not isinstance(commands, list) or not commands:
        errors.append("verification_commands must be a non-empty list")

    return errors


def benchmark_verdict(data: dict[str, Any]) -> dict[str, Any]:
    run = data["run"]
    recall = data["recall"]
    return {
        "fixture": data["fixture"],
        "findings_matched": recall["recalled_n"],
        "run_finding_count": run["finding_count"],
        "finding_count": run["finding_count"],
        "findings_expected": data.get("findings_expected", ""),
        "verdict": run.get("verdict", ""),
        "verdict_correct": data.get("verdict_correct", ""),
        "wall_clock_seconds": data.get("wall_clock_seconds", ""),
        "manifest_verify_overall": data["artifacts"].get("manifest_verify_overall", ""),
        "run_duration_seconds": data.get("run_duration_seconds", ""),
        "contradictions_found": data.get("contradictions_found", 0),
        "contradictions_auto_resolved": data.get("contradictions_auto_resolved", 0),
        "source": data.get("evidence_kind", "local-l3-fallback"),
        "local_l3_evidence": data,
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--emit", type=Path, help="write benchmark verdict JSON")
    parser.add_argument("--expected-commit", help="expected product commit SHA")
    args = parser.parse_args(argv)

    try:
        data = json.loads(args.evidence.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[l3-evidence] invalid evidence file: {exc}", file=sys.stderr)
        return 2
    if not isinstance(data, dict):
        print("[l3-evidence] evidence root must be an object", file=sys.stderr)
        return 2

    errors = validate_evidence(data, expected_commit=args.expected_commit)
    if errors:
        for error in errors:
            print(f"[l3-evidence] ERROR: {error}", file=sys.stderr)
        return 1

    if args.emit:
        args.emit.parent.mkdir(parents=True, exist_ok=True)
        args.emit.write_text(
            json.dumps(benchmark_verdict(data), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(f"[l3-evidence] emitted {args.emit}")
    print(
        "[l3-evidence] PASS: local L3 evidence validates "
        f"({data['fixture']}, findings={data['run']['finding_count']})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
