#!/usr/bin/env python3
"""Regression smoke for scripts/trace-finding tamper detection."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent
TRACE = REPO / "scripts" / "trace-finding"

_CANONICAL_SEPARATORS = (",", ":")


def _canonicalize(obj: object) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=_CANONICAL_SEPARATORS, ensure_ascii=True
    ).encode("ascii")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write_sample_run(run_dir: Path) -> None:
    """Create the smallest run that trace-finding should accept.

    The fixture has one tool call, one approved finding, a verdict artifact hash,
    and a manifest that closes over the audit chain. Tamper cases below then
    mutate this run exactly as they would mutate a committed sample packet.
    """
    run_dir.mkdir(parents=True, exist_ok=True)
    verdict = {
        "case_id": "trace-smoke",
        "verdict": "SUSPICIOUS",
        "findings": [
            {
                "finding_id": "f-trace-smoke",
                "confidence": "CONFIRMED",
                "tool_call_id": "tc-evtx-1",
                "mitre_technique": "T1070.001",
                "description": "Windows Security event log clear event observed.",
            }
        ],
    }
    verdict_bytes = _canonicalize(verdict) + b"\n"
    (run_dir / "verdict.json").write_bytes(verdict_bytes)

    records: list[dict[str, object]] = []
    prev_hash = ""
    for kind, payload in (
        (
            "tool_call_start",
            {
                "tool": "evtx_query",
                "tool_call_id": "tc-evtx-1",
                "args": {"case_id": "trace-smoke", "eids": [1102]},
            },
        ),
        (
            "tool_call_output",
            {
                "tool": "evtx_query",
                "tool_call_id": "tc-evtx-1",
                "output_hash": "a" * 64,
            },
        ),
        (
            "finding_approved",
            {"finding_id": "f-trace-smoke", "finding": verdict["findings"][0]},
        ),
        (
            "verdict_artifact",
            {"path": "verdict.json", "sha256": _sha256(verdict_bytes)},
        ),
    ):
        record = {
            "kind": kind,
            "payload": payload,
            "prev_hash": prev_hash,
            "seq": len(records),
            "ts": "2026-06-14T00:00:00Z",
        }
        raw = _canonicalize(record)
        records.append(record)
        prev_hash = _sha256(raw)

    audit_path = run_dir / "audit.jsonl"
    audit_path.write_bytes(
        b"\n".join(_canonicalize(record) for record in records) + b"\n"
    )
    manifest = {
        "audit_log_final_hash": prev_hash,
        "audit_log_record_count": len(records),
        "leaves": [
            {"record_id": "tc-evtx-1", "kind": "tool_call_output"},
            {"record_id": "f-trace-smoke", "kind": "finding_approved"},
        ],
    }
    (run_dir / "run.manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _run_trace(run_dir: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(TRACE), str(run_dir)],
        cwd=REPO,
        text=True,
        capture_output=True,
        check=False,
    )


def _tamper_verdict(run_dir: Path) -> None:
    verdict_path = run_dir / "verdict.json"
    verdict = json.loads(verdict_path.read_text(encoding="utf-8"))
    findings = verdict.get("findings") or []
    if not findings:
        raise RuntimeError("sample verdict has no findings to tamper")
    cloned = dict(findings[0])
    cloned["finding_id"] = "tampered-reused-tool-call"
    cloned["description"] = "tampered finding that reuses a real tool_call_id"
    verdict["findings"] = [*findings, cloned]
    verdict_path.write_text(
        json.dumps(verdict, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _tamper_manifest_final_hash(run_dir: Path) -> None:
    manifest_path = run_dir / "run.manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["audit_log_final_hash"] = "f" * 64
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _write_malformed_manifest(run_dir: Path) -> None:
    (run_dir / "run.manifest.json").write_text("{\n", encoding="utf-8")


def _write_semantically_malformed_manifest(run_dir: Path) -> None:
    manifest_path = run_dir / "run.manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["leaves"] = ["not-object"]
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _write_non_list_manifest_leaves(run_dir: Path) -> None:
    manifest_path = run_dir / "run.manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["leaves"] = "not-list"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="trace-finding-smoke-") as tmp:
        run_dir = Path(tmp) / "run"
        _write_sample_run(run_dir)

        baseline = _run_trace(run_dir)
        if baseline.returncode != 0:
            print("baseline trace unexpectedly failed", file=sys.stderr)
            print(baseline.stdout, file=sys.stderr)
            print(baseline.stderr, file=sys.stderr)
            return 1

        manifest_run = Path(tmp) / "manifest-run"
        shutil.copytree(run_dir, manifest_run)
        _tamper_manifest_final_hash(manifest_run)
        manifest_tampered = _run_trace(manifest_run)
        if manifest_tampered.returncode == 0:
            print("tampered manifest unexpectedly traced successfully", file=sys.stderr)
            print(manifest_tampered.stdout, file=sys.stderr)
            print(manifest_tampered.stderr, file=sys.stderr)
            return 1
        if "manifest:    BROKEN" not in manifest_tampered.stdout:
            print("tampered manifest failed without BROKEN diagnostic", file=sys.stderr)
            print(manifest_tampered.stdout, file=sys.stderr)
            print(manifest_tampered.stderr, file=sys.stderr)
            return 1

        malformed_manifest_run = Path(tmp) / "malformed-manifest-run"
        shutil.copytree(run_dir, malformed_manifest_run)
        _write_malformed_manifest(malformed_manifest_run)
        malformed_manifest = _run_trace(malformed_manifest_run)
        if malformed_manifest.returncode == 0:
            print(
                "malformed manifest unexpectedly traced successfully", file=sys.stderr
            )
            print(malformed_manifest.stdout, file=sys.stderr)
            print(malformed_manifest.stderr, file=sys.stderr)
            return 1
        if "manifest:    BROKEN -- invalid JSON" not in malformed_manifest.stdout:
            print(
                "malformed manifest failed without invalid JSON diagnostic",
                file=sys.stderr,
            )
            print(malformed_manifest.stdout, file=sys.stderr)
            print(malformed_manifest.stderr, file=sys.stderr)
            return 1

        semantic_manifest_run = Path(tmp) / "semantic-manifest-run"
        shutil.copytree(run_dir, semantic_manifest_run)
        _write_semantically_malformed_manifest(semantic_manifest_run)
        semantic_manifest = _run_trace(semantic_manifest_run)
        if semantic_manifest.returncode == 0:
            print(
                "semantically malformed manifest unexpectedly traced successfully",
                file=sys.stderr,
            )
            print(semantic_manifest.stdout, file=sys.stderr)
            print(semantic_manifest.stderr, file=sys.stderr)
            return 1
        if (
            "manifest:    BROKEN -- manifest leaf 0 is not an object"
            not in semantic_manifest.stdout
        ):
            print(
                "semantically malformed manifest failed without leaf diagnostic",
                file=sys.stderr,
            )
            print(semantic_manifest.stdout, file=sys.stderr)
            print(semantic_manifest.stderr, file=sys.stderr)
            return 1

        non_list_leaves_run = Path(tmp) / "non-list-leaves-run"
        shutil.copytree(run_dir, non_list_leaves_run)
        _write_non_list_manifest_leaves(non_list_leaves_run)
        non_list_leaves = _run_trace(non_list_leaves_run)
        if non_list_leaves.returncode == 0:
            print(
                "non-list manifest leaves unexpectedly traced successfully",
                file=sys.stderr,
            )
            print(non_list_leaves.stdout, file=sys.stderr)
            print(non_list_leaves.stderr, file=sys.stderr)
            return 1
        if (
            "manifest:    BROKEN -- manifest leaves is not a list"
            not in non_list_leaves.stdout
        ):
            print(
                "non-list manifest leaves failed without leaves diagnostic",
                file=sys.stderr,
            )
            print(non_list_leaves.stdout, file=sys.stderr)
            print(non_list_leaves.stderr, file=sys.stderr)
            return 1

        _tamper_verdict(run_dir)
        tampered = _run_trace(run_dir)
        if tampered.returncode == 0:
            print("tampered verdict unexpectedly traced successfully", file=sys.stderr)
            print(tampered.stdout, file=sys.stderr)
            print(tampered.stderr, file=sys.stderr)
            return 1

    print("trace-finding-smoke: tampered verdict and manifest rejected")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
