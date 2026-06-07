#!/usr/bin/env python3
"""Smoke-test the Windows readiness gate without real SIFT evidence.

The smoke builds a synthetic completed run directory that has the packet-level
artifacts the gate requires, runs PacketOnly mode, and verifies that the gate
packages the run as PACKET_READY_FOR_EXPERT_REVIEW without setting customer-ready.
It also checks that manifest verification failures are fail-closed.
"""

from __future__ import annotations

import json
import hashlib
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import zipfile


REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "services" / "agent"))

from findevil_agent.crypto.audit_log import AuditLog  # noqa: E402
from findevil_agent.crypto.manifest import build_manifest, write_manifest  # noqa: E402
from findevil_agent.crypto.signer import StubSigner  # noqa: E402


def powershell() -> str | None:
    return shutil.which("powershell") or shutil.which("pwsh")


def write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def make_run(
    root: Path, *, manifest_overall: bool = True, customer_releasable: bool = False
) -> Path:
    run = root / "case-ready"
    run.mkdir(parents=True)
    audit = AuditLog(run / "audit.jsonl")
    audit.append("report_qa", {"status": "PASS"})
    audit.append("customer_release_gate", {"customer_releasable": False})
    audit.append("verdict_artifact", {"path": "verdict.json", "sha256": "a" * 64})
    audit.append("expert_signoff_packet", {"expert_signoff_sha256": "b" * 64})
    audit.append(
        "tool_call_output",
        {"tool_call_id": "tc-ready", "output_hash": "c" * 64},
    )
    manifest = build_manifest(
        case_id="case-ready",
        run_id="run-ready",
        started_at="2026-05-10T00:00:00Z",
        audit_log=audit,
        signer=StubSigner(run_id="run-ready"),
        extra={"image_path": "synthetic"},
    )
    manifest_path = write_manifest(manifest, run / "run.manifest.json")
    if not manifest_overall:
        manifest_obj = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest_obj["merkle_root_hex"] = "f" * 64
        write_json(manifest_path, manifest_obj)
    report_qa = {
        "status": "PASS",
        "packet_state": "CUSTOMER_RELEASE_CANDIDATE",
        "ready_for_expert_signoff": True,
        "customer_releasable": False,
        "checks": [],
    }
    write_json(
        run / "verdict.json",
        {
            "case_id": "case-ready",
            "run_id": "run-ready",
            "verdict": "NO_EVIL",
            "report_qa": report_qa,
            "release_gate": {
                "manifest_verified": manifest_overall,
                "expert_decision": "pending",
                "customer_releasable": customer_releasable,
            },
            "expert_signoff": {
                "status": "PENDING_EXPERT_REVIEW",
                "expert_decision": "pending",
                "customer_releasable": customer_releasable,
            },
        },
    )
    write_json(
        run / "manifest_verify.json",
        {"overall": manifest_overall, "signature_present": True},
    )
    write_json(
        run / "expert_signoff.json",
        {
            "status": "PENDING_EXPERT_REVIEW",
            "decision": "pending",
            "customer_releasable": customer_releasable,
        },
    )
    write_json(
        run / "customer_release_gate.final.json",
        {
            "manifest_verified": manifest_overall,
            "expert_decision": "pending",
            "customer_releasable": customer_releasable,
        },
    )
    (run / "REPORT.html").write_text(
        "<!doctype html><html><body><h1>Find Evil Report</h1>"
        "<p>Cryptographic attestation. QA / Expert Signoff. "
        "Customer Release Gate. Findings Summary. tool_call_id. "
        "Chain of Custody. Limitations.</p>"
        "<p>Signer: <code>stub</code>; stub signatures are dev/offline only.</p>"
        "<p>customer-ready reports must embed verifier replay evidence.</p>"
        "</body></html>",
        encoding="utf-8",
    )
    (run / "REPORT.md").write_text(
        "# Find Evil Report\n\n"
        "* Signer: `stub`\n"
        "* customer release requires manifest_finalize signer=sigstore; "
        "stub signatures are dev/offline only\n\n"
        "customer-ready reports must embed verifier replay evidence.\n",
        encoding="utf-8",
    )
    return run


def run_gate(
    ps: str, run_dir: Path, out: Path, run_id: str
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            ps,
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(REPO / "scripts" / "readiness-gate.ps1"),
            "-Mode",
            "PacketOnly",
            "-ExistingRunDir",
            str(run_dir),
            "-OutputRoot",
            str(out),
            "-RunId",
            run_id,
        ],
        cwd=REPO,
        text=True,
        capture_output=True,
        timeout=120,
    )


def run_gate_without_run_dir(
    ps: str, out: Path, run_id: str
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            ps,
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(REPO / "scripts" / "readiness-gate.ps1"),
            "-Mode",
            "PacketOnly",
            "-OutputRoot",
            str(out),
            "-RunId",
            run_id,
        ],
        cwd=REPO,
        text=True,
        capture_output=True,
        timeout=120,
    )


def assert_zip_hashes(summary: dict) -> None:
    packet_zip = Path(summary["packet_zip"])
    with zipfile.ZipFile(packet_zip) as zf:
        names = {name.rstrip("/") for name in zf.namelist()}
        for required in {"readiness-summary.json", "readiness-packet-manifest.json"}:
            if required not in names:
                raise SystemExit(f"packet ZIP missing {required}")
        manifest = json.loads(zf.read("readiness-packet-manifest.json"))
        for artifact in manifest["artifacts"]:
            path = artifact["path"]
            if path not in names:
                raise SystemExit(f"packet ZIP missing manifest-listed artifact {path}")
            actual = hashlib.sha256(zf.read(path)).hexdigest()
            if actual != artifact["sha256"]:
                raise SystemExit(f"packet ZIP hash mismatch for {path}")


def main() -> int:
    ps = powershell()
    if ps is None:
        print("SKIP: powershell/pwsh not found")
        return 0
    with tempfile.TemporaryDirectory(prefix="findevil-ready-") as tmp_s:
        tmp = Path(tmp_s)
        out = tmp / "out"

        ready_run = make_run(tmp / "positive", manifest_overall=True)
        positive = run_gate(ps, ready_run, out, "positive")
        if positive.returncode != 0:
            print(positive.stdout)
            print(positive.stderr, file=sys.stderr)
            raise SystemExit("positive readiness gate smoke failed")
        summary = json.loads((out / "positive" / "readiness-summary.json").read_text())
        if summary["readiness_state"] != "PACKET_READY_FOR_EXPERT_REVIEW":
            raise SystemExit(
                f"unexpected readiness_state: {summary['readiness_state']}"
            )
        if summary["customer_releasable"] is not False:
            raise SystemExit("readiness gate must not mark customer_releasable")
        if not Path(summary["packet_zip"]).is_file():
            raise SystemExit("packet ZIP missing")
        assert_zip_hashes(summary)
        packet_manifest = json.loads(Path(summary["packet_manifest"]).read_text())
        packet_paths = {row["path"] for row in packet_manifest["artifacts"]}
        for required in {
            "audit.jsonl",
            "run.manifest.json",
            "manifest_verify.json",
            "verdict.json",
            "REPORT.html",
            "readiness-summary.json",
            "expert_signoff.json",
            "customer_release_gate.final.json",
        }:
            if required not in packet_paths:
                raise SystemExit(f"packet manifest missing {required}")

        repeat_first = run_gate(ps, ready_run, out, "repeat-run-id")
        if repeat_first.returncode != 0:
            print(repeat_first.stdout)
            print(repeat_first.stderr, file=sys.stderr)
            raise SystemExit("repeat-run-id first gate run failed")
        repeat_run = make_run(tmp / "repeat", manifest_overall=True)
        (repeat_run / "REPORT.md").unlink()
        repeat_second = run_gate(ps, repeat_run, out, "repeat-run-id")
        if repeat_second.returncode != 0:
            print(repeat_second.stdout)
            print(repeat_second.stderr, file=sys.stderr)
            raise SystemExit("repeat-run-id second gate run failed")
        repeat_summary = json.loads(
            (out / "repeat-run-id" / "readiness-summary.json").read_text()
        )
        repeat_manifest = json.loads(
            Path(repeat_summary["packet_manifest"]).read_text()
        )
        repeat_paths = {row["path"] for row in repeat_manifest["artifacts"]}
        if "REPORT.md" in repeat_paths:
            raise SystemExit("repeat RunId packet retained stale REPORT.md")

        blocked_run = make_run(tmp / "negative", manifest_overall=False)
        negative = run_gate(ps, blocked_run, out, "negative")
        if negative.returncode == 0:
            raise SystemExit("negative readiness gate smoke unexpectedly passed")
        negative_summary = json.loads(
            (out / "negative" / "readiness-summary.json").read_text()
        )
        if negative_summary["readiness_state"] != "READINESS_BLOCKED":
            raise SystemExit("negative run did not record READINESS_BLOCKED")

        missing = run_gate_without_run_dir(ps, out, "missing-run-dir")
        if missing.returncode == 0:
            raise SystemExit("PacketOnly without ExistingRunDir unexpectedly passed")
        missing_summary_path = out / "missing-run-dir" / "readiness-summary.json"
        if not missing_summary_path.is_file():
            print(missing.stdout)
            print(missing.stderr, file=sys.stderr)
            raise SystemExit("missing-run-dir did not write readiness-summary.json")
        missing_summary = json.loads(missing_summary_path.read_text())
        if missing_summary["readiness_state"] != "READINESS_BLOCKED":
            raise SystemExit("missing run dir did not record READINESS_BLOCKED")
        if not missing_summary["blockers"]:
            raise SystemExit("missing run dir did not record blockers")

        releasable_run = make_run(
            tmp / "customer-ready-claim",
            manifest_overall=True,
            customer_releasable=True,
        )
        releasable = run_gate(ps, releasable_run, out, "customer-ready-claim")
        if releasable.returncode == 0:
            raise SystemExit("customer_releasable packet unexpectedly passed")

        zip_fail_run = make_run(tmp / "zip-failure", manifest_overall=True)
        zip_fail_dir = out / "zip-failure" / "readiness-packet.zip"
        zip_fail_dir.mkdir(parents=True)
        zip_failure = run_gate(ps, zip_fail_run, out, "zip-failure")
        if zip_failure.returncode == 0:
            raise SystemExit("packet ZIP failure unexpectedly passed")
        zip_failure_summary = json.loads(
            (out / "zip-failure" / "readiness-summary.json").read_text()
        )
        if zip_failure_summary["readiness_state"] != "READINESS_BLOCKED":
            raise SystemExit("zip failure did not record READINESS_BLOCKED")

    print("readiness-gate-smoke: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
