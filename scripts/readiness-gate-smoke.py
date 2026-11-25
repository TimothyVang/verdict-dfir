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
from findevil_agent.crypto.signer import LocalEd25519Signer, StubSigner  # noqa: E402


def powershell() -> str | None:
    return shutil.which("powershell") or shutil.which("pwsh")


def json_bytes(data: dict) -> bytes:
    return json.dumps(data, indent=2, sort_keys=True).encode("utf-8")


def write_json(path: Path, data: dict) -> None:
    path.write_bytes(json_bytes(data))


def hash_json(data: dict) -> str:
    return hashlib.sha256(
        json.dumps(data, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).hexdigest()


def make_run(
    root: Path,
    *,
    manifest_overall: bool = True,
    customer_releasable: bool = False,
    cryptographic_signature: bool = True,
    findings: list[dict] | None = None,
    verifier_evidence_ids: list[str] | None = None,
    split_verifier_evidence_id: str | None = None,
    verdict_artifact_sha256: str | None = None,
    tamper_finding_approved: bool = False,
    tool_output_hash: str = "c" * 64,
) -> Path:
    run = root / "case-ready"
    run.mkdir(parents=True)
    report_qa = {
        "status": "PASS",
        "packet_state": "CUSTOMER_RELEASE_CANDIDATE",
        "ready_for_expert_signoff": True,
        "customer_releasable": False,
        "checks": [],
    }
    verdict_obj = {
        "case_id": "case-ready",
        "run_id": "run-ready",
        "verdict": "NO_EVIL",
        "findings": findings or [],
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
    }
    verdict_sha256 = hashlib.sha256(json_bytes(verdict_obj)).hexdigest()
    audit = AuditLog(run / "audit.jsonl")
    audit.append("report_qa", {"status": "PASS"})
    audit.append("customer_release_gate", {"customer_releasable": False})
    audit.append(
        "verdict_artifact",
        {"path": "verdict.json", "sha256": verdict_artifact_sha256 or verdict_sha256},
    )
    audit.append("expert_signoff_packet", {"expert_signoff_sha256": "b" * 64})
    audit.append(
        "tool_call_start",
        {"tool_call_id": "tc-ready", "tool": "evtx_query"},
    )
    audit.append(
        "tool_call_output",
        {"tool_call_id": "tc-ready", "output_hash": tool_output_hash},
    )
    verifier_ids = set(verifier_evidence_ids or [])
    for finding in findings or []:
        finding_id = str(finding.get("finding_id") or "")
        if finding_id not in verifier_ids:
            continue
        approved_finding = (
            {**finding, "description": "Audit-approved original finding."}
            if tamper_finding_approved
            else finding
        )
        audit.append(
            "finding_approved",
            {
                "finding_id": finding_id,
                "confidence": approved_finding.get("confidence"),
                "tool_call_id": approved_finding.get("tool_call_id"),
                "finding_sha256": hash_json(approved_finding),
                "finding": approved_finding,
            },
        )
    for finding_id in verifier_evidence_ids or []:
        audit.append(
            "verifier_action",
            {
                "finding_id": finding_id,
                "action": "approved",
                "reason": "readiness smoke replay matched",
                "replay_record_sha256": "d" * 64,
            },
        )
        audit.append(
            "replay",
            {
                "finding_id": finding_id,
                "replay_matched": True,
                "replay_record_sha256": "d" * 64,
            },
        )
        audit.append(
            "acp_handoff",
            {
                "from_role": "verifier",
                "to_role": "judge",
                "correlation_id": finding_id,
                "payload": {
                    "finding_id": finding_id,
                    "action": "approved",
                    "replay_record_sha256": "d" * 64,
                },
            },
        )
    if split_verifier_evidence_id is not None:
        audit.append(
            "verifier_action",
            {
                "finding_id": split_verifier_evidence_id,
                "action": "approved",
                "reason": "hash matches replay but action does not match handoff",
                "replay_record_sha256": "c" * 64,
            },
        )
        audit.append(
            "verifier_action",
            {
                "finding_id": split_verifier_evidence_id,
                "action": "downgraded",
                "reason": "action matches handoff but hash does not match replay",
                "replay_record_sha256": "e" * 64,
            },
        )
        audit.append(
            "replay",
            {
                "finding_id": split_verifier_evidence_id,
                "replay_matched": True,
                "replay_record_sha256": "c" * 64,
            },
        )
        audit.append(
            "acp_handoff",
            {
                "from_role": "verifier",
                "to_role": "judge",
                "correlation_id": split_verifier_evidence_id,
                "payload": {
                    "finding_id": split_verifier_evidence_id,
                    "action": "downgraded",
                    "replay_record_sha256": "c" * 64,
                },
            },
        )
    manifest = build_manifest(
        case_id="case-ready",
        run_id="run-ready",
        started_at="2026-05-10T00:00:00Z",
        audit_log=audit,
        signer=(
            LocalEd25519Signer(root / "signing.key")
            if cryptographic_signature
            else StubSigner(run_id="run-ready")
        ),
        extra={"image_path": "synthetic"},
    )
    manifest_path = write_manifest(manifest, run / "run.manifest.json")
    if not manifest_overall:
        manifest_obj = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest_obj["merkle_root_hex"] = "f" * 64
        write_json(manifest_path, manifest_obj)
    write_json(run / "verdict.json", verdict_obj)
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
    write_json(
        run / "coverage_manifest.json",
        {
            "summary": {"parsed": 1, "unsupported": 0},
            "truth_boundary": "synthetic coverage sidecar",
        },
    )
    write_json(
        run / "evidence_inventory.json",
        {
            "parent_case_id": "case-ready",
            "summary": {"supported": 1, "unsupported": 0},
        },
    )
    write_json(run / "disk_artifact_summary.json", {"prefetch": {"parsed": 1}})
    write_json(run / "psscan.json", {"processes": []})
    write_json(run / "psxview.json", {"rows": []})
    write_json(run / "malfind.json", {"hits": []})
    write_json(run / "malware_triage.json", {"aggregate_iocs": {}})
    write_json(run / "automation.json", {"actions": []})
    write_json(run / "self-score.json", {"score": 0})
    write_json(run / "recall-score.json", {"score": 0})
    write_json(run / "grounding.json", {"judged_by": "synthetic smoke"})
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
    (run / "REPORT-internal.md").write_text(
        "# Internal QA packet\n\nSynthetic smoke packet.\n",
        encoding="utf-8",
    )
    (run / "REPORT.new.pdf").write_bytes(b"%PDF-1.7\n% synthetic fallback\n")
    (run / "REPORT-internal.new.pdf").write_bytes(
        b"%PDF-1.7\n% synthetic internal fallback\n"
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


def assert_packet_metadata_sanitized(
    summary: dict, forbidden_paths: list[Path]
) -> None:
    packet_zip = Path(summary["packet_zip"])
    forbidden = [str(path).replace("\\", "/") for path in forbidden_paths]
    with zipfile.ZipFile(packet_zip) as zf:
        for member in [name for name in zf.namelist() if name.endswith(".json")]:
            text = zf.read(member).decode("utf-8").replace("\\", "/")
            leaked = [path for path in forbidden if path and path in text]
            if leaked:
                raise SystemExit(f"packet metadata leaked local path in {member}")


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
        assert_packet_metadata_sanitized(summary, [REPO, tmp, ready_run, out])
        packet_manifest = json.loads(Path(summary["packet_manifest"]).read_text())
        packet_paths = {row["path"] for row in packet_manifest["artifacts"]}
        for required in {
            "audit.jsonl",
            "run.manifest.json",
            "manifest_verify.json",
            "verdict.json",
            "coverage_manifest.json",
            "evidence_inventory.json",
            "disk_artifact_summary.json",
            "psscan.json",
            "psxview.json",
            "malfind.json",
            "malware_triage.json",
            "automation.json",
            "self-score.json",
            "recall-score.json",
            "grounding.json",
            "REPORT.html",
            "REPORT.new.pdf",
            "REPORT-internal.md",
            "REPORT-internal.new.pdf",
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

        bound_finding = {
            "finding_id": "f-ready",
            "tool_call_id": "tc-ready",
            "confidence": "CONFIRMED",
            "description": "Audit-bound final finding.",
        }
        bound_finding_run = make_run(
            tmp / "bound-finding",
            manifest_overall=True,
            findings=[bound_finding],
            verifier_evidence_ids=["f-ready"],
        )
        bound_finding_result = run_gate(ps, bound_finding_run, out, "bound-finding")
        if bound_finding_result.returncode != 0:
            print(bound_finding_result.stdout)
            print(bound_finding_result.stderr, file=sys.stderr)
            raise SystemExit("bound-finding readiness gate unexpectedly failed")

        invalid_output_hash_run = make_run(
            tmp / "invalid-output-hash",
            manifest_overall=True,
            findings=[bound_finding],
            verifier_evidence_ids=["f-ready"],
            tool_output_hash="not-a-sha256",
        )
        invalid_output_hash = run_gate(
            ps, invalid_output_hash_run, out, "invalid-output-hash"
        )
        if invalid_output_hash.returncode == 0:
            raise SystemExit("invalid-output-hash readiness gate unexpectedly passed")

        tampered_verdict_artifact_run = make_run(
            tmp / "tampered-verdict-artifact",
            manifest_overall=True,
            verdict_artifact_sha256="0" * 64,
        )
        tampered_verdict_artifact = run_gate(
            ps,
            tampered_verdict_artifact_run,
            out,
            "tampered-verdict-artifact",
        )
        if tampered_verdict_artifact.returncode == 0:
            raise SystemExit(
                "tampered-verdict-artifact readiness gate unexpectedly passed"
            )

        tampered_finding_approved_run = make_run(
            tmp / "tampered-finding-approved",
            manifest_overall=True,
            findings=[bound_finding],
            verifier_evidence_ids=["f-ready"],
            tamper_finding_approved=True,
        )
        tampered_finding_approved = run_gate(
            ps,
            tampered_finding_approved_run,
            out,
            "tampered-finding-approved",
        )
        if tampered_finding_approved.returncode == 0:
            raise SystemExit(
                "tampered-finding-approved readiness gate unexpectedly passed"
            )

        stub_signature_run = make_run(
            tmp / "stub-signature",
            manifest_overall=True,
            cryptographic_signature=False,
        )
        stub_signature = run_gate(ps, stub_signature_run, out, "stub-signature")
        if stub_signature.returncode == 0:
            raise SystemExit("stub-signature readiness gate unexpectedly passed")

        mismatched_verifier_run = make_run(
            tmp / "mismatched-verifier",
            manifest_overall=True,
            findings=[
                {
                    "finding_id": "f-ready",
                    "tool_call_id": "tc-ready",
                    "confidence": "CONFIRMED",
                    "description": "Final finding needs matching verifier evidence.",
                }
            ],
            verifier_evidence_ids=["f-other"],
        )
        mismatched_verifier = run_gate(
            ps, mismatched_verifier_run, out, "mismatched-verifier"
        )
        if mismatched_verifier.returncode == 0:
            raise SystemExit("mismatched-verifier readiness gate unexpectedly passed")

        split_verifier_run = make_run(
            tmp / "split-verifier",
            manifest_overall=True,
            findings=[
                {
                    "finding_id": "f-ready",
                    "tool_call_id": "tc-ready",
                    "confidence": "CONFIRMED",
                    "description": "Final finding needs one bound verifier action/replay pair.",
                }
            ],
            split_verifier_evidence_id="f-ready",
        )
        split_verifier = run_gate(ps, split_verifier_run, out, "split-verifier")
        if split_verifier.returncode == 0:
            raise SystemExit("split-verifier readiness gate unexpectedly passed")

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
