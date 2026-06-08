#!/usr/bin/env python3
"""Validate Devpost/release artifacts for final submission.

Strict validation is the default. Smoke packages may be generated for workflow
rehearsal, but final ``v-submit`` assets must pass these checks with no stubs,
placeholders, or header-only benchmark files.
"""

from __future__ import annotations

import argparse
import csv
from dataclasses import dataclass
import hashlib
import io
import json
import re
from pathlib import Path
from urllib.parse import urlparse
import zipfile

REQUIRED_ZIP_FILES = {
    "README-submission.md",
    "benchmark-results.csv",
    "demo-video-link.txt",
    "LICENSE",
    "report.html",
}

PLACEHOLDER_PATTERNS = (
    "placeholder",
    "stub",
    "pre-release",
    "pre-week",
    "pending-record",
    "<your",
    "<id>",
    "todo",
    "changeme",
)

READINESS_REQUIRED_ARTIFACTS = {
    "audit.jsonl",
    "run.manifest.json",
    "manifest_verify.json",
    "verdict.json",
    "expert_signoff.json",
    "customer_release_gate.final.json",
}

READINESS_REQUIRED_AUDIT_KINDS = {
    "report_qa",
    "customer_release_gate",
    "verdict_artifact",
    "expert_signoff_packet",
}

READINESS_REPORT_ARTIFACTS = {"report.html", "report.pdf", "report.md"}
READINESS_ALLOWED_STATES = {"PACKET_READY_FOR_EXPERT_REVIEW", "READY_FOR_EXPERT_REVIEW"}
CUSTOMER_READY_STATES = {
    "CUSTOMER_READY",
    "READY_FOR_CUSTOMER_RELEASE",
    "CUSTOMER_RELEASE_READY",
    "CUSTOMER_RELEASABLE",
}


@dataclass
class CheckResult:
    ok: bool
    message: str


def is_placeholder_text(text: str) -> bool:
    return bool(placeholder_hits(text))


def placeholder_hits(text: str) -> list[str]:
    lowered = text.lower()
    return [pattern for pattern in PLACEHOLDER_PATTERNS if pattern in lowered]


def has_disclosed_stub_signer(text: str) -> bool:
    lowered = text.lower()
    return bool(
        re.search(r"stub\s+signatures\s+are\s+dev/offline\s+only", lowered)
        or "stubsigner" in lowered
        or "signer: `stub`" in lowered
        or ("signer:" in lowered and "<code>stub</code>" in lowered)
    )


def has_customer_ready_overclaim(text: str) -> bool:
    lowered = text.lower()
    # Doctrine/rule text can describe what customer-ready reports must prove
    # without claiming this packet is customer-ready.
    scoped = lowered.replace("customer-ready reports must", "")
    scoped = scoped.replace("customer ready reports must", "")
    return any(
        token in scoped
        for token in (
            "customer ready",
            "customer-ready",
            "customer_releasable: true",
        )
    )


def validate_demo_url(url: str | None) -> CheckResult:
    if not url:
        return CheckResult(False, "DEMO_VIDEO_URL is empty")
    parsed = urlparse(url.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return CheckResult(False, f"demo URL is not an absolute http(s) URL: {url!r}")
    if is_placeholder_text(url) or parsed.netloc in {
        "example.com",
        "example.invalid",
        "localhost",
    }:
        return CheckResult(False, f"demo URL looks like a placeholder: {url!r}")
    return CheckResult(True, "demo URL is real-looking")


def parse_positive_int(value: str | int | None) -> int | None:
    if value is None:
        return None
    try:
        parsed = int(str(value).strip())
    except ValueError:
        return None
    return parsed if parsed > 0 else None


def validate_benchmark(path: Path) -> CheckResult:
    if not path.is_file():
        return CheckResult(False, f"benchmark CSV missing: {path}")
    rows = read_csv_rows(path)
    if not rows:
        return CheckResult(False, "benchmark CSV has no data rows")
    if "fixture" not in rows[0] or "findings_matched" not in rows[0]:
        return CheckResult(
            False, "benchmark CSV missing fixture/findings_matched columns"
        )
    for row in rows:
        if row_is_positive_nist(row):
            return CheckResult(
                True,
                "benchmark CSV contains nist-hacking-case with findings_matched > 0",
            )
    return CheckResult(
        False, "benchmark CSV lacks nist-hacking-case row with findings_matched > 0"
    )


def read_csv_rows(path: Path) -> list[dict[str, str]]:
    last_error: UnicodeDecodeError | None = None
    for encoding in ("utf-8-sig", "utf-16"):
        try:
            with path.open(newline="", encoding=encoding) as fh:
                return list(csv.DictReader(fh))
        except UnicodeDecodeError as exc:
            last_error = exc
    if last_error is not None:
        raise last_error
    return []


def validate_report(path: Path) -> CheckResult:
    if not path.is_file():
        return CheckResult(False, f"report.html missing: {path}")
    text = path.read_text(encoding="utf-8", errors="replace")
    return validate_report_text(text)


def validate_report_text(text: str) -> CheckResult:
    if len(text) < 1500:
        return CheckResult(False, "report.html is too small to be substantive")
    lowered = text.lower()
    required_common = (
        "<html",
        "</html>",
        "verdict",
        "cryptographic attestation",
    )
    missing = [token for token in required_common if token not in lowered]
    if missing:
        return CheckResult(
            False, f"report.html missing required marker(s): {', '.join(missing)}"
        )
    offline_release = "verdict card" in lowered
    investigation_required = (
        "qa / expert signoff",
        "customer release gate",
        "findings",
        "chain of custody",
        "tool_call_id",
        "limitations",
    )
    missing_investigation = [
        token for token in investigation_required if token not in lowered
    ]
    if not offline_release and missing_investigation:
        return CheckResult(
            False,
            "investigation report missing required marker(s): "
            + ", ".join(missing_investigation),
        )

    hits = placeholder_hits(text)
    if "stub" in hits and has_disclosed_stub_signer(text):
        hits = [hit for hit in hits if hit != "stub"]
    if hits:
        return CheckResult(
            False, "report.html contains placeholder text: " + ", ".join(sorted(hits))
        )
    return CheckResult(True, "report.html is substantive and policy-complete")


def validate_stage_dir(path: Path) -> CheckResult:
    missing = sorted(name for name in REQUIRED_ZIP_FILES if not (path / name).is_file())
    if missing:
        return CheckResult(
            False, f"stage dir missing required file(s): {', '.join(missing)}"
        )
    readme = path / "README-submission.md"
    if re.search(
        r"\$\{[A-Z_]+\}", readme.read_text(encoding="utf-8", errors="replace")
    ):
        return CheckResult(
            False, "README-submission.md contains unsubstituted ${...} placeholder"
        )
    return CheckResult(True, "stage dir contains required files")


def validate_zip(path: Path) -> CheckResult:
    if not path.is_file():
        return CheckResult(False, f"submission zip missing: {path}")
    with zipfile.ZipFile(path) as zf:
        names = {name.rstrip("/") for name in zf.namelist()}
        missing = sorted(REQUIRED_ZIP_FILES - names)
        if missing:
            return CheckResult(
                False, f"zip missing required file(s): {', '.join(missing)}"
            )
        demo_url = (
            zf.read("demo-video-link.txt").decode("utf-8", errors="replace").strip()
        )
        demo_result = validate_demo_url(demo_url)
        if not demo_result.ok:
            return CheckResult(
                False, f"zip demo-video-link.txt invalid: {demo_result.message}"
            )
        with zf.open("benchmark-results.csv") as fh:
            rows = list(csv.DictReader(io.TextIOWrapper(fh, encoding="utf-8-sig")))
        if not rows:
            return CheckResult(False, "zip benchmark-results.csv has no data rows")
        if not any(row_is_positive_nist(row) for row in rows):
            return CheckResult(
                False, "zip benchmark-results.csv lacks positive nist-hacking-case row"
            )
        report = zf.read("report.html").decode("utf-8", errors="replace")
        report_result = validate_report_text(report)
        if not report_result.ok:
            return CheckResult(
                False, f"zip report.html invalid: {report_result.message}"
            )
    return CheckResult(True, "submission zip contains required non-placeholder assets")


def resolve_summary_path(summary_path: Path, value: object) -> Path | None:
    if not isinstance(value, str) or not value.strip():
        return None
    path = Path(value.strip())
    if not path.is_absolute():
        path = summary_path.parent / path
    return path


def read_json_file(path: Path, label: str, blockers: list[str]) -> dict | None:
    if not path.is_file():
        blockers.append(f"{label} missing: {path}")
        return None
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        blockers.append(f"{label} is not valid JSON: {path}: {exc}")
        return None
    if not isinstance(obj, dict):
        blockers.append(f"{label} must be a JSON object: {path}")
        return None
    return obj


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def artifact_entries(manifest: dict, blockers: list[str]) -> dict[str, dict]:
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        blockers.append("packet_manifest lacks artifacts list")
        return {}
    entries: dict[str, dict] = {}
    for index, artifact in enumerate(artifacts):
        if not isinstance(artifact, dict):
            blockers.append(f"packet_manifest artifact #{index} is not an object")
            continue
        raw_path = artifact.get("path")
        if not isinstance(raw_path, str) or not raw_path.strip():
            blockers.append(f"packet_manifest artifact #{index} lacks path")
            continue
        normalized = raw_path.replace("\\", "/").strip("/")
        entries[normalized] = artifact
    return entries


def artifact_path(packet_dir: Path, relative_path: str) -> Path:
    return packet_dir.joinpath(*relative_path.split("/"))


def read_artifact_text(packet_dir: Path, relative_path: str) -> str | None:
    path = artifact_path(packet_dir, relative_path)
    if not path.is_file():
        return None
    return path.read_text(encoding="utf-8", errors="replace")


def read_artifact_json(
    packet_dir: Path, relative_path: str, label: str, blockers: list[str]
) -> dict | None:
    path = artifact_path(packet_dir, relative_path)
    return read_json_file(path, label, blockers)


def add_customer_ready_blockers(obj: object, label: str, blockers: list[str]) -> None:
    if not isinstance(obj, dict):
        return
    customer_releasable = obj.get("customer_releasable")
    if customer_releasable is True:
        blockers.append(
            f"{label} marks customer_releasable=true; human expert release is required"
        )
    readiness_state = obj.get("readiness_state")
    if (
        isinstance(readiness_state, str)
        and readiness_state.upper() in CUSTOMER_READY_STATES
    ):
        blockers.append(f"{label} overclaims customer-ready state: {readiness_state}")
    expert_release_gate = obj.get("expert_release_gate")
    if isinstance(expert_release_gate, str) and is_placeholder_text(
        expert_release_gate
    ):
        blockers.append(f"{label} contains placeholder expert_release_gate text")
    decision = obj.get("decision") or obj.get("expert_decision")
    if isinstance(decision, str) and decision.lower() in {
        "approved",
        "approve",
        "released",
    }:
        signer = str(obj.get("signer") or obj.get("signature_kind") or "").lower()
        if "stub" in signer:
            blockers.append(f"{label} claims approved/released with stub signer")
    for nested_key in ("report_qa", "release_gate", "expert_signoff"):
        nested = obj.get(nested_key)
        if isinstance(nested, dict):
            add_customer_ready_blockers(nested, f"{label}.{nested_key}", blockers)


def validate_readiness_audit(packet_dir: Path, blockers: list[str]) -> None:
    path = artifact_path(packet_dir, "audit.jsonl")
    if not path.is_file():
        blockers.append(f"audit.jsonl missing from packet dir: {path}")
        return
    kinds: set[str] = set()
    line_count = 0
    try:
        with path.open(encoding="utf-8") as fh:
            for line_number, line in enumerate(fh, start=1):
                if not line.strip():
                    continue
                line_count += 1
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as exc:
                    blockers.append(
                        f"audit.jsonl line {line_number} is not valid JSON: {exc}"
                    )
                    continue
                if isinstance(record, dict) and isinstance(record.get("kind"), str):
                    kinds.add(record["kind"])
    except OSError as exc:
        blockers.append(f"audit.jsonl could not be read: {exc}")
        return
    if line_count == 0:
        blockers.append("audit.jsonl has no audit records")
    missing = sorted(READINESS_REQUIRED_AUDIT_KINDS - kinds)
    if missing:
        blockers.append(
            "audit.jsonl lacks required record kind(s): " + ", ".join(missing)
        )


def validate_readiness_summary(path: Path) -> CheckResult:
    blockers: list[str] = []
    summary = read_json_file(path, "readiness summary", blockers)
    if summary is None:
        return CheckResult(False, "; ".join(blockers))

    summary_blockers = summary.get("blockers")
    if isinstance(summary_blockers, list) and summary_blockers:
        blockers.append(
            "readiness summary already contains blocker(s): "
            + "; ".join(str(blocker) for blocker in summary_blockers)
        )
    readiness_state = summary.get("readiness_state")
    if readiness_state not in READINESS_ALLOWED_STATES:
        blockers.append(
            f"readiness_state is not expert-review ready: {readiness_state!r}"
        )
    add_customer_ready_blockers(summary, "readiness-summary.json", blockers)

    packet_zip = resolve_summary_path(path, summary.get("packet_zip"))
    packet_manifest = resolve_summary_path(path, summary.get("packet_manifest"))
    if packet_zip is None:
        blockers.append("readiness summary lacks packet_zip")
    elif not packet_zip.is_file():
        blockers.append(f"packet_zip missing: {packet_zip}")
    if packet_manifest is None:
        blockers.append("readiness summary lacks packet_manifest")
        return CheckResult(False, "; ".join(blockers))

    manifest = read_json_file(packet_manifest, "packet_manifest", blockers)
    if manifest is None:
        return CheckResult(False, "; ".join(blockers))
    if manifest.get("readiness_state") != readiness_state:
        blockers.append(
            "packet_manifest readiness_state does not match readiness summary: "
            f"{manifest.get('readiness_state')!r} != {readiness_state!r}"
        )
    entries = artifact_entries(manifest, blockers)
    packet_dir = (
        resolve_summary_path(path, summary.get("packet_dir")) or packet_manifest.parent
    )

    missing_artifacts = sorted(READINESS_REQUIRED_ARTIFACTS - set(entries))
    if missing_artifacts:
        blockers.append(
            "packet_manifest missing required artifact(s): "
            + ", ".join(missing_artifacts)
        )
    report_paths = sorted(
        artifact
        for artifact in entries
        if Path(artifact).name.lower() in READINESS_REPORT_ARTIFACTS
    )
    if not report_paths:
        blockers.append(
            "packet_manifest lacks report artifact; expected REPORT.html, REPORT.pdf, or REPORT.md"
        )

    for relative_path, artifact in entries.items():
        disk_path = artifact_path(packet_dir, relative_path)
        if not disk_path.is_file():
            blockers.append(
                f"packet artifact missing on disk: {relative_path} ({disk_path})"
            )
            continue
        expected_sha = artifact.get("sha256")
        if isinstance(expected_sha, str) and expected_sha:
            actual_sha = sha256_file(disk_path)
            if actual_sha.lower() != expected_sha.lower():
                blockers.append(f"packet artifact hash mismatch: {relative_path}")

    if packet_zip is not None and packet_zip.is_file():
        try:
            with zipfile.ZipFile(packet_zip) as zf:
                names = {name.rstrip("/") for name in zf.namelist()}
                required_zip_names = (
                    set(READINESS_REQUIRED_ARTIFACTS)
                    | set(report_paths)
                    | {
                        "readiness-summary.json",
                        "readiness-packet-manifest.json",
                    }
                )
                missing_zip = sorted(required_zip_names - names)
                if missing_zip:
                    blockers.append(
                        "packet_zip missing required file(s): " + ", ".join(missing_zip)
                    )
                for relative_path, artifact in entries.items():
                    if relative_path not in names:
                        continue
                    expected_sha = artifact.get("sha256")
                    if isinstance(expected_sha, str) and expected_sha:
                        actual_sha = hashlib.sha256(zf.read(relative_path)).hexdigest()
                        if actual_sha.lower() != expected_sha.lower():
                            blockers.append(
                                f"packet_zip hash mismatch: {relative_path}"
                            )
        except zipfile.BadZipFile:
            blockers.append(f"packet_zip is not a valid ZIP file: {packet_zip}")

    validate_readiness_audit(packet_dir, blockers)
    read_artifact_json(packet_dir, "run.manifest.json", "run.manifest.json", blockers)
    manifest_verify = read_artifact_json(
        packet_dir, "manifest_verify.json", "manifest_verify.json", blockers
    )
    if manifest_verify is not None and manifest_verify.get("overall") is not True:
        blockers.append("manifest_verify.json overall is not true")
    verdict = read_artifact_json(packet_dir, "verdict.json", "verdict.json", blockers)
    if verdict is not None:
        add_customer_ready_blockers(verdict, "verdict.json", blockers)
        report_qa = verdict.get("report_qa")
        if not isinstance(report_qa, dict):
            blockers.append("verdict.json lacks report_qa object")
        else:
            if report_qa.get("status") not in {"PASS", "WARN"}:
                blockers.append(
                    f"verdict.json report_qa status is not PASS/WARN: {report_qa.get('status')!r}"
                )
            if report_qa.get("ready_for_expert_signoff") is not True:
                blockers.append(
                    "verdict.json report_qa does not mark ready_for_expert_signoff=true"
                )
    for relative_path in ("expert_signoff.json", "customer_release_gate.final.json"):
        artifact_json = read_artifact_json(
            packet_dir, relative_path, relative_path, blockers
        )
        if artifact_json is not None:
            add_customer_ready_blockers(artifact_json, relative_path, blockers)

    for report_path in report_paths:
        if Path(report_path).suffix.lower() not in {".html", ".md", ".txt"}:
            continue
        text = read_artifact_text(packet_dir, report_path)
        if text is None:
            continue
        hits = placeholder_hits(text)
        if "stub" in hits and has_disclosed_stub_signer(text):
            hits = [hit for hit in hits if hit != "stub"]
        if hits:
            blockers.append(
                f"{report_path} contains placeholder text: " + ", ".join(sorted(hits))
            )
        if has_customer_ready_overclaim(text):
            blockers.append(
                f"{report_path} contains customer-ready/releasable overclaim"
            )

    if blockers:
        return CheckResult(False, "; ".join(blockers))
    return CheckResult(
        True, "readiness summary packet is complete and expert-review gated"
    )


def row_is_positive_nist(row: dict[str, str]) -> bool:
    source_name = Path(row.get("source_file") or "").name
    fixture = row.get("fixture") or ""
    is_nist = (
        fixture == "nist-hacking-case"
        or source_name == "nist-hacking-case-verdict.json"
    )
    return is_nist and bool(parse_positive_int(row.get("findings_matched")))


def report_result(name: str, result: CheckResult) -> bool:
    marker = "PASS" if result.ok else "FAIL"
    print(f"[{marker}] {name}: {result.message}")
    return result.ok


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate final submission artifacts")
    parser.add_argument("--demo-url", help="demo video URL to validate")
    parser.add_argument("--benchmark", type=Path, help="benchmark-results.csv path")
    parser.add_argument("--report", type=Path, help="report.html path")
    parser.add_argument("--stage-dir", type=Path, help="package staging directory")
    parser.add_argument(
        "--zip", dest="zip_path", type=Path, help="find-evil-submission.zip path"
    )
    parser.add_argument(
        "--readiness-summary", type=Path, help="readiness-summary.json path"
    )
    args = parser.parse_args()

    checks: list[tuple[str, CheckResult]] = []
    if args.demo_url is not None:
        checks.append(("demo-url", validate_demo_url(args.demo_url)))
    if args.benchmark is not None:
        checks.append(("benchmark", validate_benchmark(args.benchmark)))
    if args.report is not None:
        checks.append(("report", validate_report(args.report)))
    if args.stage_dir is not None:
        checks.append(("stage-dir", validate_stage_dir(args.stage_dir)))
    if args.zip_path is not None:
        checks.append(("zip", validate_zip(args.zip_path)))
    if args.readiness_summary is not None:
        checks.append(
            ("readiness-summary", validate_readiness_summary(args.readiness_summary))
        )
    if not checks:
        parser.error("provide at least one artifact to validate")

    ok = True
    for name, result in checks:
        ok = report_result(name, result) and ok
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
