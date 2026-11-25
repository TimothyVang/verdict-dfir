#!/usr/bin/env python3
"""Validate Devpost/release artifacts for final submission.

Strict validation is the default. Smoke packages may be generated for workflow
rehearsal, but final ``v-submit`` assets must pass these checks with no stubs,
placeholders, or header-only benchmark files.
"""

from __future__ import annotations

import argparse
import base64
import csv
from dataclasses import dataclass
import hashlib
import io
import json
import re
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse
import zipfile

REQUIRED_ZIP_FILES = {
    "README-submission.md",
    "benchmark-results.csv",
    "demo-video-link.txt",
    "LICENSE",
    "report.html",
}
ALLOWED_SUBMISSION_ZIP_FILES = REQUIRED_ZIP_FILES | {"readiness-packet.zip"}

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
READINESS_OPTIONAL_ARTIFACTS = {
    "automation.json",
    "coverage_manifest.json",
    "disk_artifact_summary.json",
    "evidence_inventory.json",
    "expert_signoff_manifest_link.json",
    "grounding.json",
    "malfind.json",
    "malware_triage.json",
    "psscan.json",
    "psxview.json",
    "recall-score.json",
    "readiness-packet-manifest.json",
    "readiness-summary.json",
    "REPORT-internal.md",
    "REPORT-internal.html",
    "REPORT-internal.new.pdf",
    "REPORT-internal.pdf",
    "REPORT.md",
    "REPORT.new.pdf",
    "REPORT.pdf",
    "self-score.json",
    "timeline.csv",
    "timeline.json",
}
READINESS_ALLOWED_FIGURE_SUFFIXES = {".jpeg", ".jpg", ".png", ".webp"}

READINESS_REQUIRED_AUDIT_KINDS = {
    "report_qa",
    "customer_release_gate",
    "verdict_artifact",
    "expert_signoff_packet",
}

READINESS_FORBIDDEN_AUDIT_KINDS = {"fault_injection"}

READINESS_VERIFIER_AUDIT_KINDS = {
    "verifier_action",
    "replay",
    "acp_handoff",
}

READINESS_REPORT_ARTIFACTS = {
    "report.html",
    "report.pdf",
    "report.new.pdf",
    "report.md",
}
READINESS_ALLOWED_STATES = {"PACKET_READY_FOR_EXPERT_REVIEW", "READY_FOR_EXPERT_REVIEW"}
CUSTOMER_READY_STATES = {
    "CUSTOMER_READY",
    "READY_FOR_CUSTOMER_RELEASE",
    "CUSTOMER_RELEASE_READY",
    "CUSTOMER_RELEASABLE",
}
SHA256_HEX_RE = re.compile(r"^[0-9a-fA-F]{64}$")
CANONICAL_JSON_SEPARATORS = (",", ":")
FAULT_INJECTION_DOC_RE = re.compile(r"fault[-_\s]+injection")
FAULT_INJECTION_CONTEXT_CHARS = 240
FAULT_INJECTION_MISLEADING_PHRASES = (
    "fault_injection is natural",
    "fault_injection is organic",
    "fault_injection as natural",
    "fault_injection as organic",
    "fault_injection as primary",
    "fault_injection is primary",
    "fault_injection is flagship",
    "primary fault_injection",
    "flagship fault_injection",
)
FAULT_INJECTION_MISLEADING_WINDOW_PHRASES = (
    "as organic",
    "is organic",
    "organic evidence",
    "organic self-correction",
    "as natural",
    "is natural",
    "natural evidence",
    "natural self-correction",
    "as primary",
    "primary evidence",
    "primary self-correction",
    "flagship evidence",
    "flagship proof",
)
FAULT_INJECTION_SAFE_NEGATIONS = (
    "not organic",
    "not natural",
    "not primary",
    "not proof of organic",
    "not be counted as organic",
    "must not be counted as organic",
    "never present",
    "never replace",
)
FAULT_INJECTION_SAFE_NEGATION_PREFIXES = (
    "not ",
    "never ",
    "does not ",
    "do not ",
    "must not ",
    "should not ",
    "cannot ",
    "not be counted as ",
    "must not be counted as ",
)
READINESS_MAX_ZIP_MEMBER_BYTES = 25 * 1024 * 1024
READINESS_MAX_ZIP_TOTAL_BYTES = 100 * 1024 * 1024
READINESS_MAX_COMPRESSION_RATIO = 100
READINESS_FORBIDDEN_ZIP_SUFFIXES = {
    ".001",
    ".db",
    ".e01",
    ".dd",
    ".evtx",
    ".key",
    ".mem",
    ".ova",
    ".ovf",
    ".p12",
    ".p7b",
    ".p7c",
    ".pcap",
    ".pcapng",
    ".pem",
    ".pfx",
    ".qcow2",
    ".raw",
    ".sqlite",
    ".sqlite3",
    ".vhd",
    ".vhdx",
    ".vmdk",
    ".img",
    ".vmem",
}
READINESS_FORBIDDEN_ZIP_NAMES = {
    ".env",
    ".env.local",
    ".credentials.json",
    "credentials.json",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_rsa",
}
READINESS_FORBIDDEN_ZIP_DIRS = {"evidence", "tmp"}


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
        if row_is_coherent_nist_score(row):
            return CheckResult(
                True,
                "benchmark CSV contains coherent nist-hacking-case recall row",
            )
    return CheckResult(
        False,
        "benchmark CSV lacks coherent nist-hacking-case row "
        "(findings_matched > 0 and findings_expected >= findings_matched)",
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
    # The QA / expert-signoff and customer-release-gate sections ship in the
    # companion REPORT-internal packet, not the customer/technical report, so they
    # are no longer required markers of the main report.
    investigation_required = (
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

    # Strip embedded base64 resources (data: URIs from pandoc --embed-resources)
    # before scanning for placeholder words — short tokens like "stub" or "todo"
    # occur by chance inside base64 image data and are not real placeholders.
    scan_text = re.sub(r"data:[^\s\"')]+", "", text)
    hits = placeholder_hits(scan_text)
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
        blockers: list[str] = []
        validate_readiness_zip_members(zf, blockers, "submission zip")
        if blockers:
            return CheckResult(False, "; ".join(blockers))
        names = {name.rstrip("/") for name in zf.namelist()}
        file_names = {
            info.filename.rstrip("/") for info in zf.infolist() if not info.is_dir()
        }
        unexpected = sorted(file_names - ALLOWED_SUBMISSION_ZIP_FILES)
        if unexpected:
            return CheckResult(
                False,
                "zip contains unrecognized file(s): " + ", ".join(unexpected),
            )
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
        if not any(row_is_coherent_nist_score(row) for row in rows):
            return CheckResult(
                False,
                "zip benchmark-results.csv lacks coherent nist-hacking-case row",
            )
        report = zf.read("report.html").decode("utf-8", errors="replace")
        report_result = validate_report_text(report)
        if not report_result.ok:
            return CheckResult(
                False, f"zip report.html invalid: {report_result.message}"
            )
        if "readiness-packet.zip" in names:
            readiness_result = validate_readiness_packet_bytes(
                zf.read("readiness-packet.zip"), "readiness-packet.zip"
            )
            if not readiness_result.ok:
                return CheckResult(
                    False,
                    f"zip readiness-packet.zip invalid: {readiness_result.message}",
                )
    return CheckResult(
        True,
        "submission zip contains required assets; readiness packet validated when present",
    )


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


def read_json_text(text: str, label: str, blockers: list[str]) -> dict | None:
    try:
        obj = json.loads(text)
    except json.JSONDecodeError as exc:
        blockers.append(f"{label} is not valid JSON: {exc}")
        return None
    if not isinstance(obj, dict):
        blockers.append(f"{label} must be a JSON object")
        return None
    return obj


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_readiness_relative_path(
    relative_path: str, label: str, blockers: list[str]
) -> str | None:
    normalized = relative_path.replace("\\", "/").strip("/")
    parsed = PurePosixPath(normalized)
    parts = parsed.parts
    if (
        not normalized
        or relative_path.startswith(("/", "\\"))
        or any(":" in part for part in parts)
        or any(part in {"", ".", ".."} for part in parts)
    ):
        blockers.append(f"{label} has unsafe relative path: {relative_path!r}")
        return None
    lowered_parts = {part.lower() for part in parsed.parts}
    name = parsed.name.lower()
    if (
        name in READINESS_FORBIDDEN_ZIP_NAMES
        or name.startswith(".env")
        or any(
            suffix.lower() in READINESS_FORBIDDEN_ZIP_SUFFIXES
            for suffix in parsed.suffixes
        )
        or bool(lowered_parts & READINESS_FORBIDDEN_ZIP_DIRS)
    ):
        blockers.append(
            f"{label} contains prohibited public-release artifact path: {relative_path!r}"
        )
        return None
    return normalized


def zip_info_is_symlink(info: zipfile.ZipInfo) -> bool:
    return ((info.external_attr >> 16) & 0o170000) == 0o120000


def validate_readiness_zip_members(
    zf: zipfile.ZipFile, blockers: list[str], label: str
) -> None:
    seen: set[str] = set()
    total_size = 0
    for info in zf.infolist():
        normalized = validate_readiness_relative_path(info.filename, label, blockers)
        if normalized is None:
            continue
        if normalized in seen:
            blockers.append(f"{label} contains duplicate ZIP entry: {normalized}")
        seen.add(normalized)
        if zip_info_is_symlink(info):
            blockers.append(f"{label} contains symlink ZIP entry: {normalized}")
            continue
        if info.is_dir():
            continue
        total_size += info.file_size
        if info.file_size > READINESS_MAX_ZIP_MEMBER_BYTES:
            blockers.append(f"{label} ZIP entry too large: {normalized}")
        if total_size > READINESS_MAX_ZIP_TOTAL_BYTES:
            blockers.append(f"{label} ZIP uncompressed size exceeds limit")
            break
        compressed = max(info.compress_size, 1)
        if info.file_size / compressed > READINESS_MAX_COMPRESSION_RATIO:
            blockers.append(
                f"{label} ZIP entry compression ratio too high: {normalized}"
            )


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
        normalized = validate_readiness_relative_path(
            raw_path, f"packet_manifest artifact #{index}", blockers
        )
        if normalized is None:
            continue
        entries[normalized] = artifact
    return entries


def artifact_path(packet_dir: Path, relative_path: str) -> Path:
    return packet_dir.joinpath(*relative_path.split("/"))


def read_artifact_text(packet_dir: Path, relative_path: str) -> str | None:
    path = artifact_path(packet_dir, relative_path)
    if not path.is_file():
        return None
    return path.read_text(encoding="utf-8", errors="replace")


def read_artifact_bytes(packet_dir: Path, relative_path: str) -> bytes | None:
    path = artifact_path(packet_dir, relative_path)
    if not path.is_file():
        return None
    return path.read_bytes()


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


def parse_readiness_audit_text(text: str, blockers: list[str]) -> list[dict]:
    records: list[dict] = []
    line_count = 0
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        line_count += 1
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            blockers.append(f"audit.jsonl line {line_number} is not valid JSON: {exc}")
            continue
        if not isinstance(record, dict):
            blockers.append(f"audit.jsonl line {line_number} is not a JSON object")
            continue
        records.append(record)
        if not isinstance(record.get("kind"), str):
            blockers.append(f"audit.jsonl line {line_number} lacks top-level kind")
    if line_count == 0:
        blockers.append("audit.jsonl has no audit records")
    return records


def validate_readiness_audit_records(records: list[dict], blockers: list[str]) -> None:
    kinds: set[str] = set()
    for record in records:
        if isinstance(record, dict) and isinstance(record.get("kind"), str):
            kinds.add(record["kind"])
    missing = sorted(READINESS_REQUIRED_AUDIT_KINDS - kinds)
    if missing:
        blockers.append(
            "audit.jsonl lacks required record kind(s): " + ", ".join(missing)
        )
    forbidden = sorted(READINESS_FORBIDDEN_AUDIT_KINDS & kinds)
    if forbidden:
        blockers.append(
            "audit.jsonl contains demo-only record kind(s) not allowed in "
            "primary readiness packets: " + ", ".join(forbidden)
        )


def has_unnegated_fault_injection_claim(text: str) -> bool:
    for phrase in FAULT_INJECTION_MISLEADING_WINDOW_PHRASES:
        search_from = 0
        while True:
            index = text.find(phrase, search_from)
            if index == -1:
                break
            prefix = text[max(0, index - 40) : index]
            if not any(
                prefix.endswith(negation)
                for negation in FAULT_INJECTION_SAFE_NEGATION_PREFIXES
            ):
                return True
            search_from = index + len(phrase)
    return False


def validate_stage_two_judge_packet_text(text: str, label: str) -> CheckResult:
    lowered = text.lower()
    normalized = FAULT_INJECTION_DOC_RE.sub("fault_injection", lowered)
    blockers: list[str] = []
    for phrase in FAULT_INJECTION_MISLEADING_PHRASES:
        if phrase in normalized:
            blockers.append(
                f"{label} presents fault_injection as primary/organic evidence"
            )
            break

    for match in FAULT_INJECTION_DOC_RE.finditer(lowered):
        index = match.start()
        start = max(0, index - FAULT_INJECTION_CONTEXT_CHARS)
        end = match.end() + FAULT_INJECTION_CONTEXT_CHARS
        window = lowered[start:end]
        has_optional_label = "optional" in window and (
            "harness" in window or "demo" in window
        )
        if not has_optional_label:
            blockers.append(
                f"{label} mentions fault_injection without nearby optional harness/demo wording"
            )
            break
        normalized_window = FAULT_INJECTION_DOC_RE.sub("fault_injection", window)
        if has_unnegated_fault_injection_claim(normalized_window):
            blockers.append(
                f"{label} presents fault_injection as primary/organic evidence"
            )
            break

    if blockers:
        return CheckResult(False, "; ".join(blockers))
    return CheckResult(
        True,
        f"{label} labels fault-injection content as optional harness/demo evidence",
    )


def validate_stage_two_judge_packet(path: Path) -> CheckResult:
    if not path.is_file():
        return CheckResult(False, f"stage two judge packet missing: {path}")
    text = path.read_text(encoding="utf-8", errors="replace")
    return validate_stage_two_judge_packet_text(text, str(path))


def validate_readiness_audit_text(text: str, blockers: list[str]) -> list[dict]:
    records = parse_readiness_audit_text(text, blockers)
    validate_readiness_audit_records(records, blockers)
    return records


def validate_readiness_audit(packet_dir: Path, blockers: list[str]) -> list[dict]:
    path = artifact_path(packet_dir, "audit.jsonl")
    if not path.is_file():
        blockers.append(f"audit.jsonl missing from packet dir: {path}")
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        blockers.append(f"audit.jsonl could not be read: {exc}")
        return []
    return validate_readiness_audit_text(text, blockers)


def validate_manifest_verify_object(
    manifest_verify: dict | None, blockers: list[str]
) -> None:
    if manifest_verify is None:
        return
    if manifest_verify.get("overall") is not True:
        blockers.append("manifest_verify.json overall is not true")
    if manifest_verify.get("signature_verified") is not True:
        blockers.append("manifest_verify.json signature_verified is not true")


def canonicalize_json(obj: object) -> bytes:
    return json.dumps(
        obj,
        sort_keys=True,
        separators=CANONICAL_JSON_SEPARATORS,
        ensure_ascii=True,
    ).encode("ascii")


def hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def merkle_root_hex(leaves: list[str]) -> str:
    tier = [bytes.fromhex(leaf) for leaf in leaves]
    if not tier:
        return (b"\x00" * 32).hex()
    while len(tier) > 1:
        if len(tier) % 2:
            tier = [*tier, tier[-1]]
        tier = [
            hashlib.sha256(tier[i] + tier[i + 1]).digest()
            for i in range(0, len(tier), 2)
        ]
    return tier[0].hex()


def verifier_payload_digest(payload: dict, key: str) -> str | None:
    value = payload.get(key)
    return value if isinstance(value, str) and SHA256_HEX_RE.fullmatch(value) else None


def derive_audit_manifest_state(
    audit_text: str, blockers: list[str], label: str
) -> tuple[int, str, list[dict[str, object]]] | None:
    prev_hash = ""
    final_hash = ""
    leaves: list[dict[str, object]] = []
    record_count = 0
    for raw_line in [line for line in audit_text.splitlines() if line.strip()]:
        raw = raw_line.encode("utf-8")
        try:
            record = json.loads(raw_line)
        except json.JSONDecodeError as exc:
            blockers.append(f"{label} audit record is not valid JSON: {exc}")
            return None
        if not isinstance(record, dict):
            blockers.append(f"{label} audit record is not an object")
            return None
        canonical = canonicalize_json(record)
        if canonical != raw:
            blockers.append(
                f"{label} audit record is not canonical JSON at seq {record_count}"
            )
            return None
        if record.get("seq") != record_count:
            blockers.append(
                f"{label} audit seq mismatch at {record_count}: {record.get('seq')!r}"
            )
            return None
        if record.get("prev_hash") != prev_hash:
            blockers.append(f"{label} audit prev_hash mismatch at seq {record_count}")
            return None
        payload = (
            record.get("payload") if isinstance(record.get("payload"), dict) else {}
        )
        final_hash = hash_bytes(raw)
        kind = record.get("kind")
        if kind == "tool_call_output":
            digest = verifier_payload_digest(payload, "output_hash") or final_hash
            leaves.append(
                {
                    "seq": record_count,
                    "kind": "tool_call_output",
                    "digest_hex": digest,
                    "record_id": str(payload.get("tool_call_id", "")),
                }
            )
        elif kind == "finding_approved":
            leaves.append(
                {
                    "seq": record_count,
                    "kind": "finding",
                    "digest_hex": final_hash,
                    "record_id": str(payload.get("finding_id", "")),
                }
            )
        prev_hash = final_hash
        record_count += 1
    return record_count, final_hash, leaves


def verify_manifest_signature(manifest: dict, blockers: list[str], label: str) -> None:
    signature = manifest.get("signature")
    if not isinstance(signature, dict):
        blockers.append(f"{label} lacks signature object")
        return
    if signature.get("kind") != "ed25519":
        blockers.append(f"{label} signature kind is not ed25519")
        return
    body = {key: value for key, value in manifest.items() if key != "signature"}
    body_bytes = canonicalize_json(body)
    if signature.get("payload_sha256") != hash_bytes(body_bytes):
        blockers.append(
            f"{label} signature payload_sha256 does not match manifest body"
        )
        return
    try:
        bundle = json.loads(base64.b64decode(str(signature.get("bundle_b64") or "")))
        public_key = base64.b64decode(str(bundle["public_key_b64"]))
        signature_bytes = base64.b64decode(str(bundle["signature_b64"]))
    except (KeyError, ValueError, TypeError, json.JSONDecodeError) as exc:
        blockers.append(f"{label} ed25519 bundle malformed: {exc}")
        return
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature_bytes, body_bytes
        )
    except InvalidSignature:
        blockers.append(f"{label} ed25519 signature verification failed")
    except Exception as exc:
        blockers.append(f"{label} ed25519 signature verification error: {exc}")


def validate_recomputed_manifest(
    manifest: dict | None, audit_text: str | None, blockers: list[str], label: str
) -> None:
    if manifest is None or audit_text is None:
        return
    state = derive_audit_manifest_state(audit_text, blockers, label)
    if state is None:
        return
    record_count, final_hash, leaves = state
    declared_leaves = manifest.get("leaves")
    if not isinstance(declared_leaves, list):
        blockers.append(f"{label} lacks manifest leaves list")
        return
    if manifest.get("audit_log_record_count") != record_count:
        blockers.append(f"{label} audit_log_record_count does not match audit.jsonl")
    if manifest.get("audit_log_final_hash") != final_hash:
        blockers.append(f"{label} audit_log_final_hash does not match audit.jsonl")
    if declared_leaves != leaves:
        blockers.append(f"{label} manifest leaves do not match audit.jsonl")
    if manifest.get("leaf_count") != len(declared_leaves):
        blockers.append(f"{label} leaf_count does not match manifest leaves")
    derived_root = merkle_root_hex([str(leaf["digest_hex"]) for leaf in leaves])
    if manifest.get("merkle_root_hex") != derived_root:
        blockers.append(f"{label} merkle_root_hex does not match audit-derived leaves")
    verify_manifest_signature(manifest, blockers, label)


def audit_record_finding_id(record: dict) -> str | None:
    payload = record.get("payload")
    if not isinstance(payload, dict):
        return None
    if record.get("kind") == "acp_handoff":
        handoff_payload = payload.get("payload")
        if isinstance(handoff_payload, dict):
            value = handoff_payload.get("finding_id") or payload.get("correlation_id")
        else:
            value = payload.get("correlation_id")
    else:
        value = payload.get("finding_id")
    return str(value) if isinstance(value, str) and value else None


def audit_record_tool_call_id(record: dict) -> str | None:
    payload = record.get("payload")
    if isinstance(payload, dict):
        value = payload.get("tool_call_id") or record.get("tool_call_id")
    else:
        value = record.get("tool_call_id")
    return str(value) if isinstance(value, str) and value else None


def audit_record_has_valid_output_hash(record: dict) -> bool:
    payload = record.get("payload")
    output_hash = payload.get("output_hash") if isinstance(payload, dict) else None
    return isinstance(output_hash, str) and bool(SHA256_HEX_RE.fullmatch(output_hash))


def is_valid_verifier_evidence_record(record: dict) -> bool:
    payload = record.get("payload")
    if not isinstance(payload, dict):
        return False
    kind = record.get("kind")
    if kind == "verifier_action":
        return (
            payload.get("action") in {"approved", "downgraded"}
            and isinstance(payload.get("replay_record_sha256"), str)
            and bool(SHA256_HEX_RE.fullmatch(payload["replay_record_sha256"]))
        )
    if kind == "replay":
        legacy = payload.get("legacy_replay")
        replay_matched = payload.get("replay_matched")
        if replay_matched is None and isinstance(legacy, dict):
            replay_matched = legacy.get("replay_matched")
        return (
            replay_matched is True
            and isinstance(payload.get("replay_record_sha256"), str)
            and bool(SHA256_HEX_RE.fullmatch(payload["replay_record_sha256"]))
        )
    if kind == "acp_handoff":
        handoff_payload = payload.get("payload")
        return (
            payload.get("from_role") == "verifier"
            and payload.get("to_role") == "judge"
            and isinstance(handoff_payload, dict)
            and handoff_payload.get("action") in {"approved", "downgraded"}
            and isinstance(handoff_payload.get("replay_record_sha256"), str)
            and bool(SHA256_HEX_RE.fullmatch(handoff_payload["replay_record_sha256"]))
        )
    return False


def verifier_record_replay_hash(record: dict) -> str | None:
    payload = record.get("payload")
    if not isinstance(payload, dict):
        return None
    if record.get("kind") == "acp_handoff":
        handoff_payload = payload.get("payload")
        if isinstance(handoff_payload, dict):
            value = handoff_payload.get("replay_record_sha256")
        else:
            value = None
    else:
        value = payload.get("replay_record_sha256")
    return str(value) if isinstance(value, str) and value else None


def verifier_record_action(record: dict) -> str | None:
    payload = record.get("payload")
    if not isinstance(payload, dict):
        return None
    if record.get("kind") == "acp_handoff":
        handoff_payload = payload.get("payload")
        if isinstance(handoff_payload, dict):
            value = handoff_payload.get("action")
        else:
            value = None
    else:
        value = payload.get("action")
    return str(value) if isinstance(value, str) and value else None


def audit_payload(record: dict) -> dict | None:
    payload = record.get("payload")
    return payload if isinstance(payload, dict) else None


def artifact_basename(value: object) -> str:
    if not isinstance(value, str):
        return ""
    return value.replace("\\", "/").rstrip("/").split("/")[-1]


def validate_verdict_artifact_binding(
    verdict_bytes: bytes | None, audit_records: list[dict], blockers: list[str]
) -> None:
    if verdict_bytes is None:
        return
    actual_sha256 = hash_bytes(verdict_bytes)
    artifact_records = [
        payload
        for record in audit_records
        if record.get("kind") == "verdict_artifact"
        for payload in [audit_payload(record)]
        if payload is not None
    ]
    if not artifact_records:
        return
    matched = False
    for payload in artifact_records:
        path_name = artifact_basename(payload.get("path"))
        if path_name and path_name != "verdict.json":
            blockers.append(
                "audit.jsonl verdict_artifact does not point at verdict.json: "
                f"{payload.get('path')!r}"
            )
        declared_sha256 = payload.get("sha256")
        if not isinstance(declared_sha256, str) or not SHA256_HEX_RE.fullmatch(
            declared_sha256
        ):
            blockers.append("audit.jsonl verdict_artifact lacks valid sha256")
            continue
        if declared_sha256.lower() == actual_sha256:
            matched = True
        else:
            blockers.append(
                "audit.jsonl verdict_artifact sha256 does not match verdict.json"
            )
    if not matched:
        blockers.append("audit.jsonl has no verdict_artifact hash for verdict.json")


def finding_sha256(finding: dict) -> str:
    return hash_bytes(canonicalize_json(finding))


def finding_approved_payloads_by_id(
    audit_records: list[dict], blockers: list[str]
) -> dict[str, list[dict]]:
    payloads_by_id: dict[str, list[dict]] = {}
    for record in audit_records:
        if record.get("kind") != "finding_approved":
            continue
        payload = audit_payload(record)
        if payload is None:
            blockers.append("audit.jsonl finding_approved payload is not an object")
            continue
        finding_id = payload.get("finding_id")
        if not isinstance(finding_id, str) or not finding_id:
            blockers.append("audit.jsonl finding_approved lacks finding_id")
            continue
        embedded_finding = payload.get("finding")
        declared_sha256 = payload.get("finding_sha256")
        if not isinstance(embedded_finding, dict):
            blockers.append(
                f"audit.jsonl finding_approved lacks embedded finding for {finding_id}"
            )
            continue
        if not isinstance(declared_sha256, str) or not SHA256_HEX_RE.fullmatch(
            declared_sha256
        ):
            blockers.append(
                f"audit.jsonl finding_approved lacks valid finding_sha256 for {finding_id}"
            )
            continue
        if finding_sha256(embedded_finding) != declared_sha256.lower():
            blockers.append(
                "audit.jsonl finding_approved finding_sha256 does not match embedded "
                f"finding for {finding_id}"
            )
            continue
        payloads_by_id.setdefault(finding_id, []).append(payload)
    return payloads_by_id


def validate_verifier_audit_evidence(
    verdict: dict, audit_records: list[dict], blockers: list[str]
) -> None:
    findings = verdict.get("findings")
    if not isinstance(findings, list):
        summary = verdict.get("findings_summary")
        total = summary.get("total_merged") if isinstance(summary, dict) else None
        if isinstance(total, int) and total > 0:
            blockers.append(
                "verdict.json reports merged findings but lacks a findings list"
            )
        return
    if not findings:
        return

    approved_payloads_by_id = finding_approved_payloads_by_id(audit_records, blockers)
    finding_ids: list[str] = []
    finding_tool_call_ids: dict[str, str] = {}
    findings_by_id: dict[str, dict] = {}
    for index, finding in enumerate(findings, start=1):
        if not isinstance(finding, dict):
            blockers.append(f"verdict.json findings[{index - 1}] is not an object")
            continue
        finding_id = finding.get("finding_id")
        if not isinstance(finding_id, str) or not finding_id:
            blockers.append(f"verdict.json findings[{index - 1}] lacks finding_id")
            continue
        tool_call_id = finding.get("tool_call_id")
        if not isinstance(tool_call_id, str) or not tool_call_id:
            blockers.append(f"verdict.json findings[{index - 1}] lacks tool_call_id")
        else:
            finding_tool_call_ids[finding_id] = tool_call_id
        finding_ids.append(finding_id)
        findings_by_id[finding_id] = finding

    tool_call_starts: set[str] = set()
    tool_call_outputs: set[str] = set()
    ids_by_kind: dict[str, set[str]] = {
        kind: set() for kind in READINESS_VERIFIER_AUDIT_KINDS
    }
    replay_hashes_by_kind: dict[str, dict[str, set[str]]] = {
        kind: {} for kind in READINESS_VERIFIER_AUDIT_KINDS
    }
    pairs_by_kind: dict[str, dict[str, set[tuple[str, str]]]] = {
        "verifier_action": {},
        "acp_handoff": {},
    }
    for record in audit_records:
        kind = record.get("kind")
        if kind == "tool_call_start":
            tool_call_id = audit_record_tool_call_id(record)
            if tool_call_id is not None:
                tool_call_starts.add(tool_call_id)
        elif kind == "tool_call_output":
            tool_call_id = audit_record_tool_call_id(record)
            if tool_call_id is not None and audit_record_has_valid_output_hash(record):
                tool_call_outputs.add(tool_call_id)
        if not isinstance(kind, str) or kind not in ids_by_kind:
            continue
        if not is_valid_verifier_evidence_record(record):
            continue
        finding_id = audit_record_finding_id(record)
        if finding_id is not None:
            ids_by_kind[kind].add(finding_id)
            replay_hash = verifier_record_replay_hash(record)
            if replay_hash is not None:
                replay_hashes_by_kind[kind].setdefault(finding_id, set()).add(
                    replay_hash
                )
            action = verifier_record_action(record)
            if replay_hash is not None and action is not None and kind in pairs_by_kind:
                pairs_by_kind[kind].setdefault(finding_id, set()).add(
                    (replay_hash, action)
                )

    missing_kinds = sorted(kind for kind, ids in ids_by_kind.items() if not ids)
    if missing_kinds:
        blockers.append(
            "audit.jsonl lacks verifier evidence kind(s) for final findings: "
            + ", ".join(missing_kinds)
        )
    for finding_id in finding_ids:
        finding = findings_by_id.get(finding_id, {})
        tool_call_id = finding_tool_call_ids.get(finding_id)
        if tool_call_id is not None:
            if tool_call_id not in tool_call_starts:
                blockers.append(
                    "verdict.json cites unresolved current-case tool_call_id "
                    f"for finding_id={finding_id}: {tool_call_id}"
                )
            elif tool_call_id not in tool_call_outputs:
                blockers.append(
                    "verdict.json cites tool_call_id without matching output hash "
                    f"for finding_id={finding_id}: {tool_call_id}"
                )
        approved_payloads = approved_payloads_by_id.get(finding_id, [])
        if not approved_payloads:
            blockers.append(
                "audit.jsonl lacks finding_approved record for final finding "
                f"finding_id={finding_id}"
            )
        else:
            final_finding_sha256 = finding_sha256(finding)
            has_matching_approval = any(
                str(payload.get("finding_sha256") or "").lower() == final_finding_sha256
                and payload.get("tool_call_id") == finding.get("tool_call_id")
                and payload.get("confidence") == finding.get("confidence")
                for payload in approved_payloads
            )
            if not has_matching_approval:
                blockers.append(
                    "verdict.json final finding does not match audit finding_approved "
                    f"payload for finding_id={finding_id}"
                )
        missing_for_finding = sorted(
            kind for kind, ids in ids_by_kind.items() if finding_id not in ids
        )
        if missing_for_finding:
            blockers.append(
                f"audit.jsonl lacks verifier evidence for finding_id={finding_id}: "
                + ", ".join(missing_for_finding)
            )
            continue
        replay_hashes = replay_hashes_by_kind["replay"].get(finding_id, set())
        verifier_pairs = pairs_by_kind["verifier_action"].get(finding_id, set())
        handoff_pairs = pairs_by_kind["acp_handoff"].get(finding_id, set())
        matching_pairs = {
            pair
            for pair in (verifier_pairs & handoff_pairs)
            if pair[0] in replay_hashes
        }
        if not matching_pairs:
            blockers.append(
                "audit.jsonl has mismatched verifier replay hash/action evidence "
                f"for finding_id={finding_id}"
            )
        elif (
            "downgraded" in {action for _, action in matching_pairs}
            and str(findings_by_id.get(finding_id, {}).get("confidence") or "")
            == "CONFIRMED"
        ):
            blockers.append(
                "verifier downgraded finding but verdict.json kept CONFIRMED "
                f"for finding_id={finding_id}"
            )


def readiness_report_paths(entries: dict[str, dict]) -> list[str]:
    return sorted(
        artifact
        for artifact in entries
        if Path(artifact).name.lower() in READINESS_REPORT_ARTIFACTS
    )


def readiness_artifact_is_allowed(relative_path: str, allowed_exact: set[str]) -> bool:
    if relative_path in allowed_exact:
        return True
    parsed = PurePosixPath(relative_path)
    return (
        len(parsed.parts) >= 2
        and parsed.parts[0] == "figures"
        and parsed.suffix.lower() in READINESS_ALLOWED_FIGURE_SUFFIXES
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
    report_paths = readiness_report_paths(entries)
    if not report_paths:
        blockers.append(
            "packet_manifest lacks report artifact; expected REPORT.html, REPORT.pdf, or REPORT.md"
        )
    allowed_artifacts = (
        READINESS_REQUIRED_ARTIFACTS | READINESS_OPTIONAL_ARTIFACTS | set(report_paths)
    )
    unexpected_artifacts = sorted(
        artifact
        for artifact in entries
        if not readiness_artifact_is_allowed(artifact, allowed_artifacts)
    )
    if unexpected_artifacts:
        blockers.append(
            "packet_manifest contains unrecognized artifact(s): "
            + ", ".join(unexpected_artifacts)
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
                validate_readiness_zip_members(zf, blockers, "packet_zip")
                names = {name.rstrip("/") for name in zf.namelist()}
                file_names = {
                    info.filename.rstrip("/")
                    for info in zf.infolist()
                    if not info.is_dir()
                }
                allowed_zip_names = set(entries) | {
                    "readiness-summary.json",
                    "readiness-packet-manifest.json",
                }
                unexpected_zip = sorted(file_names - allowed_zip_names)
                if unexpected_zip:
                    blockers.append(
                        "packet_zip contains unrecognized file(s): "
                        + ", ".join(unexpected_zip)
                    )
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
                        data = read_zip_bytes(zf, relative_path, blockers)
                        if data is None:
                            continue
                        actual_sha = hashlib.sha256(data).hexdigest()
                        if actual_sha.lower() != expected_sha.lower():
                            blockers.append(
                                f"packet_zip hash mismatch: {relative_path}"
                            )
        except zipfile.BadZipFile:
            blockers.append(f"packet_zip is not a valid ZIP file: {packet_zip}")

    audit_text = read_artifact_text(packet_dir, "audit.jsonl")
    audit_records = validate_readiness_audit(packet_dir, blockers)
    run_manifest = read_artifact_json(
        packet_dir, "run.manifest.json", "run.manifest.json", blockers
    )
    manifest_verify = read_artifact_json(
        packet_dir, "manifest_verify.json", "manifest_verify.json", blockers
    )
    validate_manifest_verify_object(manifest_verify, blockers)
    validate_recomputed_manifest(
        run_manifest, audit_text, blockers, "run.manifest.json"
    )
    verdict_bytes = read_artifact_bytes(packet_dir, "verdict.json")
    validate_verdict_artifact_binding(verdict_bytes, audit_records, blockers)
    verdict = read_artifact_json(packet_dir, "verdict.json", "verdict.json", blockers)
    if verdict is not None:
        add_customer_ready_blockers(verdict, "verdict.json", blockers)
        validate_verifier_audit_evidence(verdict, audit_records, blockers)
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


def read_zip_text(
    zf: zipfile.ZipFile, relative_path: str, blockers: list[str]
) -> str | None:
    data = read_zip_bytes(zf, relative_path, blockers)
    if data is None:
        return None
    return data.decode("utf-8", errors="replace")


def read_zip_bytes(
    zf: zipfile.ZipFile, relative_path: str, blockers: list[str]
) -> bytes | None:
    try:
        info = zf.getinfo(relative_path)
    except KeyError:
        blockers.append(f"readiness packet missing {relative_path}")
        return None
    if info.file_size > READINESS_MAX_ZIP_MEMBER_BYTES:
        blockers.append(f"readiness packet member too large: {relative_path}")
        return None
    try:
        return zf.read(info)
    except OSError as exc:
        blockers.append(f"readiness packet could not read {relative_path}: {exc}")
    return None


def read_zip_json(
    zf: zipfile.ZipFile, relative_path: str, label: str, blockers: list[str]
) -> dict | None:
    text = read_zip_text(zf, relative_path, blockers)
    if text is None:
        return None
    return read_json_text(text, label, blockers)


def validate_readiness_packet_archive(
    zf: zipfile.ZipFile, label: str = "readiness packet"
) -> CheckResult:
    blockers: list[str] = []
    validate_readiness_zip_members(zf, blockers, label)
    names = {name.rstrip("/") for name in zf.namelist()}
    file_names = {
        info.filename.rstrip("/") for info in zf.infolist() if not info.is_dir()
    }
    for required in {"readiness-summary.json", "readiness-packet-manifest.json"}:
        if required not in names:
            blockers.append(f"{label} missing {required}")

    summary = read_zip_json(zf, "readiness-summary.json", "readiness-summary", blockers)
    manifest = read_zip_json(
        zf,
        "readiness-packet-manifest.json",
        "readiness-packet-manifest",
        blockers,
    )
    if summary is None or manifest is None:
        return CheckResult(False, "; ".join(blockers))

    summary_blockers = summary.get("blockers")
    if isinstance(summary_blockers, list) and summary_blockers:
        blockers.append(
            "readiness-summary.json already contains blocker(s): "
            + "; ".join(str(blocker) for blocker in summary_blockers)
        )
    readiness_state = summary.get("readiness_state")
    if readiness_state not in READINESS_ALLOWED_STATES:
        blockers.append(
            f"readiness_state is not expert-review ready: {readiness_state!r}"
        )
    if manifest.get("readiness_state") != readiness_state:
        blockers.append(
            "readiness-packet-manifest readiness_state does not match summary: "
            f"{manifest.get('readiness_state')!r} != {readiness_state!r}"
        )
    add_customer_ready_blockers(summary, "readiness-summary.json", blockers)

    entries = artifact_entries(manifest, blockers)
    missing_artifacts = sorted(READINESS_REQUIRED_ARTIFACTS - set(entries))
    if missing_artifacts:
        blockers.append(
            "readiness-packet-manifest missing required artifact(s): "
            + ", ".join(missing_artifacts)
        )
    report_paths = readiness_report_paths(entries)
    if not report_paths:
        blockers.append(
            "readiness-packet-manifest lacks report artifact; expected REPORT.html, REPORT.pdf, REPORT.new.pdf, or REPORT.md"
        )
    allowed_artifacts = (
        READINESS_REQUIRED_ARTIFACTS | READINESS_OPTIONAL_ARTIFACTS | set(report_paths)
    )
    unexpected_artifacts = sorted(
        artifact
        for artifact in entries
        if not readiness_artifact_is_allowed(artifact, allowed_artifacts)
    )
    if unexpected_artifacts:
        blockers.append(
            "readiness-packet-manifest contains unrecognized artifact(s): "
            + ", ".join(unexpected_artifacts)
        )

    required_zip_names = (
        set(READINESS_REQUIRED_ARTIFACTS)
        | set(report_paths)
        | {"readiness-summary.json", "readiness-packet-manifest.json"}
    )
    allowed_zip_names = set(entries) | {
        "readiness-summary.json",
        "readiness-packet-manifest.json",
    }
    unexpected_zip = sorted(file_names - allowed_zip_names)
    if unexpected_zip:
        blockers.append(
            "readiness packet ZIP contains unrecognized file(s): "
            + ", ".join(unexpected_zip)
        )
    missing_zip = sorted(required_zip_names - names)
    if missing_zip:
        blockers.append(
            "readiness packet ZIP missing required file(s): " + ", ".join(missing_zip)
        )

    for relative_path, artifact in entries.items():
        if relative_path not in names:
            blockers.append(f"readiness packet missing manifest-listed {relative_path}")
            continue
        expected_sha = artifact.get("sha256")
        if isinstance(expected_sha, str) and expected_sha:
            data = read_zip_bytes(zf, relative_path, blockers)
            if data is None:
                continue
            actual_sha = hashlib.sha256(data).hexdigest()
            if actual_sha.lower() != expected_sha.lower():
                blockers.append(f"readiness packet hash mismatch: {relative_path}")

    audit_records: list[dict] = []
    audit_text = read_zip_text(zf, "audit.jsonl", blockers)
    if audit_text is not None:
        audit_records = validate_readiness_audit_text(audit_text, blockers)

    manifest_verify = read_zip_json(
        zf, "manifest_verify.json", "manifest_verify.json", blockers
    )
    validate_manifest_verify_object(manifest_verify, blockers)
    run_manifest = read_zip_json(zf, "run.manifest.json", "run.manifest.json", blockers)
    validate_recomputed_manifest(
        run_manifest, audit_text, blockers, "run.manifest.json"
    )

    verdict_bytes = read_zip_bytes(zf, "verdict.json", blockers)
    validate_verdict_artifact_binding(verdict_bytes, audit_records, blockers)
    verdict = (
        read_json_text(
            verdict_bytes.decode("utf-8", errors="replace"),
            "verdict.json",
            blockers,
        )
        if verdict_bytes is not None
        else None
    )
    if verdict is not None:
        add_customer_ready_blockers(verdict, "verdict.json", blockers)
        validate_verifier_audit_evidence(verdict, audit_records, blockers)
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
        artifact_json = read_zip_json(zf, relative_path, relative_path, blockers)
        if artifact_json is not None:
            add_customer_ready_blockers(artifact_json, relative_path, blockers)

    for report_path in report_paths:
        if Path(report_path).suffix.lower() not in {".html", ".md", ".txt"}:
            continue
        text = read_zip_text(zf, report_path, blockers)
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
    return CheckResult(True, f"{label} is complete and expert-review gated")


def validate_readiness_packet_bytes(data: bytes, label: str) -> CheckResult:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            return validate_readiness_packet_archive(zf, label)
    except zipfile.BadZipFile:
        return CheckResult(False, f"{label} is not a valid ZIP file")


def validate_readiness_packet(path: Path) -> CheckResult:
    if not path.is_file():
        return CheckResult(False, f"readiness packet missing: {path}")
    try:
        with zipfile.ZipFile(path) as zf:
            return validate_readiness_packet_archive(zf, str(path))
    except zipfile.BadZipFile:
        return CheckResult(False, f"readiness packet is not a valid ZIP file: {path}")


def row_is_coherent_nist_score(row: dict[str, str]) -> bool:
    source_name = Path(row.get("source_file") or "").name
    fixture = row.get("fixture") or ""
    is_nist = (
        fixture == "nist-hacking-case"
        or source_name == "nist-hacking-case-verdict.json"
    )
    matched = parse_positive_int(row.get("findings_matched"))
    expected = parse_positive_int(row.get("findings_expected"))
    return bool(is_nist and matched and expected and expected >= matched)


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
    parser.add_argument(
        "--readiness-packet", type=Path, help="readiness-packet.zip path"
    )
    parser.add_argument(
        "--stage-two-packet", type=Path, help="Stage Two judge packet markdown path"
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
    if args.readiness_packet is not None:
        checks.append(
            ("readiness-packet", validate_readiness_packet(args.readiness_packet))
        )
    if args.stage_two_packet is not None:
        checks.append(
            ("stage-two-packet", validate_stage_two_judge_packet(args.stage_two_packet))
        )
    if not checks:
        parser.error("provide at least one artifact to validate")

    ok = True
    for name, result in checks:
        ok = report_result(name, result) and ok
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
