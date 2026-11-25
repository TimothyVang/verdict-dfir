#!/usr/bin/env python3
"""report-policy-smoke - lock executive story and signoff sections.

This smoke calls render_report.write_markdown directly so it does not require
Pandoc or Chrome. It verifies the customer-facing report policy layer: attack
story, QA / expert signoff, evidence-bound tool calls, and overclaim caveats.
"""

from __future__ import annotations

import base64
import importlib.util
import hashlib
import io
import json
import stat
import sys
import tempfile
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CANONICAL_SEPARATORS = (",", ":")
VERDICT_SHA_TOKEN = "__VERDICT_SHA256__"


def canonicalize_json(obj: object) -> bytes:
    return json.dumps(
        obj,
        sort_keys=True,
        separators=CANONICAL_SEPARATORS,
        ensure_ascii=True,
    ).encode("ascii")


def sha256_hex(data: bytes) -> str:
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


def build_chained_audit_text(audit_jsonl: str) -> str:
    lines: list[str] = []
    prev_hash = ""
    for seq, line in enumerate(
        line for line in audit_jsonl.splitlines() if line.strip()
    ):
        record = json.loads(line)
        payload = (
            record.get("payload") if isinstance(record.get("payload"), dict) else {}
        )
        chained = {
            "seq": seq,
            "ts": f"2026-05-10T00:00:{seq:02d}Z",
            "kind": str(record.get("kind") or "unknown"),
            "prev_hash": prev_hash,
            "payload": payload,
        }
        raw = canonicalize_json(chained)
        prev_hash = sha256_hex(raw)
        lines.append(raw.decode("ascii"))
    return "\n".join(lines) + "\n"


def build_manifest_bytes(audit_text: str) -> bytes:
    leaves: list[dict[str, object]] = []
    final_hash = ""
    for raw_line in [line for line in audit_text.splitlines() if line.strip()]:
        raw = raw_line.encode("ascii")
        record = json.loads(raw_line)
        final_hash = sha256_hex(raw)
        kind = record.get("kind")
        payload = (
            record.get("payload") if isinstance(record.get("payload"), dict) else {}
        )
        if kind == "tool_call_output":
            output_hash = payload.get("output_hash")
            digest = (
                output_hash
                if isinstance(output_hash, str) and len(output_hash) == 64
                else final_hash
            )
            leaves.append(
                {
                    "seq": int(record.get("seq", -1)),
                    "kind": "tool_call_output",
                    "digest_hex": digest,
                    "record_id": str(payload.get("tool_call_id", "")),
                }
            )
        elif kind == "finding_approved":
            leaves.append(
                {
                    "seq": int(record.get("seq", -1)),
                    "kind": "finding",
                    "digest_hex": final_hash,
                    "record_id": str(payload.get("finding_id", "")),
                }
            )

    body = {
        "version": "1",
        "case_id": "case-ready",
        "run_id": "run-ready",
        "started_at": "2026-05-10T00:00:00Z",
        "finalized_at": "2026-05-10T00:01:00Z",
        "audit_log_path": "audit.jsonl",
        "audit_log_final_hash": final_hash,
        "audit_log_record_count": len(
            [line for line in audit_text.splitlines() if line.strip()]
        ),
        "merkle_root_hex": merkle_root_hex(
            [str(leaf["digest_hex"]) for leaf in leaves]
        ),
        "leaf_count": len(leaves),
        "leaves": leaves,
        "extra": {"image_path": "synthetic"},
    }
    body_bytes = canonicalize_json(body)

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private_key = Ed25519PrivateKey.generate()
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    signature = private_key.sign(body_bytes)
    bundle = {
        "public_key_b64": base64.b64encode(public_bytes).decode("ascii"),
        "signature_b64": base64.b64encode(signature).decode("ascii"),
    }
    manifest = {
        **body,
        "signature": {
            "payload_sha256": sha256_hex(body_bytes),
            "bundle_b64": base64.b64encode(canonicalize_json(bundle)).decode("ascii"),
            "cert_fingerprint": None,
            "signed_at": "2026-05-10T00:01:00Z",
            "kind": "ed25519",
        },
    }
    return json.dumps(manifest, indent=2, sort_keys=True).encode() + b"\n"


def load_render_report():
    spec = importlib.util.spec_from_file_location(
        "render_report_under_test",
        REPO / "scripts" / "render_report.py",
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("could not build spec for render_report.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def load_submission_validator():
    spec = importlib.util.spec_from_file_location(
        "validate_submission_assets_under_test",
        REPO / "scripts" / "validate-submission-assets.py",
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("could not build spec for validate-submission-assets.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def build_readiness_packet_zip(
    report_html: str,
    *,
    audit_jsonl: str | None = None,
    manifest_verify: dict[str, object] | None = None,
    run_manifest: bytes | None = None,
    verdict_overrides: dict[str, object] | None = None,
) -> bytes:
    verdict_obj: dict[str, object] = {
        "verdict": "INDETERMINATE",
        "report_qa": {
            "status": "PASS",
            "ready_for_expert_signoff": True,
            "customer_releasable": False,
        },
        "release_gate": {"customer_releasable": False},
        "expert_signoff": {"customer_releasable": False},
    }
    if verdict_overrides:
        verdict_obj.update(verdict_overrides)
    verdict_bytes = json.dumps(verdict_obj, sort_keys=True).encode()
    audit_text = audit_jsonl or (
        '{"kind":"report_qa","payload":{"status":"PASS"}}\n'
        '{"kind":"customer_release_gate","payload":{"customer_releasable":false}}\n'
        '{"kind":"verdict_artifact","payload":{"path":"verdict.json","sha256":"'
        + VERDICT_SHA_TOKEN
        + '"}}\n'
        '{"kind":"expert_signoff_packet","payload":{"expert_signoff_sha256":"'
        + ("b" * 64)
        + '"}}\n'
    )
    audit_text = audit_text.replace(VERDICT_SHA_TOKEN, sha256_hex(verdict_bytes))
    if run_manifest is None:
        audit_text = build_chained_audit_text(audit_text)
        run_manifest = build_manifest_bytes(audit_text)
    packet_files: dict[str, bytes] = {
        "audit.jsonl": audit_text.encode(),
        "run.manifest.json": run_manifest,
        "manifest_verify.json": json.dumps(
            manifest_verify or {"overall": True, "signature_verified": True},
            sort_keys=True,
        ).encode(),
        "verdict.json": verdict_bytes,
        "expert_signoff.json": b'{"decision":"pending","customer_releasable":false}\n',
        "customer_release_gate.final.json": (
            b'{"customer_releasable":false,"expert_decision":"pending"}\n'
        ),
        "REPORT.html": report_html.encode(),
        "readiness-summary.json": json.dumps(
            {
                "readiness_state": "READY_FOR_EXPERT_REVIEW",
                "customer_releasable": False,
                "blockers": [],
            },
            sort_keys=True,
        ).encode(),
    }
    manifest = {
        "readiness_state": "READY_FOR_EXPERT_REVIEW",
        "artifacts": [
            {
                "path": name,
                "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
            for name, data in sorted(packet_files.items())
        ],
    }
    packet_files["readiness-packet-manifest.json"] = json.dumps(
        manifest, sort_keys=True
    ).encode()

    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in sorted(packet_files.items()):
            zf.writestr(name, data)
    return out.getvalue()


def add_manifested_packet_file(
    packet_zip: bytes, relative_path: str, data: bytes
) -> bytes:
    files: dict[str, bytes] = {}
    with zipfile.ZipFile(io.BytesIO(packet_zip)) as source:
        for info in source.infolist():
            files[info.filename] = source.read(info.filename)
    manifest = json.loads(files["readiness-packet-manifest.json"].decode())
    manifest["artifacts"] = [
        *manifest["artifacts"],
        {
            "path": relative_path,
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        },
    ]
    files[relative_path] = data
    files["readiness-packet-manifest.json"] = json.dumps(
        manifest, sort_keys=True
    ).encode()
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, content in sorted(files.items()):
            zf.writestr(name, content)
    return out.getvalue()


def raw_audit_record(kind: str, payload: dict[str, object]) -> str:
    return (
        json.dumps(
            {"kind": kind, "payload": payload},
            sort_keys=True,
            separators=CANONICAL_SEPARATORS,
        )
        + "\n"
    )


def finding_approved_audit_record(finding: dict[str, object]) -> str:
    finding_id = str(finding["finding_id"])
    return raw_audit_record(
        "finding_approved",
        {
            "finding_id": finding_id,
            "confidence": finding.get("confidence"),
            "tool_call_id": finding.get("tool_call_id"),
            "finding_sha256": sha256_hex(canonicalize_json(finding)),
            "finding": finding,
        },
    )


def load_find_evil_auto():
    spec = importlib.util.spec_from_file_location(
        "find_evil_auto_under_test",
        REPO / "scripts" / "find_evil_auto.py",
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("could not build spec for find_evil_auto.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main() -> int:
    rr = load_render_report()
    validator = load_submission_validator()
    fea = load_find_evil_auto()
    failures = 0
    expert_rules = fea.load_expert_rules()
    required_claim_rule_ids = {
        "finding_tool_call_required",
        "execution_requires_two_current_artifact_classes",
        "exfiltration_requires_staging_and_movement",
        "disk_auto_mode_custody_only",
        "verify_finding_replay_failures",
        "verify_finding_replay_embedded",
        "no_forbidden_unqualified_language",
    }
    claim_rule_ids = {str(row.get("id")) for row in expert_rules.get("claim_rules", [])}
    missing_claim_rule_ids = sorted(required_claim_rule_ids - claim_rule_ids)
    replay_rule = next(
        row
        for row in expert_rules.get("claim_rules", [])
        if row.get("id") == "verify_finding_replay_embedded"
    )
    replay_mismatch_expected_status = (
        "FAIL" if replay_rule.get("severity") == "blocker" else "WARN"
    )
    empty_qa = fea.build_report_qa_signoff(
        findings=[],
        tool_calls=[],
        verdict="INDETERMINATE",
        case_completeness={"checks": []},
        attack_coverage={"blind_spot_count": 0},
        normalized_timeline={"events": []},
        analysis_limitations=[],
        expert_rules=expert_rules,
        customer_visible_text=[],
    )
    replay_finding = {
        "finding_id": "f-replay",
        "confidence": "CONFIRMED",
        "tool_call_id": "tc-registry",
        "description": "Registry persistence artifact recorded for review.",
        "replay_matched": True,
        "replay_expected_sha256": "a" * 64,
        "replay_actual_sha256": "a" * 64,
    }
    replay_tool_calls = [{"tool": "registry_query", "tool_call_id": "tc-registry"}]
    replay_case_completeness = {
        "checks": [
            {
                "artifact_class": "registry",
                "available": True,
                "touched": True,
                "tools": ["registry_query"],
            }
        ]
    }
    replay_timeline = {
        "events": [
            {
                "linked_finding_ids": ["f-replay"],
                "artifact_class": "registry",
                "tool_call_id": "tc-registry",
                "source_record_ref": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            }
        ]
    }
    replay_match_qa = fea.build_report_qa_signoff(
        findings=[replay_finding],
        tool_calls=replay_tool_calls,
        verdict="SUSPICIOUS",
        case_completeness=replay_case_completeness,
        attack_coverage={"blind_spot_count": 0},
        normalized_timeline=replay_timeline,
        analysis_limitations=[],
        expert_rules=expert_rules,
        customer_visible_text=[],
    )
    replay_mismatch_finding = {
        **replay_finding,
        "replay_matched": False,
        "replay_actual_sha256": "b" * 64,
    }
    replay_mismatch_qa = fea.build_report_qa_signoff(
        findings=[replay_mismatch_finding],
        tool_calls=replay_tool_calls,
        verdict="SUSPICIOUS",
        case_completeness=replay_case_completeness,
        attack_coverage={"blind_spot_count": 0},
        normalized_timeline=replay_timeline,
        analysis_limitations=[],
        expert_rules=expert_rules,
        customer_visible_text=[],
    )
    # Negative-completeness gate: a NO_EVIL / scoped-clean verdict must not be
    # assertable over an artifact class the inventory marks 'available' that was
    # never actually examined (absence is not proof of no evil). The coverage
    # manifest records that gap as an `available_not_attempted` row with empty
    # tool_call_ids.
    unexamined_coverage_manifest = {
        "artifact_classes": [
            {
                "artifact_class": "memory",
                "status": "parsed",
                "available": True,
                "attempted": True,
                "parsed": True,
                "tool_call_ids": ["tc-pslist"],
            },
            {
                "artifact_class": "evtx",
                "status": "available_not_attempted",
                "available": True,
                "attempted": False,
                "parsed": False,
                "tool_call_ids": [],
            },
        ]
    }
    fully_examined_coverage_manifest = {
        "artifact_classes": [
            {
                "artifact_class": "memory",
                "status": "parsed",
                "available": True,
                "attempted": True,
                "parsed": True,
                "tool_call_ids": ["tc-pslist"],
            },
            {
                "artifact_class": "network",
                "status": "not_supplied",
                "available": False,
                "attempted": False,
                "parsed": False,
                "tool_call_ids": [],
            },
        ]
    }
    unexamined_gap_classes = fea.coverage_unexamined_available_classes(
        unexamined_coverage_manifest
    )
    fully_examined_gap_classes = fea.coverage_unexamined_available_classes(
        fully_examined_coverage_manifest
    )
    no_evil_case_completeness = {
        "checks": [
            {
                "artifact_class": "memory",
                "available": True,
                "touched": True,
                "tools": ["vol_pslist"],
            }
        ]
    }
    no_evil_unexamined_qa = fea.build_report_qa_signoff(
        findings=[],
        tool_calls=[{"tool": "vol_pslist", "tool_call_id": "tc-pslist"}],
        verdict="NO_EVIL",
        case_completeness=no_evil_case_completeness,
        attack_coverage={"blind_spot_count": 0},
        normalized_timeline={"events": []},
        analysis_limitations=[],
        expert_rules=expert_rules,
        customer_visible_text=[],
        coverage_manifest=unexamined_coverage_manifest,
    )
    no_evil_unexamined_check = next(
        row
        for row in no_evil_unexamined_qa["checks"]
        if row["check_id"] == "no_evil_is_scoped"
    )
    no_evil_complete_qa = fea.build_report_qa_signoff(
        findings=[],
        tool_calls=[{"tool": "vol_pslist", "tool_call_id": "tc-pslist"}],
        verdict="NO_EVIL",
        case_completeness=no_evil_case_completeness,
        attack_coverage={"blind_spot_count": 0},
        normalized_timeline={"events": []},
        analysis_limitations=[],
        expert_rules=expert_rules,
        customer_visible_text=[],
        coverage_manifest=fully_examined_coverage_manifest,
    )
    no_evil_complete_check = next(
        row
        for row in no_evil_complete_qa["checks"]
        if row["check_id"] == "no_evil_is_scoped"
    )

    empty_timeline_check = next(
        row
        for row in empty_qa["checks"]
        if row["check_id"] == "timeline_source_refs_present"
    )
    replay_match_check = next(
        row
        for row in replay_match_qa["checks"]
        if row["check_id"] == "verify_finding_replay_embedded"
    )
    replay_mismatch_check = next(
        row
        for row in replay_mismatch_qa["checks"]
        if row["check_id"] == "verify_finding_replay_embedded"
    )
    with tempfile.TemporaryDirectory() as tmp:
        case_dir = Path(tmp)
        manifest = {
            "case_id": "case-report-smoke",
            "run_id": "run-report-smoke",
            "started_at": "2026-05-09T00:00:00Z",
            "finalized_at": "2026-05-09T00:01:00Z",
            "audit_log_final_hash": "a" * 64,
            "merkle_root_hex": "b" * 64,
            "signature": {
                "payload_sha256": "c" * 64,
                "cert_fingerprint": "d" * 64,
            },
            "leaf_count": 2,
        }
        findings = [
            {
                "finding_id": "f-dkom",
                "confidence": "INFERRED",
                "pool_origin": "A",
                "mitre_technique": "T1014",
                "tool_call_id": "tc-psscan",
                "artifact_path": "/home/operator/.findevil/cases/case-report-smoke/extracted/disk/disk-extract-abc/prefetch/WINDOWS/Prefetch/CAIN.EXE-23D61279.pf",
                "description": "Process-view | divergence with `tick`\nand newline requires expert review.",
            }
        ]
        attack_story = {
            "headline": "Suspicious activity requires expert review before customer release",
            "customer_summary": "Finding-backed breach narrative for expert signoff.",
            "how_they_got_in": "Not established by the supplied evidence.",
            "root_cause": "Not established by the supplied evidence.",
            "business_impact": "Technical risk only; business impact requires customer context.",
            "what_we_can_say": ["A memory Finding is backed by tc-psscan."],
            "what_we_cannot_say": [
                "Who the attacker was; this report does not assert attribution."
            ],
            "recommended_next_decisions": ["Acquire disk and network artifacts."],
            "attack_chain": [
                {
                    "order": 1,
                    "phase": "Defense Evasion",
                    "phase_index": 4,
                    "title": "Process-view divergence consistent with DKOM",
                    "timestamp_utc": "2026-05-09T00:00:30Z",
                    "confidence": "INFERRED",
                    "mitre_technique": "T1014",
                    "named_technique": "Rootkit / DKOM process hiding (T1014)",
                    "tool_call_id": "tc-psscan",
                    "host": "DC01",
                    "artifact_classes": ["memory"],
                    "analyst_note": "Process-view divergence is a DKOM/rootkit signal.",
                    "next_pivot": "Compare pslist vs psscan vs psxview and pull the driver list.",
                    "hunt": "psscan-only EPROCESS not in pslist; unsigned recently-loaded drivers",
                }
            ],
        }
        host_groups = [
            {
                "host": "DC01",
                "finding_ids": ["f-dkom"],
                "evidence_sources": ["memory.img"],
                "by_confidence": {"CONFIRMED": 0, "INFERRED": 1, "HYPOTHESIS": 0},
                "event_count": 1,
                "first_seen": "2026-05-09T00:00:30Z",
                "last_seen": "2026-05-09T00:00:30Z",
                "finding_count": 1,
                "top_confidence": "INFERRED",
            }
        ]
        miss_ledger = case_dir / "expert_misses.jsonl"
        miss_ledger.write_text(
            json.dumps(
                {
                    "kind": "expert_miss",
                    "payload": {
                        "case_id": "case-report-smoke",
                        "finding_id": "f-dkom",
                        "edit_type": "qa",
                        "edit_text": "Expert requested a replay caveat.",
                        "expert_name": "Analyst One",
                    },
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        miss_summary = fea.build_expert_miss_summary("case-report-smoke", miss_ledger)
        empty_miss_summary = fea.build_expert_miss_summary("case-empty", miss_ledger)
        fea.attach_expert_miss_summary(attack_story, miss_summary)
        report_qa = {
            "status": "WARN",
            "packet_state": "EXPERT_REVIEW_DRAFT",
            "expert_decision": "pending",
            "ready_for_expert_signoff": True,
            "customer_release_candidate": False,
            "customer_releasable": False,
            "ready_for_customer_pdf": False,
            "recommended_expert_review_time": "30-60 minutes",
            "checks": [
                {
                    "check_id": "finding_tool_call_required",
                    "status": "PASS",
                    "summary": "All Findings cite current-case tool calls.",
                },
                {
                    "check_id": "attack_coverage_blind_spots",
                    "status": "WARN",
                    "summary": "Network telemetry | was not supplied. `Review` needed.",
                },
            ],
        }
        release_gate = {
            "qa_status": "WARN",
            "packet_state": "EXPERT_REVIEW_DRAFT",
            "manifest_verified": True,
            "manifest_signature_present": True,
            "signer": "stub",
            "expert_approved": False,
            "customer_releasable": False,
            "release_blockers": [
                "explicit human expert approval is required before customer release"
            ],
        }
        doctrine = {
            "operating_model": "The agent prepares an evidence-bound signoff packet; the human expert remains final authority.",
            "claim_rules": [
                {
                    "id": "finding_tool_call_required",
                    "severity": "blocker",
                    "requirement": "Every Finding | must cite a tool_call_id.",
                }
            ],
        }
        rr.fig_attack_story_timeline(
            attack_story, case_dir / "attack_story_timeline.png"
        )
        entity_timeline = [
            {
                "event_id": "timeline-0001",
                "timestamp_utc": "2026-05-04T02:49:00Z",
                "artifact_class": "evtx",
                "summary": "Security audit log clearing by CORP\\Administrator",
                "significance": "finding_support",
                "tool_call_id": "tc-evtx",
                "confidence": "INFERRED",
                "linked_finding_ids": ["f-clear"],
                "entities": {
                    "account": "Administrator",
                    "domain": "CORP",
                    "host": "DC01",
                },
            }
        ]
        entity_index = {
            "accounts": [
                {
                    "value": "CORP\\Administrator",
                    "event_count": 1,
                    "first_seen": "2026-05-04T02:49:00Z",
                    "last_seen": "2026-05-04T02:49:00Z",
                    "artifact_classes": ["evtx"],
                    "tool_call_ids": ["tc-evtx"],
                    "linked_finding_ids": ["f-clear"],
                }
            ]
        }
        indicators = {
            "accounts": ["CORP\\Administrator"],
            "note": "Indicators are observed artifacts; corroborate before deployment.",
        }
        event_narratives = [
            {
                "text": "At 2026-05-04T02:49:00Z UTC, Security audit log cleared by "
                "CORP\\Administrator (tool call tc-evtx, INFERRED)."
            }
        ]
        practitioner_coverage = {
            "lanes": {
                "memory": {
                    "label": "Memory Forensics",
                    "status": "automated",
                    "artifact_classes_seen": ["memory"],
                    "tools_run": ["vol_psscan"],
                    "attck_data_sources_seen": ["DS0009"],
                    "coverage_gaps": [],
                }
            },
            "overclaim_guardrails_applied": [
                "Domain coverage describes triage/orchestration across the typed "
                "tools that ran, not certified-analyst judgment"
            ],
        }
        md_path = rr.write_markdown(
            case_dir,
            manifest,
            findings,
            contras=0,
            kept=1,
            downgraded=0,
            evidence="memory` ![x](file:///etc/passwd)\n.img",
            verdict="SUSPICIOUS",
            has_psscan=False,
            attack_story=attack_story,
            report_qa=report_qa,
            expert_doctrine=doctrine,
            release_gate=release_gate,
            coverage_manifest={
                "truth_boundary": "If no parser/tool extracts an artifact class, VERDICT cannot reason over it.",
                "summary": {
                    "artifact_classes_recorded": 2,
                    "attempted": 1,
                    "parsed": 1,
                    "failed": 0,
                    "unsupported": 0,
                    "not_supplied": 1,
                    "attack_blind_spot_count": 3,
                    "status_counts": {"not_supplied": 1, "parsed": 1},
                },
                "artifact_classes": [
                    {
                        "artifact_class": "evtx",
                        "status": "parsed",
                        "available": True,
                        "attempted": True,
                        "parsed": True,
                        "failed": False,
                        "unsupported": False,
                        "not_supplied": False,
                        "parse_errors": 0,
                        "records_seen": 5,
                        "rows_returned": 5,
                        "tools_attempted": ["evtx_query"],
                    },
                    {
                        "artifact_class": "network",
                        "status": "not_supplied",
                        "available": False,
                        "attempted": False,
                        "parsed": False,
                        "failed": False,
                        "unsupported": False,
                        "not_supplied": True,
                        "parse_errors": 0,
                        "records_seen": 0,
                        "rows_returned": 0,
                        "tools_attempted": [],
                    },
                    {
                        "artifact_class": "unsupported",
                        "status": "unsupported",
                        "available": True,
                        "attempted": False,
                        "parsed": False,
                        "failed": False,
                        "unsupported": True,
                        "not_supplied": False,
                        "parse_errors": 0,
                        "records_seen": 2,
                        "rows_returned": 0,
                        "tools_attempted": [],
                        "sample_paths": [
                            "unsupported/evil.bin",
                            "collection.zip::Uploads/odd-artifact.bin",
                        ],
                    },
                ],
            },
            timeline=entity_timeline,
            normalized_timeline={"events": entity_timeline},
            entity_index=entity_index,
            indicators=indicators,
            event_narratives=event_narratives,
            practitioner_coverage=practitioner_coverage,
            rejected_finding_leads=[
                {
                    "finding_id": "f-rejected",
                    "tool_call_id": "tc-rejected",
                    "confidence": "CONFIRMED",
                    "pool_origin": "pool_a",
                    "mitre_technique": "T1005",
                    "artifact_path": "artifact.json",
                    "description": "Rejected lead with a | pipe and `tick`.",
                    "verifier_reason": "tool re-run failed",
                    "verdict_effect": "excluded_from_final_findings",
                    "analyst_action": (
                        "Inspect this as a rejected lead; do not treat it as evidence until replay succeeds."
                    ),
                }
            ],
            verdict_revisions=[
                {
                    "finding_id": "f-flip",
                    "from_verdict": "CONFIRMED",
                    "to_verdict": "INFERRED",
                    "mechanism": "correlation_downgrade",
                    "trigger_tool_call_id": "tc-correlate",
                    "reason": "only 1 artifact class; execution needs >=2 with a | pipe.",
                }
            ],
            has_attack_story_fig=True,
            host_groups=host_groups,
        )
        main_text = md_path.read_text(encoding="utf-8")
        internal_md = md_path.parent / "REPORT-internal.md"
        internal_text = (
            internal_md.read_text(encoding="utf-8") if internal_md.is_file() else ""
        )
        # The internal QA/signoff gates now ship as a companion REPORT-internal file;
        # the combined text keeps the existing section-marker assertions valid while
        # the split itself is checked separately below.
        text = main_text + "\n" + internal_text
        public_text = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (
                REPO / "README.md",
                REPO / "QUICKSTART.md",
                REPO / "docs" / "release-surface.md",
                REPO / "docs" / "release-evidence" / "README.md",
            )
            if path.is_file()
        )
        valid_html_text = """<!doctype html><html><body>
            <h1>VERDICT — Forensic Investigation Report</h1>
            <h2>Cryptographic Attestation</h2>
            <h2>QA / Expert Signoff</h2>
            <h2>Customer Release Gate</h2>
            <h2>Findings Summary</h2>
            <h2>Chain of Custody</h2>
            <p>tool_call_id tc-psscan</p>
            <h2>Limitations</h2>
            <p>stub signatures are dev/offline only; this is an explicit release blocker.</p>
            <p>Evidence-bound report text.</p>
            </body></html>""" + ("x" * 1800)
        stage_two_good_result = validator.validate_stage_two_judge_packet_text(
            "The optional harness/demo is the only place a fault injection or "
            "`fault_injection` record may appear. The primary clean packet contains "
            "no `fault_injection` records.",
            "good stage two judge packet",
        )
        stage_two_bad_result = validator.validate_stage_two_judge_packet_text(
            "The primary self-correction proof uses `fault_injection` as organic evidence.",
            "bad stage two judge packet",
        )
        stage_two_bad_hyphen_result = validator.validate_stage_two_judge_packet_text(
            "The primary self-correction proof uses fault-injection as organic evidence.",
            "bad hyphenated stage two judge packet",
        )
        stage_two_bad_space_result = validator.validate_stage_two_judge_packet_text(
            "The primary self-correction proof uses fault injection as organic evidence.",
            "bad spaced stage two judge packet",
        )
        stage_two_bad_optional_organic_result = (
            validator.validate_stage_two_judge_packet_text(
                "The optional harness/demo `fault_injection` run is organic "
                "self-correction evidence.",
                "bad optional-organic stage two judge packet",
            )
        )
        stage_two_bad_optional_primary_result = (
            validator.validate_stage_two_judge_packet_text(
                "The optional harness fault injection shows primary "
                "self-correction proof.",
                "bad optional-primary stage two judge packet",
            )
        )
        stage_two_bad_negation_window_result = (
            validator.validate_stage_two_judge_packet_text(
                "The optional harness/demo is not organic evidence; "
                "the fault_injection trial is primary evidence.",
                "bad negation-window stage two judge packet",
            )
        )
        stage_two_bad_cross_negation_result = (
            validator.validate_stage_two_judge_packet_text(
                "The optional harness/demo fault_injection run is not natural, "
                "but it remains organic evidence.",
                "bad cross-negation stage two judge packet",
            )
        )
        stage_two_actual_result = validator.validate_stage_two_judge_packet(
            REPO / "docs" / "release-evidence" / "stage-two-judge-packet.md"
        )
        valid_html = case_dir / "valid-investigation-report.html"
        valid_html.write_text(valid_html_text, encoding="utf-8")
        invalid_html = case_dir / "invalid-investigation-report.html"
        invalid_html.write_text(
            """<!doctype html><html><body>
            <h1>VERDICT — Forensic Investigation Report</h1>
            <h2>Cryptographic Attestation</h2>
            <h2>QA / Expert Signoff</h2>
            <h2>Customer Release Gate</h2>
            <h2>Findings Summary</h2>
            <h2>Chain of Custody</h2>
            <p>tool_call_id tc-psscan</p>
            <h2>Limitations</h2>
            <p>TODO placeholder report text.</p>
            </body></html>"""
            + ("x" * 1800),
            encoding="utf-8",
        )
        valid_report_result = validator.validate_report(valid_html)
        invalid_report_result = validator.validate_report(invalid_html)
        valid_zip = case_dir / "valid-investigation-report.zip"
        with zipfile.ZipFile(valid_zip, "w") as zf:
            zf.writestr("README-submission.md", "Find Evil submission package\n")
            zf.writestr(
                "benchmark-results.csv",
                "fixture,source_file,findings_matched,findings_expected\nnist-hacking-case,,1,14\n",
            )
            zf.writestr("demo-video-link.txt", "https://example.org/findevil-demo\n")
            zf.writestr("LICENSE", "Test license fixture\n")
            zf.writestr("report.html", valid_html_text)
            zf.writestr(
                "readiness-packet.zip", build_readiness_packet_zip(valid_html_text)
            )
        valid_zip_result = validator.validate_zip(valid_zip)
        forbidden_extra_zip = case_dir / "forbidden-extra-investigation-report.zip"
        with zipfile.ZipFile(forbidden_extra_zip, "w") as zf:
            zf.writestr("README-submission.md", "Find Evil submission package\n")
            zf.writestr(
                "benchmark-results.csv",
                "fixture,source_file,findings_matched,findings_expected\nnist-hacking-case,,1,14\n",
            )
            zf.writestr("demo-video-link.txt", "https://example.org/findevil-demo\n")
            zf.writestr("LICENSE", "Test license fixture\n")
            zf.writestr("report.html", valid_html_text)
            zf.writestr(".env", "TOKEN=do-not-ship\n")
            zf.writestr("evidence/sample-disk.dd", b"raw disk evidence")
        forbidden_extra_zip_result = validator.validate_zip(forbidden_extra_zip)
        unknown_extra_zip = case_dir / "unknown-extra-investigation-report.zip"
        with zipfile.ZipFile(unknown_extra_zip, "w") as zf:
            zf.writestr("README-submission.md", "Find Evil submission package\n")
            zf.writestr(
                "benchmark-results.csv",
                "fixture,source_file,findings_matched,findings_expected\nnist-hacking-case,,1,14\n",
            )
            zf.writestr("demo-video-link.txt", "https://example.org/findevil-demo\n")
            zf.writestr("LICENSE", "Test license fixture\n")
            zf.writestr("report.html", valid_html_text)
            zf.writestr("notes.txt", "operator scratch notes must not ship\n")
        unknown_extra_zip_result = validator.validate_zip(unknown_extra_zip)
        finding_packet_audit = (
            '{"kind":"report_qa","payload":{"status":"PASS"}}\n'
            '{"kind":"customer_release_gate","payload":{"customer_releasable":false}}\n'
            '{"kind":"verdict_artifact","payload":{"path":"verdict.json","sha256":"'
            + VERDICT_SHA_TOKEN
            + '"}}\n'
            '{"kind":"expert_signoff_packet","payload":{"expert_signoff_sha256":"'
            + ("b" * 64)
            + '"}}\n'
        )
        ready_finding = {
            "finding_id": "f-ready",
            "tool_call_id": "tc-ready",
            "confidence": "CONFIRMED",
            "description": "Replay-backed finding.",
        }
        tampered_finding = {
            **ready_finding,
            "description": "Tampered finding was not audit-approved.",
        }
        finding_packet = build_readiness_packet_zip(
            valid_html_text,
            audit_jsonl=finding_packet_audit,
            verdict_overrides={
                "findings": [
                    {
                        "finding_id": "f-ready",
                        "tool_call_id": "tc-ready",
                        "confidence": "CONFIRMED",
                        "description": "Replay-backed finding.",
                    }
                ]
            },
        )
        fault_injection_packet_audit = (
            finding_packet_audit
            + '{"kind":"fault_injection","payload":{"mode":"verifier_reject_once"}}\n'
        )
        fault_injection_packet_result = validator.validate_readiness_packet_bytes(
            build_readiness_packet_zip(
                valid_html_text,
                audit_jsonl=fault_injection_packet_audit,
            ),
            "readiness packet with fault-injection demo record",
        )
        missing_verifier_packet_result = validator.validate_readiness_packet_bytes(
            finding_packet, "finding packet missing verifier evidence"
        )
        valid_verifier_audit = (
            finding_packet_audit
            + '{"kind":"tool_call_start","payload":{"tool_call_id":"tc-ready",'
            '"tool":"evtx_query"}}\n'
            + '{"kind":"tool_call_output","payload":{"tool_call_id":"tc-ready",'
            '"output_hash":"'
            + ("d" * 64)
            + '"}}\n'
            + '{"kind":"verifier_action","payload":{"finding_id":"f-ready",'
            '"action":"approved","reason":"replay matched",'
            '"replay_record_sha256":"'
            + ("c" * 64)
            + '"}}\n'
            + '{"kind":"replay","payload":{"finding_id":"f-ready",'
            '"replay_matched":true,"replay_record_sha256":"'
            + ("c" * 64)
            + '"}}\n'
            + '{"kind":"acp_handoff","payload":{"from_role":"verifier",'
            '"to_role":"judge","correlation_id":"f-ready",'
            '"payload":{"finding_id":"f-ready","action":"approved",'
            '"replay_record_sha256":"' + ("c" * 64) + '"}}}\n'
        )
        valid_bound_finding_audit = (
            finding_packet_audit
            + finding_approved_audit_record(ready_finding)
            + '{"kind":"tool_call_start","payload":{"tool_call_id":"tc-ready",'
            '"tool":"evtx_query"}}\n'
            + '{"kind":"tool_call_output","payload":{"tool_call_id":"tc-ready",'
            '"output_hash":"'
            + ("d" * 64)
            + '"}}\n'
            + '{"kind":"verifier_action","payload":{"finding_id":"f-ready",'
            '"action":"approved","reason":"replay matched",'
            '"replay_record_sha256":"'
            + ("c" * 64)
            + '"}}\n'
            + '{"kind":"replay","payload":{"finding_id":"f-ready",'
            '"replay_matched":true,"replay_record_sha256":"'
            + ("c" * 64)
            + '"}}\n'
            + '{"kind":"acp_handoff","payload":{"from_role":"verifier",'
            '"to_role":"judge","correlation_id":"f-ready",'
            '"payload":{"finding_id":"f-ready","action":"approved",'
            '"replay_record_sha256":"' + ("c" * 64) + '"}}}\n'
        )
        valid_bound_finding_packet_result = validator.validate_readiness_packet_bytes(
            build_readiness_packet_zip(
                valid_html_text,
                audit_jsonl=valid_bound_finding_audit,
                verdict_overrides={"findings": [ready_finding]},
            ),
            "packet with audit-bound final finding",
        )
        tampered_verdict_artifact_packet_result = (
            validator.validate_readiness_packet_bytes(
                build_readiness_packet_zip(
                    valid_html_text,
                    audit_jsonl=finding_packet_audit.replace(
                        VERDICT_SHA_TOKEN, "0" * 64
                    ),
                ),
                "packet with tampered verdict artifact hash",
            )
        )
        tampered_finding_approved_packet_result = (
            validator.validate_readiness_packet_bytes(
                build_readiness_packet_zip(
                    valid_html_text,
                    audit_jsonl=valid_bound_finding_audit,
                    verdict_overrides={"findings": [tampered_finding]},
                ),
                "packet with tampered audit-approved finding",
            )
        )
        missing_tool_call_packet_result = validator.validate_readiness_packet_bytes(
            build_readiness_packet_zip(
                valid_html_text,
                audit_jsonl=valid_verifier_audit,
                verdict_overrides={
                    "findings": [
                        {
                            "finding_id": "f-ready",
                            "confidence": "CONFIRMED",
                            "description": "Replay-backed finding without citation.",
                        }
                    ]
                },
            ),
            "packet with final finding missing tool_call_id",
        )
        ghost_tool_call_packet_result = validator.validate_readiness_packet_bytes(
            build_readiness_packet_zip(
                valid_html_text,
                audit_jsonl=valid_verifier_audit,
                verdict_overrides={
                    "findings": [
                        {
                            "finding_id": "f-ready",
                            "tool_call_id": "tc-ghost",
                            "confidence": "CONFIRMED",
                            "description": "Replay-backed finding with a ghost citation.",
                        }
                    ]
                },
            ),
            "packet with final finding citing ghost tool_call_id",
        )
        invalid_output_hash_audit = valid_bound_finding_audit.replace(
            '"output_hash":"' + ("d" * 64) + '"',
            '"output_hash":"not-a-sha256"',
        )
        invalid_output_hash_packet_result = validator.validate_readiness_packet_bytes(
            build_readiness_packet_zip(
                valid_html_text,
                audit_jsonl=invalid_output_hash_audit,
                verdict_overrides={"findings": [ready_finding]},
            ),
            "packet with final finding citation missing valid output hash",
        )
        invalid_verifier_audit = (
            '{"kind":"report_qa","payload":{"status":"PASS"}}\n'
            '{"kind":"customer_release_gate","payload":{"customer_releasable":false}}\n'
            '{"kind":"verdict_artifact","payload":{"path":"verdict.json","sha256":"'
            + VERDICT_SHA_TOKEN
            + '"}}\n'
            '{"kind":"expert_signoff_packet","payload":{"expert_signoff_sha256":"'
            + ("b" * 64)
            + '"}}\n'
            '{"kind":"verifier_action","payload":{"finding_id":"f-ready",'
            '"action":"rejected","reason":"replay mismatch"}}\n'
            '{"kind":"replay","payload":{"finding_id":"f-ready",'
            '"replay_matched":false,"replay_record_sha256":"' + ("c" * 64) + '"}}\n'
            '{"kind":"acp_handoff","payload":{"from_role":"pool_a",'
            '"to_role":"judge","correlation_id":"f-ready",'
            '"payload":{"finding_id":"f-ready","action":"rejected",'
            '"replay_record_sha256":"' + ("c" * 64) + '"}}}\n'
        )
        invalid_verifier_packet_result = validator.validate_readiness_packet_bytes(
            build_readiness_packet_zip(
                valid_html_text,
                audit_jsonl=invalid_verifier_audit,
                verdict_overrides={
                    "findings": [
                        {
                            "finding_id": "f-ready",
                            "tool_call_id": "tc-ready",
                            "confidence": "CONFIRMED",
                            "description": "Replay-backed finding.",
                        }
                    ]
                },
            ),
            "packet with invalid verifier evidence",
        )
        mismatched_replay_hash_audit = (
            '{"kind":"report_qa","payload":{"status":"PASS"}}\n'
            '{"kind":"customer_release_gate","payload":{"customer_releasable":false}}\n'
            '{"kind":"verdict_artifact","payload":{"path":"verdict.json","sha256":"'
            + VERDICT_SHA_TOKEN
            + '"}}\n'
            '{"kind":"expert_signoff_packet","payload":{"expert_signoff_sha256":"'
            + ("b" * 64)
            + '"}}\n'
            '{"kind":"verifier_action","payload":{"finding_id":"f-ready",'
            '"action":"approved","reason":"replay matched",'
            '"replay_record_sha256":"' + ("c" * 64) + '"}}\n'
            '{"kind":"replay","payload":{"finding_id":"f-ready",'
            '"replay_matched":true,"replay_record_sha256":"' + ("d" * 64) + '"}}\n'
            '{"kind":"acp_handoff","payload":{"from_role":"verifier",'
            '"to_role":"judge","correlation_id":"f-ready",'
            '"payload":{"finding_id":"f-ready","action":"approved",'
            '"replay_record_sha256":"' + ("c" * 64) + '"}}}\n'
        )
        mismatched_replay_hash_packet_result = (
            validator.validate_readiness_packet_bytes(
                build_readiness_packet_zip(
                    valid_html_text,
                    audit_jsonl=mismatched_replay_hash_audit,
                    verdict_overrides={
                        "findings": [
                            {
                                "finding_id": "f-ready",
                                "tool_call_id": "tc-ready",
                                "confidence": "CONFIRMED",
                                "description": "Replay-backed finding.",
                            }
                        ]
                    },
                ),
                "packet with mismatched verifier replay hashes",
            )
        )
        split_hash_action_audit = (
            '{"kind":"report_qa","payload":{"status":"PASS"}}\n'
            '{"kind":"customer_release_gate","payload":{"customer_releasable":false}}\n'
            '{"kind":"verdict_artifact","payload":{"path":"verdict.json","sha256":"'
            + VERDICT_SHA_TOKEN
            + '"}}\n'
            '{"kind":"expert_signoff_packet","payload":{"expert_signoff_sha256":"'
            + ("b" * 64)
            + '"}}\n'
            '{"kind":"verifier_action","payload":{"finding_id":"f-ready",'
            '"action":"approved","reason":"replay matched",'
            '"replay_record_sha256":"' + ("c" * 64) + '"}}\n'
            '{"kind":"verifier_action","payload":{"finding_id":"f-ready",'
            '"action":"downgraded","reason":"weaker support",'
            '"replay_record_sha256":"' + ("d" * 64) + '"}}\n'
            '{"kind":"replay","payload":{"finding_id":"f-ready",'
            '"replay_matched":true,"replay_record_sha256":"' + ("c" * 64) + '"}}\n'
            '{"kind":"acp_handoff","payload":{"from_role":"verifier",'
            '"to_role":"judge","correlation_id":"f-ready",'
            '"payload":{"finding_id":"f-ready","action":"downgraded",'
            '"replay_record_sha256":"' + ("c" * 64) + '"}}}\n'
        )
        split_hash_action_packet_result = validator.validate_readiness_packet_bytes(
            build_readiness_packet_zip(
                valid_html_text,
                audit_jsonl=split_hash_action_audit,
                verdict_overrides={
                    "findings": [
                        {
                            "finding_id": "f-ready",
                            "tool_call_id": "tc-ready",
                            "confidence": "CONFIRMED",
                            "description": "Replay-backed finding.",
                        }
                    ]
                },
            ),
            "packet with split verifier hash/action evidence",
        )
        downgraded_not_reflected_audit = (
            '{"kind":"report_qa","payload":{"status":"PASS"}}\n'
            '{"kind":"customer_release_gate","payload":{"customer_releasable":false}}\n'
            '{"kind":"verdict_artifact","payload":{"path":"verdict.json","sha256":"'
            + VERDICT_SHA_TOKEN
            + '"}}\n'
            '{"kind":"expert_signoff_packet","payload":{"expert_signoff_sha256":"'
            + ("b" * 64)
            + '"}}\n'
            '{"kind":"verifier_action","payload":{"finding_id":"f-ready",'
            '"action":"downgraded","reason":"weak replay",'
            '"replay_record_sha256":"' + ("c" * 64) + '"}}\n'
            '{"kind":"replay","payload":{"finding_id":"f-ready",'
            '"replay_matched":true,"replay_record_sha256":"' + ("c" * 64) + '"}}\n'
            '{"kind":"acp_handoff","payload":{"from_role":"verifier",'
            '"to_role":"judge","correlation_id":"f-ready",'
            '"payload":{"finding_id":"f-ready","action":"downgraded",'
            '"replay_record_sha256":"' + ("c" * 64) + '"}}}\n'
        )
        downgraded_not_reflected_packet_result = (
            validator.validate_readiness_packet_bytes(
                build_readiness_packet_zip(
                    valid_html_text,
                    audit_jsonl=downgraded_not_reflected_audit,
                    verdict_overrides={
                        "findings": [
                            {
                                "finding_id": "f-ready",
                                "tool_call_id": "tc-ready",
                                "confidence": "CONFIRMED",
                                "description": "Downgrade was not reflected.",
                            }
                        ]
                    },
                ),
                "packet with unreflected verifier downgrade",
            )
        )
        multi_downgrade_bypass_audit = (
            '{"kind":"report_qa","payload":{"status":"PASS"}}\n'
            '{"kind":"customer_release_gate","payload":{"customer_releasable":false}}\n'
            '{"kind":"verdict_artifact","payload":{"path":"verdict.json","sha256":"'
            + VERDICT_SHA_TOKEN
            + '"}}\n'
            '{"kind":"expert_signoff_packet","payload":{"expert_signoff_sha256":"'
            + ("b" * 64)
            + '"}}\n'
            '{"kind":"tool_call_start","payload":{"tool_call_id":"tc-dg"}}\n'
            '{"kind":"tool_call_output","payload":{"tool_call_id":"tc-dg",'
            '"output_hash":"' + ("1" * 64) + '"}}\n'
            '{"kind":"tool_call_start","payload":{"tool_call_id":"tc-ok"}}\n'
            '{"kind":"tool_call_output","payload":{"tool_call_id":"tc-ok",'
            '"output_hash":"' + ("2" * 64) + '"}}\n'
            '{"kind":"verifier_action","payload":{"finding_id":"f-dg",'
            '"action":"downgraded","reason":"weak replay",'
            '"replay_record_sha256":"' + ("c" * 64) + '"}}\n'
            '{"kind":"replay","payload":{"finding_id":"f-dg",'
            '"replay_matched":true,"replay_record_sha256":"' + ("c" * 64) + '"}}\n'
            '{"kind":"acp_handoff","payload":{"from_role":"verifier",'
            '"to_role":"judge","correlation_id":"f-dg",'
            '"payload":{"finding_id":"f-dg","action":"downgraded",'
            '"replay_record_sha256":"' + ("c" * 64) + '"}}}\n'
            '{"kind":"verifier_action","payload":{"finding_id":"f-ok",'
            '"action":"approved","reason":"matched",'
            '"replay_record_sha256":"' + ("d" * 64) + '"}}\n'
            '{"kind":"replay","payload":{"finding_id":"f-ok",'
            '"replay_matched":true,"replay_record_sha256":"' + ("d" * 64) + '"}}\n'
            '{"kind":"acp_handoff","payload":{"from_role":"verifier",'
            '"to_role":"judge","correlation_id":"f-ok",'
            '"payload":{"finding_id":"f-ok","action":"approved",'
            '"replay_record_sha256":"' + ("d" * 64) + '"}}}\n'
        )
        multi_downgrade_bypass_packet_result = (
            validator.validate_readiness_packet_bytes(
                build_readiness_packet_zip(
                    valid_html_text,
                    audit_jsonl=multi_downgrade_bypass_audit,
                    verdict_overrides={
                        "findings": [
                            {
                                "finding_id": "f-dg",
                                "tool_call_id": "tc-dg",
                                "confidence": "CONFIRMED",
                                "description": "Downgrade bypass first finding.",
                            },
                            {
                                "finding_id": "f-ok",
                                "tool_call_id": "tc-ok",
                                "confidence": "INFERRED",
                                "description": "Second finding masks stale lookup.",
                            },
                        ]
                    },
                ),
                "packet with multi-finding downgrade bypass",
            )
        )
        forged_manifest_packet_result = validator.validate_readiness_packet_bytes(
            build_readiness_packet_zip(
                valid_html_text,
                run_manifest=b'{"case_id":"case-ready","merkle_root_hex":"forged"}\n',
                manifest_verify={"overall": True, "signature_verified": True},
            ),
            "packet with forged manifest verification",
        )
        unknown_extra_packet = io.BytesIO()
        with zipfile.ZipFile(unknown_extra_packet, "w") as zf:
            with zipfile.ZipFile(
                io.BytesIO(build_readiness_packet_zip(valid_html_text))
            ) as source:
                for info in source.infolist():
                    zf.writestr(info, source.read(info.filename))
            zf.writestr("notes.txt", "operator scratch notes must not ship\n")
        unknown_extra_packet_result = validator.validate_readiness_packet_bytes(
            unknown_extra_packet.getvalue(), "packet with unknown extra file"
        )
        non_image_figure_packet_result = validator.validate_readiness_packet_bytes(
            add_manifested_packet_file(
                build_readiness_packet_zip(valid_html_text),
                "figures/debug.txt",
                b"debug text must not ship as a figure\n",
            ),
            "packet with non-image figure artifact",
        )
        unsafe_path_packet = io.BytesIO()
        with zipfile.ZipFile(unsafe_path_packet, "w") as zf:
            zf.writestr("../audit.jsonl", "{}\n")
        unsafe_path_packet_result = validator.validate_readiness_packet_bytes(
            unsafe_path_packet.getvalue(), "packet with traversal path"
        )
        nested_colon_path_packet = io.BytesIO()
        with zipfile.ZipFile(
            io.BytesIO(build_readiness_packet_zip(valid_html_text))
        ) as src:
            with zipfile.ZipFile(nested_colon_path_packet, "w") as zf:
                for member in src.infolist():
                    zf.writestr(member.filename, src.read(member.filename))
                zf.writestr("safe/C:/REPORT.html", valid_html_text)
        nested_colon_path_packet_result = validator.validate_readiness_packet_bytes(
            nested_colon_path_packet.getvalue(), "packet with nested colon path"
        )
        symlink_dir_packet = io.BytesIO()
        with zipfile.ZipFile(
            io.BytesIO(build_readiness_packet_zip(valid_html_text))
        ) as src:
            with zipfile.ZipFile(symlink_dir_packet, "w") as zf:
                for member in src.infolist():
                    zf.writestr(member.filename, src.read(member.filename))
                symlink_dir = zipfile.ZipInfo("linkdir/")
                symlink_dir.external_attr = (stat.S_IFLNK | 0o777) << 16
                zf.writestr(symlink_dir, "target")
        symlink_dir_packet_result = validator.validate_readiness_packet_bytes(
            symlink_dir_packet.getvalue(), "packet with symlink directory"
        )
        unverifiable_signature_packet_result = (
            validator.validate_readiness_packet_bytes(
                build_readiness_packet_zip(
                    valid_html_text,
                    manifest_verify={
                        "overall": True,
                        "signature_present": True,
                        "signature_verified": False,
                    },
                ),
                "packet with unverified manifest signature",
            )
        )

    checks = [
        (
            "expert rules contain report QA claim IDs",
            not missing_claim_rule_ids,
        ),
        (
            "empty findings report QA warns without failing",
            empty_qa["status"] == "WARN" and empty_timeline_check["status"] == "WARN",
        ),
        (
            "coverage gate flags available-but-unexamined artifact class",
            unexamined_gap_classes == ["evtx"],
        ),
        (
            "coverage gate ignores not-supplied artifact class",
            fully_examined_gap_classes == [],
        ),
        (
            "NO_EVIL over unexamined available class FAILs no_evil_is_scoped",
            no_evil_unexamined_check["status"] == "FAIL",
        ),
        (
            "NO_EVIL over fully examined coverage keeps no_evil_is_scoped PASS",
            no_evil_complete_check["status"] == "PASS",
        ),
        (
            "embedded replay match passes report QA check",
            replay_match_check["status"] == "PASS",
        ),
        (
            "embedded replay mismatch follows configured severity",
            replay_mismatch_check["status"] == replay_mismatch_expected_status,
        ),
        (
            "executive attack story wrapper removed",
            "## Executive Attack Story" not in text,
        ),
        ("qa signoff heading", "## QA / Expert Signoff" in text),
        ("customer release gate heading", "## Customer Release Gate" in text),
        ("analysis doctrine heading", "## Analysis Doctrine" in text),
        ("verdict rebrand title", "# VERDICT — Forensic Investigation Report" in text),
        ("bottom line up front heading", "## Bottom Line Up Front" in text),
        ("host analysis heading", "## Host Analysis" in text),
        ("per-host section rendered", "### DC01" in text),
        ("named technique in host analysis", "Rootkit / DKOM process hiding" in text),
        ("per-finding next pivot rendered", "*Next:*" in text),
        ("per-finding hunt query rendered", "*Hunt:*" in text),
        ("full event timeline heading", "## Full Event Timeline" in text),
        (
            "observed entities heading",
            "## Observed Hosts, Accounts & Processes" in text,
        ),
        ("iocs heading", "## Indicators of Compromise (IOCs)" in text),
        (
            "analysis coverage by domain heading",
            "## Analysis Coverage by Domain" in text,
        ),
        ("technical report tier divider", "# Technical Report {.tier-break}" in text),
        (
            "internal gates shipped as companion packet",
            "# VERDICT — Internal QA & Release Gates" in internal_text,
        ),
        (
            "internal gates removed from main customer/technical report",
            "## QA / Expert Signoff" not in main_text
            and "## Customer Release Gate" not in main_text
            and "## Analysis Doctrine" not in main_text
            and "## Readiness State" not in main_text,
        ),
        (
            "main report references the internal packet",
            "REPORT-internal" in main_text,
        ),
        ("legacy practitioner heading removed", "## Practitioner Coverage" not in text),
        (
            "no GIAC certification wording",
            not any(cert in text for cert in ("GREM", "GCFA", "GNFA")),
        ),
        (
            "entity timeline surfaces source account and host",
            "Administrator" in text and "DC01" in text,
        ),
        ("finding tool call preserved", "tc-psscan" in text),
        ("verifier-rejected leads heading", "## Verifier-Rejected Leads" in text),
        (
            "rejected lead marked non-evidentiary",
            "tc-rejected" in text and "excluded_from_final_findings" in text,
        ),
        ("self-correction heading", "## Self-Correction" in text),
        (
            "self-correction renders from->to confidence flip",
            "CONFIRMED" in text and "INFERRED" in text,
        ),
        (
            "self-correction cites trigger tool call",
            "tc-correlate" in text,
        ),
        ("limitations section present", "## Limitations" in text),
        ("coverage manifest section present", "## Coverage Manifest" in text),
        (
            "coverage manifest renders not-supplied scope",
            "`not_supplied`" in text and "network" in text,
        ),
        (
            "coverage manifest names unsupported samples",
            "unsupported/evil.bin" in text
            and "collection.zip::Uploads/odd-artifact.bin" in text,
        ),
        (
            "no narrative leftovers (story/cast/beats)",
            not any(
                s in text
                for s in (
                    "## Cast of Characters",
                    "## Finding-Backed Story Beats",
                    "What happened, in order",
                )
            ),
        ),
        (
            "expert miss summary rendered",
            "Expert misses captured this case: 1 \\(qa=1\\)" in text,
        ),
        (
            "empty expert miss summary flags QA defect",
            "uncaptured edits are a QA defect" in empty_miss_summary["summary"],
        ),
        (
            "packet state visible",
            "Packet state: `EXPERT_REVIEW_DRAFT`" in text,
        ),
        (
            "customer release remains pending expert approval",
            "Customer releasable after expert approval: `False`" in text,
        ),
        ("qa pass row rendered", "`finding_tool_call_required` | PASS" in text),
        ("qa warn row rendered", "`attack_coverage_blind_spots` | WARN" in text),
        ("manifest verified rendered", "Manifest verified: `True`" in text),
        ("release blocker rendered", "human expert approval is required" in text),
        ("doctrine rule row rendered", "Every Finding \\| must cite" in text),
        ("pipe escaped in finding", "Process-view \\| divergence" in text),
        ("backtick neutralized", "with 'tick' and newline" in text),
        (
            "evidence path cannot inject image markdown",
            "![x](file:///etc/passwd)" not in text,
        ),
        (
            "finding artifact display strips operator path",
            "/home/operator/.findevil" not in text
            and "case-extracted://disk-extract-abc/prefetch/WINDOWS/Prefetch/CAIN.EXE-23D61279.pf"
            in text,
        ),
        (
            "legacy manifest command absent",
            "manifest_verify <run.manifest.json>" not in text,
        ),
        ("verification library command present", "verify_manifest(Path(" in text),
        (
            "caveats avoid forbidden wording",
            "clean, cleared" not in text and "clean/cleared" not in text,
        ),
        (
            "public copy frames supported local disk parsing honestly",
            "Supported disk images can be parsed locally through Sleuth Kit direct-read when prerequisites are present"
            in public_text
            and "`case_open` alone remains custody-only" in public_text
            and "unsupported artifact classes stay as named limitations" in public_text,
        ),
        (
            "public copy names expert signoff packet",
            "expert-signoff packet" in public_text,
        ),
        (
            "public copy avoids raw disk end-to-end overclaim",
            "disk images, memory captures, EVTX logs) end-to-end" not in public_text,
        ),
        (
            "public copy avoids unconditional Rekor overclaim",
            "signs with sigstore (Rekor inclusion proof)" not in public_text,
        ),
        (
            "stage two packet allows labeled optional fault-injection appendix",
            stage_two_good_result.ok,
        ),
        (
            "stage two packet rejects organic fault-injection framing",
            not stage_two_bad_result.ok,
        ),
        (
            "stage two packet rejects hyphenated organic fault-injection framing",
            not stage_two_bad_hyphen_result.ok,
        ),
        (
            "stage two packet rejects spaced organic fault injection framing",
            not stage_two_bad_space_result.ok,
        ),
        (
            "stage two packet rejects optional organic fault-injection framing",
            not stage_two_bad_optional_organic_result.ok,
        ),
        (
            "stage two packet rejects optional primary fault-injection framing",
            not stage_two_bad_optional_primary_result.ok,
        ),
        (
            "stage two packet rejects negation-window fault-injection framing",
            not stage_two_bad_negation_window_result.ok,
        ),
        (
            "stage two packet rejects cross-claim negation fault-injection framing",
            not stage_two_bad_cross_negation_result.ok,
        ),
        (
            "stage two packet file validates optional harness framing",
            stage_two_actual_result.ok,
        ),
        (
            "case report HTML validator accepts explicit stub blocker",
            valid_report_result.ok,
        ),
        (
            "case report HTML validator rejects placeholder text",
            not invalid_report_result.ok,
        ),
        (
            "zip validator accepts policy-complete investigation report",
            valid_zip_result.ok,
        ),
        (
            "zip validator rejects forbidden extra artifacts",
            not forbidden_extra_zip_result.ok,
        ),
        (
            "zip validator rejects unknown extra artifacts",
            not unknown_extra_zip_result.ok,
        ),
        (
            "readiness packet rejects fault-injection demo records",
            not fault_injection_packet_result.ok,
        ),
        (
            "readiness packet rejects findings without verifier audit evidence",
            not missing_verifier_packet_result.ok,
        ),
        (
            "readiness packet rejects final findings without tool_call_id",
            not missing_tool_call_packet_result.ok,
        ),
        (
            "readiness packet rejects unresolved final finding tool_call_id",
            not ghost_tool_call_packet_result.ok,
        ),
        (
            "readiness packet rejects cited tool_call_id without valid output hash",
            not invalid_output_hash_packet_result.ok,
        ),
        (
            "readiness packet accepts audit-bound final finding",
            valid_bound_finding_packet_result.ok,
        ),
        (
            "readiness packet rejects tampered verdict artifact hash",
            not tampered_verdict_artifact_packet_result.ok,
        ),
        (
            "readiness packet rejects tampered audit-approved finding",
            not tampered_finding_approved_packet_result.ok,
        ),
        (
            "readiness packet rejects invalid verifier audit evidence",
            not invalid_verifier_packet_result.ok,
        ),
        (
            "readiness packet rejects mismatched verifier replay hashes",
            not mismatched_replay_hash_packet_result.ok,
        ),
        (
            "readiness packet rejects split verifier hash/action evidence",
            not split_hash_action_packet_result.ok,
        ),
        (
            "readiness packet rejects unreflected verifier downgrade",
            not downgraded_not_reflected_packet_result.ok,
        ),
        (
            "readiness packet rejects multi-finding downgrade bypass",
            not multi_downgrade_bypass_packet_result.ok,
        ),
        (
            "readiness packet rejects forged manifest verification",
            not forged_manifest_packet_result.ok,
        ),
        (
            "readiness packet rejects unknown extra files",
            not unknown_extra_packet_result.ok,
        ),
        (
            "readiness packet rejects non-image figure artifacts",
            not non_image_figure_packet_result.ok,
        ),
        (
            "readiness packet rejects unsafe ZIP paths",
            not unsafe_path_packet_result.ok,
        ),
        (
            "readiness packet rejects nested colon ZIP paths",
            not nested_colon_path_packet_result.ok
            and "unsafe relative path" in nested_colon_path_packet_result.message,
        ),
        (
            "readiness packet rejects symlink directory ZIP entries",
            not symlink_dir_packet_result.ok,
        ),
        (
            "readiness packet rejects unverified manifest signature when reported",
            not unverifiable_signature_packet_result.ok,
        ),
    ]
    print("=" * 60)
    print("Find Evil! - report policy smoke")
    print("=" * 60)
    for label, ok in checks:
        marker = "OK  " if ok else "FAIL"
        print(f"  [{marker}] {label}")
        failures += 0 if ok else 1
    print("=" * 60)
    if failures:
        print(f"FAIL - {failures} report policy checks failed.")
        return 1
    print(f"OK - all {len(checks)} report policy checks pass.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
