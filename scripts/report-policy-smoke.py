#!/usr/bin/env python3
"""report-policy-smoke - lock executive story and signoff sections.

This smoke calls render_report.write_markdown directly so it does not require
Pandoc or Chrome. It verifies the customer-facing report policy layer: attack
story, QA / expert signoff, evidence-bound tool calls, and overclaim caveats.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


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
                "artifact_path": "memory.img",
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
                    "title": "Process-view divergence consistent with DKOM",
                    "timestamp_utc": "2026-05-09T00:00:30Z",
                    "confidence": "INFERRED",
                    "mitre_technique": "T1014",
                    "tool_call_id": "tc-psscan",
                    "artifact_classes": ["memory"],
                    "caveat": "Inferred evidence needs expert review.",
                }
            ],
        }
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
            timeline=entity_timeline,
            normalized_timeline={"events": entity_timeline},
            entity_index=entity_index,
            indicators=indicators,
            event_narratives=event_narratives,
            practitioner_coverage=practitioner_coverage,
            has_attack_story_fig=True,
        )
        text = md_path.read_text(encoding="utf-8")
        public_text = "\n".join(
            [
                (REPO / "README.md").read_text(encoding="utf-8"),
                (REPO / "docs" / "templates" / "devpost-readme.md").read_text(
                    encoding="utf-8"
                ),
                (REPO / "QUICKSTART.md").read_text(encoding="utf-8"),
            ]
        )
        valid_html_text = """<!doctype html><html><body>
            <h1>Find Evil investigation report</h1>
            <h2>Cryptographic Attestation</h2>
            <h2>QA / Expert Signoff</h2>
            <h2>Customer Release Gate</h2>
            <h2>Findings Overview</h2>
            <h2>Cryptographic chain of custody</h2>
            <p>tool_call_id tc-psscan</p>
            <h3>What We Cannot Prove</h3>
            <p>stub signatures are dev/offline only; this is an explicit release blocker.</p>
            <p>Evidence-bound report text.</p>
            </body></html>""" + ("x" * 1800)
        valid_html = case_dir / "valid-investigation-report.html"
        valid_html.write_text(valid_html_text, encoding="utf-8")
        invalid_html = case_dir / "invalid-investigation-report.html"
        invalid_html.write_text(
            """<!doctype html><html><body>
            <h1>Find Evil investigation report</h1>
            <h2>Cryptographic Attestation</h2>
            <h2>QA / Expert Signoff</h2>
            <h2>Customer Release Gate</h2>
            <h2>Findings Overview</h2>
            <h2>Cryptographic chain of custody</h2>
            <p>tool_call_id tc-psscan</p>
            <h3>What We Cannot Prove</h3>
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
                "fixture,source_file,findings_matched\nnist-hacking-case,,1\n",
            )
            zf.writestr("demo-video-link.txt", "https://example.org/findevil-demo\n")
            zf.writestr("LICENSE", "Test license fixture\n")
            zf.writestr("report.html", valid_html_text)
        valid_zip_result = validator.validate_zip(valid_zip)

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
            "embedded replay match passes report QA check",
            replay_match_check["status"] == "PASS",
        ),
        (
            "embedded replay mismatch follows configured severity",
            replay_mismatch_check["status"] == replay_mismatch_expected_status,
        ),
        ("executive attack story heading", "## Executive Attack Story" in text),
        ("qa signoff heading", "## QA / Expert Signoff" in text),
        ("customer release gate heading", "## Customer Release Gate" in text),
        ("expert doctrine heading", "## Expert Doctrine Applied" in text),
        ("verdict rebrand title", "# VERDICT — Forensic Investigation Report" in text),
        ("bottom line up front heading", "## Bottom Line Up Front" in text),
        ("timeline of events heading", "## Timeline of Events" in text),
        ("detailed event timeline heading", "## Detailed Event Timeline" in text),
        ("cast of characters heading", "## Cast of Characters" in text),
        ("indicators heading", "## Indicators" in text),
        ("analysis coverage by domain heading", "## Analysis Coverage by Domain" in text),
        ("technical report tier divider", "# Technical Report {.tier-break}" in text),
        (
            "internal gates tier divider",
            "# Internal — QA & Release Gates" in text,
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
        ("cannot prove section present", "### What We Cannot Prove" in text),
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
            "legacy manifest command absent",
            "manifest_verify <run.manifest.json>" not in text,
        ),
        ("verification library command present", "verify_manifest(Path(" in text),
        (
            "caveats avoid forbidden wording",
            "clean, cleared" not in text and "clean/cleared" not in text,
        ),
        (
            "public copy frames disk-only as custody registration",
            "disk-content conclusions require mounted or extracted artifacts"
            in public_text,
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
