#!/usr/bin/env python3
"""verdict-policy-smoke — lock in the compute_verdict policy in CI.

`docs/verdict-semantics.md` describes the verdict policy as
"deterministic policy, not learned classifier; changing the policy
is a code change with a clear diff and CI run." This smoke test
makes that claim load-bearing — every CI build asserts that
`compute_verdict` produces the documented output for each
canonical case.

Loads `Investigation.compute_verdict` from `find_evil_auto.py` via
importlib (same pattern find_evil_auto uses for fleet_correlate's
COMMON_WIN_PROCS — single-source-of-truth, no copy-paste of
policy logic).

If you intend to change the policy, change `compute_verdict` AND
update this file's expected outputs together. The diff in the
commit will then encode the policy change explicitly.

Exit code: 0 on full pass, 1 on first assertion failure.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent


def load_find_evil_auto():
    """Load scripts/find_evil_auto.py as a module without spinning up
    the orchestrator's main()."""
    spec = importlib.util.spec_from_file_location(
        "find_evil_auto_under_test",
        REPO / "scripts" / "find_evil_auto.py",
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("could not build spec for find_evil_auto.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def case(label: str, merged: list[dict[str, Any]], expected: str) -> tuple[str, bool]:
    return (label, merged, expected)


def main() -> int:
    fea = load_find_evil_auto()

    # Empty-result verdicts depend on evidence scope. Use an instance
    # with a substantive EVTX tool call so NO_EVIL means "scoped no
    # Findings", not custody-only or unknown evidence.
    def compute_verdict(merged: list[dict[str, Any]]) -> str:
        inv = fea.Investigation("Security.evtx", unattended=True, with_report=False)
        inv.tool_calls = [{"tool": "evtx_query", "tool_call_id": "tc-evtx"}]
        return inv.compute_verdict(merged)

    detect_evidence_type = fea.detect_evidence_type
    classify_artifact_path = fea.classify_artifact_path
    classify_velociraptor_zip_member = fea.classify_velociraptor_zip_member
    build_local_evidence_inventory = fea.build_local_evidence_inventory
    finalize_evidence_inventory = fea.finalize_evidence_inventory
    build_attack_coverage = fea.build_attack_coverage
    build_coverage_manifest = fea.build_coverage_manifest
    build_evtx_summary = fea.build_evtx_summary
    build_next_actions = fea.build_next_actions
    build_attck_practitioner_coverage = fea.build_attck_practitioner_coverage
    build_malware_triage = fea.build_malware_triage
    build_normalized_timeline = fea.build_normalized_timeline
    build_report_evidence_cards = fea.build_report_evidence_cards
    extract_evtx_entities = fea._extract_evtx_entities  # noqa: SLF001
    build_entity_index = fea.build_entity_index
    build_indicators = fea.build_indicators
    build_event_narratives = fea.build_event_narratives
    build_executive_attack_story = fea.build_executive_attack_story
    build_expert_doctrine = fea.build_expert_doctrine
    build_expert_miss_summary = fea.build_expert_miss_summary
    build_report_qa_signoff = fea.build_report_qa_signoff
    build_source_bibliography = fea.build_source_bibliography
    build_contradiction_resolution_record = fea.build_contradiction_resolution_record
    evtx_rows_to_findings = fea.evtx_rows_to_findings
    extract_ascii_strings = fea._extract_ascii_strings_from_hex  # noqa: SLF001
    extract_iocs = fea._extract_iocs_from_texts  # noqa: SLF001
    process_sets_diverge = fea.process_sets_diverge
    write_normalized_timeline_csv = fea.write_normalized_timeline_csv
    write_timeline_csv = fea.write_timeline_csv
    load_expert_rules = fea.load_expert_rules
    print("=" * 60)
    print("Find Evil! — verdict + evidence/process policy smoke")
    print("=" * 60)

    cases: list[tuple[str, list[dict[str, Any]], str]] = [
        # ----- empty -----
        case("substantive EVTX run with empty merged list -> NO_EVIL", [], "NO_EVIL"),
        # ----- CONFIRMED tier triggers SUSPICIOUS regardless of MITRE -----
        case(
            "single CONFIRMED finding (no MITRE) -> SUSPICIOUS",
            [{"confidence": "CONFIRMED", "mitre_technique": None}],
            "SUSPICIOUS",
        ),
        case(
            "CONFIRMED with low-severity MITRE -> SUSPICIOUS",
            [{"confidence": "CONFIRMED", "mitre_technique": "T1098"}],
            "SUSPICIOUS",
        ),
        # ----- INFERRED on T1014 / T1055 triggers SUSPICIOUS -----
        case(
            "INFERRED + T1014 (DKOM) -> SUSPICIOUS",
            [{"confidence": "INFERRED", "mitre_technique": "T1014"}],
            "SUSPICIOUS",
        ),
        case(
            "INFERRED + T1055 (Process Injection) -> SUSPICIOUS",
            [{"confidence": "INFERRED", "mitre_technique": "T1055"}],
            "SUSPICIOUS",
        ),
        # ----- INFERRED on a non-severe technique stays INDETERMINATE -----
        case(
            "INFERRED + T1098 (Account Manipulation) -> INDETERMINATE",
            [{"confidence": "INFERRED", "mitre_technique": "T1098"}],
            "INDETERMINATE",
        ),
        # ----- HYPOTHESIS-only -> INDETERMINATE even with severe MITRE -----
        case(
            "HYPOTHESIS + T1014 -> INDETERMINATE (HYPOTHESIS doesn't count)",
            [{"confidence": "HYPOTHESIS", "mitre_technique": "T1014"}],
            "INDETERMINATE",
        ),
        case(
            "HYPOTHESIS + T1055 -> INDETERMINATE",
            [{"confidence": "HYPOTHESIS", "mitre_technique": "T1055"}],
            "INDETERMINATE",
        ),
        # ----- mixed: CONFIRMED dominates -----
        case(
            "mixed CONFIRMED + HYPOTHESIS -> SUSPICIOUS",
            [
                {"confidence": "HYPOTHESIS", "mitre_technique": "T1098"},
                {"confidence": "CONFIRMED", "mitre_technique": None},
            ],
            "SUSPICIOUS",
        ),
        # ----- mixed: INFERRED + non-severe MITRE -> INDETERMINATE
        # unless one of them has T1014/T1055 -----
        case(
            "INFERRED T1098 + INFERRED T1014 -> SUSPICIOUS (T1014 carries it)",
            [
                {"confidence": "INFERRED", "mitre_technique": "T1098"},
                {"confidence": "INFERRED", "mitre_technique": "T1014"},
            ],
            "SUSPICIOUS",
        ),
        # ----- the SRL-2018 base-rd-05 real-world case (commit 94c08dd
        #       end-to-end test): 2 HYPOTHESIS findings, no CONFIRMED,
        #       INFERRED T1055 absent -> INDETERMINATE -----
        case(
            "real base-rd-05 shape (2 HYPOTHESIS, no severe INFERRED) -> INDETERMINATE",
            [
                {"confidence": "HYPOTHESIS", "mitre_technique": "T1055"},
                {"confidence": "HYPOTHESIS", "mitre_technique": None},
            ],
            "INDETERMINATE",
        ),
    ]

    failures = 0
    for label, merged, expected in cases:
        actual = compute_verdict(merged)
        ok = actual == expected
        marker = "OK  " if ok else "FAIL"
        print(f"  [{marker}] verdict: {label}")
        if not ok:
            print(f"         expected: {expected!r}")
            print(f"         actual  : {actual!r}")
            failures += 1

    # ----- detect_evidence_type dispatch -----------------------------
    # Routes the orchestrator to the right per-type playbook (memory
    # → vol_pslist+psscan+malfind; evtx → evtx_query+hayabusa;
    # disk → case_open only). A regression here means evidence
    # silently dispatches to the wrong tool sequence.
    et_cases: list[tuple[str, str, str]] = [
        # memory variants
        ("base-dc-memory.img -> memory", "/mnt/x/base-dc-memory.img", "memory"),
        ("foo.mem -> memory", "foo.mem", "memory"),
        ("foo.raw -> memory", "foo.raw", "memory"),
        ("foo.vmem -> memory", "foo.vmem", "memory"),
        ("foo.dmp -> memory", "foo.dmp", "memory"),
        ("foo.lime -> memory", "foo.lime", "memory"),
        # evtx
        ("Security.evtx -> evtx", "/var/log/Security.evtx", "evtx"),
        # disk variants
        ("foo.E01 -> disk (case-insensitive)", "foo.E01", "disk"),
        ("foo.e01 -> disk", "foo.e01", "disk"),
        ("foo.dd -> disk", "foo.dd", "disk"),
        ("foo.aff -> disk", "foo.aff", "disk"),
        ("foo.aff4 -> disk", "foo.aff4", "disk"),
        ("foo.001 -> disk (split-image)", "foo.001", "disk"),
        (
            "foo.zip -> Velociraptor collection zip",
            "foo.zip",
            "velociraptor",
        ),
        # unknown
        ("foo.txt -> unknown", "foo.txt", "unknown"),
        ("no extension -> unknown", "foo", "unknown"),
    ]
    for label, path, expected in et_cases:
        actual = detect_evidence_type(path)
        ok = actual == expected
        marker = "OK  " if ok else "FAIL"
        print(f"  [{marker}] evtype: {label}")
        if not ok:
            print(f"         path    : {path!r}")
            print(f"         expected: {expected!r}")
            print(f"         actual  : {actual!r}")
            failures += 1

    # ----- resolve_evidence_path default-directory policy -------------
    # `find-evil-auto` with no positional path falls back to
    # $FINDEVIL_EVIDENCE_ROOT, else the repo's evidence/ dir. An explicit
    # path is returned verbatim (it may live inside the SIFT VM and must
    # NOT be validated against the host filesystem); a directory fallback
    # must exist and hold a real evidence entry, not just placeholders.
    resolve_evidence_path = fea.resolve_evidence_path
    with tempfile.TemporaryDirectory() as ev_tmp:
        ev_root = Path(ev_tmp)
        empty_root = ev_root / "empty"
        empty_root.mkdir()
        (empty_root / "README.md").write_text("placeholder", encoding="utf-8")
        (empty_root / ".gitkeep").write_text("", encoding="utf-8")
        filled_root = ev_root / "filled"
        filled_root.mkdir()
        (filled_root / "Security.evtx").write_bytes(b"evtx")
        missing_root = ev_root / "missing"

        def _evidence_raises(path: str | None, env: dict[str, str]) -> bool:
            try:
                resolve_evidence_path(path, env=env)
            except ValueError:
                return True
            return False

        evidence_root_cases = [
            (
                "explicit path returned verbatim (not host-validated)",
                resolve_evidence_path("/mnt/hgfs/evidence/x.img", env={}),
                "/mnt/hgfs/evidence/x.img",
            ),
            (
                "FINDEVIL_EVIDENCE_ROOT with evidence resolves to it",
                resolve_evidence_path(
                    None, env={"FINDEVIL_EVIDENCE_ROOT": str(filled_root)}
                ),
                str(filled_root),
            ),
            (
                "empty default dir (placeholders only) raises",
                _evidence_raises(None, {"FINDEVIL_EVIDENCE_ROOT": str(empty_root)}),
                True,
            ),
            (
                "missing default dir raises",
                _evidence_raises(None, {"FINDEVIL_EVIDENCE_ROOT": str(missing_root)}),
                True,
            ),
        ]
    for label, actual, expected in evidence_root_cases:
        ok = actual == expected
        marker = "OK  " if ok else "FAIL"
        print(f"  [{marker}] evidence-root: {label}")
        if not ok:
            print(f"         expected: {expected!r}")
            print(f"         actual  : {actual!r}")
            failures += 1

    inventory_checks = 0
    artifact_cases = [
        ("classify $MFT", "/case/C/$MFT", "mft"),
        ("classify Prefetch", "/case/C/Windows/Prefetch/CMD.EXE-1234.pf", "prefetch"),
        ("classify Registry", "/case/Users/Alice/NTUSER.DAT", "registry"),
        ("classify random DAT as unknown", "/case/tmp/random.dat", "unknown"),
        ("classify UsnJrnl", "/case/C/$Extend/$UsnJrnl/$J", "usnjrnl"),
        ("classify raw disk", "/case/disk.E01", "raw_disk"),
        ("classify Velociraptor zip", "/case/collection.zip", "velociraptor"),
    ]
    for label, path, expected in artifact_cases:
        inventory_checks += 1
        actual = classify_artifact_path(path).get("artifact_class")
        ok = actual == expected
        marker = "OK  " if ok else "FAIL"
        print(f"  [{marker}] inventory: {label}")
        if not ok:
            print(f"         expected: {expected!r}")
            print(f"         actual  : {actual!r}")
            failures += 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "a").mkdir()
        (root / "b").mkdir()
        for rel in (
            "memory.mem",
            "a/Security.evtx",
            "b/Security.evtx",
            "collection.zip",
            "$MFT",
            "$J",
            "CMD.EXE-1234.pf",
            "NTUSER.DAT",
            "disk.E01",
            "notes.txt",
        ):
            (root / rel).write_bytes(rel.encode("utf-8"))
        symlink_supported = True
        try:
            (root / "unsafe.link").symlink_to(root / "memory.mem")
        except (OSError, NotImplementedError):
            symlink_supported = False
        inventory = build_local_evidence_inventory(root)
        truncated_inventory = build_local_evidence_inventory(root, limit=2)
        rejected_symlinks = [
            entry
            for entry in inventory.get("entries", [])
            if entry.get("custody_status") == "rejected_symlink"
        ]
        dir_inv = fea.Investigation(str(root), unattended=True, with_report=False)
        dir_inv.evidence_inventory = inventory
        # The directory holds a Velociraptor collection.zip as well, so a scoped
        # NO_EVIL is only honest once that class is examined too: vel_collect
        # closes the negative-completeness gate (absence is not proof of no evil).
        dir_inv.tool_calls = [
            {"tool": "evtx_query", "tool_call_id": "tc-evtx"},
            {"tool": "vol_psscan", "tool_call_id": "tc-memory"},
            {"tool": "mft_timeline", "tool_call_id": "tc-mft"},
            {"tool": "prefetch_parse", "tool_call_id": "tc-prefetch"},
            {"tool": "registry_query", "tool_call_id": "tc-registry"},
            {"tool": "usnjrnl_query", "tool_call_id": "tc-usn"},
            {"tool": "vel_collect", "tool_call_id": "tc-velociraptor"},
        ]
        truncated_inv = fea.Investigation(str(root), unattended=True, with_report=False)
        truncated_inv.evidence_inventory = truncated_inventory
        truncated_inv.tool_calls = [{"tool": "evtx_query", "tool_call_id": "tc-evtx"}]
        dispatch_inventory = finalize_evidence_inventory(
            str(root),
            str(root.resolve()),
            True,
            [
                dict(entry)
                for entry in inventory.get("entries", [])
                if entry.get("artifact_class")
                in {"mft", "usnjrnl", "prefetch", "registry", "raw_disk"}
            ],
            limit=500,
        )
        dispatch_inv = fea.Investigation(str(root), unattended=True, with_report=False)
        dispatch_inv.evidence_inventory = dispatch_inventory
        dispatch_inv.handle = {"id": "dir-smoke"}

        zip_dispatch_inventory = finalize_evidence_inventory(
            str(root),
            str(root.resolve()),
            True,
            [
                {
                    "path": str(root / "collection.zip"),
                    "canonical_path": str((root / "collection.zip").resolve()),
                    "artifact_class": "velociraptor",
                    "evidence_type": "velociraptor",
                    "parser_tool": "vel_collect",
                    "sha256": "0" * 64,
                    "size_bytes": (root / "collection.zip").stat().st_size,
                    "symlink_status": "not_symlink",
                    "custody_status": "custody_registered",
                }
            ],
            limit=500,
        )
        zip_dispatch_inv = fea.Investigation(
            str(root / "collection.zip"), unattended=True, with_report=False
        )
        zip_dispatch_inv.evidence_inventory = zip_dispatch_inventory
        zip_dispatch_inv.handle = {"id": "zip-smoke"}

        class FakeExtractedRust:
            def __init__(self) -> None:
                self.calls: list[tuple[str, dict[str, Any]]] = []

            def call_tool(
                self, name: str, args: dict[str, Any], timeout: float | None = None
            ) -> dict[str, Any]:
                self.calls.append((name, args))
                if name == "case_open":
                    # Directory-mode disk lane registers the disk image as a real
                    # Rust case so disk_mount/extract have a case work dir
                    # ($FINDEVIL_HOME/cases/<id>/); see investigate_disk.
                    return {
                        "id": "disk-smoke-case",
                        "image_hash": "0" * 64,
                        "image_size_bytes": 1,
                        "case_dir": str(root / "disk-smoke-case"),
                    }
                if name == "disk_mount":
                    fs_root = str(Path(str(args["image_path"])).parent)
                    return {
                        "case_id": args["case_id"],
                        "mount_id": "mount-smoke",
                        "status": "mounted",
                        "image_path": args["image_path"],
                        "mount_point": fs_root,
                        "fs_root": fs_root,
                        "ledger_path": str(Path(fs_root) / "session_resources.json"),
                        "command": ["mock", "disk_mount"],
                        "stderr_tail": "",
                        "note": "mock mount for policy smoke",
                    }
                if name == "disk_extract_artifacts":
                    fs_root = root
                    artifacts = [
                        ("mft", fs_root / "$MFT"),
                        ("usnjrnl", fs_root / "$J"),
                        ("prefetch", fs_root / "CMD.EXE-1234.pf"),
                        ("registry", fs_root / "NTUSER.DAT"),
                    ]
                    return {
                        "case_id": args["case_id"],
                        "mount_id": args["mount_id"],
                        "extract_id": "extract-smoke",
                        "output_dir": str(fs_root),
                        "artifacts_seen": len(artifacts),
                        "ledger_path": str(fs_root / "session_resources.json"),
                        "artifacts": [
                            {
                                "artifact_class": artifact_class,
                                "source_path": str(path),
                                "extracted_path": str(path),
                                "size_bytes": path.stat().st_size,
                            }
                            for artifact_class, path in artifacts
                        ],
                    }
                if name == "disk_unmount":
                    return {
                        "case_id": args["case_id"],
                        "mount_id": args["mount_id"],
                        "status": "unmounted",
                        "ledger_path": str(root / "session_resources.json"),
                        "command": ["mock", "disk_unmount"],
                        "stderr_tail": "",
                    }
                if name == "mft_timeline":
                    return {
                        "entries": [],
                        "row_count": 0,
                        "records_seen": 0,
                        "parse_errors": 0,
                    }
                if name == "usnjrnl_query":
                    return {
                        "entries": [],
                        "row_count": 0,
                        "records_seen": 0,
                        "parse_errors": 0,
                    }
                if name == "prefetch_parse":
                    return {
                        "executable_name": "CMD.EXE",
                        "run_count": 1,
                        "last_run_times_iso": ["2026-05-09T00:00:00Z"],
                    }
                if name == "registry_query":
                    return {"entries": [], "keys_visited": 0, "parse_errors": 0}
                raise AssertionError(f"unexpected tool {name}")

        fake_extracted_rust = FakeExtractedRust()

        class FakeInventoryAudit:
            def __init__(self) -> None:
                self.records: list[dict[str, Any]] = []

            def call_tool(
                self, name: str, args: dict[str, Any], timeout: float | None = None
            ) -> dict[str, Any]:
                if name == "audit_append":
                    self.records.append(args)
                    return {"ok": True}
                raise AssertionError(f"unexpected audit tool {name}")

        fake_dispatch_audit = FakeInventoryAudit()
        dispatch_inv.investigate_inventory(fake_extracted_rust, fake_dispatch_audit)
        dispatched_tools = [name for name, _ in fake_extracted_rust.calls]
        dispatched_call_args = {name: args for name, args in fake_extracted_rust.calls}
        raw_disk_entry = next(
            entry
            for entry in dispatch_inventory.get("entries", [])
            if entry.get("artifact_class") == "raw_disk"
        )
        disk_case_open_args = dispatched_call_args.get("case_open", {})
        disk_case_open_audit_args = next(
            (
                record.get("payload", {}).get("arguments", {})
                for record in fake_dispatch_audit.records
                if record.get("kind") == "tool_call_start"
                and record.get("payload", {}).get("tool") == "case_open"
            ),
            None,
        )

        class FakeRegistrationFailureRust:
            def __init__(self) -> None:
                self.calls: list[tuple[str, dict[str, Any]]] = []

            def call_tool(
                self, name: str, args: dict[str, Any], timeout: float | None = None
            ) -> dict[str, Any]:
                self.calls.append((name, args))
                if name == "case_open":
                    return {"_error": {"message": "hash mismatch"}}
                if name == "disk_mount":
                    return {"_error": {"message": "case not found: dir-fail"}}
                raise AssertionError(f"unexpected failure tool {name}")

        failed_registration_inv = fea.Investigation(
            str(root), unattended=True, with_report=False
        )
        failed_registration_inv.evidence_inventory = dispatch_inventory
        failed_registration_inv.handle = {"id": "dir-fail"}
        failed_registration_audit = FakeInventoryAudit()
        failed_registration_inv.investigate_disk(
            FakeRegistrationFailureRust(),
            failed_registration_audit,
            str(root / "disk.E01"),
        )
        failed_case_open_outputs = [
            record.get("payload", {})
            for record in failed_registration_audit.records
            if record.get("kind") == "tool_call_output"
            and record.get("payload", {}).get("error") == "hash mismatch"
        ]

        old_zip_extract = fea.extract_velociraptor_zip_artifacts

        def fake_zip_extract(
            zip_path: str,
            output_dir: str,
            *,
            limit: int = 500,
            max_member_bytes: int = 0,
        ) -> dict[str, Any]:
            del output_dir, limit, max_member_bytes
            pf = root / "CMD.EXE-1234.pf"
            return {
                "zip_path": zip_path,
                "entries": [
                    {
                        "path": str(pf),
                        "canonical_path": str(pf.resolve()),
                        "source_container_path": zip_path,
                        "source_container_type": "velociraptor_zip",
                        "zip_member_path": "uploads/C/Windows/Prefetch/CMD.EXE-1234.pf",
                        "artifact_class": "prefetch",
                        "evidence_type": "extracted_disk",
                        "parser_tool": "prefetch_parse",
                        "size_bytes": pf.stat().st_size,
                        "sha256": "1" * 64,
                    }
                ],
                "unsupported_count": 0,
                "unsupported_samples": [],
                "skipped_unsafe": 0,
                "skipped_oversize": 0,
                "truncated": False,
                "limit": 500,
            }

        fake_zip_rust = FakeExtractedRust()
        fake_zip_audit = FakeInventoryAudit()
        fea.extract_velociraptor_zip_artifacts = fake_zip_extract
        try:
            zip_dispatch_inv.investigate_inventory(fake_zip_rust, fake_zip_audit)
        finally:
            fea.extract_velociraptor_zip_artifacts = old_zip_extract
        zip_dispatched_tools = [name for name, _ in fake_zip_rust.calls]
        zip_comp = zip_dispatch_inv._case_completeness()  # noqa: SLF001
        zip_checks = {
            row.get("artifact_class"): row for row in zip_comp.get("checks", [])
        }
        dir_comp = dir_inv._case_completeness()  # noqa: SLF001
        dir_checks = {
            row.get("artifact_class"): row for row in dir_comp.get("checks", [])
        }
        inventory_cases = [
            (
                "directory inventory has stable parent case id",
                str(inventory.get("parent_case_id", "")).startswith("dir-"),
                True,
            ),
            (
                "directory inventory counts duplicate names",
                "Security.evtx"
                in inventory.get("summary", {}).get("duplicate_names", []),
                True,
            ),
            (
                "directory inventory assigns child evidence ids",
                all(
                    str(entry.get("child_evidence_id", "")).startswith("ev-")
                    for entry in inventory.get("entries", [])
                ),
                True,
            ),
            (
                "directory inventory records unsupported artifacts",
                inventory.get("summary", {}).get("class_counts", {}).get("unknown", 0)
                >= 1,
                True,
            ),
            (
                "directory inventory names unsupported samples",
                any(
                    str(sample).endswith("notes.txt")
                    for sample in inventory.get("summary", {}).get(
                        "unsupported_samples", []
                    )
                ),
                True,
            ),
            (
                "directory inventory records truncation",
                truncated_inventory.get("summary", {}).get("truncated"),
                True,
            ),
            (
                "directory inventory rejects symlinks when OS supports them",
                bool(rejected_symlinks) if symlink_supported else True,
                True,
            ),
            (
                "directory completeness marks memory available and touched",
                (
                    dir_checks["memory"].get("available"),
                    dir_checks["memory"].get("touched"),
                ),
                (True, True),
            ),
            (
                "directory completeness marks EVTX available and touched",
                (
                    dir_checks["evtx"].get("available"),
                    dir_checks["evtx"].get("touched"),
                ),
                (True, True),
            ),
            (
                "directory completeness marks extracted disk available and touched",
                (
                    dir_checks["disk/filesystem"].get("available"),
                    dir_checks["disk/filesystem"].get("touched"),
                ),
                (True, True),
            ),
            (
                "directory substantive empty run can produce scoped NO_EVIL",
                dir_inv.compute_verdict([]),
                "NO_EVIL",
            ),
            (
                "truncated directory inventory blocks scoped NO_EVIL",
                truncated_inv.compute_verdict([]),
                "INDETERMINATE",
            ),
            (
                "inventory dispatch runs MFT parser",
                "mft_timeline" in dispatched_tools,
                True,
            ),
            (
                "inventory dispatch runs USN parser",
                "usnjrnl_query" in dispatched_tools,
                True,
            ),
            (
                "inventory dispatch runs Prefetch parser",
                "prefetch_parse" in dispatched_tools,
                True,
            ),
            (
                "inventory dispatch runs Registry parser",
                "registry_query" in dispatched_tools,
                True,
            ),
            (
                "raw disk inventory dispatch attempts auto mount/extract",
                "disk_mount" in dispatched_tools
                and "disk_extract_artifacts" in dispatched_tools
                and "disk_unmount" in dispatched_tools,
                True,
            ),
            (
                "raw disk directory case_open is bound to inventory sha",
                disk_case_open_args.get("expected_sha256"),
                raw_disk_entry.get("sha256"),
            ),
            (
                "raw disk directory case_open audit records exact arguments",
                disk_case_open_audit_args,
                disk_case_open_args,
            ),
            (
                "raw disk mount uses registered Rust case id",
                dispatched_call_args.get("disk_mount", {}).get("case_id"),
                "disk-smoke-case",
            ),
            (
                "raw disk extract uses registered Rust case id",
                dispatched_call_args.get("disk_extract_artifacts", {}).get("case_id"),
                "disk-smoke-case",
            ),
            (
                "raw disk unmount uses registered Rust case id",
                dispatched_call_args.get("disk_unmount", {}).get("case_id"),
                "disk-smoke-case",
            ),
            (
                "raw disk failed case registration is audit-chained",
                bool(failed_case_open_outputs),
                True,
            ),
            (
                "Velociraptor zip member classifier accepts contained Prefetch",
                classify_velociraptor_zip_member(
                    "uploads/C/Windows/Prefetch/CMD.EXE-1234.pf"
                ).get("supported"),
                True,
            ),
            (
                "Velociraptor zip member classifier rejects zip-slip paths",
                classify_velociraptor_zip_member("../Security.evtx").get(
                    "reject_reason"
                ),
                "unsafe_zip_member_path",
            ),
            (
                "Velociraptor zip inventory dispatch extracts contained artifacts",
                len(zip_dispatch_inv.velociraptor_zip_extractions),
                1,
            ),
            (
                "Velociraptor zip inventory dispatch runs contained Prefetch parser",
                "prefetch_parse" in zip_dispatched_tools,
                True,
            ),
            (
                "Velociraptor completeness marks parsed zip touched",
                (
                    zip_checks["velociraptor"].get("available"),
                    zip_checks["velociraptor"].get("touched"),
                ),
                (True, True),
            ),
        ]
    for label, actual, expected in inventory_cases:
        inventory_checks += 1
        ok = actual == expected
        marker = "OK  " if ok else "FAIL"
        print(f"  [{marker}] inventory: {label}")
        if not ok:
            print(f"         expected: {expected!r}")
            print(f"         actual  : {actual!r}")
            failures += 1

    disk_inv = fea.Investigation("foo.E01", unattended=True, with_report=False)
    disk_inv.tool_calls = [{"tool": "case_open", "tool_call_id": "tc-disk"}]
    disk_comp = disk_inv._case_completeness()  # noqa: SLF001 - smoke covers policy
    disk_comp_case_open_only = disk_comp
    disk_checks = {
        row.get("artifact_class"): row for row in disk_comp.get("checks", [])
    }
    disk_policy_checks = 0
    disk_cases = [
        (
            "disk case-open-only verdict is INDETERMINATE",
            disk_inv.compute_verdict([]),
            "INDETERMINATE",
        ),
        (
            "disk class is available but not touched by case_open only",
            (
                disk_checks["disk/filesystem"].get("available"),
                disk_checks["disk/filesystem"].get("touched"),
            ),
            (True, False),
        ),
    ]
    unknown_inv = fea.Investigation("foo.unknown", unattended=True, with_report=False)
    unknown_inv.tool_calls = [{"tool": "case_open", "tool_call_id": "tc-unknown"}]
    disk_cases.append(
        (
            "unknown evidence case-open-only verdict is INDETERMINATE",
            unknown_inv.compute_verdict([]),
            "INDETERMINATE",
        )
    )
    memory_error_inv = fea.Investigation(
        "memory.img", unattended=True, with_report=False
    )
    memory_error_inv.tool_calls = [
        {"tool": "vol_pslist", "tool_call_id": "tc-memory", "error": "tool failed"}
    ]
    disk_cases.append(
        (
            "memory tool failure verdict is INDETERMINATE",
            memory_error_inv.compute_verdict([]),
            "INDETERMINATE",
        )
    )
    for label, actual, expected in disk_cases:
        disk_policy_checks += 1
        ok = actual == expected
        marker = "OK  " if ok else "FAIL"
        print(f"  [{marker}] disk: {label}")
        if not ok:
            print(f"         expected: {expected!r}")
            print(f"         actual  : {actual!r}")
            failures += 1
    disk_inv.tool_calls = [
        {"tool": "case_open", "tool_call_id": "tc-disk"},
        {"tool": "yara_scan", "tool_call_id": "tc-yara"},
    ]
    disk_comp_yara = disk_inv._case_completeness()  # noqa: SLF001 - smoke covers policy
    disk_checks = {
        row.get("artifact_class"): row for row in disk_comp_yara.get("checks", [])
    }
    disk_policy_checks += 1
    ok = disk_checks["disk/filesystem"].get("touched") is True
    marker = "OK  " if ok else "FAIL"
    print(f"  [{marker}] disk: yara_scan counts as disk/filesystem touch")
    if not ok:
        print(f"         disk check: {disk_checks['disk/filesystem']!r}")
        failures += 1

    # ----- EVTX parse success is summary/timeline, not suspicion -------
    benign_evtx_rows = [
        {
            "event_id": 4624,
            "ts": "2026-05-04T00:00:00Z",
            "channel": "Security",
            "record_id": 1,
            "data": {"Event": {"System": {"EventID": 4624}}},
        },
        {
            "event_id": 4634,
            "ts": "2026-05-04T00:01:00Z",
            "channel": "Security",
            "record_id": 2,
            "data": {"Event": {"System": {"EventID": 4634}}},
        },
    ]
    benign_summary = build_evtx_summary(benign_evtx_rows, 2, 0)
    benign_findings = evtx_rows_to_findings(
        benign_evtx_rows, "tc-evtx", "case-evtx", "Security.evtx"
    )
    suspicious_rows = [
        {
            "event_id": 1102,
            "ts": "2026-05-04T00:02:00Z",
            "channel": "Security",
            "record_id": 3,
            "data": {"Event": {"System": {"EventID": 1102}}},
        }
    ]
    suspicious_findings = evtx_rows_to_findings(
        suspicious_rows, "tc-evtx", "case-evtx", "Security.evtx"
    )
    scheduled_task_rows = [
        {
            "event_id": "4698",
            "ts": "2026-05-04T00:03:00Z",
            "channel": "Security",
            "record_id": 4,
            "data": {
                "Event": {
                    "System": {"EventID": 4698},
                    "EventData": {
                        "TaskName": "\\Updater",
                        "TaskContent": (
                            "<Actions><Exec><Command>powershell.exe</Command>"
                            "<Arguments>-EncodedCommand SQBFAFgA</Arguments>"
                            "</Exec></Actions>"
                        ),
                    },
                }
            },
        }
    ]
    scheduled_task_summary = build_evtx_summary(scheduled_task_rows, 1, 0)
    scheduled_task_findings = evtx_rows_to_findings(
        scheduled_task_rows, "tc-evtx", "case-evtx", "Security.evtx"
    )
    # 4688 process creation: child resolved to a WmiPrvSE.exe parent by PID
    # correlation (these records carry only ProcessId, not ParentProcessName).
    wmi_rows = [
        {
            "event_id": 4688,
            "ts": "2026-05-04T00:04:00Z",
            "channel": "Security",
            "record_id": 1,
            "data": {
                "Event": {
                    "System": {"EventID": 4688, "Computer": "WIN7"},
                    "EventData": {
                        "SubjectUserName": "WIN7$",
                        "SubjectDomainName": "CORP",
                        "NewProcessName": "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe",
                        "NewProcessId": "0xae8",
                        "ProcessId": "0x248",
                    },
                }
            },
        },
        {
            "event_id": 4688,
            "ts": "2026-05-04T00:04:01Z",
            "channel": "Security",
            "record_id": 2,
            "data": {
                "Event": {
                    "System": {"EventID": 4688, "Computer": "WIN7"},
                    "EventData": {
                        "SubjectUserName": "Administrator",
                        "SubjectDomainName": "CORP",
                        "NewProcessName": "C:\\Windows\\System32\\calc.exe",
                        "NewProcessId": "0xb10",
                        "ProcessId": "0xae8",
                    },
                }
            },
        },
    ]
    wmi_findings = evtx_rows_to_findings(
        wmi_rows, "tc-evtx", "case-evtx", "Security.evtx"
    )
    # 7045 service install with a cmd.exe image path.
    service_rows = [
        {
            "event_id": 7045,
            "ts": "2026-05-04T00:05:00Z",
            "channel": "System",
            "record_id": 1,
            "data": {
                "Event": {
                    "System": {"EventID": 7045},
                    "EventData": {
                        "ServiceName": "spoolfool",
                        "ImagePath": "C:\\Windows\\System32\\cmd.exe /c whoami",
                    },
                }
            },
        }
    ]
    service_findings = evtx_rows_to_findings(
        service_rows, "tc-evtx", "case-evtx", "Security.evtx"
    )
    # 4624 Type 10 = Remote Desktop logon.
    rdp_rows = [
        {
            "event_id": 4624,
            "ts": "2026-05-04T00:06:00Z",
            "channel": "Security",
            "record_id": 1,
            "data": {
                "Event": {
                    "System": {"EventID": 4624},
                    "EventData": {
                        "TargetUserName": "jadmin",
                        "TargetDomainName": "CORP",
                        "LogonType": "10",
                        "IpAddress": "203.0.113.9",
                    },
                }
            },
        }
    ]
    rdp_findings = evtx_rows_to_findings(
        rdp_rows, "tc-evtx", "case-evtx", "Security.evtx"
    )
    # Five 4625 failures = brute-force / password-spray lead.
    brute_rows = [
        {
            "event_id": 4625,
            "ts": f"2026-05-04T00:07:0{i}Z",
            "channel": "Security",
            "record_id": 10 + i,
            "data": {
                "Event": {
                    "System": {"EventID": 4625},
                    "EventData": {
                        "TargetUserName": "admin",
                        "TargetDomainName": "CORP",
                        "IpAddress": "203.0.113.9",
                    },
                }
            },
        }
        for i in range(5)
    ]
    brute_findings = evtx_rows_to_findings(
        brute_rows, "tc-evtx", "case-evtx", "Security.evtx"
    )
    # A single ordinary Type 3 network logon must NOT create a finding.
    benign_logon_rows = [
        {
            "event_id": 4624,
            "ts": "2026-05-04T00:08:00Z",
            "channel": "Security",
            "record_id": 1,
            "data": {
                "Event": {
                    "System": {"EventID": 4624},
                    "EventData": {
                        "TargetUserName": "svc",
                        "LogonType": "3",
                        "IpAddress": "10.0.0.5",
                    },
                }
            },
        }
    ]
    benign_logon_findings = evtx_rows_to_findings(
        benign_logon_rows, "tc-evtx", "case-evtx", "Security.evtx"
    )
    evtx_cases = [
        (
            "benign EVTX summary counts records",
            benign_summary.get("records_seen"),
            2,
        ),
        (
            "benign EVTX parse success creates no findings",
            len(benign_findings),
            0,
        ),
        (
            "benign EVTX findings produce NO_EVIL",
            compute_verdict(benign_findings),
            "NO_EVIL",
        ),
        (
            "audit-log clear EVTX creates a finding",
            len(suspicious_findings),
            1,
        ),
        (
            "audit-log clear EVTX can drive SUSPICIOUS",
            compute_verdict(suspicious_findings),
            "SUSPICIOUS",
        ),
        (
            "suspicious scheduled-task EVTX creates one finding",
            len(scheduled_task_findings),
            1,
        ),
        (
            "scheduled-task finding cites typed EVTX tool call",
            scheduled_task_findings[0].get("tool_call_id")
            if scheduled_task_findings
            else None,
            "tc-evtx",
        ),
        (
            "scheduled-task finding maps to T1053.005",
            scheduled_task_findings[0].get("mitre_technique")
            if scheduled_task_findings
            else None,
            "T1053.005",
        ),
        (
            "scheduled-task hypothesis alone stays indeterminate",
            compute_verdict(scheduled_task_findings),
            "INDETERMINATE",
        ),
        (
            "scheduled-task EVTX summary counts suspicious event",
            scheduled_task_summary.get("suspicious_event_count"),
            1,
        ),
        (
            "WMI-spawned 4688 child creates one finding (PID-correlated parent)",
            len(wmi_findings),
            1,
        ),
        (
            "WMI 4688 finding maps to T1047",
            wmi_findings[0].get("mitre_technique") if wmi_findings else None,
            "T1047",
        ),
        (
            "WMI 4688 lead stays HYPOTHESIS",
            wmi_findings[0].get("confidence") if wmi_findings else None,
            "HYPOTHESIS",
        ),
        (
            "7045 service install creates one finding",
            len(service_findings),
            1,
        ),
        (
            "service install maps to T1543.003",
            service_findings[0].get("mitre_technique") if service_findings else None,
            "T1543.003",
        ),
        (
            "RDP Type 10 logon creates one finding",
            len(rdp_findings),
            1,
        ),
        (
            "RDP logon maps to T1021.001",
            rdp_findings[0].get("mitre_technique") if rdp_findings else None,
            "T1021.001",
        ),
        (
            "five 4625 failures create one brute-force finding",
            len(brute_findings),
            1,
        ),
        (
            "brute-force lead maps to T1110",
            brute_findings[0].get("mitre_technique") if brute_findings else None,
            "T1110",
        ),
        (
            "single Type 3 network logon creates no finding",
            len(benign_logon_findings),
            0,
        ),
    ]
    for label, actual, expected in evtx_cases:
        ok = actual == expected
        marker = "OK  " if ok else "FAIL"
        print(f"  [{marker}] evtx: {label}")
        if not ok:
            print(f"         expected: {expected!r}")
            print(f"         actual  : {actual!r}")
            failures += 1

    # ----- ATT&CK coverage + next-actions process layer -------------
    process_checks = 0
    completeness = {
        "checks": [
            {"artifact_class": "memory", "available": True, "touched": True},
            {"artifact_class": "evtx", "available": False, "touched": False},
            {
                "artifact_class": "disk/filesystem",
                "available": False,
                "touched": False,
            },
            {"artifact_class": "network", "available": False, "touched": False},
        ]
    }
    tool_calls = [
        {"tool": "case_open"},
        {"tool": "vol_pslist"},
        {"tool": "vol_psscan"},
        {"tool": "vol_psxview"},
        {"tool": "vol_malfind"},
    ]
    findings = [
        {"confidence": "INFERRED", "mitre_technique": "T1014"},
        {"confidence": "CONFIRMED", "mitre_technique": "T1055"},
    ]
    coverage = build_attack_coverage(tool_calls, findings, completeness)
    by_tid = {r["technique_id"]: r for r in coverage["targets"]}
    coverage_cases = [
        (
            "T1014 finding is marked finding-level coverage",
            by_tid["T1014"].get("status"),
            "finding",
        ),
        (
            "T1055 preserves best finding confidence",
            by_tid["T1055"].get("finding_confidence"),
            "CONFIRMED",
        ),
        (
            "T1041 exfil remains a blind spot without network telemetry",
            by_tid["T1041"].get("status"),
            "blind_spot",
        ),
        (
            "covered_no_finding caveat uses limited-coverage wording",
            "limited coverage" in by_tid["T1003"].get("gap", ""),
            True,
        ),
    ]
    for label, actual, expected in coverage_cases:
        process_checks += 1
        ok = actual == expected
        marker = "OK  " if ok else "FAIL"
        print(f"  [{marker}] coverage: {label}")
        if not ok:
            print(f"         expected: {expected!r}")
            print(f"         actual  : {actual!r}")
            failures += 1

    coverage_manifest = build_coverage_manifest(
        case_id="case-coverage-smoke",
        evidence_path="mixed-case/",
        case_completeness={
            "evidence_type": "directory",
            "checks": [
                {"artifact_class": "evtx", "available": True, "touched": True},
                {"artifact_class": "network", "available": False, "touched": False},
            ],
        },
        attack_coverage=coverage,
        tool_calls=[
            {
                "tool": "case_open",
                "tool_call_id": "tc-open",
                "output_hash": "a" * 64,
            },
            {
                "tool": "evtx_query",
                "tool_call_id": "tc-evtx",
                "error": "EVTX parser failed",
                "records_seen": 12,
                "row_count": 0,
                "parse_errors": 3,
            },
        ],
        evidence_inventory={
            "summary": {
                "class_counts": {"unknown": 2},
                "unsupported_samples": ["notes.txt", "unknown/payload.weird"],
            }
        },
        velociraptor_zip_extractions=[
            {
                "zip_path": "collection.zip",
                "unsupported_count": 1,
                "unsupported_samples": ["Uploads/odd-artifact.bin"],
            }
        ],
        analysis_limitations=["evtx_query failed: parser failure"],
    )
    manifest_by_class = {
        row["artifact_class"]: row
        for row in coverage_manifest.get("artifact_classes", [])
    }
    coverage_manifest_cases = [
        (
            "coverage manifest states parser boundary",
            "cannot reason over it" in coverage_manifest.get("truth_boundary", ""),
            True,
        ),
        (
            "coverage manifest preserves failed parser status",
            manifest_by_class["evtx"].get("status"),
            "failed",
        ),
        (
            "coverage manifest records parse errors",
            manifest_by_class["evtx"].get("parse_errors"),
            3,
        ),
        (
            "coverage manifest records unsupported artifacts",
            manifest_by_class["unsupported"].get("records_seen"),
            3,
        ),
        (
            "coverage manifest names unsupported samples",
            manifest_by_class["unsupported"].get("sample_paths"),
            [
                "notes.txt",
                "unknown/payload.weird",
                "collection.zip::Uploads/odd-artifact.bin",
            ],
        ),
        (
            "coverage manifest records not-supplied classes",
            manifest_by_class["network"].get("status"),
            "not_supplied",
        ),
    ]
    for label, actual, expected in coverage_manifest_cases:
        process_checks += 1
        ok = actual == expected
        marker = "OK  " if ok else "FAIL"
        print(f"  [{marker}] coverage-manifest: {label}")
        if not ok:
            print(f"         expected: {expected!r}")
            print(f"         actual  : {actual!r}")
            failures += 1

    disk_actions = build_next_actions([], coverage, disk_comp_case_open_only, [])
    disk_gap_actions = [
        action for action in disk_actions if "disk_gap" in action.get("based_on", [])
    ]
    process_checks += 1
    ok = (
        bool(disk_gap_actions)
        and "read-only" in disk_gap_actions[0].get("action", "").lower()
    )
    marker = "OK  " if ok else "FAIL"
    print(f"  [{marker}] action: disk next action uses read-only SIFT wording")
    if not ok:
        print(f"         actions: {disk_actions!r}")
        failures += 1

    # ----- Correlator refined findings drive final verdict input ------

    class FakeReasonClient:
        def __init__(self) -> None:
            self.pre = {
                "case_id": "case-corr",
                "finding_id": "f-corr",
                "tool_call_id": "tc-corr",
                "artifact_path": "Amcache.hve",
                "description": "Binary executed according to Amcache only.",
                "confidence": "CONFIRMED",
                "pool_origin": "A",
                "mitre_technique": None,
            }
            self.refined = [{**self.pre, "confidence": "INFERRED"}]
            self.verify_calls = 0
            self.call_sequence: list[str] = []
            self.pool_handoffs: list[dict[str, Any]] = []

        def call_tool(
            self, name: str, args: dict[str, Any], timeout: float | None = None
        ) -> dict[str, Any]:
            self.call_sequence.append(name)
            if name == "detect_contradictions":
                return {"contradictions": []}
            if name == "verify_finding":
                self.verify_calls += 1
                finding = args["finding"]
                return {
                    "action": "approved",
                    "finding_id": finding["finding_id"],
                    "reason": "tool re-run output_sha256 matches audit log",
                    "replay_tool_name": "evtx_query",
                    "replay_expected_sha256": "a" * 64,
                    "replay_actual_sha256": "a" * 64,
                    "replay_matched": True,
                    "replay_error": None,
                }
            if name == "audit_append":
                return {"ok": True}
            if name == "pool_handoff":
                self.pool_handoffs.append(args)
                return {
                    "acp_version": "ibm-acp-0.1",
                    "from_role": args["from_role"],
                    "to_role": args["to_role"],
                    "correlation_id": args.get("correlation_id") or "f-corr",
                    "ts": "2026-05-09T00:00:00Z",
                }
            if name == "judge_findings":
                return {"merged": [{"finding": self.pre}]}
            if name == "correlate_findings":
                return {
                    "refined": self.refined,
                    "outcomes": [
                        {
                            "finding_id": "f-corr",
                            "action": "downgraded",
                            "reason": "single artifact execution claim",
                        }
                    ],
                }
            raise AssertionError(f"unexpected tool call: {name}")

    fake_py = FakeReasonClient()
    inv = fea.Investigation("Security.evtx", unattended=True, with_report=False)
    inv.handle = {"id": "case-corr"}
    inv.findings_pool_a = [fake_py.pre]
    inv.tool_calls = [
        {
            "tool": "evtx_query",
            "tool_call_id": "tc-corr",
            "output_hash": "a" * 64,
            "arguments": {"case_id": "case-corr", "evtx_path": "Security.evtx"},
        }
    ]
    corr_merged, _, corr_kept, corr_downgraded = inv.reason(fake_py)
    pool_handoff_before_judge = (
        "pool_handoff" in fake_py.call_sequence
        and fake_py.call_sequence.index("pool_handoff")
        < fake_py.call_sequence.index("judge_findings")
    )
    # reason() now also emits supervisor->pool dispatch handoffs (which carry no
    # replay digest), so the verifier->judge handoff is no longer index 0 — find
    # it by role rather than position.
    verifier_handoffs = [
        h for h in fake_py.pool_handoffs if h.get("from_role") == "verifier"
    ]
    corr_cases = [
        ("verify_finding called before judge", fake_py.verify_calls, 1),
        (
            "verifier ACP handoff is emitted before judge",
            pool_handoff_before_judge,
            True,
        ),
        (
            "verifier handoff cites replay digest",
            bool(
                verifier_handoffs
                and verifier_handoffs[0]["payload"].get("replay_record_sha256")
            ),
            True,
        ),
        (
            "verifier replay is embedded in final finding",
            corr_merged[0].get("replay_matched"),
            True,
        ),
        (
            "correlator refined confidence is returned",
            corr_merged[0].get("confidence"),
            "INFERRED",
        ),
        ("correlator downgraded count is surfaced", corr_downgraded, 1),
        (
            "downgraded non-severe finding no longer drives SUSPICIOUS",
            compute_verdict(corr_merged),
            "INDETERMINATE",
        ),
        ("correlator kept count remains zero", corr_kept, 0),
    ]
    for label, actual, expected in corr_cases:
        process_checks += 1
        ok = actual == expected
        marker = "OK  " if ok else "FAIL"
        print(f"  [{marker}] correlation: {label}")
        if not ok:
            print(f"         expected: {expected!r}")
            print(f"         actual  : {actual!r}")
            failures += 1

    class FakeDowngradeVerifierClient(FakeReasonClient):
        def __init__(self) -> None:
            super().__init__()
            self.judge_saw_pool_a: list[dict[str, Any]] | None = None

        def call_tool(
            self, name: str, args: dict[str, Any], timeout: float | None = None
        ) -> dict[str, Any]:
            if name == "verify_finding":
                self.verify_calls += 1
                finding = args["finding"]
                return {
                    "action": "downgraded",
                    "finding_id": finding["finding_id"],
                    "reason": "tool replay matched but confidence reduced",
                    "replay_tool_name": "evtx_query",
                    "replay_expected_sha256": "a" * 64,
                    "replay_actual_sha256": "a" * 64,
                    "replay_matched": True,
                    "replay_error": None,
                }
            if name == "judge_findings":
                self.judge_saw_pool_a = args["pool_a_findings"]
                return {
                    "merged": [
                        {"finding": finding} for finding in args["pool_a_findings"]
                    ]
                }
            return super().call_tool(name, args, timeout)

    downgrade_py = FakeDowngradeVerifierClient()
    downgrade_inv = fea.Investigation(
        "Security.evtx", unattended=True, with_report=False
    )
    downgrade_inv.handle = {"id": "case-downgrade"}
    downgrade_inv.findings_pool_a = [{**downgrade_py.pre, "case_id": "case-downgrade"}]
    downgrade_inv.tool_calls = [
        {
            "tool": "evtx_query",
            "tool_call_id": "tc-corr",
            "output_hash": "a" * 64,
            "arguments": {"case_id": "case-downgrade", "evtx_path": "Security.evtx"},
        }
    ]
    downgraded_merged, _, _, _ = downgrade_inv.reason(downgrade_py)
    downgrade_cases = [
        (
            "downgraded verifier finding remains before judge",
            [f.get("finding_id") for f in (downgrade_py.judge_saw_pool_a or [])],
            ["f-corr"],
        ),
        (
            "downgraded verifier replay is embedded in final finding",
            downgraded_merged[0].get("replay_matched") if downgraded_merged else None,
            True,
        ),
    ]
    for label, actual, expected in downgrade_cases:
        process_checks += 1
        ok = actual == expected
        marker = "OK  " if ok else "FAIL"
        print(f"  [{marker}] verifier-downgrade: {label}")
        if not ok:
            print(f"         expected: {expected!r}")
            print(f"         actual  : {actual!r}")
            failures += 1

    class FakeRejectVerifierClient(FakeReasonClient):
        def __init__(self) -> None:
            super().__init__()
            self.judge_input_pool_a: list[dict[str, Any]] | None = None
            self.judge_saw_pool_a: list[dict[str, Any]] | None = None

        def call_tool(
            self, name: str, args: dict[str, Any], timeout: float | None = None
        ) -> dict[str, Any]:
            if name == "verify_finding":
                self.verify_calls += 1
                finding = args["finding"]
                return {
                    "action": "rejected",
                    "finding_id": finding["finding_id"],
                    "reason": "tool re-run failed",
                    "replay_tool_name": "evtx_query",
                    "replay_expected_sha256": "a" * 64,
                    "replay_actual_sha256": None,
                    "replay_matched": False,
                    "replay_error": "tool re-run failed",
                }
            if name == "judge_findings":
                self.judge_input_pool_a = args["pool_a_findings"]
                rejected_ids = {
                    action.get("finding_id")
                    for action in args.get("pool_a_verifier_actions", [])
                    if action.get("action") == "rejected"
                }
                self.judge_saw_pool_a = [
                    finding
                    for finding in args["pool_a_findings"]
                    if finding.get("finding_id") not in rejected_ids
                ]
                return {"merged": []}
            return super().call_tool(name, args, timeout)

    reject_py = FakeRejectVerifierClient()
    reject_inv = fea.Investigation("Security.evtx", unattended=True, with_report=False)
    reject_inv.handle = {"id": "case-reject"}
    reject_inv.findings_pool_a = [{**reject_py.pre, "case_id": "case-reject"}]
    reject_inv.tool_calls = [
        {
            "tool": "evtx_query",
            "tool_call_id": "tc-corr",
            "output_hash": "a" * 64,
            "arguments": {"case_id": "case-reject", "evtx_path": "Security.evtx"},
        }
    ]
    rejected_merged, _, _, _ = reject_inv.reason(reject_py)
    reject_cases = [
        (
            "rejected verifier action reaches judge bound to source finding",
            [f.get("finding_id") for f in (reject_py.judge_input_pool_a or [])],
            ["f-corr"],
        ),
        (
            "rejected verifier finding is removed before core judge",
            reject_py.judge_saw_pool_a,
            [],
        ),
        (
            "rejected verifier finding does not reach final findings",
            rejected_merged,
            [],
        ),
        (
            "rejected verifier finding forces INDETERMINATE",
            reject_inv.compute_verdict(rejected_merged),
            "INDETERMINATE",
        ),
        (
            "rejected verifier finding is preserved as a non-evidentiary lead",
            reject_inv.verifier_rejected_leads[0].get("verdict_effect"),
            "excluded_from_final_findings",
        ),
    ]
    for label, actual, expected in reject_cases:
        process_checks += 1
        ok = actual == expected
        marker = "OK  " if ok else "FAIL"
        print(f"  [{marker}] verifier-veto: {label}")
        if not ok:
            print(f"         expected: {expected!r}")
            print(f"         actual  : {actual!r}")
            failures += 1

    # ----- Shared audit client used by the report-QA / release-gate checks --

    class FakeAuditClient:
        def __init__(self) -> None:
            self.records: list[dict[str, Any]] = []

        def call_tool(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
            if name != "audit_append":
                raise AssertionError(f"unexpected tool call: {name}")
            self.records.append(args)
            return {"ok": True}

    # ----- Process-view divergence triggers psxview policy -----------
    process_divergence_cases = [
        (
            "count divergence triggers psxview",
            process_sets_diverge(
                [{"pid": 4, "image_name": "System"}],
                [
                    {"pid": 4, "image_name": "System"},
                    {"pid": 100, "image_name": "smss.exe"},
                ],
                1,
                2,
            )[0],
            True,
        ),
        (
            "same-count different PID sets trigger psxview",
            process_sets_diverge(
                [
                    {"pid": 4, "image_name": "System"},
                    {"pid": 100, "image_name": "smss.exe"},
                ],
                [
                    {"pid": 4, "image_name": "System"},
                    {"pid": 200, "image_name": "smss.exe"},
                ],
                2,
                2,
            )[0],
            True,
        ),
        (
            "same-count different process identities trigger psxview",
            process_sets_diverge(
                [{"pid": 100, "image_name": "svchost.exe"}],
                [{"pid": 100, "image_name": "evil.exe"}],
                1,
                1,
            )[0],
            True,
        ),
        (
            "matching process views skip psxview",
            process_sets_diverge(
                [{"pid": 4, "image_name": "System"}],
                [{"pid": 4, "image_name": "System"}],
                1,
                1,
            )[0],
            False,
        ),
    ]
    for label, actual, expected in process_divergence_cases:
        process_checks += 1
        ok = actual == expected
        marker = "OK  " if ok else "FAIL"
        print(f"  [{marker}] psxview: {label}")
        if not ok:
            print(f"         expected: {expected!r}")
            print(f"         actual  : {actual!r}")
            failures += 1

    actions = build_next_actions(findings, coverage, completeness, [])
    action_cases = [
        ("next actions are capped at five", len(actions), 5),
        (
            "DKOM follow-up is prioritized first",
            actions[0].get("based_on"),
            ["T1014"],
        ),
    ]
    for label, actual, expected in action_cases:
        process_checks += 1
        ok = actual == expected
        marker = "OK  " if ok else "FAIL"
        print(f"  [{marker}] action: {label}")
        if not ok:
            print(f"         expected: {expected!r}")
            print(f"         actual  : {actual!r}")
            failures += 1

    practitioner = build_attck_practitioner_coverage(
        tool_calls,
        findings,
        completeness,
        coverage,
    )
    practitioner_cases = [
        (
            "analysis coverage keeps memory domain automated",
            practitioner["lanes"]["memory"].get("status"),
            "automated",
        ),
        (
            "analysis coverage does not claim network without network evidence",
            practitioner["lanes"]["network"].get("status"),
            "not_covered",
        ),
        (
            "analysis coverage keeps memory-only malware lane partial",
            practitioner["lanes"]["malware"].get("status"),
            "partial",
        ),
        (
            "analysis coverage maps memory process output to ATT&CK DS0009",
            "DS0009"
            in practitioner["lanes"]["memory"].get("attck_data_sources_seen", []),
            True,
        ),
        (
            "analysis coverage uses DFIR domain labels, not GIAC certs",
            practitioner["lanes"]["memory"].get("label"),
            "Memory Forensics",
        ),
        (
            "analysis coverage records overclaim guardrails",
            bool(practitioner.get("overclaim_guardrails_applied")),
            True,
        ),
        (
            "vel_collect alone does not claim network without network artifact",
            build_attck_practitioner_coverage(
                [{"tool": "vel_collect"}], [], completeness, coverage
            )["lanes"]["network"].get("status"),
            "not_covered",
        ),
    ]
    for label, actual, expected in practitioner_cases:
        process_checks += 1
        ok = actual == expected
        marker = "OK  " if ok else "FAIL"
        print(f"  [{marker}] practitioner: {label}")
        if not ok:
            print(f"         expected: {expected!r}")
            print(f"         actual  : {actual!r}")
            failures += 1

    # --- EVTX entity extraction + observed-entities index + indicators ----
    evtx_1102 = {
        "Event": {
            "System": {"EventID": 1102, "Channel": "Security", "Computer": "DC01"},
            "UserData": {
                "LogFileCleared": {
                    "SubjectUserName": "Administrator",
                    "SubjectDomainName": "CORP",
                }
            },
        }
    }
    evtx_4624 = {
        "Event": {
            "System": {"EventID": 4624, "Channel": "Security", "Computer": "WS7"},
            "EventData": {
                "TargetUserName": "jsmith",
                "TargetDomainName": "CORP",
                "LogonType": "3",
                "IpAddress": "10.0.0.55",
                "WorkstationName": "KALI",
            },
        }
    }
    ent_1102 = extract_evtx_entities(evtx_1102, 1102)
    ent_4624 = extract_evtx_entities(evtx_4624, 4624)
    evtx_timeline_events = [
        {
            "ts": "2026-05-04T02:47:00Z",
            "source": "evtx_query",
            "artifact_class": "evtx",
            "description": ent_4624.get("summary", ""),
            "tool_call_id": "tc-evtx",
            "details": {
                "event_id": 4624,
                **{k: v for k, v in ent_4624.items() if k != "summary"},
            },
        },
        {
            "ts": "2026-05-04T02:49:00Z",
            "source": "evtx_query",
            "artifact_class": "evtx",
            "description": ent_1102.get("summary", ""),
            "tool_call_id": "tc-evtx",
            "details": {
                "event_id": 1102,
                **{k: v for k, v in ent_1102.items() if k != "summary"},
            },
        },
    ]
    evtx_findings = [
        {
            "finding_id": "f-clear",
            "tool_call_id": "tc-evtx",
            "confidence": "INFERRED",
            "mitre_technique": "T1070.001",
            "description": "security log cleared",
        }
    ]
    evtx_norm = build_normalized_timeline(evtx_timeline_events, evtx_findings)
    entity_index = build_entity_index(evtx_norm["events"], evtx_findings)
    indicators = build_indicators(evtx_norm["events"], evtx_findings, None)
    narratives = build_event_narratives(evtx_norm["events"], evtx_findings)
    account_values = {row["value"] for row in entity_index.get("accounts", [])}
    entity_cases = [
        (
            "1102 extraction names the account that cleared the log",
            ent_1102.get("account"),
            "Administrator",
        ),
        (
            "4624 extraction surfaces source IP",
            ent_4624.get("source_ip"),
            "10.0.0.55",
        ),
        (
            "4624 extraction labels logon type 3 as Network",
            ent_4624.get("logon_type_label"),
            "Network",
        ),
        (
            "normalized timeline carries entities block",
            evtx_norm["events"][0].get("entities", {}).get("source_ip"),
            "10.0.0.55",
        ),
        (
            "observed-entities index includes the acting accounts",
            account_values == {"CORP\\Administrator", "CORP\\jsmith"},
            True,
        ),
        (
            "Indicators collect the observed source IP",
            "10.0.0.55" in indicators.get("ip_addresses", []),
            True,
        ),
        (
            "event narratives are produced for pivotal events",
            len(narratives) >= 1,
            True,
        ),
    ]
    for label, actual, expected in entity_cases:
        process_checks += 1
        ok = actual == expected
        marker = "OK  " if ok else "FAIL"
        print(f"  [{marker}] entity: {label}")
        if not ok:
            print(f"         expected: {expected!r}")
            print(f"         actual  : {actual!r}")
            failures += 1

    # --- Evidence-driven attack story: confident headline + justified unknowns ---
    narr_findings = [
        {
            "finding_id": "f-clear",
            "tool_call_id": "tc-evtx",
            "confidence": "CONFIRMED",
            "mitre_technique": "T1070.001",
            "description": "EVTX Security EID 1102 audit-log clear event",
        }
    ]
    narr_nt = {
        "events": [
            {
                "event_id": "timeline-0001",
                "timestamp_utc": "2026-05-04T02:49:00Z",
                "artifact_class": "evtx",
                "tool_call_id": "tc-evtx",
                "summary": "Security audit log clearing by CORP\\Administrator",
                "significance": "finding_support",
                "linked_finding_ids": ["f-clear"],
                "confidence": "CONFIRMED",
                "entities": {
                    "account": "Administrator",
                    "domain": "CORP",
                    "host": "DC01",
                },
                "source_record_ref": "evtx_query:event_id=1102;record_id=1",
            }
        ]
    }
    narr_completeness = {
        "checks": [
            {"artifact_class": "evtx", "available": True, "touched": True},
            {"artifact_class": "disk/filesystem", "available": False, "touched": False},
            {"artifact_class": "network", "available": False, "touched": False},
        ]
    }
    story = build_executive_attack_story(
        narr_findings,
        "SUSPICIOUS",
        narr_nt,
        narr_completeness,
        {"blind_spot_count": 3, "targets": []},
        {"status": "WARN", "packet_state": "EXPERT_REVIEW_DRAFT"},
        [{"action": "Collect forwarded Security logs"}],
        [],
        "/ev.evtx",
    )
    narr_blob = " ".join(
        [story["headline"], story["assessment"], story["certainty"]]
        + story["what_we_cannot_say"]
    )
    narrative_cases = [
        (
            "headline is confident, not 'expert review'",
            "Confirmed" in story["headline"]
            and "clearing" in story["headline"]
            and "Administrator" in story["headline"]
            and "expert review" not in story["headline"].lower(),
            True,
        ),
        (
            "headline avoids overclaiming verbs (wiped/cleared)",
            "wiped" not in narr_blob and "cleared" not in narr_blob,
            True,
        ),
        (
            "certainty is reproducibility, not source tamper-evidence",
            "reproducible" in story["certainty"] and "High" in story["certainty"],
            True,
        ),
        (
            "unknowns are justified with a recovery path",
            any("To resolve:" in item for item in story["what_we_cannot_say"]),
            True,
        ),
        (
            "no-attribution caveat retained",
            any("attribution" in item.lower() for item in story["what_we_cannot_say"]),
            True,
        ),
        (
            "what-we-can-say states the cited fact",
            any(
                "T1070.001" in item and "tc-evtx" in item
                for item in story["what_we_can_say"]
            ),
            True,
        ),
    ]
    for label, actual, expected in narrative_cases:
        process_checks += 1
        ok = actual == expected
        marker = "OK  " if ok else "FAIL"
        print(f"  [{marker}] narrative: {label}")
        if not ok:
            print(f"         expected: {expected!r}")
            print(f"         actual  : {actual!r}")
            failures += 1

    timeline_events = [
        {
            "ts": "2026-05-04T00:00:00Z",
            "source": "vol_psscan",
            "artifact_class": "memory",
            "description": "recovered process object: evil.exe pid=31337",
            "tool_call_id": "tc-psscan",
            "details": {"pid": 31337, "image_name": "evil.exe"},
        }
    ]
    timeline_findings = [
        {
            "finding_id": "f-dkom",
            "tool_call_id": "tc-psscan",
            "confidence": "HYPOTHESIS",
            "mitre_technique": "T1014",
            "description": "process-view divergence lead",
        }
    ]
    normalized = build_normalized_timeline(timeline_events, timeline_findings)
    bibliography = build_source_bibliography()
    bibliography_ids = {row["citation_id"] for row in bibliography}
    cards = build_report_evidence_cards(
        timeline_findings,
        normalized["events"],
        bibliography,
    )
    timeline_cases = [
        (
            "normalized timeline preserves timestamp provenance",
            normalized["events"][0].get("timestamp_source"),
            "CreateTime",
        ),
        (
            "normalized timeline preserves tool_call_id",
            normalized["events"][0].get("tool_call_id"),
            "tc-psscan",
        ),
        (
            "normalized timeline links supporting finding",
            normalized["events"][0].get("linked_finding_ids"),
            ["f-dkom"],
        ),
        (
            "evidence card resolves MITRE citation",
            set(cards[0].get("citation_ids", [])) <= bibliography_ids,
            True,
        ),
        (
            "evidence card cites parsed tool output",
            cards[0].get("tool_call_id"),
            "tc-psscan",
        ),
        (
            "evidence card explains suspiciousness",
            "T1014" in cards[0].get("why_suspicious", ""),
            True,
        ),
    ]
    for label, actual, expected in timeline_cases:
        process_checks += 1
        ok = actual == expected
        marker = "OK  " if ok else "FAIL"
        print(f"  [{marker}] timeline-schema: {label}")
        if not ok:
            print(f"         expected: {expected!r}")
            print(f"         actual  : {actual!r}")
            failures += 1

    expert_rules = load_expert_rules()
    doctrine = build_expert_doctrine(expert_rules)

    def qa_check_status(report_qa: dict[str, Any], check_id: str) -> str | None:
        for check in report_qa.get("checks", []):
            if check.get("check_id") == check_id:
                return check.get("status")
        return None

    def single_tool_overclaim_qa(
        *,
        finding_id: str,
        tool: str,
        tool_call_id: str,
        artifact_class: str,
        description: str,
    ) -> dict[str, Any]:
        return build_report_qa_signoff(
            [
                {
                    "finding_id": finding_id,
                    "tool_call_id": tool_call_id,
                    "description": description,
                }
            ],
            [{"tool": tool, "tool_call_id": tool_call_id}],
            "SUSPICIOUS",
            {
                "checks": [
                    {
                        "artifact_class": artifact_class,
                        "available": True,
                        "touched": True,
                    }
                ]
            },
            {"blind_spot_count": 0},
            {"events": []},
            [],
            expert_rules,
        )

    report_qa = build_report_qa_signoff(
        timeline_findings,
        [{"tool": "vol_psscan", "tool_call_id": "tc-psscan"}],
        "SUSPICIOUS",
        completeness,
        coverage,
        normalized,
        [],
        expert_rules,
    )
    qa_audit_client = FakeAuditClient()
    qa_inv = fea.Investigation("memory.img", unattended=True, with_report=False)
    qa_inv._emit_report_qa(  # noqa: SLF001 - smoke covers audit output
        qa_audit_client,
        report_qa,
    )
    qa_audit_payload = qa_audit_client.records[0]["payload"]
    qa_release_gate = qa_inv._emit_release_gate(  # noqa: SLF001 - smoke covers audit output
        qa_audit_client,
        report_qa,
    )
    pass_qa = build_report_qa_signoff(
        [],
        [{"tool": "vol_psscan", "tool_call_id": "tc-psscan"}],
        "INDETERMINATE",
        {"checks": [{"artifact_class": "memory", "available": True, "touched": True}]},
        {"blind_spot_count": 0},
        {
            "events": [
                {
                    "timestamp_utc": "2026-05-09T00:00:30Z",
                    "artifact_class": "memory",
                    "tool_call_id": "tc-psscan",
                }
            ]
        },
        [],
        expert_rules,
    )
    qa_inv.handle = {"id": "case-smoke"}
    packet_release_gate = qa_inv._build_release_gate(pass_qa)  # noqa: SLF001
    approved_qa = {**pass_qa, "expert_decision": "approved"}
    sigstore_inv = fea.Investigation(
        "memory.img", unattended=True, with_report=False, signer="sigstore"
    )
    sigstore_release_gate = sigstore_inv._build_release_gate(approved_qa)  # noqa: SLF001
    sigstore_verified_release_gate = sigstore_inv._build_release_gate(  # noqa: SLF001
        approved_qa,
        {"overall": True},
        {"signature": {"payload_sha256": "f" * 64}},
    )
    stub_inv = fea.Investigation(
        "memory.img", unattended=True, with_report=False, signer="stub"
    )
    stub_release_gate = stub_inv._build_release_gate(approved_qa)  # noqa: SLF001
    # ed25519 is a REAL signature (integrity, offline-verifiable) but proves no
    # identity — the customer-release tier stays sigstore-only by policy.
    ed25519_inv = fea.Investigation(
        "memory.img", unattended=True, with_report=False, signer="ed25519"
    )
    ed25519_release_gate = ed25519_inv._build_release_gate(  # noqa: SLF001
        approved_qa,
        {"overall": True},
        {"signature": {"payload_sha256": "f" * 64, "kind": "ed25519"}},
    )
    packet_attestation = qa_inv._build_packet_attestation(  # noqa: SLF001
        [],
        "INDETERMINATE",
        0,
        0,
        0,
        {
            "case_completeness": {"checks": []},
            "attack_coverage": {"blind_spot_count": 0},
            "report_qa": pass_qa,
        },
        packet_release_gate,
    )
    expert_signoff_packet = qa_inv._build_expert_signoff_packet(  # noqa: SLF001
        pass_qa, packet_release_gate, packet_attestation
    )
    expert_signoff_packet["referenced_hashes"]["verdict_artifact_sha256"] = "e" * 64
    packet_attestation["expert_signoff_packet_sha256"] = qa_inv._hash_obj(  # noqa: SLF001
        expert_signoff_packet
    )
    with tempfile.TemporaryDirectory() as miss_tmp:
        miss_ledger = Path(miss_tmp) / "expert_misses.jsonl"
        miss_inv = fea.Investigation("memory.img", unattended=True, with_report=False)
        miss_inv.handle = {"id": miss_inv.case_id}
        miss_inv.tool_calls = [
            {
                "tool": "vol_psscan",
                "tool_call_id": "tc-psscan",
                "output_hash": "a" * 64,
            }
        ]
        miss_records = [
            {
                "seq": 0,
                "ts": "2026-05-09T00:00:00Z",
                "kind": "expert_miss",
                "prev_hash": "",
                "payload": {
                    "case_id": miss_inv.case_id,
                    "finding_id": "f-rejected",
                    "edit_type": "qa",
                    "edit_text": "Rejected packet needed a replay-mismatch QA check.",
                    "expert_name": "Analyst One",
                },
            },
            {
                "seq": 1,
                "ts": "2026-05-09T00:01:00Z",
                "kind": "expert_miss",
                "prev_hash": "0" * 64,
                "payload": {
                    "case_id": miss_inv.case_id,
                    "finding_id": None,
                    "edit_type": "language",
                    "edit_text": "Rejected packet used customer-ready wording too early.",
                    "expert_name": None,
                },
            },
        ]
        miss_ledger.write_text(
            "\n".join(json.dumps(record, sort_keys=True) for record in miss_records)
            + "\n",
            encoding="utf-8",
        )
        captured_miss_summary = build_expert_miss_summary(miss_inv.case_id, miss_ledger)
        old_miss_path = fea.EXPERT_MISSES_PATH
        fea.EXPERT_MISSES_PATH = miss_ledger
        try:
            miss_metadata = miss_inv._build_report_metadata(  # noqa: SLF001
                [], "INDETERMINATE"
            )
        finally:
            fea.EXPERT_MISSES_PATH = old_miss_path
        miss_signoff_packet = miss_inv._build_expert_signoff_packet(  # noqa: SLF001
            pass_qa,
            packet_release_gate,
            packet_attestation,
            captured_miss_summary,
        )
    qa_inv._emit_packet_attestation(  # noqa: SLF001
        qa_audit_client,
        packet_attestation,
    )
    qa_inv._emit_final_findings(  # noqa: SLF001
        qa_audit_client,
        timeline_findings,
    )

    class FakeManifestVerifyClient:
        def __init__(self, response: dict[str, Any]) -> None:
            self.response = response
            self.calls: list[tuple[str, dict[str, Any]]] = []

        def call_tool(
            self, name: str, args: dict[str, Any], timeout: float | None = None
        ) -> dict[str, Any]:
            self.calls.append((name, args))
            return self.response

    verify_inv = fea.Investigation("memory.img", unattended=True, with_report=False)
    verify_client = FakeManifestVerifyClient({"overall": True})
    verify_result = verify_inv.verify_final_manifest(verify_client)
    verify_error_inv = fea.Investigation(
        "memory.img", unattended=True, with_report=False
    )
    verify_error_result = verify_error_inv.verify_final_manifest(
        FakeManifestVerifyClient({"_error": {"message": "manifest broken"}})
    )
    qa_kinds = [record["kind"] for record in qa_audit_client.records]
    finding_approved_payloads = [
        record["payload"]
        for record in qa_audit_client.records
        if record["kind"] == "finding_approved"
    ]
    missing_citation_qa = build_report_qa_signoff(
        [{"finding_id": "f-missing", "description": "Confirmed issue."}],
        [{"tool": "evtx_query", "tool_call_id": "tc-evtx"}],
        "SUSPICIOUS",
        completeness,
        coverage,
        normalized,
        [],
        expert_rules,
    )
    single_source_execution_qa = build_report_qa_signoff(
        [
            {
                "finding_id": "f-exec-single",
                "tool_call_id": "tc-evtx",
                "description": "Execution observed in one event.",
            }
        ],
        [
            {"tool": "evtx_query", "tool_call_id": "tc-evtx"},
            {"tool": "vol_psscan", "tool_call_id": "tc-unrelated-memory"},
        ],
        "SUSPICIOUS",
        completeness,
        coverage,
        normalized,
        [],
        expert_rules,
    )
    forbidden_language_qa = build_report_qa_signoff(
        [
            {
                "finding_id": "f-forbidden",
                "tool_call_id": "tc-evtx",
                "description": "The host is clean based on this event log.",
            }
        ],
        [{"tool": "evtx_query", "tool_call_id": "tc-evtx"}],
        "NO_EVIL",
        completeness,
        coverage,
        normalized,
        [],
        expert_rules,
    )
    verifier_failure_qa = build_report_qa_signoff(
        [],
        [{"tool": "evtx_query", "tool_call_id": "tc-evtx"}],
        "INDETERMINATE",
        completeness,
        coverage,
        normalized,
        ["verify_finding rejected or failed for f-1: tool re-run failed"],
        expert_rules,
    )
    customer_text_forbidden_qa = build_report_qa_signoff(
        [],
        [{"tool": "evtx_query", "tool_call_id": "tc-evtx"}],
        "NO_EVIL",
        completeness,
        coverage,
        normalized,
        [],
        expert_rules,
        customer_visible_text=["The executive summary says the host is clean."],
    )
    absent_language_qa = build_report_qa_signoff(
        [],
        [{"tool": "evtx_query", "tool_call_id": "tc-evtx"}],
        "NO_EVIL",
        completeness,
        coverage,
        normalized,
        [],
        expert_rules,
        customer_visible_text=["Network evidence is absent."],
    )
    customer_ready_language_qa = build_report_qa_signoff(
        [],
        [{"tool": "evtx_query", "tool_call_id": "tc-evtx"}],
        "INDETERMINATE",
        {"checks": [{"artifact_class": "evtx", "available": True, "touched": True}]},
        {"blind_spot_count": 0},
        {
            "events": [
                {
                    "artifact_class": "evtx",
                    "tool_call_id": "tc-evtx",
                    "timestamp_utc": "2026-05-09T00:00:00Z",
                }
            ]
        },
        [],
        expert_rules,
        customer_visible_text=["This report is customer-ready."],
    )
    yara_only_execution_qa = single_tool_overclaim_qa(
        finding_id="f-yara-exec",
        tool="yara_scan",
        tool_call_id="tc-yara",
        artifact_class="yara",
        description="YARA-only match proves the binary executed.",
    )
    hayabusa_only_execution_qa = single_tool_overclaim_qa(
        finding_id="f-hayabusa-exec",
        tool="hayabusa_scan",
        tool_call_id="tc-hayabusa",
        artifact_class="evtx",
        description="Hayabusa-only alert proves the command executed.",
    )
    malfind_only_execution_qa = single_tool_overclaim_qa(
        finding_id="f-malfind-exec",
        tool="vol_malfind",
        tool_call_id="tc-malfind",
        artifact_class="memory",
        description="malfind-only VAD output proves the payload executed.",
    )
    memory_only_execution_qa = single_tool_overclaim_qa(
        finding_id="f-memory-exec",
        tool="vol_psscan",
        tool_call_id="tc-psscan",
        artifact_class="memory",
        description="Memory-only process evidence proves execution.",
    )
    evtx_only_execution_qa = single_tool_overclaim_qa(
        finding_id="f-evtx-exec",
        tool="evtx_query",
        tool_call_id="tc-evtx",
        artifact_class="evtx",
        description="EVTX-only process creation evidence proves execution.",
    )
    network_only_execution_qa = single_tool_overclaim_qa(
        finding_id="f-network-exec",
        tool="pcap_triage",
        tool_call_id="tc-pcap",
        artifact_class="network",
        description="Network-only beacon evidence proves code execution.",
    )
    network_tool_only_exfil_qa = single_tool_overclaim_qa(
        finding_id="f-network-exfil",
        tool="pcap_triage",
        tool_call_id="tc-pcap",
        artifact_class="network",
        description="PCAP-only outbound traffic proves data was exfiltrated.",
    )
    network_only_completeness = {
        "evidence_type": "evtx",
        "checks": [
            {"artifact_class": "network", "touched": True},
            {"artifact_class": "disk/filesystem", "touched": False},
        ],
    }
    network_only_exfil_qa = build_report_qa_signoff(
        [
            {
                "finding_id": "f-exfil-network-only",
                "tool_call_id": "tc-evtx",
                "description": "Data was exfiltrated outbound based on network telemetry.",
            }
        ],
        [{"tool": "evtx_query", "tool_call_id": "tc-evtx"}],
        "SUSPICIOUS",
        network_only_completeness,
        coverage,
        normalized,
        [],
        expert_rules,
    )
    unrelated_global_exfil_qa = build_report_qa_signoff(
        [
            {
                "finding_id": "f-exfil-unrelated",
                "tool_call_id": "tc-evtx",
                "description": "Data was exfiltrated outbound based on one event.",
            }
        ],
        [
            {"tool": "evtx_query", "tool_call_id": "tc-evtx"},
            {"tool": "mft_timeline", "tool_call_id": "tc-mft"},
            {"tool": "vel_collect", "tool_call_id": "tc-vel"},
        ],
        "SUSPICIOUS",
        {
            "evidence_type": "evtx",
            "checks": [
                {"artifact_class": "network", "touched": True},
                {"artifact_class": "disk/filesystem", "touched": True},
            ],
        },
        coverage,
        normalized,
        [],
        expert_rules,
    )
    vel_only_exfil_qa = build_report_qa_signoff(
        [
            {
                "finding_id": "f-exfil-vel-only",
                "tool_call_id": "tc-vel",
                "description": "Data was exfiltrated based on one Velociraptor collection row.",
            }
        ],
        [{"tool": "vel_collect", "tool_call_id": "tc-vel"}],
        "SUSPICIOUS",
        {
            "evidence_type": "velociraptor",
            "checks": [{"artifact_class": "velociraptor", "touched": True}],
        },
        {"blind_spot_count": 0},
        {"events": []},
        [],
        expert_rules,
    )
    vel_network_only_exfil_qa = build_report_qa_signoff(
        [
            {
                "finding_id": "f-exfil-vel-network",
                "tool_call_id": "tc-vel",
                "description": "Data was exfiltrated based on one Velociraptor network row.",
            }
        ],
        [{"tool": "vel_collect", "tool_call_id": "tc-vel"}],
        "SUSPICIOUS",
        {
            "evidence_type": "velociraptor",
            "checks": [
                {"artifact_class": "velociraptor", "touched": True},
                {"artifact_class": "network", "touched": True},
            ],
        },
        {"blind_spot_count": 0},
        {
            "events": [
                {
                    "artifact_class": "network",
                    "tool_call_id": "tc-vel",
                    "linked_finding_ids": ["f-exfil-vel-network"],
                }
            ]
        },
        [],
        expert_rules,
    )
    story = build_executive_attack_story(
        timeline_findings,
        "SUSPICIOUS",
        normalized,
        completeness,
        coverage,
        report_qa,
        [],
        [],
        "memory.img",
    )
    expert_cases = [
        (
            "expert doctrine documents signoff operating model",
            "human expert" in doctrine.get("operating_model", "").lower(),
            True,
        ),
        (
            "report QA blocks missing replay artifacts after Track 3b",
            report_qa.get("ready_for_expert_signoff"),
            False,
        ),
        (
            "report QA audit includes full attested payload",
            bool(
                qa_audit_payload.get("report_qa")
                and len(qa_audit_payload.get("report_qa_sha256", "")) == 64
            ),
            True,
        ),
        (
            "report QA audit records packet state",
            qa_audit_payload.get("packet_state"),
            report_qa.get("packet_state"),
        ),
        (
            "release gate blocks customer release pending expert decision",
            qa_release_gate.get("customer_releasable"),
            False,
        ),
        (
            "PASS QA is only a customer-release candidate",
            pass_qa.get("packet_state"),
            "CUSTOMER_RELEASE_CANDIDATE",
        ),
        (
            "PASS QA still requires expert approval before customer-ready PDF",
            pass_qa.get("ready_for_customer_pdf"),
            False,
        ),
        (
            "PASS QA leaves expert decision pending",
            pass_qa.get("expert_decision"),
            "pending",
        ),
        (
            "stub signer blocks customer release even with expert approval",
            stub_release_gate.get("customer_releasable"),
            False,
        ),
        (
            "ed25519 signer (real but identity-less) still blocks customer release",
            ed25519_release_gate.get("customer_releasable"),
            False,
        ),
        (
            "sigstore plus expert approval still waits for manifest verification",
            sigstore_release_gate.get("customer_releasable"),
            False,
        ),
        (
            "sigstore plus expert approval and manifest verification allows release",
            sigstore_verified_release_gate.get("customer_releasable"),
            True,
        ),
        (
            "sigstore release gate marks customer PDF ready only after approval",
            sigstore_verified_release_gate.get("ready_for_customer_pdf"),
            True,
        ),
        (
            "packet attestation records verdict packet digest",
            len(packet_attestation.get("verdict_packet_sha256", "")),
            64,
        ),
        (
            "expert signoff packet records pending human decision",
            expert_signoff_packet.get("decision"),
            "pending",
        ),
        (
            "expert signoff packet references report QA digest",
            len(
                expert_signoff_packet.get("referenced_hashes", {}).get(
                    "report_qa_sha256", ""
                )
            ),
            64,
        ),
        (
            "expert signoff packet reserves manifest digest linkage",
            "run_manifest_sha256" in expert_signoff_packet.get("referenced_hashes", {}),
            True,
        ),
        (
            "expert signoff packet hash matches final emitted packet",
            packet_attestation.get("expert_signoff_packet_sha256"),
            qa_inv._hash_obj(expert_signoff_packet),  # noqa: SLF001
        ),
        (
            "expert miss summary counts rejected packet feedback",
            captured_miss_summary.get("total"),
            2,
        ),
        (
            "expert miss QA edit becomes QA-check follow-up",
            captured_miss_summary.get("items", [])[0].get("conversion_target"),
            "qa_check",
        ),
        (
            "expert miss language edit becomes report-copy follow-up",
            captured_miss_summary.get("items", [])[1].get("conversion_target"),
            "report_copy_fix",
        ),
        (
            "expert miss feedback item keeps ledger hash",
            len(captured_miss_summary.get("items", [])[0].get("ledger_line_sha256")),
            64,
        ),
        (
            "expert signoff packet carries captured feedback items",
            len(miss_signoff_packet.get("feedback_items", [])),
            2,
        ),
        (
            "report metadata exposes expert miss summary",
            miss_metadata.get("expert_miss_summary", {}).get("total"),
            2,
        ),
        (
            "attack story summarizes expert miss feedback",
            any(
                "Expert misses captured" in item
                for item in miss_metadata.get("attack_story", {}).get(
                    "what_we_can_say", []
                )
            ),
            True,
        ),
        (
            "packet attestation is audited before manifest finalize",
            "verdict_packet" in qa_kinds,
            True,
        ),
        (
            "post-finalize manifest verification calls manifest_verify",
            verify_client.calls[0][0] if verify_client.calls else None,
            "manifest_verify",
        ),
        (
            "post-finalize manifest verification stores pass status",
            verify_result.get("overall"),
            True,
        ),
        (
            "post-finalize manifest verification stores errors as failed status",
            verify_error_result.get("overall"),
            False,
        ),
        (
            "final findings become manifest-eligible audit records",
            finding_approved_payloads[0].get("finding_id")
            if finding_approved_payloads
            else None,
            "f-dkom",
        ),
        (
            "report QA blocks missing tool_call_id citations",
            missing_citation_qa.get("status"),
            "FAIL",
        ),
        (
            "report QA blocks case-global execution corroboration",
            single_source_execution_qa.get("status"),
            "FAIL",
        ),
        (
            "report QA blocks forbidden clean wording",
            forbidden_language_qa.get("status"),
            "FAIL",
        ),
        (
            "report QA keeps unverified replay out of customer-ready state",
            report_qa.get("ready_for_customer_pdf"),
            False,
        ),
        (
            "report QA blocks verifier replay failures",
            verifier_failure_qa.get("status"),
            "FAIL",
        ),
        (
            "report QA scans customer-visible text for forbidden wording",
            customer_text_forbidden_qa.get("status"),
            "FAIL",
        ),
        (
            "report QA blocks absent wording for coverage gaps",
            absent_language_qa.get("status"),
            "FAIL",
        ),
        (
            "report QA blocks customer-ready wording before release gates",
            qa_check_status(
                customer_ready_language_qa, "no_forbidden_unqualified_language"
            ),
            "FAIL",
        ),
        (
            "report QA blocks YARA-only execution overclaim",
            qa_check_status(
                yara_only_execution_qa,
                "execution_requires_two_current_artifact_classes",
            ),
            "FAIL",
        ),
        (
            "report QA blocks Hayabusa-only execution overclaim",
            qa_check_status(
                hayabusa_only_execution_qa,
                "execution_requires_two_current_artifact_classes",
            ),
            "FAIL",
        ),
        (
            "report QA blocks malfind-only execution overclaim",
            qa_check_status(
                malfind_only_execution_qa,
                "execution_requires_two_current_artifact_classes",
            ),
            "FAIL",
        ),
        (
            "report QA blocks memory-only execution overclaim",
            qa_check_status(
                memory_only_execution_qa,
                "execution_requires_two_current_artifact_classes",
            ),
            "FAIL",
        ),
        (
            "report QA blocks EVTX-only execution overclaim",
            qa_check_status(
                evtx_only_execution_qa,
                "execution_requires_two_current_artifact_classes",
            ),
            "FAIL",
        ),
        (
            "report QA blocks network-only execution overclaim",
            qa_check_status(
                network_only_execution_qa,
                "execution_requires_two_current_artifact_classes",
            ),
            "FAIL",
        ),
        (
            "report QA blocks network-only exfil overclaim",
            qa_check_status(
                network_tool_only_exfil_qa,
                "exfiltration_requires_staging_and_movement",
            ),
            "FAIL",
        ),
        (
            "report QA blocks exfil without staging coverage",
            network_only_exfil_qa.get("status"),
            "FAIL",
        ),
        (
            "report QA rejects unrelated global exfil coverage",
            unrelated_global_exfil_qa.get("status"),
            "FAIL",
        ),
        (
            "report QA rejects single generic Velociraptor exfil coverage",
            vel_only_exfil_qa.get("status"),
            "FAIL",
        ),
        (
            "report QA rejects Velociraptor-only network exfil coverage",
            vel_network_only_exfil_qa.get("status"),
            "FAIL",
        ),
        (
            "attack story preserves evidence-bound tool call",
            story["attack_chain"][0].get("tool_call_id"),
            "tc-psscan",
        ),
        (
            "attack story refuses attribution",
            any("attribution" in item.lower() for item in story["what_we_cannot_say"]),
            True,
        ),
    ]
    for label, actual, expected in expert_cases:
        process_checks += 1
        ok = actual == expected
        marker = "OK  " if ok else "FAIL"
        print(f"  [{marker}] expert-signoff: {label}")
        if not ok:
            print(f"         expected: {expected!r}")
            print(f"         actual  : {actual!r}")
            failures += 1

    extracted_strings = extract_ascii_strings("687474703a2f2f6576696c2e746573742f61")
    extracted_iocs = extract_iocs(extracted_strings)
    malware_triage = build_malware_triage(
        {
            "injections": [
                {
                    "pid": 31337,
                    "image_name": "rundll32.exe",
                    "vad_start_hex": "0x1000",
                    "vad_end_hex": "0x1fff",
                    "protection": "PAGE_EXECUTE_READWRITE",
                    "mz_match": True,
                    "sample_hex": "687474703a2f2f6576696c2e746573742f61",
                }
            ],
            "injections_seen": 1,
        },
        None,
        {"vol_malfind": "tc-malfind"},
        "memory.img",
    )
    malware_cases = [
        (
            "hex string extraction recovers URL string",
            "http://evil.test/a" in extracted_strings,
            True,
        ),
        (
            "IOC extraction records URL",
            "http://evil.test/a" in extracted_iocs["urls"],
            True,
        ),
        (
            "malware triage is triage-only",
            malware_triage.get("scope"),
            "triage_only",
        ),
        (
            "malware triage contributes lead not verdict proof",
            malware_triage["summary"].get("verdict_contribution"),
            "triage_lead",
        ),
        (
            "malware triage observable stays HYPOTHESIS",
            malware_triage["observables"][0].get("confidence"),
            "HYPOTHESIS",
        ),
        (
            "malware triage observable cites tool output",
            malware_triage["observables"][0].get("tool_call_id"),
            "tc-malfind",
        ),
        (
            "malware triage does not change empty verdict policy",
            compute_verdict([]),
            "NO_EVIL",
        ),
    ]
    for label, actual, expected in malware_cases:
        process_checks += 1
        ok = actual == expected
        marker = "OK  " if ok else "FAIL"
        print(f"  [{marker}] malware: {label}")
        if not ok:
            print(f"         expected: {expected!r}")
            print(f"         actual  : {actual!r}")
            failures += 1

    with tempfile.TemporaryDirectory() as tmp:
        csv_path = Path(tmp) / "timeline.csv"
        write_timeline_csv(
            [
                {
                    "ts": "2026-05-04T00:00:00Z",
                    "source": "vol_psscan",
                    "artifact_class": "memory",
                    "description": "process start",
                    "tool_call_id": "tc-003",
                    "details": {"pid": 4},
                }
            ],
            csv_path,
        )
        text = csv_path.read_text(encoding="utf-8")
    process_checks += 1
    ok = "details_json" in text and "tc-003" in text and '""pid"":4' in text
    marker = "OK  " if ok else "FAIL"
    print(
        "  [{marker}] timeline: CSV export includes details_json".format(marker=marker)
    )
    if not ok:
        print(f"         csv text: {text!r}")
        failures += 1

    with tempfile.TemporaryDirectory() as tmp:
        csv_path = Path(tmp) / "normalized-timeline.csv"
        write_normalized_timeline_csv(normalized["events"], csv_path)
        text = csv_path.read_text(encoding="utf-8")
    process_checks += 1
    ok = (
        "event_id" in text
        and "timestamp_utc" in text
        and "source_record_ref" in text
        and "tc-psscan" in text
        and "T1014" in text
    )
    marker = "OK  " if ok else "FAIL"
    print(
        "  [{marker}] timeline: normalized CSV export includes analyst fields".format(
            marker=marker
        )
    )
    if not ok:
        print(f"         csv text: {text!r}")
        failures += 1

    matrix_disk_inv = fea.Investigation(
        "fixture.E01", unattended=True, with_report=False
    )
    matrix_disk_inv.tool_calls = [{"tool": "case_open", "tool_call_id": "tc-disk"}]
    matrix_disk_checks = {
        row.get("artifact_class"): row
        for row in matrix_disk_inv._case_completeness().get("checks", [])  # noqa: SLF001
    }
    regression_fixture_matrix_cases = [
        (
            "benign",
            "synthetic benign EVTX rows",
            "python scripts/verdict-policy-smoke.py",
            compute_verdict(benign_findings),
            "NO_EVIL",
        ),
        (
            "EVTX-only",
            "synthetic Security EID 4698 scheduled-task row",
            "python scripts/verdict-policy-smoke.py",
            (len(scheduled_task_findings), compute_verdict(scheduled_task_findings)),
            (1, "INDETERMINATE"),
        ),
        (
            "memory DKOM",
            "synthetic pslist/psscan process-view divergence",
            "python scripts/verdict-policy-smoke.py",
            process_sets_diverge(
                [],
                [{"pid": 31337, "image_name": "evil.exe"}],
                0,
                1,
            )[0],
            True,
        ),
        (
            "memory injection",
            "synthetic malfind RWX/MZ observable",
            "python scripts/verdict-policy-smoke.py",
            (
                malware_triage["observables"][0].get("confidence"),
                malware_triage["observables"][0].get("tool_call_id"),
            ),
            ("HYPOTHESIS", "tc-malfind"),
        ),
        (
            "custody-only disk",
            "synthetic E01 case_open-only observable",
            "python scripts/verdict-policy-smoke.py",
            (
                matrix_disk_inv.compute_verdict([]),
                matrix_disk_checks["disk/filesystem"].get("touched"),
            ),
            ("INDETERMINATE", False),
        ),
        (
            "extracted-disk persistence",
            "synthetic extracted Prefetch plus Registry artifacts",
            "python scripts/verdict-policy-smoke.py",
            {"prefetch_parse", "registry_query"} <= set(dispatched_tools),
            True,
        ),
        (
            "network-only",
            "synthetic PCAP-only execution overclaim QA packet",
            "python scripts/verdict-policy-smoke.py",
            qa_check_status(
                network_only_execution_qa,
                "execution_requires_two_current_artifact_classes",
            ),
            "FAIL",
        ),
        (
            "Velociraptor zip",
            "synthetic Velociraptor zip with contained Prefetch artifact",
            "python scripts/verdict-policy-smoke.py",
            (
                len(zip_dispatch_inv.velociraptor_zip_extractions),
                "prefetch_parse" in zip_dispatched_tools,
            ),
            (1, True),
        ),
        (
            "mixed full-case",
            "synthetic case directory with memory, EVTX, extracted disk, and "
            "Velociraptor artifacts all examined",
            "python scripts/verdict-policy-smoke.py",
            (
                dir_checks["memory"].get("touched"),
                dir_checks["evtx"].get("touched"),
                dir_checks["disk/filesystem"].get("touched"),
                dir_inv.compute_verdict([]),
            ),
            (True, True, True, "NO_EVIL"),
        ),
    ]
    matrix_checks = 0
    for scenario, fixture, command, actual, expected in regression_fixture_matrix_cases:
        matrix_checks += 1
        ok = actual == expected
        marker = "OK  " if ok else "FAIL"
        print(f"  [{marker}] fixture-matrix: {scenario} via {command}")
        print(f"         fixture : {fixture}")
        if not ok:
            print(f"         expected: {expected!r}")
            print(f"         actual  : {actual!r}")
            failures += 1

    red_team_challenge_cases = [
        (
            "RT-01 unsupported artifact evil stays explicit scope gap",
            manifest_by_class["unsupported"].get("status"),
            "unsupported",
        ),
        (
            "RT-02 benign admin activity produces no finding",
            (len(benign_logon_findings), compute_verdict(benign_logon_findings)),
            (0, "NO_EVIL"),
        ),
        (
            "RT-03 single-source execution trap is blocked by QA",
            qa_check_status(
                evtx_only_execution_qa,
                "execution_requires_two_current_artifact_classes",
            ),
            "FAIL",
        ),
        (
            "RT-04 log-clear event remains cited finding",
            (
                len(suspicious_findings),
                suspicious_findings[0].get("tool_call_id")
                if suspicious_findings
                else None,
            ),
            (1, "tc-evtx"),
        ),
        (
            "RT-05 DKOM divergence requests corroboration, not conviction",
            (
                process_sets_diverge(
                    [],
                    [{"pid": 4, "image_name": "System"}],
                    0,
                    1,
                )[0],
                compute_verdict(
                    [{"confidence": "HYPOTHESIS", "mitre_technique": "T1014"}]
                ),
            ),
            (True, "INDETERMINATE"),
        ),
        (
            "RT-06 exfil without staging/movement is blocked by QA",
            qa_check_status(
                network_only_exfil_qa,
                "exfiltration_requires_staging_and_movement",
            ),
            "FAIL",
        ),
        (
            "RT-07 parser failure records failed coverage row",
            (
                manifest_by_class["evtx"].get("status"),
                manifest_by_class["evtx"].get("parse_errors"),
            ),
            ("failed", 3),
        ),
    ]
    red_team_checks = 0
    for label, actual, expected in red_team_challenge_cases:
        red_team_checks += 1
        ok = actual == expected
        marker = "OK  " if ok else "FAIL"
        print(f"  [{marker}] red-team-challenge: {label}")
        if not ok:
            print(f"         expected: {expected!r}")
            print(f"         actual  : {actual!r}")
            failures += 1

    # --- contradiction resolution record check ---
    contra_record = build_contradiction_resolution_record(
        contradiction_id="test-contra-1",
        resolution="auto_higher_credibility",
        approved_by="auto",
    )
    contra_ok = (
        contra_record.get("kind") == "contradiction_resolved"
        and contra_record.get("contradiction_id") == "test-contra-1"
        and contra_record.get("resolution") == "auto_higher_credibility"
        and contra_record.get("approved_by") == "auto"
    )
    marker = "OK  " if contra_ok else "FAIL"
    print(
        f"  [{marker}] check_contradiction_resolution_record: kind + required fields present"
    )
    if not contra_ok:
        print(f"         actual: {contra_record!r}")
        failures += 1
    contradiction_checks = 1

    # CVE tagging (Phase 6): _extract_cve_ids surfaces literal CVE ids from finding
    # text — additive only, no verdict impact. Grounding validates ids vs NVD later.
    extract = getattr(fea, "_extract_cve_ids", None)
    cve_ok = (
        callable(extract)
        and extract("exploited CVE-2021-34527 then cve-2017-0144 again CVE-2021-34527")
        == ["CVE-2017-0144", "CVE-2021-34527"]
        and extract("no cve here") == []
    )
    marker = "OK  " if cve_ok else "FAIL"
    print(
        f"  [{marker}] _extract_cve_ids: dedupes + uppercases literal CVE ids, [] when none"
    )
    if not cve_ok:
        failures += 1
    cve_checks = 1

    # Host grouping + named-technique signatures (analyst rework). Pure functions
    # over synthetic findings + a normalized timeline.
    host_checks = 0
    hg_findings = [
        {
            "finding_id": "f-A-evtx-audit-log-cleared",
            "confidence": "CONFIRMED",
            "mitre_technique": "T1070.001",
            "tool_call_id": "tc-002",
            "artifact_path": "/ev/DE_1102.evtx",
            "description": "EVTX contains Security EID 1102 audit-log clear event (record 1).",
        },
        {
            "finding_id": "f-B-evtx-service-install",
            "confidence": "HYPOTHESIS",
            "mitre_technique": "T1543.003",
            "tool_call_id": "tc-003",
            "artifact_path": "/ev/LM_7045.evtx",
            "description": "EVTX EID 7045 records installation of service 'spoolfool' (image cmd.exe) (record 1).",
        },
        {
            "finding_id": "f-B-evtx-wmi-exec",
            "confidence": "HYPOTHESIS",
            "mitre_technique": "T1047",
            "tool_call_id": "tc-004",
            "artifact_path": "/ev/LM_WMI.evtx",
            "description": "EVTX Security EID 4688 shows calc.exe with WmiPrvSE.exe as its parent process (record 6).",
        },
    ]
    hg_timeline = {
        "events": [
            {
                "timestamp_utc": "2019-03-19T23:35:07Z",
                "entities": {"host": "PC01"},
                "linked_finding_ids": ["f-A-evtx-audit-log-cleared"],
            },
            {
                "timestamp_utc": "2019-03-03T09:20:28Z",
                "entities": {"host": "WIN-7"},
                "linked_finding_ids": ["f-B-evtx-service-install"],
            },
            {
                "timestamp_utc": "2019-03-18T22:15:49Z",
                "entities": {"host": "WIN-7"},
                "linked_finding_ids": ["f-B-evtx-wmi-exec"],
            },
        ]
    }
    fea.tag_finding_hosts(hg_findings, hg_timeline)
    fea.apply_signature_profiles(hg_findings)
    hg_groups = fea.build_host_groups(hg_findings, hg_timeline)
    spool = next(f for f in hg_findings if f["mitre_technique"] == "T1543.003")
    host_cases = [
        (
            "finding host denormalized from linked event",
            hg_findings[0].get("host"),
            "PC01",
        ),
        (
            "spoolfool recognized as SpoolFool",
            "SpoolFool" in (spool.get("named_technique") or ""),
            True,
        ),
        (
            "spoolfool tags CVE-2022-21999",
            "CVE-2022-21999" in (spool.get("cves") or []),
            True,
        ),
        ("spoolfool carries a hunt query", bool(spool.get("hunt")), True),
        ("host_groups splits into two hosts", len(hg_groups), 2),
        (
            "strongest (CONFIRMED) host ordered first",
            hg_groups[0]["host"] if hg_groups else None,
            "PC01",
        ),
        (
            "WMI maps to Lateral Movement phase",
            fea._phase_for_technique("T1047")[1],
            "Lateral Movement",
        ),
        (
            "log-clear maps to Defense Evasion phase",
            fea._phase_for_technique("T1070.001")[1],
            "Defense Evasion",
        ),
        (
            "unknown technique gets no signature",
            fea._signature_for_finding(
                {"mitre_technique": "T1234", "description": "x"}
            ),
            None,
        ),
    ]
    for label, actual, expected in host_cases:
        host_checks += 1
        ok = actual == expected
        marker = "OK  " if ok else "FAIL"
        print(f"  [{marker}] host: {label}")
        if not ok:
            print(f"         expected: {expected!r}")
            print(f"         actual  : {actual!r}")
            failures += 1

    print()
    print("=" * 60)
    total = (
        len(cases)
        + len(et_cases)
        + inventory_checks
        + len(evtx_cases)
        + disk_policy_checks
        + process_checks
        + matrix_checks
        + red_team_checks
        + contradiction_checks
        + cve_checks
        + host_checks
    )
    if failures == 0:
        print(f"OK - all {total} verdict + evidence/process cases pass.")
        print("=" * 60)
        return 0
    print(f"FAIL - {failures} of {total} cases failed.")
    print("If the change is intentional, update both:")
    print("  - scripts/find_evil_auto.py (verdict / evidence / process helpers)")
    print("  - scripts/verdict-policy-smoke.py expected outputs")
    print("  - docs/verdict-semantics.md per-verdict trigger list")
    print("=" * 60)
    return 1


if __name__ == "__main__":
    sys.exit(main())
