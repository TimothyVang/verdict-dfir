#!/usr/bin/env python3
"""Smoke test for Windows-focused golden coverage.

This intentionally validates metadata and fetch contracts only. Raw Windows
evidence stays outside git under fixtures/ and is downloaded/staged by the
operator when they want to run the benchmark.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
FETCH_SCRIPT = REPO_ROOT / "scripts" / "fetch-fixtures.sh"
DATASET_DOC = REPO_ROOT / "docs" / "DATASET.md"
L3_SCRIPT = REPO_ROOT / "scripts" / "l3-run-goldens.sh"

EXPECTED_WINDOWS_CASES = {
    "otrf-apt3-mordor": {
        "classes": {"log"},
        "min_findings": 4,
        "fetch_tokens": ["datasets/atomic/windows", "otrf-apt3-mordor"],
    },
    "memlabs-lab1": {
        "classes": {"memory"},
        "min_findings": 3,
        "fetch_tokens": ["MEMLABS_LAB1_URL", "MEMLABS_LAB1_SHA256", "memlabs-lab1"],
    },
    "memlabs-lab2": {
        "classes": {"memory"},
        "min_findings": 3,
        "fetch_tokens": ["MEMLABS_LAB2_URL", "MEMLABS_LAB2_SHA256", "memlabs-lab2"],
    },
    "memlabs-lab3": {
        "classes": {"memory"},
        "min_findings": 3,
        "fetch_tokens": ["MEMLABS_LAB3_URL", "MEMLABS_LAB3_SHA256", "memlabs-lab3"],
    },
    "digitalcorpora-lonewolf": {
        "classes": set(),
        "min_findings": 0,
        "fetch_tokens": ["LONEWOLF_URL", "LONEWOLF_SHA256", "digitalcorpora-lonewolf"],
    },
}


def load_golden(case_id: str) -> dict:
    path = REPO_ROOT / "goldens" / case_id / "expected-findings.json"
    assert path.exists(), f"missing golden: {path}"
    return json.loads(path.read_text(encoding="utf-8"))


def test_windows_goldens_exist_and_have_schema() -> None:
    for case_id, expected in EXPECTED_WINDOWS_CASES.items():
        golden = load_golden(case_id)
        assert golden.get("case_id") == case_id, f"{case_id}: case_id mismatch"
        assert golden.get("source_url"), f"{case_id}: missing source_url"
        assert golden.get("license"), f"{case_id}: missing license"
        assert golden.get("verdict") in {
            "SUSPICIOUS",
            "CONFIRMED_EVIL",
            "INDETERMINATE",
            "UNKNOWN",
        }, f"{case_id}: unsupported verdict {golden.get('verdict')!r}"
        assert isinstance(
            golden.get("min_recall_percent"), int
        ), f"{case_id}: min_recall_percent must be an int"
        findings = golden.get("findings")
        assert isinstance(findings, list), f"{case_id}: findings must be a list"
        assert (
            len(findings) >= expected["min_findings"]
        ), f"{case_id}: expected at least {expected['min_findings']} findings"
        if case_id.startswith("memlabs-"):
            source_hashes = golden.get("source_hashes") or {}
            assert source_hashes.get("archive_md5"), f"{case_id}: missing archive_md5"
            assert source_hashes.get(
                "memory_dump_md5"
            ), f"{case_id}: missing memory_dump_md5"
            serialized = json.dumps(golden).lower()
            forbidden_flag_markers = ("flag{", "inctf{", "ctf{")
            assert not any(
                marker in serialized for marker in forbidden_flag_markers
            ), f"{case_id}: golden must not commit actual CTF flag values"
        if case_id == "digitalcorpora-lonewolf":
            assert golden.get("status") == "teacher_guide_gated_candidate"
            assert golden.get("verdict") == "INDETERMINATE"
            assert golden.get("min_recall_percent") == 0
            required_artifacts = golden.get("required_artifacts") or []
            assert "LoneWolf.E01-LoneWolf.E09" in required_artifacts
            assert "memdump.mem" in required_artifacts
            assert "pagefile.sys" in required_artifacts
            assert golden.get(
                "lead_hypotheses"
            ), "Lone Wolf should keep unscored leads separate"
        classes = {f.get("artifact_class") for f in findings}
        assert expected["classes"].issubset(
            classes
        ), f"{case_id}: expected classes {expected['classes']}, got {classes}"
        for finding in findings:
            assert finding.get("finding_id"), f"{case_id}: finding missing id"
            assert finding.get("description"), f"{case_id}: finding missing description"
            assert finding.get("confidence") in {
                "CONFIRMED",
                "INFERRED",
                "HYPOTHESIS",
            }, f"{case_id}: unsupported confidence {finding.get('confidence')!r}"
            assert finding.get("artifact_hint"), f"{case_id}: missing artifact_hint"


def test_fetch_contract_mentions_windows_cases() -> None:
    text = FETCH_SCRIPT.read_text(encoding="utf-8")
    assert "OTRF_SECURITY_DATASETS_REF" in text
    assert "must be a full 40-hex commit SHA" in text
    assert "git sparse-checkout set" in text
    assert "cached, pinned sha verified" in text
    assert "cached sha mismatch" in text
    assert "safe_url_label" in text
    assert "extract_zip_fixture" in text
    assert "SANS_STARTER_SHA256 is missing" in text
    assert "DATA_LEAKAGE_SHA256 is missing" in text
    assert "DFRWS2008_REF" in text
    cached_block = text[
        text.index('if [[ -f "${abs}" ]]; then') : text.index("local url_label")
    ]
    assert cached_block.index('if [[ -n "${expected_sha}" ]]') < cached_block.index(
        'if [[ -n "${manifest_sha}" &&'
    )
    for case_id, expected in EXPECTED_WINDOWS_CASES.items():
        for token in expected["fetch_tokens"]:
            assert token in text, f"fetch-fixtures.sh missing {token!r} for {case_id}"
        if case_id.startswith("memlabs-"):
            golden = load_golden(case_id)
            memory_dump_md5 = golden["source_hashes"]["memory_dump_md5"]
            assert (
                memory_dump_md5 in text
            ), f"fetch-fixtures.sh missing {memory_dump_md5}"
            assert "memory dump MD5 mismatch" in text
            assert "extracted memory dump direct/file:// URL" in text


def test_l3_keeps_fast_controls_before_large_optional_cases() -> None:
    text = L3_SCRIPT.read_text(encoding="utf-8")
    fast_controls = ['"synthetic-benign"', '"nitroba"', '"nist-hacking-case"']
    optional_cases = [
        '"otrf-apt3-mordor"',
        '"memlabs-lab1"',
        '"memlabs-lab2"',
        '"memlabs-lab3"',
        '"digitalcorpora-lonewolf"',
    ]
    last_fast = max(text.index(case) for case in fast_controls)
    first_optional = min(text.index(case) for case in optional_cases)
    assert (
        last_fast < first_optional
    ), "fast controls must run before optional Windows cases"


def test_dataset_doc_mentions_windows_cases() -> None:
    text = DATASET_DOC.read_text(encoding="utf-8")
    assert "Windows-focused golden expansion" in text
    for case_id in EXPECTED_WINDOWS_CASES:
        assert case_id in text, f"DATASET.md missing {case_id}"


def main() -> int:
    tests = [
        (
            "windows_goldens_exist_and_have_schema",
            test_windows_goldens_exist_and_have_schema,
        ),
        (
            "fetch_contract_mentions_windows_cases",
            test_fetch_contract_mentions_windows_cases,
        ),
        (
            "l3_keeps_fast_controls_before_large_optional_cases",
            test_l3_keeps_fast_controls_before_large_optional_cases,
        ),
        ("dataset_doc_mentions_windows_cases", test_dataset_doc_mentions_windows_cases),
    ]
    passed = 0
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"  [PASS] {name}")
            passed += 1
        except Exception as exc:
            print(f"  [FAIL] {name}: {exc}")
            failed += 1
    print(f"\nwindows-goldens-smoke: {passed} passed, {failed} failed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
