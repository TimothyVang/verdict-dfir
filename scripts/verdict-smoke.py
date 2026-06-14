#!/usr/bin/env python3
"""Smoke test: scripts/verdict — the one-command entry point.

Verifies via bash -n (syntax) and grep-asserts that the single workflow wires
each stage (preflight → build → investigate → dashboard). --dry-run is
exercised without running any investigation.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "verdict"
VERDICT_SKILL = REPO_ROOT / ".claude" / "skills" / "verdict" / "SKILL.md"


def test_script_exists_and_executable() -> None:
    assert SCRIPT.exists(), f"Missing: {SCRIPT}"


def test_bash_syntax_clean() -> None:
    result = subprocess.run(["bash", "-n", str(SCRIPT)], capture_output=True, text=True)
    assert result.returncode == 0, f"bash -n failed: {result.stderr}"


def test_chains_doctor() -> None:
    assert "doctor.sh" in SCRIPT.read_text(
        encoding="utf-8"
    ), "verdict does not reference doctor.sh"


def test_chains_build() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert (
        "cargo build" in text or "findevil-mcp" in text
    ), "verdict does not reference cargo build / findevil-mcp"


def test_chains_engine() -> None:
    assert "find_evil_auto" in SCRIPT.read_text(
        encoding="utf-8"
    ), "verdict does not chain the find_evil_auto engine"


def test_has_sift_and_dashboard_flags() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert "--sift" in text, "verdict missing --sift flag"
    assert "--no-dashboard" in text, "verdict missing --no-dashboard flag"


def test_sift_staging_rejects_unsafe_remote_names() -> None:
    test_sift_staging_sanitizer_selftest()
    text = SCRIPT.read_text(encoding="utf-8")
    assert "safe_guest_basename" in text, "verdict lacks SIFT basename sanitizer"
    assert (
        "unsafe evidence filename for --sift staging" in text
    ), "verdict does not reject shell-unsafe SIFT evidence filenames"
    assert (
        "unsafe SIFT guest evidence dir" in text
    ), "verdict does not reject shell-unsafe SIFT guest evidence directories"


def test_n8n_status_wording_does_not_overclaim_actions() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert (
        "n8n fired" not in text
    ), "verdict overclaims n8n reachability as fired action"
    assert (
        "n8n reachable; automation sidecar recorded" in text
    ), "verdict should distinguish n8n reachability from action creation"


def test_sift_staging_sanitizer_selftest() -> None:
    env = {**os.environ, "FINDEVIL_VERDICT_SELFTEST": "sift-sanitizers"}
    result = subprocess.run(
        ["bash", str(SCRIPT)], capture_output=True, text=True, timeout=10, env=env
    )
    assert (
        result.returncode == 0
    ), f"SIFT sanitizer selftest failed: stdout={result.stdout!r} stderr={result.stderr!r}"
    assert (
        "sift sanitizer selftest OK" in result.stdout
    ), f"SIFT sanitizer selftest did not confirm success: {result.stdout!r}"


def test_sift_directory_staging_selftest() -> None:
    env = {**os.environ, "FINDEVIL_VERDICT_SELFTEST": "sift-staging"}
    result = subprocess.run(
        ["bash", str(SCRIPT)], capture_output=True, text=True, timeout=15, env=env
    )
    assert (
        result.returncode == 0
    ), f"SIFT staging selftest failed: stdout={result.stdout!r} stderr={result.stderr!r}"
    assert (
        "sift staging selftest OK" in result.stdout
    ), f"SIFT staging selftest did not confirm success: {result.stdout!r}"


def test_sift_cleanup_guard_selftest() -> None:
    env = {**os.environ, "FINDEVIL_VERDICT_SELFTEST": "sift-cleanup-guard"}
    result = subprocess.run(
        ["bash", str(SCRIPT)], capture_output=True, text=True, timeout=15, env=env
    )
    assert (
        result.returncode == 0
    ), f"SIFT cleanup guard selftest failed: stdout={result.stdout!r} stderr={result.stderr!r}"
    assert (
        "sift cleanup guard selftest OK" in result.stdout
    ), f"SIFT cleanup guard selftest did not confirm success: {result.stdout!r}"


def test_sift_staging_defaults_to_run_owned_cleanup() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert (
        ".verdict-staging" in text
    ), "verdict should stage SIFT evidence under a run-owned staging root"
    assert (
        "STAGED_REMOTE_PATH" in text
    ), "verdict should record the current run's staged evidence path"
    assert (
        "cleanup_current_sift_staging" in text
    ), "verdict should clean current-run SIFT staging after success"
    assert (
        "cleaned SIFT staging" in text
    ), "verdict should log successful SIFT staging cleanup"
    cleanup_call = "  cleanup_current_sift_staging\n"
    assert text.index('"${ENGINE[@]}"') < text.rindex(
        cleanup_call
    ), "verdict should clean SIFT staging only after the engine succeeds"


def test_sift_staging_has_keep_opt_out() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert "--keep-sift-staging" in text, "verdict should expose a keep-staging flag"
    assert "KEEP_SIFT_STAGING=0" in text, "verdict should clean staging by default"
    assert (
        "KEEP_SIFT_STAGING=1" in text
    ), "verdict should parse --keep-sift-staging as an opt-out"
    assert (
        "kept SIFT staging" in text
    ), "verdict should report retained staging when the opt-out is used"


def test_sift_cleanup_uses_remote_realpath_guards() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert (
        "prepare_sift_staging_parent" in text
    ), "verdict should validate the remote staging parent before mkdir/copy"
    assert (
        "create_sift_staging_root" in text
    ), "verdict should create a fresh owned staging root before copy"
    assert "realpath -e" in text, "verdict should validate physical remote paths"
    assert (
        "[ ! -L ${qparent} ]" in text
    ), "verdict should refuse a symlinked .verdict-staging parent"
    assert (
        "[ ! -L ${qroot} ]" in text
    ), "verdict should refuse a symlinked current-run staging root"


def test_sift_cleanup_does_not_delete_root_level_temp_paths() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert (
        "cleanup_stale_stage_temps" not in text
    ), "verdict should not run root-level stale temp cleanup under GEVDIR"
    assert (
        "find ${qdir}" not in text
    ), "verdict should not recursively delete temp paths from the GEVDIR root"


def test_sift_stage_id_collision_fails_closed() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert (
        "run-owned SIFT staging root already exists" in text
    ), "verdict should fail closed if the generated/overridden staging root already exists"


def test_sift_run_owned_staging_never_reuses_existing_copy() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert "should_stage" not in text, "run-owned SIFT staging should always copy fresh"
    assert (
        "evidence already staged in the VM" not in text
    ), "run-owned SIFT staging should not reuse stale or colliding staged evidence"


def test_verdict_skill_documents_sift_staging_cleanup_contract() -> None:
    text = VERDICT_SKILL.read_text(encoding="utf-8")
    assert (
        "current-run SIFT staging" in text
    ), "repo-local verdict skill should document automatic SIFT staging cleanup"
    assert (
        "--keep-sift-staging" in text
    ), "repo-local verdict skill should document the keep-staging escape hatch"
    assert (
        "legacy root-level staging" in text
    ), "repo-local verdict skill should distinguish automatic cleanup from legacy staging cleanup"


def test_sift_directory_staging_uses_remote_type_and_fingerprint_helpers() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert (
        "remote_evidence_type" in text
    ), "verdict should inspect remote staging root type before creating a run-owned root"
    assert (
        "remote_evidence_fingerprint" in text
    ), "verdict should verify remote temp staging fingerprints before promotion"
    assert (
        "remote_evidence_size" not in text
    ), "verdict should not keep stale remote-size cache logic"
    assert (
        "stat -c%s '${remote}'" not in text
    ), "verdict should not use file-only stat size as the directory staging equivalence check"


def test_sift_directory_staging_uses_temp_then_promote() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert ".tmp-" in text, "verdict should stage directories through a temp path"
    assert (
        "promote_staged_directory" in text
    ), "verdict should promote staged directories through a no-nesting helper"
    assert "rollback" in text, "verdict should attempt rollback if promotion fails"
    assert (
        '"${EVIDENCE}/."' in text
    ), "verdict should copy directory contents into the temp directory"
    assert (
        '"${scpflag[@]}" -- "${EVIDENCE}" "${GADDR}:${remote}"' not in text
    ), "verdict should not recursively scp a directory directly to the final remote path"


def test_sift_staging_validates_before_copy_and_hashes_files() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    pre_copy = 'lfingerprint="$(local_evidence_fingerprint "${EVIDENCE}")"'
    dir_copy = '"${EVIDENCE}/." "${GADDR}:${tmp_remote}/"'
    assert pre_copy in text, "verdict should fingerprint local evidence before staging"
    assert dir_copy in text, "verdict should stage directory contents into the temp dir"
    assert text.index(pre_copy) < text.index(
        dir_copy
    ), "verdict should reject symlinks/special files before recursive scp reads them"
    assert (
        '"${EVIDENCE}" "${GADDR}:${remote}"' not in text
    ), "verdict should not scp files directly to the final remote evidence path"
    assert (
        'tfingerprint="$(remote_evidence_fingerprint "${tmp_remote}")"' in text
    ), "verdict should verify the remote temp copy fingerprint before promotion"
    assert (
        'postfingerprint="$(local_evidence_fingerprint "${EVIDENCE}")"' in text
    ), "verdict should detect evidence changes during staging before promotion"
    assert (
        "evidence changed during staging" in text
    ), "verdict should fail closed when local evidence changes during staging"
    assert (
        '[[ -e "${EVIDENCE}" || -L "${EVIDENCE}" ]]' in text
    ), "verdict should reject dangling local symlinks instead of treating them as in-VM paths"


def test_sift_fingerprint_fails_closed_on_unreadable_directories() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert (
        "def on_walk_error(error):" in text
    ), "verdict fingerprint helper should define an os.walk error handler"
    assert (
        "onerror=on_walk_error" in text
    ), "verdict fingerprint helper should fail closed on unreadable subtrees"


def test_dry_run_produces_no_investigation() -> None:
    result = subprocess.run(
        ["bash", str(SCRIPT), "--dry-run"], capture_output=True, text=True, timeout=10
    )
    assert (
        result.returncode == 0
    ), f"--dry-run exited {result.returncode}: {result.stderr}"
    combined = result.stdout + result.stderr
    assert (
        "DRY-RUN" in combined
    ), f"--dry-run did not emit DRY-RUN markers: {combined[:300]}"
    assert "4/4" in combined, "verdict --dry-run did not reach the final stage (4/4)"


def test_dry_run_with_skip_build() -> None:
    result = subprocess.run(
        ["bash", str(SCRIPT), "--dry-run", "--skip-build"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, f"--skip-build failed: {result.stderr}"


def main() -> int:
    tests = [
        ("script_exists_and_executable", test_script_exists_and_executable),
        ("bash_syntax_clean", test_bash_syntax_clean),
        ("chains_doctor", test_chains_doctor),
        ("chains_build", test_chains_build),
        ("chains_engine", test_chains_engine),
        ("has_sift_and_dashboard_flags", test_has_sift_and_dashboard_flags),
        (
            "sift_staging_rejects_unsafe_remote_names",
            test_sift_staging_rejects_unsafe_remote_names,
        ),
        (
            "n8n_status_wording_does_not_overclaim_actions",
            test_n8n_status_wording_does_not_overclaim_actions,
        ),
        ("sift_directory_staging_selftest", test_sift_directory_staging_selftest),
        ("sift_cleanup_guard_selftest", test_sift_cleanup_guard_selftest),
        (
            "sift_staging_defaults_to_run_owned_cleanup",
            test_sift_staging_defaults_to_run_owned_cleanup,
        ),
        ("sift_staging_has_keep_opt_out", test_sift_staging_has_keep_opt_out),
        (
            "sift_cleanup_uses_remote_realpath_guards",
            test_sift_cleanup_uses_remote_realpath_guards,
        ),
        (
            "sift_cleanup_does_not_delete_root_level_temp_paths",
            test_sift_cleanup_does_not_delete_root_level_temp_paths,
        ),
        (
            "sift_stage_id_collision_fails_closed",
            test_sift_stage_id_collision_fails_closed,
        ),
        (
            "sift_run_owned_staging_never_reuses_existing_copy",
            test_sift_run_owned_staging_never_reuses_existing_copy,
        ),
        (
            "verdict_skill_documents_sift_staging_cleanup_contract",
            test_verdict_skill_documents_sift_staging_cleanup_contract,
        ),
        (
            "sift_directory_staging_uses_remote_type_and_fingerprint_helpers",
            test_sift_directory_staging_uses_remote_type_and_fingerprint_helpers,
        ),
        (
            "sift_directory_staging_uses_temp_then_promote",
            test_sift_directory_staging_uses_temp_then_promote,
        ),
        (
            "sift_staging_validates_before_copy_and_hashes_files",
            test_sift_staging_validates_before_copy_and_hashes_files,
        ),
        (
            "sift_fingerprint_fails_closed_on_unreadable_directories",
            test_sift_fingerprint_fails_closed_on_unreadable_directories,
        ),
        ("dry_run_produces_no_investigation", test_dry_run_produces_no_investigation),
        ("dry_run_with_skip_build", test_dry_run_with_skip_build),
    ]
    passed = failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"  [PASS] {name}")
            passed += 1
        except Exception as exc:
            print(f"  [FAIL] {name}: {exc}")
            failed += 1
    print(f"\nverdict-smoke: {passed} passed, {failed} failed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
