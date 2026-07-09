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
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "verdict"
VERDICT_SKILL = REPO_ROOT / ".claude" / "skills" / "verdict" / "SKILL.md"
VERDICT_PLAN = (
    REPO_ROOT
    / "docs"
    / "superpowers"
    / "plans"
    / "2026-06-14-verdict-case-root-consolidation.md"
)


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


def test_case_id_rejects_traversal_before_engine_args() -> None:
    commands = [
        [
            "bash",
            str(SCRIPT),
            "README.md",
            "--dry-run",
            "--skip-build",
            "--case-id",
            "../../outside",
        ],
        [
            "bash",
            str(SCRIPT),
            "README.md",
            "--dry-run",
            "--skip-build",
            "--case-id=../../outside",
        ],
        [
            "bash",
            str(SCRIPT),
            "README.md",
            "--dry-run",
            "--skip-build",
            "--",
            "--case-id",
            "../../outside",
        ],
        [
            "bash",
            str(SCRIPT),
            "README.md",
            "--dry-run",
            "--skip-build",
            "--",
            "--case-id=../../outside",
        ],
    ]
    for command in commands:
        result = subprocess.run(command, capture_output=True, text=True, timeout=10)
        combined = result.stdout + result.stderr
        assert result.returncode != 0, f"unsafe --case-id was accepted: {combined!r}"
        assert (
            "unsafe --case-id" in combined
            or "--case-id must be a top-level" in combined
        ), f"unsafe --case-id lacked clear error: {combined!r}"


def test_case_id_validation_happens_before_preflight_and_sift() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    validation = 'CASE_ID_OVERRIDE="$(safe_case_id "${CASE_ID_OVERRIDE}")"'
    assert validation in text, "verdict should validate top-level --case-id"
    assert text.index(validation) < text.index(
        "# Resolve evidence"
    ), "verdict should reject unsafe --case-id before evidence resolution side effects"
    assert text.index(validation) < text.index(
        "# 1. preflight"
    ), "verdict should reject unsafe --case-id before preflight/build side effects"
    assert text.index(validation) < text.index(
        "# 3. SIFT-VM toggle"
    ), "verdict should reject unsafe --case-id before SIFT SSH/staging side effects"


def test_case_dir_resolution_selftest() -> None:
    env = {**os.environ, "FINDEVIL_VERDICT_SELFTEST": "case-dir-resolution"}
    result = subprocess.run(
        ["bash", str(SCRIPT), "--dry-run", "--skip-build"],
        capture_output=True,
        text=True,
        timeout=15,
        env=env,
    )
    assert (
        result.returncode == 0
    ), f"case dir resolution selftest failed: stdout={result.stdout!r} stderr={result.stderr!r}"
    assert (
        "case dir resolution selftest OK" in result.stdout
    ), f"case dir resolution selftest did not confirm success: {result.stdout!r}"
    assert (
        "case dir resolution mixed rejection OK" in result.stdout
    ), f"case dir resolution selftest did not cover mixed rejection: {result.stdout!r}"
    assert (
        "case dir fallback symlink rejection OK" in result.stdout
    ), f"case dir resolution selftest did not cover symlink fallback rejection: {result.stdout!r}"


def test_case_id_ownership_selftest() -> None:
    env = {**os.environ, "FINDEVIL_VERDICT_SELFTEST": "case-id-ownership"}
    result = subprocess.run(
        ["bash", str(SCRIPT), "--dry-run", "--skip-build"],
        capture_output=True,
        text=True,
        timeout=15,
        env=env,
    )
    assert (
        result.returncode == 0
    ), f"case id ownership selftest failed: stdout={result.stdout!r} stderr={result.stderr!r}"
    assert (
        "case id ownership selftest OK" in result.stdout
    ), f"case id ownership selftest did not confirm success: {result.stdout!r}"


def test_case_layout_ownership_selftest() -> None:
    env = {**os.environ, "FINDEVIL_VERDICT_SELFTEST": "case-layout-ownership"}
    result = subprocess.run(
        ["bash", str(SCRIPT), "--dry-run", "--skip-build"],
        capture_output=True,
        text=True,
        timeout=15,
        env=env,
    )
    assert (
        result.returncode == 0
    ), f"case layout ownership selftest failed: stdout={result.stdout!r} stderr={result.stderr!r}"
    assert (
        "case layout ownership selftest OK" in result.stdout
    ), f"case layout ownership selftest did not confirm success: {result.stdout!r}"
    assert (
        "case sidecar symlink rejection OK" in result.stdout
    ), f"case layout ownership selftest did not cover sidecar symlink rejection: {result.stdout!r}"
    assert (
        "case sidecar parent symlink rejection OK" in result.stdout
    ), f"case layout ownership selftest did not cover sidecar parent symlink rejection: {result.stdout!r}"


def test_run_summary_rejects_outside_project_tmp_before_engine() -> None:
    result = subprocess.run(
        [
            "bash",
            str(SCRIPT),
            "README.md",
            "--dry-run",
            "--skip-build",
            "--run-summary",
            "/tmp/verdict-outside.json",
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )
    combined = result.stdout + result.stderr
    assert result.returncode != 0, f"out-of-tree run summary was accepted: {combined!r}"
    assert (
        "run summary" in combined.lower()
    ), f"run summary rejection lacked clear error: {combined!r}"


def test_run_summary_requires_value() -> None:
    result = subprocess.run(
        [
            "bash",
            str(SCRIPT),
            "README.md",
            "--dry-run",
            "--skip-build",
            "--run-summary",
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )
    combined = result.stdout + result.stderr
    assert (
        result.returncode != 0
    ), f"missing --run-summary value was accepted: {combined!r}"
    assert (
        "--run-summary requires a value" in combined
    ), f"missing value error was unclear: {combined!r}"


def test_case_local_run_summary_path_does_not_precreate_case_dir() -> None:
    case_id = f"summary-case-{os.getpid()}"
    result = subprocess.run(
        [
            "bash",
            str(SCRIPT),
            "README.md",
            "--dry-run",
            "--skip-build",
            "--case-id",
            case_id,
            "--run-summary",
            f"tmp/auto-runs/{case_id}/summaries/custom.json",
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )
    combined = result.stdout + result.stderr
    assert (
        result.returncode == 0
    ), f"case-local run summary pre-created case dir: {combined!r}"


def test_sift_staging_defaults_to_run_owned_cleanup() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert (
        "staging/sift" in text
    ), "verdict should stage SIFT evidence under a run-owned staging root"
    assert (
        "FINDEVIL_SIFT_CASE_STAGING_ROOT" in text
    ), "host-path SIFT staging should require a guest-visible project staging root"
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


def test_verdict_uses_case_local_artifact_layout() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert "CASE_ROOT" in text, "verdict should define one canonical case root"
    assert (
        'CASE_ROOT="tmp/auto-runs"' in text
    ), "case root should match engine output root"
    assert (
        "FINDEVIL_VERDICT_CASE_ROOT" not in text
    ), "verdict should not advertise an output root override the engine does not honor"
    assert "CASE_STAGING_DIR" in text, "verdict should define case-local staging"
    assert "CASE_SUMMARY_DIR" in text, "verdict should define case-local summaries"
    assert "CASE_LOG_DIR" in text, "verdict should define case-local logs"


def test_sift_staging_is_case_local_and_marker_guarded() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert "staging/sift" in text, "SIFT staging should live under the case directory"
    assert (
        ".verdict-stage-marker" in text
    ), "SIFT staging cleanup should require a marker"
    assert (
        "safe_sift_case_staging_parent" in text
    ), "SIFT host-path staging should validate the configured case staging parent"
    assert (
        "GEVDIR}/.verdict-staging" not in text
    ), "SIFT staging should not default to legacy GEVDIR staging"


def test_guest_mounted_evidence_bypasses_copy_staging() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert (
        "is_guest_mounted_evidence" in text
    ), "verdict should detect guest-mounted evidence"
    assert (
        "safe_guest_mounted_evidence_path" in text
    ), "guest-mounted evidence paths should reject traversal before bypassing staging"
    assert (
        "validate_guest_mounted_evidence" in text
    ), "guest-mounted evidence paths should be validated in the VM"
    assert (
        "/mnt/hgfs/" in text
    ), "VMware HGFS mounted evidence should bypass copy staging"
    assert (
        "treating it as an in-VM path" in text
    ), "existing direct guest path behavior should remain"
    assert (
        "/proc/self/mountinfo" in text
    ), "guest-mounted evidence should verify mount options before direct use"
    assert (
        "read-only" in text
    ), "guest-mounted evidence should require a read-only mount"
    assert (
        text.count("require_read_only_mount(path)") >= 2
    ), "guest-mounted evidence should require read-only mounts for nested entries"


def test_case_root_is_ignored() -> None:
    ignore = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")
    assert (
        "tmp/" in ignore or "tmp/auto-runs/" in ignore
    ), "case root must remain ignored"


def test_sift_cleanup_uses_remote_realpath_guards() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert (
        "prepare_sift_staging_parent" in text
    ), "verdict should validate the remote staging parent before mkdir/copy"
    assert (
        "mkdir -p -- ${qparent}" not in text
    ), "verdict should not create the SIFT staging parent before symlink/component validation"
    assert (
        "os.lstat(next_path)" in text
    ), "verdict should lstat existing remote staging parent components before creating children"
    assert (
        "create_sift_staging_root" in text
    ), "verdict should create a fresh owned staging root before copy"
    assert "realpath -e" in text, "verdict should validate physical remote paths"
    assert (
        "[ ! -L ${qparent} ]" in text
    ), "verdict should refuse a symlinked SIFT staging parent"
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


def test_sift_host_staging_is_bound_to_case_id() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert (
        "sift_case_id_from_staging_parent" in text
    ), "SIFT host-path staging should extract the case id from FINDEVIL_SIFT_CASE_STAGING_ROOT"
    assert (
        "host evidence copy requires --case-id" in text
    ), "SIFT host-path staging should require an explicit case id"
    assert (
        "does not match --case-id" in text
    ), "SIFT host-path staging should reject a staging root for a different case id"
    assert (
        "FIND_EVIL_GUEST_REPO" in text
    ), "SIFT host-path staging should be bound to the configured guest project root"


def test_sift_case_id_reserves_host_case_dir() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert (
        'if [[ "${SIFT}" == "1" ]]; then' in text
    ), "SIFT runs should reserve the host-side case directory before execution"
    assert (
        'create_owned_case_dir "${CASE_DIR}" "$(case_root_abs)"' in text
    ), "SIFT case reservation should use the same owned-case guard as local mode"


def test_sift_run_owned_staging_never_reuses_existing_copy() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert "should_stage" not in text, "run-owned SIFT staging should always copy fresh"
    assert (
        "evidence already staged in the VM" not in text
    ), "run-owned SIFT staging should not reuse stale or colliding staged evidence"


def test_verdict_skill_documents_sift_staging_cleanup_contract() -> None:
    text = VERDICT_SKILL.read_text(encoding="utf-8")
    assert (
        "current-run sift staging" in text.lower()
    ), "repo-local verdict skill should document automatic SIFT staging cleanup"
    assert (
        "--keep-sift-staging" in text
    ), "repo-local verdict skill should document the keep-staging escape hatch"
    assert (
        "legacy root-level staging" in text
    ), "repo-local verdict skill should distinguish automatic cleanup from legacy staging cleanup"
    assert (
        "n8n <fired" not in text
    ), "repo-local verdict skill should not overclaim n8n reachability as fired actions"
    assert (
        "reachable/recorded" in text
    ), "repo-local verdict skill should describe n8n as reachable/recorded, skipped, or unavailable"
    assert (
        "ARTIFACT=" in text
    ), "repo-local verdict skill SIFT example should use shell-safe artifact variables"
    assert (
        'CASE_ID="auto-$(python3' in text
    ), "repo-local verdict skill should generate shell-safe case ids in examples"
    assert (
        "bash scripts/verdict <evidence>" not in text
    ), "repo-local verdict skill local example should not use shell redirection-like placeholders"
    assert (
        'EVIDENCE="/path/to/evidence"' in text
    ), "repo-local verdict skill local example should use a shell-safe evidence variable"
    assert (
        "tmp/auto-runs/<case-id>/summaries/run-summary.json" in text
    ), "repo-local verdict skill should prefer case-local run summaries"
    assert (
        "Read `tmp/verdict-last-run.json` if it exists" not in text
    ), "repo-local verdict skill should not prefer potentially stale last-run summaries"


def test_plan_documents_case_local_summary_flow() -> None:
    text = VERDICT_PLAN.read_text(encoding="utf-8")
    sync = 'sync_case_summary "${SUMMARY}"'
    copy = 'copy_requested_run_summary "${SUMMARY}"'
    assert (
        'SUMMARY="${RUN_SUMMARY:-tmp/verdict-last-run.json}"' not in text
    ), "plan should not preserve stale default run-summary behavior"
    assert (
        'cp -f -- "${SUMMARY}"' not in text
    ), "plan should not document raw summary copies"
    assert (
        'SUMMARY="${CASE_SUMMARY_DIR}/engine-run-summary.json"' in text
    ), "plan should document case-local engine summary writes"
    assert sync in text, "plan should document case-local summary syncing"
    assert (
        copy in text
    ), "plan should document symlink-safe requested summary publishing"
    assert text.index(sync) < text.index(
        copy
    ), "plan should sync case summary before requested summary copy"


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


def test_sift_mounted_evidence_selftest() -> None:
    env = {**os.environ, "FINDEVIL_VERDICT_SELFTEST": "sift-mounted-evidence"}
    result = subprocess.run(
        ["bash", str(SCRIPT)], capture_output=True, text=True, timeout=10, env=env
    )
    assert (
        result.returncode == 0
    ), f"SIFT mounted evidence selftest failed: stdout={result.stdout!r} stderr={result.stderr!r}"
    assert (
        "sift mounted evidence selftest OK" in result.stdout
    ), f"SIFT mounted evidence selftest did not confirm success: {result.stdout!r}"


def test_sift_mounted_evidence_env_contract_present() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert (
        "FINDEVIL_SIFT_HOST_EVIDENCE_ROOT" in text
    ), "verdict should expose a host evidence root env for SIFT mount mapping"
    assert (
        "FINDEVIL_SIFT_GUEST_EVIDENCE_ROOT" in text
    ), "verdict should expose a guest evidence root env for SIFT mount mapping"
    assert (
        "map_sift_mounted_evidence" in text
    ), "verdict should map host evidence paths to read-only guest mount paths"


def test_sift_mapped_paths_verify_guest_and_skip_scp() -> None:
    # The SIFT host-path branch detects guest-mounted evidence and validates it
    # read-only in the VM *before* falling back to scp copy-staging. This replaced
    # the older map_sift_mounted_evidence/mounted_remote orchestration; the
    # in-VM validation detail is covered by
    # test_guest_mounted_evidence_bypasses_copy_staging.
    text = SCRIPT.read_text(encoding="utf-8")
    assert (
        'is_guest_mounted_evidence "${EVIDENCE}"' in text
    ), "verdict should detect guest-mounted evidence in the SIFT host-path branch"
    assert (
        'validate_guest_mounted_evidence "${EVIDENCE}"' in text
    ), "guest-mounted SIFT evidence must be validated in the VM before use"
    assert (
        "using read-only in-VM path without copy staging" in text
    ), "verdict should log when it uses mounted SIFT evidence without copying"
    assert text.index('is_guest_mounted_evidence "${EVIDENCE}"') < text.index(
        "into the VM temp"
    ), "verdict should try mounted evidence before scp copy-staging"


def test_sift_directory_identity_uses_file_manifest_not_directory_bytes() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    identity_fn = text.split("verify_sift_guest_evidence_identity() {", 1)[1].split(
        "\n}", 1
    )[0]
    local_helper = text.split("sift_local_evidence_identity() {", 1)[1].split("\n}", 1)[
        0
    ]
    remote_helper = text.split("sift_remote_evidence_identity() {", 1)[1].split(
        "\n}", 1
    )[0]
    assert (
        "sift_local_evidence_identity" in text
    ), "verdict should compute host identity through a dedicated file manifest helper"
    assert (
        "sift_remote_evidence_identity" in text
    ), "verdict should compute guest identity through the same file manifest semantics"
    assert (
        "du -sb" not in identity_fn
    ), "directory identity should not depend on filesystem-specific directory entry sizes"
    assert (
        "_evidence_size" not in identity_fn
    ), "directory identity should not reuse debounce-size totals for evidence comparison"
    for helper in (local_helper, remote_helper):
        assert (
            "du -sb" not in helper
        ), "manifest helpers should not use raw directory allocation size"
        assert "hash_file(" in helper, "manifest helpers should hash file contents"
        assert (
            "onerror=fail_walk" in helper
        ), "manifest helpers should fail on traversal errors"
        assert (
            "digest.update" in helper
        ), "manifest helpers should hash relative path/size entries"
        assert (
            "relative_to(path).as_posix()" in helper
        ), "manifest helpers should use relative paths, not absolute host or guest paths"
        assert "lstat()" in helper, "manifest helpers should avoid following symlinks"
        assert "S_ISLNK" in helper, "manifest helpers should reject symlinks"


def test_sift_fallback_staging_does_not_reuse_size_only_remote_files() -> None:
    # When evidence is on the host (not guest-mounted), it is copied into a fresh,
    # run-owned staging root and verified by content fingerprint — never reused by
    # byte-size alone. This replaced the older .verdict-staging /
    # host_identity_output size-compare fallback.
    text = SCRIPT.read_text(encoding="utf-8")
    assert (
        "run-owned SIFT staging root already exists" in text
    ), "SIFT staging must fail closed on an existing root, never reuse it"
    assert (
        "local_evidence_fingerprint" in text and "remote_evidence_fingerprint" in text
    ), "SIFT staging must verify by content fingerprint, not byte size"
    assert (
        'tfingerprint="$(remote_evidence_fingerprint' in text
    ), "staged guest evidence must be fingerprint-verified after the copy"
    assert (
        "promote_staged_directory" in text
    ), "SIFT staging should promote a verified temp copy into place atomically"
    assert (
        "evidence already staged" not in text
    ), "SIFT staging must not skip the copy based on an existing remote basename"


def test_sift_direct_guest_paths_are_verified() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    guest_branch = "treating it as an in-VM path"
    assert guest_branch in text, "verdict should keep direct in-VM path support"
    assert (
        'verify_sift_guest_evidence_readable "${EVIDENCE}" 1' in text
    ), "direct in-VM SIFT evidence paths should require read-only guest mount verification"
    assert (
        'sift_remote_evidence_identity "${EVIDENCE}" >/dev/null' in text
    ), "direct in-VM SIFT directories should run nested symlink/non-regular validation"
    assert text.index(
        'verify_sift_guest_evidence_readable "${EVIDENCE}" 1'
    ) < text.index(
        guest_branch
    ), "verdict should verify direct in-VM paths before continuing"
    assert text.index(
        'sift_remote_evidence_identity "${EVIDENCE}" >/dev/null'
    ) < text.index(
        guest_branch
    ), "verdict should validate direct in-VM tree contents before continuing"


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


def test_run_summary_rejects_evidence_contamination() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        evidence_dir = Path(tmp) / "evidence"
        evidence_dir.mkdir()
        evidence = evidence_dir / "sample.evtx"
        evidence.write_text("sample", encoding="utf-8")
        result = subprocess.run(
            [
                "bash",
                str(SCRIPT),
                str(evidence),
                "--run-summary",
                str(evidence_dir / "summary.json"),
                "--dry-run",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
    assert result.returncode != 0, "verdict should reject run summaries inside evidence"
    assert "--run-summary" in result.stderr, result.stderr
    assert "evidence" in result.stderr, result.stderr


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
        (
            "case_id_rejects_traversal_before_engine_args",
            test_case_id_rejects_traversal_before_engine_args,
        ),
        (
            "case_id_validation_happens_before_preflight_and_sift",
            test_case_id_validation_happens_before_preflight_and_sift,
        ),
        ("case_dir_resolution_selftest", test_case_dir_resolution_selftest),
        ("case_id_ownership_selftest", test_case_id_ownership_selftest),
        ("case_layout_ownership_selftest", test_case_layout_ownership_selftest),
        (
            "run_summary_rejects_outside_project_tmp_before_engine",
            test_run_summary_rejects_outside_project_tmp_before_engine,
        ),
        ("run_summary_requires_value", test_run_summary_requires_value),
        (
            "case_local_run_summary_path_does_not_precreate_case_dir",
            test_case_local_run_summary_path_does_not_precreate_case_dir,
        ),
        ("sift_staging_has_keep_opt_out", test_sift_staging_has_keep_opt_out),
        (
            "verdict_uses_case_local_artifact_layout",
            test_verdict_uses_case_local_artifact_layout,
        ),
        (
            "sift_staging_is_case_local_and_marker_guarded",
            test_sift_staging_is_case_local_and_marker_guarded,
        ),
        (
            "guest_mounted_evidence_bypasses_copy_staging",
            test_guest_mounted_evidence_bypasses_copy_staging,
        ),
        ("case_root_is_ignored", test_case_root_is_ignored),
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
            "sift_host_staging_is_bound_to_case_id",
            test_sift_host_staging_is_bound_to_case_id,
        ),
        (
            "sift_case_id_reserves_host_case_dir",
            test_sift_case_id_reserves_host_case_dir,
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
            "plan_documents_case_local_summary_flow",
            test_plan_documents_case_local_summary_flow,
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
        ("sift_mounted_evidence_selftest", test_sift_mounted_evidence_selftest),
        (
            "sift_mounted_evidence_env_contract_present",
            test_sift_mounted_evidence_env_contract_present,
        ),
        (
            "sift_mapped_paths_verify_guest_and_skip_scp",
            test_sift_mapped_paths_verify_guest_and_skip_scp,
        ),
        (
            "sift_directory_identity_uses_file_manifest_not_directory_bytes",
            test_sift_directory_identity_uses_file_manifest_not_directory_bytes,
        ),
        (
            "sift_fallback_staging_does_not_reuse_size_only_remote_files",
            test_sift_fallback_staging_does_not_reuse_size_only_remote_files,
        ),
        (
            "sift_direct_guest_paths_are_verified",
            test_sift_direct_guest_paths_are_verified,
        ),
        ("dry_run_produces_no_investigation", test_dry_run_produces_no_investigation),
        ("dry_run_with_skip_build", test_dry_run_with_skip_build),
        (
            "run_summary_rejects_evidence_contamination",
            test_run_summary_rejects_evidence_contamination,
        ),
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
