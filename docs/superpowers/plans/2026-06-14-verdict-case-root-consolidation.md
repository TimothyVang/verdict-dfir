# VERDICT Case Root Consolidation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Keep every VERDICT run artifact under one ignored project-local case directory while preserving read-only evidence handling and existing report paths.

**Architecture:** Preserve `tmp/auto-runs/<case-id>/` as the canonical project-local case directory because current summaries, reports, dashboard roots, and operator habits already depend on it. Add structured subdirectories under each case for run summaries, logs, staging, proof artifacts, and evidence references; direct mounted SIFT paths remain references and are never copied.

**Tech Stack:** Bash launcher (`scripts/verdict`), Python smoke tests (`scripts/verdict-smoke.py`), existing ignored `tmp/` workspace.

---

## Proposed Layout

```text
tmp/auto-runs/
  <case-id>/
    verdict.json
    manifest_verify.json
    REPORT.html
    REPORT.pdf
    audit.jsonl
    run.manifest.json
    coverage_manifest.json
    evidence/
      refs.json
    logs/
      n8n.log
      grounding.log
    summaries/
      run-summary.json
    artifacts/
      proof/
      derived/
    staging/
      local/
      sift/
        <stage-id>/
          .verdict-stage-marker
          input/
          logs/
```

## Rules

- Original evidence paths remain read-only and are never modified.
- Direct guest-mounted evidence such as `/mnt/hgfs/evidence/SCHARDT.dd` is referenced, not copied.
- Host paths that must be copied into SIFT are copied only into a run-owned staging directory.
- The existing customer-facing case outputs stay at the top of `tmp/auto-runs/<case-id>/` to avoid breaking current consumers.
- Legacy `/home/sansforensics/evidence` and mounted evidence roots are never deleted by cleanup code.

## Files

- Modify: `scripts/verdict`
- Modify: `scripts/verdict-smoke.py`
- Check: `.gitignore`
- Check: `.claude/skills/verdict/SKILL.md`
- Check: `QUICKSTART.md`

### Task 1: Add RED Smoke Coverage

**Files:**
- Modify: `scripts/verdict-smoke.py`

- [ ] **Step 1: Add smoke assertions for the new contract**

Add tests that require these strings before implementation:

```python
def test_verdict_uses_case_local_artifact_layout() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert "CASE_ROOT" in text, "verdict should define one canonical case root"
    assert 'CASE_ROOT="tmp/auto-runs"' in text, "case root should match engine output root"
    assert "FINDEVIL_VERDICT_CASE_ROOT" not in text, "do not add an output root override the engine does not honor"
    assert "CASE_STAGING_DIR" in text, "verdict should define case-local staging"
    assert "CASE_SUMMARY_DIR" in text, "verdict should define case-local summaries"
    assert "CASE_LOG_DIR" in text, "verdict should define case-local logs"


def test_sift_staging_is_case_local_and_marker_guarded() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert "staging/sift" in text, "SIFT staging should live under the case directory"
    assert ".verdict-stage-marker" in text, "SIFT staging cleanup should require a marker"
    assert "safe_sift_case_staging_parent" in text, "SIFT staging parent should be constrained"
    assert "GEVDIR}/.verdict-staging" not in text, "SIFT staging should not default to legacy GEVDIR staging"


def test_guest_mounted_evidence_bypasses_copy_staging() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert "is_guest_mounted_evidence" in text, "verdict should detect guest-mounted evidence"
    assert "safe_guest_mounted_evidence_path" in text, "guest-mounted evidence should reject traversal"
    assert "validate_guest_mounted_evidence" in text, "guest-mounted evidence should be remotely validated"
    assert "/mnt/hgfs/" in text, "VMware HGFS mounted evidence should bypass copy staging"
    assert "treating it as an in-VM path" in text, "existing direct guest path behavior should remain"


def test_case_root_is_ignored() -> None:
    ignore = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")
    assert "tmp/" in ignore or "tmp/auto-runs/" in ignore, "case root must remain ignored"
```

- [ ] **Step 2: Register the tests in `main()`**

Add these names to the existing `tests` list:

```python
("verdict_uses_case_local_artifact_layout", test_verdict_uses_case_local_artifact_layout),
("sift_staging_is_case_local_and_marker_guarded", test_sift_staging_is_case_local_and_marker_guarded),
("guest_mounted_evidence_bypasses_copy_staging", test_guest_mounted_evidence_bypasses_copy_staging),
("case_root_is_ignored", test_case_root_is_ignored),
```

- [ ] **Step 3: Run RED check**

Run:

```bash
python3 scripts/verdict-smoke.py
```

Expected: the new tests fail because the launcher has not introduced `CASE_ROOT`, `CASE_STAGING_DIR`, `CASE_SUMMARY_DIR`, `CASE_LOG_DIR`, marker-guarded case staging, or explicit mounted-evidence detection yet.

### Task 2: Add Case Layout Variables

**Files:**
- Modify: `scripts/verdict`

- [ ] **Step 1: Define canonical layout variables after argument parsing**

Add:

```bash
CASE_ROOT="tmp/auto-runs"
CASE_STAGING_DIR=""
CASE_SUMMARY_DIR=""
CASE_LOG_DIR=""
CASE_ARTIFACT_DIR=""
CASE_EVIDENCE_REF_DIR=""
```

- [ ] **Step 2: Add a helper to initialize case-local subdirectories**

Add:

```bash
initialize_case_layout() {
  local case_dir="$1"
  CASE_STAGING_DIR="${case_dir}/staging"
  CASE_SUMMARY_DIR="${case_dir}/summaries"
  CASE_LOG_DIR="${case_dir}/logs"
  CASE_ARTIFACT_DIR="${case_dir}/artifacts"
  CASE_EVIDENCE_REF_DIR="${case_dir}/evidence"
  mkdir -p \
    "${CASE_STAGING_DIR}/local" \
    "${CASE_STAGING_DIR}/sift" \
    "${CASE_SUMMARY_DIR}" \
    "${CASE_LOG_DIR}" \
    "${CASE_ARTIFACT_DIR}/proof" \
    "${CASE_ARTIFACT_DIR}/derived" \
    "${CASE_EVIDENCE_REF_DIR}"
}
```

- [ ] **Step 3: Keep top-level case outputs unchanged**

Replace local-mode hardcoded case creation:

```bash
CASE_DIR="${REPO_ROOT}/tmp/auto-runs/${CASE_ID}"
mkdir -p "${CASE_DIR}"
```

with:

```bash
CASE_DIR="${REPO_ROOT}/${CASE_ROOT}/${CASE_ID}"
mkdir -p "${CASE_DIR}"
initialize_case_layout "${CASE_DIR}"
```

- [ ] **Step 4: Run focused smoke**

Run:

```bash
python3 scripts/verdict-smoke.py
```

Expected: the case layout variable tests pass; SIFT marker/mount tests may still fail until later tasks.

### Task 3: Preserve Direct Guest-Mounted Evidence

**Files:**
- Modify: `scripts/verdict`

- [ ] **Step 1: Add guest-mounted path detection**

Add before SIFT staging logic:

```bash
is_guest_mounted_evidence() {
  local path="$1"
  case "${path}" in
    /mnt/hgfs/*|/media/hgfs/*|/mnt/verdict-evidence/*) return 0 ;;
    *) return 1 ;;
  esac
}

safe_guest_mounted_evidence_path() {
  local value="$1" normalized
  normalized="/${value#/}/"
  if [[ -z "${value}" || ! "${value}" =~ ^/[[:alnum:]_./+-]+$ || "${normalized}" == *"/../"* || "${normalized}" == *"/./"* ]]; then
    fail "--sift: unsafe guest-mounted evidence path: ${value}"
  fi
  case "${value}" in
    /mnt/hgfs/*|/media/hgfs/*|/mnt/verdict-evidence/*) printf '%s' "${value}" ;;
    *) fail "--sift: unsupported guest-mounted evidence root: ${value}" ;;
  esac
}
```

- [ ] **Step 2: Remotely validate mounted evidence before bypassing copy staging**

Validate the root over SSH before running the engine. The implemented launcher uses remote Python to reject traversal, symlinks, special files, entries resolving outside allowed mount roots, unreadable directory walks, and non-read-only mounts via `/proc/self/mountinfo`:

```bash
# Superseded by the current remote Python validator in scripts/verdict.
# Keep these requirements if this plan is replayed: lstat every entry,
# reject symlinks/special files, require realpaths under allowed mount roots,
# and require a read-only mount from /proc/self/mountinfo.
validate_guest_mounted_evidence() {
  local path qpath
  path="$(safe_guest_mounted_evidence_path "$1")"
  qpath="$(remote_quote "${path}")"
  "${SSHB[@]}" "${GADDR}" "set -e
if [ -L ${qpath} ]; then exit 1; fi
if [ ! -f ${qpath} ] && [ ! -d ${qpath} ]; then exit 1; fi
resolved=\$(realpath -e -- ${qpath})
case \"\${resolved}\" in
  /mnt/hgfs/*|/media/hgfs/*|/mnt/verdict-evidence/*) ;;
  *) exit 1 ;;
esac" 2>/dev/null || fail "--sift: unsafe guest-mounted evidence path: ${path}"
}
```

- [ ] **Step 3: Bypass local staging when evidence is already guest-mounted**

In SIFT staging, before checking local `-e` paths, add:

```bash
  if is_guest_mounted_evidence "${EVIDENCE}"; then
    validate_guest_mounted_evidence "${EVIDENCE}"
    ok "--sift: '${EVIDENCE}' is guest-mounted evidence — using read-only in-VM path without copy staging"
  elif [[ -e "${EVIDENCE}" || -L "${EVIDENCE}" ]]; then
    # existing host-path staging branch
```

Close the new `elif` branch around the existing staging code and keep the final `else` branch for non-host guest paths.

- [ ] **Step 4: Run focused smoke**

Run:

```bash
python3 scripts/verdict-smoke.py
```

Expected: mounted-evidence smoke passes.

### Task 4: Move SIFT Copy Staging Under Case Directory

**Files:**
- Modify: `scripts/verdict`

- [ ] **Step 1: Create a SIFT-local case staging path**

Use a validated case id and a marker-owned case directory. Do not reuse or `mkdir -p` a pinned case directory:

```bash
CASE_ID="${CASE_ID_OVERRIDE:-auto-$(python3 -c 'import uuid;print(uuid.uuid4())')}"
CASE_DIR="${REPO_ROOT}/${CASE_ROOT}/${CASE_ID}"
create_owned_case_dir "${CASE_DIR}" "$(case_root_abs)"
initialize_case_layout "${CASE_DIR}"
```

- [ ] **Step 2: Change SIFT staging root from guest evidence root to case staging**

Replace:

```bash
SIFT_STAGING_PARENT="${GEVDIR}/.verdict-staging"
SIFT_STAGING_ROOT="${GEVDIR}/.verdict-staging/${SIFT_STAGE_ID}"
```

with a guest-visible staging root only when the project case directory is available in the SIFT VM. If it is not available, fail clearly instead of copying into legacy evidence:

```bash
SIFT_STAGING_PARENT="${FINDEVIL_SIFT_CASE_STAGING_ROOT:-}"
[[ -n "${SIFT_STAGING_PARENT}" ]] || fail "--sift: host evidence copy needs FINDEVIL_SIFT_CASE_STAGING_ROOT pointing at the case staging directory inside the VM; mounted paths under /mnt/hgfs do not need copy staging"
SIFT_STAGING_PARENT="$(safe_sift_case_staging_parent "${SIFT_STAGING_PARENT}")"
[[ -n "${CASE_ID_OVERRIDE:-}" ]] || fail "--sift: host evidence copy requires --case-id matching FINDEVIL_SIFT_CASE_STAGING_ROOT"
[[ "$(sift_case_id_from_staging_parent "${SIFT_STAGING_PARENT}")" == "${CASE_ID_OVERRIDE}" ]] || fail "--sift: FINDEVIL_SIFT_CASE_STAGING_ROOT case does not match --case-id"
SIFT_STAGING_ROOT="${SIFT_STAGING_PARENT}/${SIFT_STAGE_ID}"
```

- [ ] **Step 3: Add marker creation after staging root creation**

After `mkdir -- ${qroot}`, create the marker:

```bash
: > "${CASE_STAGING_DIR}/sift/${SIFT_STAGE_ID}/.verdict-stage-marker"
```

For guest-side cleanup, also create a marker in the guest staging directory:

```bash
touch -- ${qroot}/.verdict-stage-marker
```

- [ ] **Step 4: Guard cleanup with marker checks**

Before `rm -rf -- ${qroot}`, require:

```bash
[ -f ${qroot}/.verdict-stage-marker ]
```

- [ ] **Step 5: Run focused smoke**

Run:

```bash
python3 scripts/verdict-smoke.py
```

Expected: SIFT staging location and marker tests pass.

### Task 5: Move Sidecar Logs and Summary Pointers Into Case Layout

**Files:**
- Modify: `scripts/verdict`

- [ ] **Step 1: Write engine summaries case-local first, then publish explicit `--run-summary` copies**

Use the case-local engine summary path once the launcher has reserved and initialized a case directory:

```bash
SUMMARY="${CASE_SUMMARY_DIR}/engine-run-summary.json"
```

After the engine succeeds, keep the normalized case-local pointer and publish an explicit requested summary only through the symlink-safe helper:

```bash
sync_case_summary "${SUMMARY}"
copy_requested_run_summary "${SUMMARY}"
```

`prepare_requested_run_summary_path` validates requested paths under project `tmp/` without pre-creating future case dirs during argument parsing; `copy_requested_run_summary` creates parents only after the owned case dir exists.

- [ ] **Step 2: Move n8n and grounding logs into case logs when available**

Replace fixed `/tmp` logs with case logs after `CASE_DIR` is resolved:

```bash
N8N_LOG="${CASE_LOG_DIR:-/tmp}/verdict-n8n.log"
GROUNDING_LOG="${CASE_LOG_DIR:-/tmp}/verdict-grounding.log"
```

- [ ] **Step 3: Run focused smoke**

Run:

```bash
python3 scripts/verdict-smoke.py
```

Expected: smoke passes.

### Task 6: Documentation and Verification

**Files:**
- Modify if needed: `.claude/skills/verdict/SKILL.md`
- Modify if needed: `QUICKSTART.md`

- [ ] **Step 1: Document the case-local layout**

Document that canonical outputs remain in:

```text
tmp/auto-runs/<case-id>/
```

and generated sidecars are grouped under:

```text
tmp/auto-runs/<case-id>/{summaries,logs,staging,artifacts,evidence}/
```

- [ ] **Step 2: Run focused checks**

Run:

```bash
bash -n scripts/verdict
python3 scripts/verdict-smoke.py
ruff check scripts/verdict-smoke.py
ruff format --check scripts/verdict-smoke.py
git diff --check
```

Expected: all pass.

- [ ] **Step 3: Run broader smoke if time permits**

Run:

```bash
bash scripts/run-all-smokes.sh
```

Expected: existing unrelated doc/fixture failures may remain; `verdict-smoke` must pass.

## Risks

- SIFT copy-staging under a project-local case directory requires a guest-visible path. Direct mounted evidence already avoids this problem and should remain the preferred disk-image path.
- Generating a SIFT case id before running the engine may diverge from the engine's own case id unless the engine supports an explicit case id in SIFT mode. If it does not, keep SIFT copy-staging under a pre-run `tmp/auto-runs/preflight-<run-id>/staging/sift/` and sync final outputs afterward.
- Cleanup must never remove original evidence, mounted evidence, `/home/sansforensics/evidence`, or directories without `.verdict-stage-marker`.
- Existing dashboard/report consumers expect top-level case files under `tmp/auto-runs/<case-id>/`; do not move those files.

## Approval Gate

Decision captured during implementation: SIFT host-path copy staging fails closed unless `FINDEVIL_SIFT_CASE_STAGING_ROOT` is configured and bound to the explicit `--case-id`. Legacy `/home/sansforensics/evidence/.verdict-staging` is not a fallback for non-mounted host paths.
