#!/usr/bin/env bash
# readiness-gate.sh - strict final-submission gate.
#
# Unlike build-local.sh, this script is allowed to fail on external blockers.
# It never creates placeholder artifacts; missing/stubbed/skipped inputs are
# reported as READINESS_BLOCKED.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

failed=0

log() { printf '[readiness-gate] %s\n' "$*" >&2; }
fail() { log "BLOCKER: $*"; failed=$((failed + 1)); }

run_check() {
  local label="$1"
  shift
  log "checking: ${label}"
  if "$@"; then
    log "PASS: ${label}"
  else
    fail "${label}"
  fi
}

if command -v python3 >/dev/null 2>&1; then
  PYTHON_BIN=python3
elif command -v python >/dev/null 2>&1; then
  PYTHON_BIN=python
else
  fail "python3/python not found"
  PYTHON_BIN=python
fi

build_status_cmd=("${PYTHON_BIN}" scripts/build-checker.py)
if [[ -n "${BUILD_RUN_ID:-}" ]]; then
  build_status_cmd+=(--run "${BUILD_RUN_ID}")
fi
run_check "full local build has passed" "${build_status_cmd[@]}"

run_check "submission assets are non-placeholder" \
  "${PYTHON_BIN}" scripts/validate-submission-assets.py \
    --demo-url "${DEMO_VIDEO_URL:-}" \
    --benchmark benchmark-results.csv \
    --report release-assets/report.html \
    --zip find-evil-submission.zip

if [[ -n "${EVIDENCE_RUN_DIR:-}" ]]; then
  if [[ "${EVIDENCE_RUN_DIR}" == *smoke* ]]; then
    fail "EVIDENCE_RUN_DIR looks like a smoke run: ${EVIDENCE_RUN_DIR}"
  elif [[ -f "${EVIDENCE_RUN_DIR}/run.manifest.json" && -f "${EVIDENCE_RUN_DIR}/audit.jsonl" && -f "${EVIDENCE_RUN_DIR}/verdict.json" ]]; then
    if grep -q '"kind":"report_qa"' "${EVIDENCE_RUN_DIR}/audit.jsonl" || grep -q '"kind": "report_qa"' "${EVIDENCE_RUN_DIR}/audit.jsonl"; then
      log "PASS: explicit evidence run artifact set present (${EVIDENCE_RUN_DIR})"
    else
      fail "EVIDENCE_RUN_DIR audit log lacks report_qa records: ${EVIDENCE_RUN_DIR}"
    fi
  else
    fail "EVIDENCE_RUN_DIR must contain run.manifest.json, audit.jsonl, and verdict.json: ${EVIDENCE_RUN_DIR}"
  fi
else
  fail "EVIDENCE_RUN_DIR missing; set it to a completed real scripts/find-evil-auto run directory"
fi

if [[ "${RUN_L1_DOCKER:-0}" == "1" ]]; then
  run_check "L1 Docker compose exits zero" docker compose -f docker/l1-compose.yml up --build --exit-code-from l1
elif [[ "${L1_DOCKER_STATUS:-}" == "passed" ]]; then
  if [[ -n "${L1_DOCKER_LOG:-}" && -f "${L1_DOCKER_LOG}" ]]; then
    if grep -q 'READINESS_L1_PASS' "${L1_DOCKER_LOG}"; then
      log "PASS: L1 Docker evidence marker present (${L1_DOCKER_LOG})"
    else
      fail "L1_DOCKER_LOG must contain exact marker READINESS_L1_PASS: ${L1_DOCKER_LOG}"
    fi
  else
    fail "L1_DOCKER_STATUS=passed requires L1_DOCKER_LOG pointing to evidence"
  fi
else
  fail "L1 Docker evidence missing; run with RUN_L1_DOCKER=1 or set L1_DOCKER_STATUS=passed plus L1_DOCKER_LOG containing READINESS_L1_PASS"
fi

if [[ "${failed}" -eq 0 ]]; then
  log "SUBMISSION_READY"
  exit 0
fi

log "READINESS_BLOCKED (${failed} blocker(s))"
exit 1
