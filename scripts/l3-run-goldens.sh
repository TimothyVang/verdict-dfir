#!/usr/bin/env bash
# l3-run-goldens.sh — boot the Packer-built warm qcow2 and run the
# Product against canonical fixtures, asserting expected findings.
#
# Spec #3 §4.4. Intended for both local verification and the
# .github/workflows/l3-nightly.yml runner.
#
# Prerequisites:
#   1. packer/artifacts/sift-microvm-warm.qcow2.zst exists (built by
#      `packer build packer/sift-microvm.pkr.hcl` — Spec #3 Task 7).
#   2. `qemu-system-x86_64` on PATH and KVM accessible (/dev/kvm).
#   3. Fixtures downloaded via `scripts/fetch-fixtures.sh` — Task 10.
#   4. Built Product binary or install script available at
#      release/ (or will be pulled via scp from a tag release in CI).
#
# Output: logs/l3/run-<timestamp>.log + logs/l3/verdict.json per
# fixture. Compared to goldens/<fixture>/expected-findings.json and
# diffs are exit-code-fatal.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

WARM_ZST="${WARM_ZST:-packer/artifacts/sift-microvm-warm.qcow2.zst}"
WARM_QCOW="${WARM_QCOW:-/tmp/sift-microvm-warm.qcow2}"
LOG_DIR="${LOG_DIR:-logs/l3}"
SSH_PORT="${SSH_PORT:-2222}"
SSH_USER="${SSH_USER:-sansforensics}"
SSH_PASS="${SSH_PASS:-forensics}"

# Ordered list of fixtures to run. Missing and explicitly NOT_READY fixtures
# are skipped with a reason before anything is copied into the VM.
FIXTURES=(
  "nist-hacking-case"
  "sans-starter"
  "synthetic-benign"
  "synthetic-decoy"
  "nitroba"
  "nist-data-leakage"
  "m57-jean"
  "dfrws-2008-linux"
  "alihadi-01-webserver"
  "alihadi-07-sysinternals"
  "alihadi-09-encrypt"
  "dfrws-2011-android"
  "volatility-cridex"
  "otrf-apt3-mordor"
  "memlabs-lab1"
  "memlabs-lab2"
  "memlabs-lab3"
  "digitalcorpora-lonewolf"
)

mkdir -p "${LOG_DIR}"

log() { printf '[l3-goldens] %s\n' "$*" >&2; }

require() {
  command -v "$1" >/dev/null 2>&1 || { log "ERROR: $1 not on PATH"; exit 2; }
}

require qemu-system-x86_64
require zstd
require ssh
require scp
require sshpass
require jq

# ---------------------------------------------------------------------
# 1. Decompress warm qcow2.
# ---------------------------------------------------------------------
if [[ ! -f "${WARM_QCOW}" ]]; then
  if [[ ! -f "${WARM_ZST}" ]]; then
    log "ERROR: ${WARM_ZST} missing; run 'packer build packer/sift-microvm.pkr.hcl' first"
    exit 2
  fi
  log "decompressing ${WARM_ZST} → ${WARM_QCOW}"
  zstd -d --force --output-dir-flat "$(dirname "${WARM_QCOW}")" \
    -o "${WARM_QCOW}" "${WARM_ZST}"
fi

# ---------------------------------------------------------------------
# 2. Boot VM (load the 'warm' snapshot).
# ---------------------------------------------------------------------
log "booting SIFT microvm with -loadvm warm..."
QEMU_PIDFILE="/tmp/l3-qemu.pid"
qemu-system-x86_64 \
  -machine q35,accel=kvm \
  -cpu host \
  -smp "${CPUS:-4}" \
  -m "${MEMORY_MB:-8192}" \
  -drive "file=${WARM_QCOW},if=virtio,format=qcow2" \
  -netdev "user,id=net0,hostfwd=tcp::${SSH_PORT}-:22" \
  -device virtio-net,netdev=net0 \
  -loadvm warm \
  -nographic -serial null \
  -pidfile "${QEMU_PIDFILE}" \
  -daemonize

trap 'if [[ -f "${QEMU_PIDFILE}" ]]; then kill "$(cat "${QEMU_PIDFILE}")" 2>/dev/null || true; fi' EXIT

# Wait for SSH. Snapshot-restore should land in 3-8s; allow 30s
# generous margin.
log "waiting for SSH on localhost:${SSH_PORT}..."
for i in $(seq 1 30); do
  if nc -z localhost "${SSH_PORT}" 2>/dev/null; then
    log "SSH up at attempt ${i}"
    break
  fi
  sleep 1
  if [[ $i -eq 30 ]]; then
    log "ERROR: SSH did not come up in 30s"
    exit 2
  fi
done

SSH_OPTS=(
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o ConnectTimeout=10
  -p "${SSH_PORT}"
)

ssh_exec() {
  sshpass -p "${SSH_PASS}" ssh "${SSH_OPTS[@]}" \
    "${SSH_USER}@localhost" "$@"
}

scp_to() {
  sshpass -p "${SSH_PASS}" scp -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null -P "${SSH_PORT}" -r "$@" \
    "${SSH_USER}@localhost:"
}

# ---------------------------------------------------------------------
# 3. Push Product + install.
# ---------------------------------------------------------------------
log "pushing release/ (if present)..."
if [[ -d release ]]; then
  scp_to release/
  ssh_exec "cd release && bash install.sh --mock-run || true"
else
  log "WARN: no release/ dir; skipping Product install (expected until Week 2)"
fi

# ---------------------------------------------------------------------
# 4. Run each fixture, capture verdict, diff against golden.
# ---------------------------------------------------------------------
OVERALL_EXIT=0
for fixture in "${FIXTURES[@]}"; do
  log "--- fixture: ${fixture} ---"
  # Benchmark data is required to live under fixtures/, paired 1:1 with its
  # golden under goldens/. The runner only ever reads fixtures/<case> — a dataset
  # dropped in evidence/ is invisible here by design (evidence/ is the ad-hoc
  # drop zone, not the scored corpus).
  golden_dir="goldens/${fixture}"
  fixture_dir="fixtures/${fixture}"
  if [[ ! -d "${golden_dir}" ]] || [[ ! -d "${fixture_dir}" ]]; then
    log "SKIP ${fixture}: missing ${golden_dir} or ${fixture_dir}"
    continue
  fi
  expected="${golden_dir}/expected-findings.json"
  if [[ ! -f "${expected}" ]]; then
    log "SKIP ${fixture}: missing ${expected}"
    continue
  fi
  if readiness_json="$(
    python3 scripts/fixture-readiness.py --json "${expected}" "${fixture_dir}"
  )"; then
    readiness_status="READY"
  else
    readiness_exit=$?
    readiness_status="$(
      jq -r '.status // empty' <<<"${readiness_json}" 2>/dev/null || true
    )"
    readiness_reason="$(
      jq -r '.reason // "fixture readiness check failed"' <<<"${readiness_json}" \
        2>/dev/null || printf '%s' "${readiness_json}"
    )"
    if [[ "${readiness_exit}" -eq 3 ]] && [[ "${readiness_status}" == "NOT_READY" ]]; then
      log "SKIP ${fixture}: NOT_READY ${readiness_reason}"
      continue
    fi
    log "FAIL ${fixture}: fixture readiness ERROR ${readiness_reason}"
    OVERALL_EXIT=1
    continue
  fi
  staging_root="$(jq -er '.staging_root' <<<"${readiness_json}")"
  analysis_entrypoint="$(
    jq -er '.analysis_entrypoint_relative' <<<"${readiness_json}"
  )"
  log "READY ${fixture}: $(jq -r '.reason' <<<"${readiness_json}")"

  # Copy only the contract-selected canonical staging root. In particular, this
  # keeps DFRWS competitor submissions and repository metadata out of the case.
  scp_to "${staging_root}"
  log "running Product against ${fixture}..."
  # scp_to copies into the remote user's HOME, which is ssh_exec's working dir.
  remote_staging_root="${staging_root##*/}"
  case_path="${remote_staging_root}/${analysis_entrypoint}"
  if [[ "${analysis_entrypoint}" == "." ]]; then
    case_path="${remote_staging_root}"
  fi
  printf -v case_path_q '%q' "${case_path}"
  run_log="${LOG_DIR}/${fixture}-run.log"

  # `scripts/find-evil-auto` is the internal headless engine that the
  # user-facing `scripts/verdict` command calls; L3 invokes the engine
  # wrapper directly. (The pre-A2 `find-evil run` subcommand was dropped
  # along with findevil_agent/cli.py.) Guarded by `|| true` so the L3
  # workflow stays exercised even when the SIFT VM doesn't have the
  # orchestrator deployed yet.
  ssh_exec "bash scripts/find-evil-auto ${case_path_q} --unattended 2>/dev/null" \
    > "${run_log}" \
    || {
      log "WARN: find-evil-auto not callable on VM yet (expected pre-Week-2)"
      continue
    }

  verdict_json="${LOG_DIR}/${fixture}-verdict.json"
  jq '.' "${run_log}" > "${verdict_json}" 2>/dev/null \
    || cp "${run_log}" "${verdict_json}"

  # Score against golden expected-findings via the recall scorer. Real run
  # findings never byte-match a hand-authored golden, so we score recall
  # (MITRE + description token overlap) and honest verdict consistency
  # instead of an exact diff. score-recall.py reads <case_dir>/verdict.json,
  # so stage the captured verdict under a per-fixture case dir.
  run_case_dir="${LOG_DIR}/${fixture}-case"
  mkdir -p "${run_case_dir}"
  cp "${verdict_json}" "${run_case_dir}/verdict.json"
  log "scoring recall vs ${expected}"
  # score-recall.py exits 0 PASS / 1 FAIL / 2 ERROR / 3 EXCLUDED-by-key. Mapping
  # every non-zero to FAIL is what made `synthetic-benign` — whose key carries
  # scoring_status=not_ready — read as an accuracy failure with no metrics, and
  # pointed the operator at a recall-score.json that path never writes. Same
  # 3=NOT_READY / 2=ERROR split the fixture-readiness gate above already uses.
  # `set -e` is on: a bare non-zero would abort the whole sweep, so capture the
  # code instead of letting it kill the loop.
  score_exit=0
  python3 scripts/score-recall.py "${run_case_dir}" --golden "${golden_dir}" || score_exit=$?
  if [[ "${score_exit}" -eq 0 ]]; then
    log "PASS ${fixture}: recall >= target and verdict consistent"
  elif [[ "${score_exit}" -eq 3 ]]; then
    # The KEY declared itself unscoreable. Not a pass, not a failure — excluded.
    # OVERALL_EXIT is deliberately untouched: no accuracy claim, for or against
    # the engine, can be made from a golden that asked not to be scored.
    score_excluded_reason="$(
      jq -r '.reason // "golden declares scoring_status=not_ready"' \
        "${run_case_dir}/recall-excluded.json" 2>/dev/null \
        || printf 'golden declares scoring_status=not_ready'
    )"
    log "EXCLUDED ${fixture}: not scoreable by its own key — ${score_excluded_reason}"
  elif [[ "${score_exit}" -eq 1 ]]; then
    log "FAIL ${fixture}: recall below target or verdict mismatch (see ${run_case_dir}/recall-score.json)"
    OVERALL_EXIT=1
  else
    log "FAIL ${fixture}: scorer ERROR (exit ${score_exit}) — no score was produced"
    OVERALL_EXIT=1
  fi
done

# ---------------------------------------------------------------------
# 5. Shutdown VM cleanly via QEMU system_powerdown.
# ---------------------------------------------------------------------
log "shutting down VM..."
ssh_exec "echo ${SSH_PASS} | sudo -S shutdown -h now" || true
sleep 3
kill "$(cat "${QEMU_PIDFILE}")" 2>/dev/null || true
rm -f "${QEMU_PIDFILE}"

if [[ ${OVERALL_EXIT} -eq 0 ]]; then
  log "all goldens matched (or skipped pre-Week-2)."
else
  log "at least one fixture diverged from its golden."
fi
exit ${OVERALL_EXIT}
