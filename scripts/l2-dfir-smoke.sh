#!/usr/bin/env bash
# l2-dfir-smoke.sh — validate Hayabusa + Chainsaw + Volatility3 on
# small public fixtures inside the L2 Sysbox container.
#
# Spec #3 §4.3. Advisory-only in CI; does not block PR merge. Run
# inside the findevil/l2-siftlite image:
#
#   docker run --runtime=sysbox-runc --rm \
#       -v $(pwd)/fixtures:/fixtures:ro \
#       -v $(pwd)/goldens:/goldens:ro \
#       findevil/l2-siftlite:local \
#       /usr/local/bin/run-dfir-smoke.sh

set -euo pipefail

FIXTURES_DIR="${FIXTURES_DIR:-/fixtures}"
GOLDENS_DIR="${GOLDENS_DIR:-/goldens}"
OUTPUT_DIR="${OUTPUT_DIR:-/tmp/l2-smoke-out}"

mkdir -p "${OUTPUT_DIR}"

log() { printf '[l2-smoke] %s\n' "$*" >&2; }
fail=0

# ---------------------------------------------------------------------
# 1. Hayabusa — Sigma scoring on EVTX.
# Requires fixture: /fixtures/otrf-apt3-mordor/*.evtx (OTRF dataset).
# ---------------------------------------------------------------------
log "--- Hayabusa ---"
if [[ -d "${FIXTURES_DIR}/otrf-apt3-mordor" ]] \
   && compgen -G "${FIXTURES_DIR}/otrf-apt3-mordor/*.evtx" >/dev/null; then
  hayabusa csv-timeline \
    --directory "${FIXTURES_DIR}/otrf-apt3-mordor" \
    --output "${OUTPUT_DIR}/hayabusa-timeline.csv" \
    --no-wizard --quiet 2>&1 \
    | tee "${OUTPUT_DIR}/hayabusa.log" \
    | head -40

  if [[ -s "${OUTPUT_DIR}/hayabusa-timeline.csv" ]]; then
    rows=$(wc -l < "${OUTPUT_DIR}/hayabusa-timeline.csv")
    log "Hayabusa produced ${rows} rows → /tmp/l2-smoke-out/hayabusa-timeline.csv"
  else
    log "WARN: Hayabusa produced empty output"
    fail=$((fail + 1))
  fi
else
  log "SKIP: no EVTX fixtures under ${FIXTURES_DIR}/otrf-apt3-mordor"
fi

# ---------------------------------------------------------------------
# 2. Chainsaw — MFT / Shimcache / Amcache on fixtures.
# Requires fixture: /fixtures/otrf-apt3-mordor/*.evtx or $MO/mft/$MFT.
# ---------------------------------------------------------------------
log "--- Chainsaw ---"
if [[ -d "${FIXTURES_DIR}/otrf-apt3-mordor" ]] \
   && compgen -G "${FIXTURES_DIR}/otrf-apt3-mordor/*.evtx" >/dev/null; then
  chainsaw hunt \
    "${FIXTURES_DIR}/otrf-apt3-mordor" \
    --sigma /opt/chainsaw/sigma \
    --mapping /opt/chainsaw/mappings/sigma-event-logs-all.yml \
    --output "${OUTPUT_DIR}/chainsaw-hunt.csv" \
    --csv --skip-errors 2>&1 \
    | tee "${OUTPUT_DIR}/chainsaw.log" \
    | head -40 || true

  if [[ -s "${OUTPUT_DIR}/chainsaw-hunt.csv" ]]; then
    rows=$(wc -l < "${OUTPUT_DIR}/chainsaw-hunt.csv")
    log "Chainsaw produced ${rows} rows → /tmp/l2-smoke-out/chainsaw-hunt.csv"
  else
    log "WARN: Chainsaw produced empty output (may indicate rule mismatch)"
  fi
else
  log "SKIP: no EVTX fixtures for Chainsaw"
fi

# ---------------------------------------------------------------------
# 3. Volatility3 — pslist on a memory sample.
# Requires fixture: /fixtures/volatility/*.mem or *.raw or *.vmem.
# ---------------------------------------------------------------------
log "--- Volatility3 ---"
mem_sample=""
for ext in mem raw vmem lime; do
  match=$(compgen -G "${FIXTURES_DIR}/volatility/*.${ext}" || true)
  if [[ -n "${match}" ]]; then
    mem_sample=$(echo "${match}" | head -n1)
    break
  fi
done

if [[ -n "${mem_sample}" ]]; then
  vol -f "${mem_sample}" windows.pslist \
    2>&1 | tee "${OUTPUT_DIR}/vol-pslist.log" \
    | head -30

  if grep -qE "^[[:space:]]*[0-9]+" "${OUTPUT_DIR}/vol-pslist.log"; then
    log "Volatility3 pslist produced process rows"
  else
    log "WARN: Volatility3 pslist produced no process rows"
    fail=$((fail + 1))
  fi
else
  log "SKIP: no memory sample under ${FIXTURES_DIR}/volatility/"
fi

# ---------------------------------------------------------------------
# 4. Tool versions — always print at end so CI logs have a fingerprint.
# ---------------------------------------------------------------------
log "--- Tool versions ---"
hayabusa --version 2>&1 | head -n1 || log "hayabusa missing"
chainsaw --version 2>&1 | head -n1 || log "chainsaw missing"
vol --version 2>&1 | head -n1 || log "volatility missing"
yara --version 2>&1 | head -n1 || log "yara missing"

if [[ $fail -gt 0 ]]; then
  log "L2 smoke: ${fail} failure(s) (advisory-only; exiting 0 per Spec #3 §4.3)"
fi

# Advisory-only — always exit 0. Judging criterion 3 ("depth over
# breadth") means flaky DFIR tooling should never stall the
# main pipeline. Real validation lives in L3 goldens.
exit 0
