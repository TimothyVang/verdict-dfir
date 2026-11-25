#!/usr/bin/env bash
# package-devpost.sh — assemble the Devpost submission zip.
#
# Glue Spec #4 §9. Runs inside .github/workflows/devpost-submit.yml
# after release.yml is green. Expects:
#
#   - DEMO_VIDEO_URL env var set (checked)
#   - RELEASE_TAG env var (defaults to 'v-submit')
#   - RELEASE_ASSETS_DIR env var (defaults to release-assets/) containing report.html and optional legacy .deb (from
#     `gh release download`)
#   - BENCHMARK_CSV env var (defaults to benchmark-results.csv at cwd, produced by json-to-benchmark-csv.py)
#   - optional READINESS_PACKET_ZIP env var (defaults to release-assets/readiness-packet.zip)
#     containing the validated expert-review packet from scripts/readiness-gate.ps1
#   - LICENSE from the repo; README-submission.md is generated from current
#     release metadata so deleted historical templates cannot break packaging.
#
# Strict mode is the default. Set FINDEVIL_DEVPOST_MODE=smoke only for
# non-final workflow rehearsal; smoke mode is rejected for RELEASE_TAG=v-submit.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

OUT_ZIP="${OUT_ZIP:-find-evil-submission.zip}"
RELEASE_ASSETS_DIR="${RELEASE_ASSETS_DIR:-release-assets}"
BENCHMARK_CSV="${BENCHMARK_CSV:-benchmark-results.csv}"
READINESS_PACKET_ZIP="${READINESS_PACKET_ZIP:-${RELEASE_ASSETS_DIR}/readiness-packet.zip}"
STAGE_DIR="$(mktemp -d)"
trap 'rm -rf "${STAGE_DIR}"' EXIT

log() { printf '[package-devpost] %s\n' "$*" >&2; }

if command -v python3 >/dev/null 2>&1; then
  PYTHON_BIN=python3
elif command -v python >/dev/null 2>&1; then
  PYTHON_BIN=python
else
  log "ERROR: python3/python not found on PATH"
  exit 127
fi

# ---------------------------------------------------------------------
# Pre-flight.
# ---------------------------------------------------------------------
RELEASE_TAG="${RELEASE_TAG:-v-submit}"
DATE="${DATE:-$(date -u +%Y-%m-%d)}"
FINDEVIL_DEVPOST_MODE="${FINDEVIL_DEVPOST_MODE:-strict}"
case "${FINDEVIL_DEVPOST_MODE}" in
  strict|smoke) ;;
  *) log "ERROR: FINDEVIL_DEVPOST_MODE must be strict or smoke"; exit 1 ;;
esac
if [[ "${RELEASE_TAG}" == "v-submit" && "${FINDEVIL_DEVPOST_MODE}" != "strict" ]]; then
  log "ERROR: smoke mode is forbidden for RELEASE_TAG=v-submit"
  exit 1
fi
if [[ "${FINDEVIL_DEVPOST_MODE}" == "strict" ]]; then
  : "${DEMO_VIDEO_URL:?DEMO_VIDEO_URL not set — run: gh variable set DEMO_VIDEO_URL --body '<url>'}"
else
  DEMO_VIDEO_URL="${DEMO_VIDEO_URL:-https://example.invalid/findevil-smoke-demo}"
  log "WARN: smoke mode enabled; generated package is NOT submission-ready"
fi

ACCURACY="${ACCURACY:-}"
if [[ -z "${ACCURACY}" || "${ACCURACY}" == "0" ]] && [[ -f "${BENCHMARK_CSV}" ]]; then
  derived_accuracy="$("${PYTHON_BIN}" - "${BENCHMARK_CSV}" <<'PY'
import csv
import sys

path = sys.argv[1]
try:
    with open(path, newline="", encoding="utf-8-sig") as fh:
        rows = list(csv.DictReader(fh))
except OSError:
    rows = []

for row in rows:
    if row.get("fixture") != "nist-hacking-case":
        continue
    try:
        matched = int(str(row.get("findings_matched", "")).strip())
        expected = int(str(row.get("findings_expected", "")).strip())
    except ValueError:
        continue
    if matched > 0 and expected >= matched:
        print(round((matched / expected) * 100))
        break
PY
)"
  if [[ -n "${derived_accuracy}" ]]; then
    ACCURACY="${derived_accuracy}"
    log "derived ACCURACY=${ACCURACY} from ${BENCHMARK_CSV}"
  fi
fi
ACCURACY="${ACCURACY:-0}"

# ---------------------------------------------------------------------
# 1. README-submission.md from current release metadata.
# ---------------------------------------------------------------------
cat > "${STAGE_DIR}/README-submission.md" <<EOF
# VERDICT DFIR Submission

- Release tag: ${RELEASE_TAG}
- Demo video: ${DEMO_VIDEO_URL}
- Reported recall score: ${ACCURACY}%
- Package date (UTC): ${DATE}

VERDICT is a read-only DFIR agent that opens a Case, drives typed forensic MCP
tools, verifies Findings, and emits a signed Verdict plus report. The public
repository README is the canonical product overview; this file records the
release metadata bundled with the Devpost package.

Contents:

- \`report.html\` - sample/customer-facing report artifact
- \`benchmark-results.csv\` - reproducible scoring export when available
- \`demo-video-link.txt\` - demo video URL
- \`readiness-packet.zip\` - optional expert-review packet when available
- \`LICENSE\` - Apache-2.0 license
EOF

# Sanity: no unsubstituted placeholders.
if grep -qE '\$\{[A-Z_]+\}' "${STAGE_DIR}/README-submission.md"; then
  log "ERROR: unsubstituted \${...} in README-submission.md"
  grep -nE '\$\{[A-Z_]+\}' "${STAGE_DIR}/README-submission.md" | head -5
  exit 1
fi

# ---------------------------------------------------------------------
# 2. demo-video-link.txt — plaintext URL.
# ---------------------------------------------------------------------
echo "${DEMO_VIDEO_URL}" > "${STAGE_DIR}/demo-video-link.txt"

# ---------------------------------------------------------------------
# 3. LICENSE — canonical Apache-2.0.
# ---------------------------------------------------------------------
if [[ ! -f LICENSE ]]; then
  log "ERROR: LICENSE missing at repo root"; exit 1
fi
cp LICENSE "${STAGE_DIR}/LICENSE"

# ---------------------------------------------------------------------
# 4. report.html — from release-assets/.
# ---------------------------------------------------------------------
if [[ -f "${RELEASE_ASSETS_DIR}/report.html" ]]; then
  cp "${RELEASE_ASSETS_DIR}/report.html" "${STAGE_DIR}/"
elif [[ "${FINDEVIL_DEVPOST_MODE}" == "smoke" ]]; then
  log "WARN: no report.html in ${RELEASE_ASSETS_DIR}; creating smoke-only report"
  cat > "${STAGE_DIR}/report.html" <<'EOF'
<!doctype html><html><body><h1>Find Evil smoke package placeholder</h1><p>Not valid for final submission.</p></body></html>
EOF
else
  log "ERROR: no report.html in ${RELEASE_ASSETS_DIR}/"
  exit 1
fi

# ---------------------------------------------------------------------
# 5. readiness-packet.zip — optional portable proof packet.
# ---------------------------------------------------------------------
if [[ -f "${READINESS_PACKET_ZIP}" ]]; then
  cp "${READINESS_PACKET_ZIP}" "${STAGE_DIR}/readiness-packet.zip"
else
  log "WARN: no readiness packet at ${READINESS_PACKET_ZIP}; package will omit optional readiness-packet.zip"
fi

# ---------------------------------------------------------------------
# 6. benchmark-results.csv.
# ---------------------------------------------------------------------
if [[ -f "${BENCHMARK_CSV}" ]]; then
  cp "${BENCHMARK_CSV}" "${STAGE_DIR}/benchmark-results.csv"
elif [[ "${FINDEVIL_DEVPOST_MODE}" == "smoke" ]]; then
  log "WARN: no ${BENCHMARK_CSV}; creating smoke-only stub"
  echo 'fixture,findings_matched,findings_expected' > "${STAGE_DIR}/benchmark-results.csv"
else
  log "ERROR: no ${BENCHMARK_CSV}"
  exit 1
fi

# ---------------------------------------------------------------------
# Integrity check per Spec #4 §9 step 6.
# (SUBMISSION_NOTES.md was a 7th required entry pre-Phase-3d; deleted
# 2026-05-02 along with the file at repo root. The judge-facing Q&A
# that was its only unique content lives at README.md "Anticipated
# questions" — and README-submission.md is generated from current release
# metadata above.)
# ---------------------------------------------------------------------
required=(
  "README-submission.md"
  "benchmark-results.csv"
  "demo-video-link.txt"
  "LICENSE"
  "report.html"
)
missing=0
for f in "${required[@]}"; do
  if [[ ! -f "${STAGE_DIR}/${f}" ]]; then
    log "ERROR: missing from stage dir: ${f}"
    missing=$((missing + 1))
  fi
done
if [[ "${missing}" -gt 0 ]]; then
  log "aborting — ${missing} required file(s) missing"
  exit 1
fi

if [[ "${FINDEVIL_DEVPOST_MODE}" == "strict" ]]; then
  validator_args=(
    --demo-url "${DEMO_VIDEO_URL}" \
    --benchmark "${STAGE_DIR}/benchmark-results.csv" \
    --report "${STAGE_DIR}/report.html" \
    --stage-dir "${STAGE_DIR}"
  )
  if [[ -f "${STAGE_DIR}/readiness-packet.zip" ]]; then
    validator_args+=(--readiness-packet "${STAGE_DIR}/readiness-packet.zip")
  fi
  "${PYTHON_BIN}" scripts/validate-submission-assets.py "${validator_args[@]}"
else
  log "WARN: skipping strict artifact validator in smoke mode"
fi

# ---------------------------------------------------------------------
# Zip.
# ---------------------------------------------------------------------
rm -f -- "${REPO_ROOT}/${OUT_ZIP}"
if command -v zip >/dev/null 2>&1; then
  (cd "${STAGE_DIR}" && zip -q -r "${REPO_ROOT}/${OUT_ZIP}" .)
else
  log "WARN: zip not found; using Python zipfile fallback"
  "${PYTHON_BIN}" - "${STAGE_DIR}" "${REPO_ROOT}/${OUT_ZIP}" <<'PY'
import pathlib
import sys
import zipfile

stage = pathlib.Path(sys.argv[1])
out = pathlib.Path(sys.argv[2])
with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as zf:
    for path in sorted(p for p in stage.rglob("*") if p.is_file()):
        zf.write(path, path.relative_to(stage).as_posix())
PY
fi
ls -lh "${REPO_ROOT}/${OUT_ZIP}"
if [[ "${FINDEVIL_DEVPOST_MODE}" == "strict" ]]; then
  "${PYTHON_BIN}" scripts/validate-submission-assets.py --zip "${OUT_ZIP}"
fi
log "done: ${OUT_ZIP}"
