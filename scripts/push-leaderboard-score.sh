#!/usr/bin/env bash
# push-leaderboard-score.sh — publish an L3 golden-run score to
# findevil-bench.dev per glue Spec #4 §7.
#
# Called from .github/workflows/l3-nightly.yml and release.yml.
# Reads aggregated scores from logs/l3/ (one *-verdict.json per
# fixture) and POSTs a single payload. Non-blocking: failure is
# logged but never red-lights the caller.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

LOGS_DIR="${LOGS_DIR:-logs/l3}"
COMMIT_SHA="${COMMIT_SHA:-}"
RUN_ID="${RUN_ID:-}"
RELEASE_TAG="${RELEASE_TAG:-}"
RELEASE_FLAG="${RELEASE_FLAG:-false}"
ENDPOINT="${LEADERBOARD_ENDPOINT:-https://findevil-bench.dev/api/scores}"

# Arg parsing — keep simple; no getopts for a single-purpose script.
while [[ $# -gt 0 ]]; do
  case "$1" in
    --commit-sha)    COMMIT_SHA="$2"; shift 2 ;;
    --run-id)        RUN_ID="$2"; shift 2 ;;
    --release)       RELEASE_FLAG="$2"; shift 2 ;;
    --tag)           RELEASE_TAG="$2"; shift 2 ;;
    --endpoint)      ENDPOINT="$2"; shift 2 ;;
    --logs-dir)      LOGS_DIR="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

log() { printf '[leaderboard] %s\n' "$*" >&2; }

if [[ -z "${LEADERBOARD_API_KEY:-}" ]]; then
  log "LEADERBOARD_API_KEY empty — skipping push (non-fatal)"
  exit 0
fi

if [[ ! -d "${LOGS_DIR}" ]]; then
  log "no ${LOGS_DIR} dir — skipping (L3 may not have run yet)"
  exit 0
fi

# Aggregate per-fixture verdicts into the schema glue Spec #4 §7 defines.
tmpfile=$(mktemp)
cleanup() { rm -f "${tmpfile}"; }
trap cleanup EXIT

# Build the JSON payload with jq — more reliable than hand-rolling.
cases_json="[]"
for verdict_file in "${LOGS_DIR}"/*-verdict.json; do
  [[ -f "${verdict_file}" ]] || continue
  fixture_name=$(basename "${verdict_file}" -verdict.json)
  # Minimal extraction — real L3 output populates these from the
  # product's --output-format json.
  this_case=$(jq --arg fixture "${fixture_name}" '{
    fixture: $fixture,
    findings_matched: (.finding_count // (.findings // [] | length)),
    findings_expected: (.findings_expected // null),
    verdict: (.verdict // "INCONCLUSIVE"),
    verdict_correct: (.verdict_correct // false),
    wall_clock_seconds: (.run_duration_seconds // 0)
  }' "${verdict_file}" 2>/dev/null || echo '{}')
  cases_json=$(echo "${cases_json}" | jq --argjson c "${this_case}" '. + [$c]')
done

# Simple aggregate. Real leaderboard computes richer stats server-side.
total_matched=$(echo "${cases_json}" | jq '[.[].findings_matched // 0] | add // 0')
total_expected=$(echo "${cases_json}" | jq '[.[].findings_expected // 0] | add // 0')
accuracy=$(echo "${cases_json}" \
  | jq 'if length == 0 then 0 else ([.[].verdict_correct | if . then 1 else 0 end] | add / length) end')
mean_wall=$(echo "${cases_json}" | jq 'if length == 0 then 0 else ([.[].wall_clock_seconds // 0] | add / length) end')

payload=$(jq -n \
  --arg submitter "find-evil" \
  --arg commit_sha "${COMMIT_SHA}" \
  --arg run_id "${RUN_ID}" \
  --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --argjson release "${RELEASE_FLAG}" \
  --arg release_tag "${RELEASE_TAG}" \
  --argjson cases "${cases_json}" \
  --argjson accuracy "${accuracy}" \
  --argjson total_matched "${total_matched}" \
  --argjson total_expected "${total_expected}" \
  --argjson mean_wall "${mean_wall}" \
  '{
    submitter: $submitter,
    commit_sha: $commit_sha,
    run_id: $run_id,
    timestamp_utc: $ts,
    release: $release,
    release_tag: (if ($release_tag | length) == 0 then null else $release_tag end),
    cases: $cases,
    aggregate: {
      accuracy: $accuracy,
      total_findings_matched: $total_matched,
      total_findings_expected: $total_expected,
      mean_wall_clock_seconds: $mean_wall
    }
  }')

log "posting to ${ENDPOINT}"
echo "${payload}" > "${tmpfile}"

http_code=$(curl -fsSL --max-time 30 \
  -o /tmp/leaderboard-response.txt -w '%{http_code}' \
  -X POST "${ENDPOINT}" \
  -H "Authorization: Bearer ${LEADERBOARD_API_KEY}" \
  -H "Content-Type: application/json" \
  --data @"${tmpfile}" \
  || echo "000")

if [[ "${http_code}" -ge 200 ]] && [[ "${http_code}" -lt 300 ]]; then
  log "leaderboard push ok (HTTP ${http_code})"
else
  log "WARN: leaderboard push failed (HTTP ${http_code}); response:"
  cat /tmp/leaderboard-response.txt >&2 || true
  # Non-fatal per glue Spec #4 §7.
fi
exit 0
