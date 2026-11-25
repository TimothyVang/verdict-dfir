#!/usr/bin/env bash
# Local route readiness smoke.
#
# This intentionally runs separately from the ChatGPT OAuth operator path. It
# proves the local route remains configured and that doctor reports the selected
# local endpoint without requiring that endpoint to be running on this machine.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

die() {
  echo "local-route-smoke: $*" >&2
  exit 1
}

resolve_dfir_home() {
  if [ -n "${VERDICT_DFIR_HOME:-}" ]; then
    printf '%s\n' "${VERDICT_DFIR_HOME}"
    return 0
  fi

  local candidate
  for candidate in \
    "${ROOT}/../dev-verdict-next" \
    "${ROOT}/../dev" \
    "${ROOT}/../verdict-dfir-community" \
    "${ROOT}/../../verdict/dev"
  do
    if [ -f "${candidate}/scripts/run-mcp-rust.sh" ]; then
      printf '%s\n' "${candidate}"
      return 0
    fi
  done

  return 1
}

CLI="${ROOT}/packages/caseforge-cli/dist/src/cli.js"
[ -f "${CLI}" ] || npm run build

DFIR_HOME="$(resolve_dfir_home)" || die "set VERDICT_DFIR_HOME to a Dev VERDICT checkout with scripts/run-mcp-rust.sh"
route="${CASEFORGE_LOCAL_ROUTE:-local-ollama}"
endpoint="${VERDICT_LLM_BASEURL:-http://127.0.0.1:9/v1}"

node "${CLI}" models --privacy local-only --evidence sensitive >/dev/null

set +e
output="$(VERDICT_DFIR_HOME="${DFIR_HOME}" VERDICT_LLM_BASEURL="${endpoint}" node "${CLI}" doctor --route "${route}" 2>&1)"
rc=$?
set -e
printf '%s\n' "${output}"

if [ "${CASEFORGE_REQUIRE_LOCAL_ENDPOINT:-0}" = "1" ]; then
  exit "${rc}"
fi

if [ "${rc}" -eq 0 ]; then
  exit 0
fi

grep -Fq "VERDICT toolkit (VERDICT_DFIR_HOME): ${DFIR_HOME}" <<<"${output}"
grep -Fq "selected route: ${route}" <<<"${output}"
grep -Fq "selected local endpoint down (${endpoint})" <<<"${output}"
