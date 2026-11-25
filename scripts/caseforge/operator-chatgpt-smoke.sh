#!/usr/bin/env bash
# Operator happy-path smoke for the ChatGPT subscription OAuth route.
#
# This is intentionally a script, not a public CLI command. It stitches together
# the operator-facing checks that must stay true for the cloud worktree:
# auth status -> route doctor -> ChatGPT OAuth investigation -> produced case
# verification, with OPENAI_API_KEY removed from the live investigation env.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

die() {
  echo "operator-smoke: $*" >&2
  exit 1
}

say() {
  echo
  echo "==> $*"
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

matching_case_dir() {
  local cases_dir="$1"
  local evidence_hash="$2"
  local marker="$3"
  [ -d "${cases_dir}" ] || return 0
  local dir
  while IFS= read -r dir; do
    if { [ -f "${dir}/case.json" ] && grep -Fq "\"image_hash\": \"${evidence_hash}\"" "${dir}/case.json"; } \
      || { [ -f "${dir}/audit.jsonl" ] && grep -Fq "${evidence_hash}" "${dir}/audit.jsonl"; } \
      || { [ -f "${dir}/run.manifest.json" ] && grep -Fq "${evidence_hash}" "${dir}/run.manifest.json"; }; then
      printf '%s\n' "${dir}"
      return 0
    fi
  done < <(find "${cases_dir}" -mindepth 1 -maxdepth 1 -type d -newer "${marker}" -printf '%T@ %p\n' 2>/dev/null \
    | sort -nr \
    | cut -d' ' -f2-)
}

CLI="${ROOT}/packages/caseforge-cli/dist/src/cli.js"
[ -f "${CLI}" ] || npm run build
[ -f "${CLI}" ] || die "missing built CLI at ${CLI}"

DFIR_HOME="$(resolve_dfir_home)" || die "set VERDICT_DFIR_HOME to a Dev VERDICT checkout with scripts/run-mcp-rust.sh"
[ -f "${DFIR_HOME}/scripts/run-mcp-rust.sh" ] || die "Dev VERDICT MCP launcher missing: ${DFIR_HOME}/scripts/run-mcp-rust.sh"

FIND_EVIL_HOME="${DFIR_HOME}/.project-local/findevil"
CASES_DIR="${FIND_EVIL_HOME}/cases"
if [ -n "${CASEFORGE_OPERATOR_EVIDENCE:-}" ] && [ "${CASEFORGE_OPERATOR_EVIDENCE_APPROVED:-0}" != "1" ]; then
  die "CASEFORGE_OPERATOR_EVIDENCE uses cloud-ok; set CASEFORGE_OPERATOR_EVIDENCE_APPROVED=1 for approved synthetic/public/redacted evidence"
fi
EVIDENCE="${CASEFORGE_OPERATOR_EVIDENCE:-${DFIR_HOME}/.project-local/caseforge-operator-smoke/empty.pcap}"
DEFAULT_EVIDENCE_CLASS="synthetic"
if [ -n "${CASEFORGE_OPERATOR_EVIDENCE:-}" ]; then
  DEFAULT_EVIDENCE_CLASS="approved"
fi
EVIDENCE_CLASS="${CASEFORGE_OPERATOR_EVIDENCE_CLASS:-${DEFAULT_EVIDENCE_CLASS}}"
PRIVACY_MODE="${CASEFORGE_OPERATOR_PRIVACY:-cloud-ok}"

if [ ! -f "${EVIDENCE}" ]; then
  mkdir -p "$(dirname "${EVIDENCE}")"
  # Minimal libpcap file: global header, zero packets. It exercises the normal
  # network workflow without pretending arbitrary bytes are a disk or memory image.
  printf '\324\303\262\241\002\000\004\000\000\000\000\000\000\000\000\000\377\377\000\000\001\000\000\000' >"${EVIDENCE}"
fi
EVIDENCE_HASH="$(sha256sum "${EVIDENCE}" | awk '{print $1}')"

say "ChatGPT OAuth credential status"
env -u OPENAI_API_KEY node "${CLI}" auth status

say "ChatGPT OAuth route doctor"
VERDICT_DFIR_HOME="${DFIR_HOME}" env -u OPENAI_API_KEY node "${CLI}" doctor --route chatgpt-oauth

marker_dir="${DFIR_HOME}/.project-local/caseforge-operator-smoke"
mkdir -p "${marker_dir}"
marker="$(mktemp "${marker_dir}/marker.XXXXXX")"
touch "${marker}"

say "ChatGPT OAuth investigation"
investigate_cmd=(
  node "${CLI}" investigate "${EVIDENCE}"
  --privacy "${PRIVACY_MODE}"
  --evidence "${EVIDENCE_CLASS}"
  --route chatgpt-oauth
  --command network
)
timeout_s="${CASEFORGE_OPERATOR_SMOKE_TIMEOUT:-600}"
if command -v timeout >/dev/null 2>&1; then
  env -u OPENAI_API_KEY VERDICT_DFIR_HOME="${DFIR_HOME}" FINDEVIL_HOME="${FIND_EVIL_HOME}" timeout "${timeout_s}" "${investigate_cmd[@]}"
else
  env -u OPENAI_API_KEY VERDICT_DFIR_HOME="${DFIR_HOME}" FINDEVIL_HOME="${FIND_EVIL_HOME}" "${investigate_cmd[@]}"
fi

after="$(matching_case_dir "${CASES_DIR}" "${EVIDENCE_HASH}" "${marker}" || true)"
rm -f "${marker}"
[ -n "${after}" ] || die "investigation completed without a fresh case matching evidence hash ${EVIDENCE_HASH} under ${CASES_DIR}"
case "${after}" in
  "${CASES_DIR}"/*) ;;
  *) die "matched case escaped expected case store: ${after}" ;;
esac

say "Verify produced case"
node "${CLI}" verify "${after}"

echo
echo "operator smoke complete: ${after}"
