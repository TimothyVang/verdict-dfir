#!/usr/bin/env bash
# scripts/place-gated-download.sh — put a downloaded gated asset where the
# project expects it, instead of leaving it in the browser's Downloads folder.
#
# The SANS SIFT OVA download (a public Egnyte share) lands wherever the browser
# saves files — typically ~/Downloads. scripts/sift-vm-bootstrap.sh::resolve_ova
# expects it at the REPO ROOT as sift-<version>.ova (or any *.ova). This script
# finds a freshly downloaded OVA and moves it into place.
#
# Use it: (a) the browser-fallback flow calls it after the download finishes, or
# (b) run it yourself if you downloaded the OVA manually and it went to Downloads.
# Idempotent: if a valid OVA is already at the repo root, it does nothing.
#
# Usage: bash scripts/place-gated-download.sh [tool-id]      (default: sift-ova)
# Env:   FINDEVIL_REPO_ROOT      override the destination repo root (default: this repo)
#        FINDEVIL_DOWNLOAD_DIR   extra directory to search first (the controlled
#                                download dir the browser was pointed at)

set -uo pipefail

REPO="${FINDEVIL_REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

c_grn=$'\033[0;32m'; c_yel=$'\033[0;33m'; c_red=$'\033[0;31m'; c_dim=$'\033[2m'; c_off=$'\033[0m'

TOOL_ID="${1:-sift-ova}"
REGISTRY="${SCRIPT_DIR}/gated-tools.json"

if [ ! -f "${REGISTRY}" ]; then
  echo "${c_red}error${c_off} registry not found: ${REGISTRY}" >&2; exit 2
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "${c_red}error${c_off} python3 is required to read the registry" >&2; exit 2
fi

# Pull glob + min_bytes from the registry (tab-separated).
meta="$(python3 - "${REGISTRY}" "${TOOL_ID}" <<'PY'
import json, sys
reg = json.load(open(sys.argv[1]))
tool = next((t for t in reg.get("tools", []) if t.get("id") == sys.argv[2]), None)
if not tool:
    sys.exit(3)
v, pres = tool.get("verify", {}), tool.get("presence", {})
glob = v.get("filename_glob") or pres.get("glob") or "*"
minb = int(v.get("min_bytes") or pres.get("min_bytes") or 0)
print("%s\t%d" % (glob, minb))
PY
)" || { echo "${c_red}error${c_off} unknown tool id '${TOOL_ID}' in ${REGISTRY}" >&2; exit 3; }

FILE_GLOB="${meta%%$'\t'*}"
MIN_BYTES="${meta##*$'\t'}"

# is_valid PATH — exists, matches the glob's size floor, and is not an HTML page.
is_valid() {
  local f="$1"
  [ -f "${f}" ] || return 1
  local sz; sz="$(stat -c '%s' "${f}" 2>/dev/null || echo 0)"
  [ "${sz}" -ge "${MIN_BYTES}" ] || return 1
  # reject an error page saved with a .ova name
  head -c 512 "${f}" 2>/dev/null | grep -qiE '<!doctype|<html' && return 1
  return 0
}

# Already placed? Mirror resolve_ova: a valid OVA at the repo root means we're done.
existing="$(ls -S "${REPO}/"${FILE_GLOB} 2>/dev/null | head -1 || true)"
if [ -n "${existing}" ] && is_valid "${existing}"; then
  echo "${c_grn}already placed${c_off} ${existing#"${REPO}"/} ${c_dim}($(du -h "${existing}" | cut -f1))${c_off}"
  exit 0
fi

# Search likely download locations, newest first.
# Targeted locations only — never a blanket /tmp scan (it would grab unrelated or
# partial files). To pull from elsewhere, point FINDEVIL_DOWNLOAD_DIR at it.
declare -a SEARCH=()
[ -n "${FINDEVIL_DOWNLOAD_DIR:-}" ] && SEARCH+=("${FINDEVIL_DOWNLOAD_DIR}")
SEARCH+=(
  "${REPO}/tmp/gated-downloads"
  "${HOME}/Downloads"
  "${HOME}/snap/firefox/common/Downloads"
  "${HOME}/.cache/gated-downloads"
)

candidate=""
for dir in "${SEARCH[@]}"; do
  [ -d "${dir}" ] || continue
  while IFS= read -r line; do
    f="${line#* }"
    if is_valid "${f}"; then candidate="${f}"; break; fi
  done < <(find "${dir}" -maxdepth 2 -name "${FILE_GLOB}" -size +"${MIN_BYTES}"c -printf '%T@ %p\n' 2>/dev/null | sort -rn)
  [ -n "${candidate}" ] && break
done

if [ -z "${candidate}" ]; then
  echo "${c_yel}not found${c_off} no '${FILE_GLOB}' (>= $((MIN_BYTES / 1000000000)) GB) in: ${SEARCH[*]}"
  echo "${c_dim}Download it first (see scripts/gated-tools.json -> ${TOOL_ID}), then re-run this.${c_off}"
  exit 1
fi

dest="${REPO}/$(basename "${candidate}")"
if [ "${candidate}" = "${dest}" ]; then
  echo "${c_grn}already placed${c_off} ${dest#"${REPO}"/}"
  exit 0
fi

mkdir -p "${REPO}"
if mv -n "${candidate}" "${dest}"; then
  echo "${c_grn}placed${c_off} ${candidate} ${c_dim}->${c_off} ${dest#"${REPO}"/} ${c_dim}($(du -h "${dest}" | cut -f1))${c_off}"
  exit 0
else
  echo "${c_red}error${c_off} could not move ${candidate} -> ${dest} (target may already exist)" >&2
  exit 1
fi
