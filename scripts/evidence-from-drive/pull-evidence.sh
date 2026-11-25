#!/usr/bin/env bash
# Download one named VERDICT evidence case from a read-only Google Drive remote.
#
# The helper is path-agnostic: its catalog is resolved from this file, and its
# cache defaults to the XDG cache directory rather than the caller's CWD.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${HERE}/../.." && pwd)"
CATALOG="${CATALOG:-${HERE}/catalog.yaml}"
REMOTE="${VERDICT_DRIVE_REMOTE:-${REMOTE:-verdictdrive}}"

if [[ -n "${EVIDENCE_CACHE:-}" ]]; then
    CACHE="${EVIDENCE_CACHE}"
else
    CACHE="${XDG_CACHE_HOME:-${HOME}/.cache}/verdict-evidence"
fi
if [[ "${CACHE}" != /* ]]; then
    CACHE="${PWD}/${CACHE}"
fi

log() {
    printf '[pull-evidence] %s\n' "$*" >&2
}

usage() {
    cat <<EOF
pull-evidence.sh — download one VERDICT lab evidence case from Google Drive

Usage:
  bash scripts/evidence-from-drive/pull-evidence.sh --list
  bash scripts/evidence-from-drive/pull-evidence.sh <case-id>
  bash scripts/evidence-from-drive/pull-evidence.sh --evict <case-id>
  bash scripts/evidence-from-drive/pull-evidence.sh --help

Environment:
  EVIDENCE_CACHE         Download root (default: \${XDG_CACHE_HOME:-~/.cache}/verdict-evidence)
  VERDICT_DRIVE_REMOTE   rclone remote name (default: verdictdrive)
  CATALOG                Path to catalog.yaml (default: next to this script)

Current settings:
  repo_root   ${REPO_ROOT}
  remote      ${REMOTE}
  cache       ${CACHE}
  catalog     ${CATALOG}

Docs: docs/using/evidence-from-drive.md
Drive folder id: 1j4nPm3vjAcRwVdKOauIVc8yurxoADhOv

Safety: downloads use rclone copy only. --evict deletes only
        EVIDENCE_CACHE/<case-id>; it never deletes from Google Drive.
EOF
}

usage_error() {
    log "FAIL: $1"
    usage >&2
    exit 2
}

require_catalog() {
    if [[ ! -f "${CATALOG}" ]]; then
        log "FAIL: catalog missing: ${CATALOG}"
        exit 1
    fi
}

valid_case_id() {
    [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9_-]*$ ]]
}

list_case_ids() {
    awk '
        /^cases:/{in_cases=1; next}
        in_cases && /^  [a-zA-Z0-9_-]+:[[:space:]]*$/ {
            name=$1
            sub(/:$/, "", name)
            print name
            next
        }
        in_cases && /^[^[:space:]#]/ && !/^cases:/{in_cases=0}
    ' "${CATALOG}"
}

case_remote_paths() {
    local case_id="$1"
    awk -v case_id="${case_id}" '
        $0 == "  " case_id ":" {found=1; next}
        found && /^  [a-zA-Z0-9_-]+:/ {exit}
        found && /^    remote_paths:/ {in_paths=1; next}
        in_paths && /^      - / {
            line=$0
            sub(/^      - /, "", line)
            if (line ~ /^".*"$/) {
                sub(/^"/, "", line)
                sub(/"$/, "", line)
            }
            print line
            next
        }
        in_paths && /^    [a-zA-Z0-9_-]+:/ {in_paths=0}
    ' "${CATALOG}"
}

case_size_hint() {
    local case_id="$1"
    awk -v case_id="${case_id}" '
        $0 == "  " case_id ":" {found=1; next}
        found && /^  [a-zA-Z0-9_-]+:/ {exit}
        found && /^    size_hint:/ {
            sub(/^    size_hint:[[:space:]]*/, "")
            if ($0 ~ /^".*"$/) {
                sub(/^"/, "")
                sub(/"$/, "")
            }
            print
            exit
        }
    ' "${CATALOG}"
}

validate_case_id() {
    local case_id="$1"
    if ! valid_case_id "${case_id}"; then
        log "FAIL: invalid case-id '${case_id}'"
        exit 2
    fi
}

known_case_paths() {
    local case_id="$1"
    local paths
    paths="$(case_remote_paths "${case_id}")"
    if [[ -z "${paths}" ]]; then
        log "FAIL: unknown case-id '${case_id}'"
        log "      Run: bash scripts/evidence-from-drive/pull-evidence.sh --list"
        exit 2
    fi
    printf '%s\n' "${paths}"
}

list_cases() {
    printf 'Available cases (remote=%s):\n\n' "${REMOTE}"
    printf '  %-28s %-12s %s\n' "CASE_ID" "SIZE_HINT" "REMOTE_PATHS"
    printf '  %-28s %-12s %s\n' "-------" "---------" "------------"
    while IFS= read -r case_id; do
        local paths hint
        paths="$(case_remote_paths "${case_id}" | tr '\n' ' ')"
        hint="$(case_size_hint "${case_id}")"
        printf '  %-28s %-12s %s\n' "${case_id}" "${hint:-?}" "${paths}"
    done < <(list_case_ids)
    printf '\nPull:  bash scripts/evidence-from-drive/pull-evidence.sh <case-id>\n'
    printf 'Cache: %s/<case-id>\n' "${CACHE}"
}

evict_case() {
    local case_id="$1"
    local destination="${CACHE}/${case_id}"

    # A strict case-id cannot introduce separators, dot traversal, or options.
    # rm receives one fully quoted cache child and never a remote path.
    if [[ -e "${destination}" || -L "${destination}" ]]; then
        du -sh -- "${destination}" 2>/dev/null || true
        rm -rf -- "${destination}"
        log "evicted local cache only: ${destination}"
    else
        log "nothing to evict at ${destination}"
    fi
}

require_pull_dependencies() {
    if ! command -v rclone >/dev/null 2>&1; then
        log "FAIL: rclone not on PATH. Install: https://rclone.org/install/"
        log "      Then configure remote '${REMOTE}' — see docs/using/evidence-from-drive.md"
        exit 1
    fi
    if ! command -v python3 >/dev/null 2>&1; then
        log "FAIL: python3 not on PATH; it is required to write CASE_META.json"
        exit 1
    fi
    if ! rclone listremotes 2>/dev/null | grep -Fqx -- "${REMOTE}:"; then
        log "FAIL: rclone remote '${REMOTE}:' is not configured."
        log "      Run: rclone config"
        log "      name=${REMOTE}  storage=drive  root_folder_id=1j4nPm3vjAcRwVdKOauIVc8yurxoADhOv"
        log "      Full steps: docs/using/evidence-from-drive.md"
        exit 1
    fi
}

copy_failed() {
    local remote_path="$1"
    log "FAIL: rclone copy failed for ${REMOTE}:${remote_path}"
    log "      Check access: rclone lsd ${REMOTE}:"
    log "      If it reports invalid_grant, run: rclone config reconnect ${REMOTE}:"
    log "      Partial local files were retained so rclone can resume safely."
    exit 1
}

probe_failed() {
    local remote_path="$1"
    log "FAIL: unable to list remote path ${REMOTE}:${remote_path}"
    log "      Check access: rclone lsd ${REMOTE}:"
    log "      If it reports invalid_grant, run: rclone config reconnect ${REMOTE}:"
    exit 1
}

require_nonempty_remote_path() {
    local remote_path="$1"
    local inventory

    if [[ "${remote_path}" == */ ]]; then
        inventory="$(
            rclone lsf "${REMOTE}:${remote_path}" --files-only --recursive
        )" || probe_failed "${remote_path}"
    else
        inventory="$(
            rclone lsf "${REMOTE}:$(dirname "${remote_path}")" \
                --files-only --include "$(basename "${remote_path}")"
        )" || probe_failed "${remote_path}"
    fi
    if ! grep -q '[^[:space:]]' <<<"${inventory}"; then
        log "FAIL: remote path contains no files: ${REMOTE}:${remote_path}"
        log "      Cached files were left unchanged; verify catalog.yaml before retrying."
        exit 1
    fi
}

write_case_metadata() {
    local destination="$1"
    local case_id="$2"
    local pulled_utc="$3"
    local remote_paths="$4"

    META_PATH="${destination}/CASE_META.json" \
        META_CASE_ID="${case_id}" \
        META_REMOTE="${REMOTE}" \
        META_PULLED_UTC="${pulled_utc}" \
        META_REMOTE_PATHS="${remote_paths}" \
        META_CACHE_ROOT="${CACHE}" \
        python3 - <<'PY'
from __future__ import annotations

import json
import os
from pathlib import Path

metadata = {
    "case_id": os.environ["META_CASE_ID"],
    "remote": os.environ["META_REMOTE"],
    "pulled_utc": os.environ["META_PULLED_UTC"],
    "remote_paths": [
        path
        for path in os.environ["META_REMOTE_PATHS"].splitlines()
        if path.strip()
    ],
    "cache_root": os.environ["META_CACHE_ROOT"],
}
Path(os.environ["META_PATH"]).write_text(
    json.dumps(metadata, indent=2) + "\n",
    encoding="utf-8",
)
PY
}

pull_case() {
    local case_id="$1"
    local paths="$2"
    local hint destination remote_path file_count pulled_utc size

    hint="$(case_size_hint "${case_id}")"
    destination="${CACHE}/${case_id}"
    pulled_utc="$(date -u +%Y%m%dT%H%M%SZ)"

    while IFS= read -r remote_path; do
        [[ -z "${remote_path}" ]] && continue
        require_nonempty_remote_path "${remote_path}"
    done <<<"${paths}"

    mkdir -p -- "${destination}"
    rm -f -- "${destination}/CASE_META.json"
    log "case=${case_id} size_hint=${hint:-unknown}"
    log "remote=${REMOTE}"
    log "dest=${destination}"

    while IFS= read -r remote_path; do
        [[ -z "${remote_path}" ]] && continue
        log "rclone copy ${REMOTE}:${remote_path} → ${destination}/"
        if [[ "${remote_path}" == */ ]]; then
            rclone copy "${REMOTE}:${remote_path}" "${destination}/" \
                --progress --transfers 4 \
                || copy_failed "${remote_path}"
        else
            rclone copy "${REMOTE}:$(dirname "${remote_path}")" "${destination}/" \
                --include "$(basename "${remote_path}")" --progress \
                || copy_failed "${remote_path}"
        fi
    done <<<"${paths}"

    file_count="$(
        find "${destination}" -type f ! -name 'CASE_META.json' -print 2>/dev/null \
            | awk 'END {print NR + 0}'
    )"
    if [[ "${file_count}" -eq 0 ]]; then
        log "FAIL: no evidence files landed in ${destination}"
        log "      Check the catalog path with: rclone lsf ${REMOTE}:$(printf '%s\n' "${paths}" | head -1)"
        exit 1
    fi

    write_case_metadata "${destination}" "${case_id}" "${pulled_utc}" "${paths}"
    size="$(du -sh -- "${destination}" 2>/dev/null | awk '{print $1}' || true)"
    log "done: ${destination} (${size:-size unknown})"
    log "run:  bash scripts/verdict ${destination}"
    log "evict: bash scripts/evidence-from-drive/pull-evidence.sh --evict ${case_id}"
    printf '%s\n' "${destination}"
}

if [[ "$#" -eq 0 ]]; then
    usage
    exit 0
fi

case "$1" in
    -h | --help)
        [[ "$#" -eq 1 ]] || usage_error "--help does not accept arguments"
        usage
        exit 0
        ;;
    --list)
        [[ "$#" -eq 1 ]] || usage_error "--list does not accept arguments"
        require_catalog
        list_cases
        exit 0
        ;;
    --evict)
        [[ "$#" -eq 2 ]] || usage_error "--evict requires exactly one case-id"
        validate_case_id "$2"
        evict_case "$2"
        exit 0
        ;;
    *)
        [[ "$#" -eq 1 ]] || usage_error "pull accepts exactly one case-id"
        require_catalog
        validate_case_id "$1"
        paths="$(known_case_paths "$1")"
        require_pull_dependencies
        pull_case "$1" "${paths}"
        ;;
esac
