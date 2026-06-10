#!/usr/bin/env bash
# build-local.sh - resumable local build lane.
#
# This is intentionally NOT the submission-readiness gate. It avoids
# external blockers such as SIFT VM access, Docker L1 memory, real evidence,
# Devpost assets, and L3 goldens so contributors can keep coding.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

WSL_WITHOUT_CARGO=0
case "$(uname -s 2>/dev/null || echo unknown)" in
  Linux*)
    if grep -qi microsoft /proc/version 2>/dev/null && ! command -v cargo >/dev/null 2>&1; then
      WSL_WITHOUT_CARGO=1
    fi
    preferred=(python3 python)
    ;;
  MINGW*|MSYS*|CYGWIN*)
    # Prefer Windows python here. MSYS python treats Windows PATH as POSIX
    # paths and may not resolve tools such as cargo.exe even when Windows can.
    preferred=(python python3)
    ;;
  *)
    preferred=(python3 python)
    ;;
esac

PYTHON_BIN=""
for candidate in "${preferred[@]}"; do
  if command -v "${candidate}" >/dev/null 2>&1; then
    PYTHON_BIN="${candidate}"
    break
  fi
done
if [[ -z "${PYTHON_BIN}" ]]; then
  echo "[build-local] ERROR: python3/python not found on PATH" >&2
  exit 127
fi

usage() {
  cat <<'EOF'
Usage:
  bash scripts/build-local.sh [--resume] [--fast] [--run-id ID]
  bash scripts/build-local.sh --status [--json] [--run RUN]

Local build statuses are deliberately scoped:
  LOCAL_BUILD_PASS       repo-local build/check lane passed
  LOCAL_BUILD_FAST_PASS  explicit --fast run passed with local skips
  LOCAL_BUILD_FAIL       repo-local build/check lane failed
  LOCAL_BUILD_INCOMPLETE interrupted or still resumable

This command never emits SUBMISSION_READY. Use a strict readiness gate for
Docker L1, SIFT evidence, Devpost assets, and final package validation.

Options:
  --resume       continue the latest or named run from its checkpoint
  --fast         skip optional web tests and slow Rust smoke test
  --run-id ID    create or resume tmp/build-runs/ID
EOF
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  usage
  exit 0
fi

if [[ "${1:-}" == "--status" ]]; then
  shift
  exec "${PYTHON_BIN}" scripts/build-checker.py "$@"
fi

if [[ "${WSL_WITHOUT_CARGO}" == "1" ]]; then
  cat >&2 <<'EOF'
[build-local] ERROR: WSL bash detected without a Linux Rust toolchain.
[build-local] This host exposes cargo.exe to Windows, not to WSL.
[build-local] Use one of these instead:
[build-local]   PowerShell/OpenCode: python scripts/build-checker.py run --resume
[build-local]   Git Bash: bash scripts/build-local.sh --resume
[build-local] Or install Rust inside WSL, then rerun this command.
EOF
  exit 2
fi

exec "${PYTHON_BIN}" scripts/build-checker.py run "$@"
