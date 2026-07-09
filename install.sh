#!/usr/bin/env bash
# install.sh — one-line bootstrap for VERDICT DFIR.
#
# Usage (from a bare machine):
#   curl -fsSL https://raw.githubusercontent.com/TimothyVang/verdict-dfir-beta/main/install.sh | bash
#
# This is a CLONE-AND-DELEGATE bootstrap, NOT a self-contained binary
# installer. VERDICT runs inside Claude Code and drives a real forensics
# toolchain, so there is nothing to "download and run" the way a single
# static binary would be. This script:
#
#   1. Ensures `git` is present (it cannot install git for you).
#   2. Clones the repo (depth 1) into ./verdict (override with --dir=PATH).
#   3. Hands off to `bash scripts/setup`, the canonical onboarding entry
#      point, which builds the Rust MCP server, syncs the Python MCP env,
#      installs the host DFIR tools it can, and runs the preflight doctor.
#      `scripts/setup` already passes --bootstrap to install.sh, so a
#      missing cargo/uv/node gets installed via the official installers.
#
# Still required and NOT installed by this wrapper:
#   - a Claude Code credential (CLAUDE_CODE_OAUTH_TOKEN, a logged-in
#     `claude`, or ANTHROPIC_API_KEY) — VERDICT is a Claude Code agent.
#   - git (see step 1).
# Recommended for full disk-image parity: the SANS SIFT VM (pass --with-sift,
# or run `setup` inside `claude`). Local mode works without it.
#
# Flags (all optional):
#   --dir=PATH     clone target directory (default: ./verdict)
#   --ref=REF      branch or tag to clone (default: main)
#   --with-sift    forwarded to scripts/setup (also set up the SIFT VM)
#   --run          forwarded to scripts/setup (investigate after setup)
#   -h | --help    show this help and exit
#
# Env:
#   VERDICT_REPO   override the clone URL (e.g. a fork or the dev repo).

set -euo pipefail

REPO_URL="${VERDICT_REPO:-https://github.com/TimothyVang/verdict-dfir-beta.git}"
CLONE_DIR="verdict"
CLONE_REF="main"
SETUP_ARGS=()

c_grn=$'\033[0;32m'; c_yel=$'\033[0;33m'; c_blu=$'\033[0;34m'; c_red=$'\033[0;31m'; c_off=$'\033[0m'
info() { echo "${c_blu}[verdict]${c_off} $*"; }
ok()   { echo "${c_grn}[verdict]${c_off} $*"; }
warn() { echo "${c_yel}[verdict]${c_off} $*"; }
die()  { echo "${c_red}[verdict]${c_off} $*" >&2; exit 1; }

usage() {
  cat <<'USAGE'
install.sh — one-line bootstrap for VERDICT DFIR.

  curl -fsSL https://raw.githubusercontent.com/TimothyVang/verdict-dfir-beta/main/install.sh | bash

Clones the repo and hands off to `bash scripts/setup`. This is a convenience
wrapper, not a standalone binary: it still needs `git` and a Claude Code
credential present, and on a bare machine relies on the official Rust/uv/Node
installers (driven by setup's --bootstrap).

Flags:
  --dir=PATH     clone target directory (default: ./verdict)
  --ref=REF      branch or tag to clone (default: main)
  --with-sift    also set up the SANS SIFT VM (forwarded to scripts/setup)
  --run          investigate evidence once setup is green (forwarded)
  -h, --help     show this help and exit

Env:
  VERDICT_REPO   override the clone URL (a fork or the dev repo).
USAGE
}

for arg in "$@"; do
  case "${arg}" in
    --dir=*)     CLONE_DIR="${arg#*=}" ;;
    --ref=*)     CLONE_REF="${arg#*=}" ;;
    --with-sift) SETUP_ARGS+=(--with-sift) ;;
    --run)       SETUP_ARGS+=(--run) ;;
    -h|--help)   usage; exit 0 ;;
    *) die "unknown argument '${arg}' (try --help)" ;;
  esac
done

# Already inside a VERDICT checkout? Skip the clone and run setup in place.
if [ -f "scripts/setup" ] && [ -d "agent-config" ]; then
  info "running inside an existing VERDICT checkout — skipping clone."
  exec bash scripts/setup ${SETUP_ARGS[@]+"${SETUP_ARGS[@]}"}
fi

command -v git >/dev/null 2>&1 \
  || die "git is required and is not installed. Install git, then re-run."

if [ -e "${CLONE_DIR}" ]; then
  if [ -f "${CLONE_DIR}/scripts/setup" ]; then
    info "reusing existing checkout at ${CLONE_DIR}/"
  else
    die "'${CLONE_DIR}/' already exists and is not a VERDICT checkout — pass --dir=PATH."
  fi
else
  info "cloning ${REPO_URL} (ref: ${CLONE_REF}) into ${CLONE_DIR}/ ..."
  git clone --depth 1 --branch "${CLONE_REF}" "${REPO_URL}" "${CLONE_DIR}" \
    || git clone --depth 1 "${REPO_URL}" "${CLONE_DIR}" \
    || die "git clone failed (check the URL/ref and your network)."
fi

cd "${CLONE_DIR}"
ok "checkout ready at $(pwd)"
info "handing off to scripts/setup (builds MCP servers, syncs envs, installs DFIR tools, preflight)..."
echo
exec bash scripts/setup ${SETUP_ARGS[@]+"${SETUP_ARGS[@]}"}
