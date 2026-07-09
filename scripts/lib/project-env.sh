#!/usr/bin/env bash
# project-env.sh — contain ALL runtime state inside the project folder.
#
# Source this from any launcher/entrypoint (the MCP wrappers, scripts/verdict,
# smokes) BEFORE it spawns the server or a forensic tool. It redirects every
# place a tool would otherwise write outside the repo — /tmp, ~/.findevil,
# ~/.local/share, ~/.cache, the npm/npx cache, the Playwright/Puppeteer browser
# downloads — into one gitignored tree: $REPO/.project-local/.
#
# The result: a self-contained "project MCP" surface. Nothing the servers or
# tools produce escapes the project directory, and nothing here is committed
# (.project-local/ is gitignored), so the "never bundle convenience servers"
# release rule is preserved.
#
# Every export honours a pre-set value (`${VAR:-default}`) so an operator can
# still override any single location; we only fill in a project-local default.
#
# Path-agnostic: REPO is derived from this file's location, so it works from any
# CWD and any machine.

# Resolve the repo root from this script's own path (scripts/lib/ -> repo root).
_PE_SELF="${BASH_SOURCE[0]}"
PROJECT_ROOT="$(cd "$(dirname "${_PE_SELF}")/../.." && pwd)"
export PROJECT_ROOT

# Single gitignored home for all runtime state.
PROJECT_LOCAL="${PROJECT_LOCAL:-${PROJECT_ROOT}/.project-local}"
export PROJECT_LOCAL

# Create the subtree up front so every consumer can assume the dirs exist.
mkdir -p \
  "${PROJECT_LOCAL}/tmp" \
  "${PROJECT_LOCAL}/share" \
  "${PROJECT_LOCAL}/state" \
  "${PROJECT_LOCAL}/cache" \
  "${PROJECT_LOCAL}/findevil" \
  "${PROJECT_LOCAL}/npm" \
  "${PROJECT_LOCAL}/ms-playwright" \
  "${PROJECT_LOCAL}/puppeteer" 2>/dev/null || true

# --- Generic POSIX/XDG escape hatches (cover most third-party tools) ---
# std::env::temp_dir() (Rust), tempfile/mkdtemp (Python), and most CLI tools
# honour $TMPDIR; setting it keeps plaso/ez/suricata/etc. scratch in-project.
export TMPDIR="${TMPDIR:-${PROJECT_LOCAL}/tmp}"
export XDG_DATA_HOME="${XDG_DATA_HOME:-${PROJECT_LOCAL}/share}"
export XDG_STATE_HOME="${XDG_STATE_HOME:-${PROJECT_LOCAL}/state}"
export XDG_CACHE_HOME="${XDG_CACHE_HOME:-${PROJECT_LOCAL}/cache}"

# --- VERDICT case store + cross-case memory sqlite ---
# find_evil_auto.py / config.py resolve the case home from $FINDEVIL_HOME first
# (else $HOME/.findevil). Pinning it keeps cases, extracts, and memory.sqlite
# inside the project.
export FINDEVIL_HOME="${FINDEVIL_HOME:-${PROJECT_LOCAL}/findevil}"

# --- Hayabusa rules base (Rust hayabusa_scan resolves under $XDG_DATA_HOME) ---
export HAYABUSA_RULES_BASE="${HAYABUSA_RULES_BASE:-${XDG_DATA_HOME}/hayabusa-mcp}"

# --- npm / npx + browser downloads for the convenience MCP servers ---
# `npx -y <pkg>` resolves and caches under $npm_config_cache; browser engines go
# to their own cache dirs. Redirecting all three keeps the convenience servers'
# bytes inside the project (still gitignored, never committed).
export npm_config_cache="${npm_config_cache:-${PROJECT_LOCAL}/npm}"
export PLAYWRIGHT_BROWSERS_PATH="${PLAYWRIGHT_BROWSERS_PATH:-${PROJECT_LOCAL}/ms-playwright}"
export PUPPETEER_CACHE_DIR="${PUPPETEER_CACHE_DIR:-${PROJECT_LOCAL}/puppeteer}"

# --- Language toolchain caches (project-local COPIES; globals untouched) ---
# A project-specific copy of each build cache lives under .project-local/toolchain
# so this project builds entirely from in-folder state. The machine-wide
# ~/.cargo, ~/.rustup, ~/.cache/uv, ~/.local/share/pnpm stay intact for other
# projects. Each honours ${VAR:-default} so it's still overridable.
TOOLCHAIN="${PROJECT_LOCAL}/toolchain"
mkdir -p \
  "${TOOLCHAIN}/cargo" "${TOOLCHAIN}/rustup" \
  "${TOOLCHAIN}/uv-cache" "${TOOLCHAIN}/uv-python" \
  "${TOOLCHAIN}/pnpm-store" 2>/dev/null || true
# Rust: CARGO_HOME holds the registry/git crate cache; RUSTUP_HOME holds the
# toolchains. The rustup proxy binaries on PATH read RUSTUP_HOME at runtime.
export CARGO_HOME="${CARGO_HOME:-${TOOLCHAIN}/cargo}"
export RUSTUP_HOME="${RUSTUP_HOME:-${TOOLCHAIN}/rustup}"
# Keep the rustup proxy (cargo/rustc) reachable even with CARGO_HOME redirected.
export PATH="${HOME}/.cargo/bin:${CARGO_HOME}/bin:${PATH}"
# Python (uv): downloaded wheels + managed interpreters.
export UV_CACHE_DIR="${UV_CACHE_DIR:-${TOOLCHAIN}/uv-cache}"
export UV_PYTHON_INSTALL_DIR="${UV_PYTHON_INSTALL_DIR:-${TOOLCHAIN}/uv-python}"
# pnpm: PNPM_HOME is the global-bin home; the content-addressable STORE follows
# XDG_DATA_HOME (set above) -> .project-local/share/pnpm, so it's already
# in-project. Do NOT set npm_config_store_dir — npm rejects it as an unknown
# config and emits a warning (it's a pnpm-only key, not an npm one).
export PNPM_HOME="${PNPM_HOME:-${TOOLCHAIN}/pnpm-store}"
