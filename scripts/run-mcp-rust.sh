#!/usr/bin/env bash
set -euo pipefail
# Prefer a prebuilt release binary (containers, CI, post scripts/install.sh): no
# multi-minute `cargo run` recompile on every cold MCP spawn. Falls back to
# `cargo run` for a source-only dev checkout that hasn't been built yet.
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${FINDEVIL_MCP_BIN:-${REPO}/target/release/findevil-mcp}"
if [ -x "${BIN}" ]; then
  exec "${BIN}"
fi
[ -f "$HOME/.cargo/env" ] && source "$HOME/.cargo/env"
export PATH="$HOME/.cargo/bin:$PATH"
# --manifest-path keeps the cargo-run fallback CWD-independent (works from any dir).
exec cargo run --manifest-path "${REPO}/Cargo.toml" --release -p findevil-mcp --quiet
