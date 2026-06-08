#!/usr/bin/env bash
# run-mcp-qmd.sh — machine-independent launcher for the obsidian-mind QMD memory
# MCP server, referenced from .mcp.json so memory recall (mcp__qmd__query) works
# from a fresh clone without a per-machine `claude mcp add`.
#
# It resolves Node 22 via nvm (the vault QMD machinery needs --experimental-strip-types
# + the global @tobilu/qmd) and runs the vault's qmd-mcp.mjs, which scopes itself to the
# `verdict-memory` index from obsidian-mind/vault-manifest.json.
#
# If Node 22 / QMD isn't installed, the server simply doesn't start — the product is
# unaffected. This is a DEV/OPERATOR memory server: NOT in the audit chain, never
# touches evidence, emits no Findings. See docs/runbooks/obsidian-mind-memory.md.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
QMD_MCP="$REPO/obsidian-mind/.claude/scripts/qmd-mcp.mjs"
[ -f "$QMD_MCP" ] || { echo "qmd memory server: vault not present (skipping)" >&2; exit 0; }

export NVM_DIR="${NVM_DIR:-$HOME/.nvm}"
# shellcheck disable=SC1091
[ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh" >/dev/null 2>&1 \
  || { echo "qmd memory server: nvm/Node 22 not installed (skipping)" >&2; exit 0; }
NODE22="$(nvm which 22 2>/dev/null || true)"
[ -n "$NODE22" ] && [ -x "$NODE22" ] \
  || { echo "qmd memory server: Node 22 not installed (skipping)" >&2; exit 0; }
NODE22_BIN_DIR="$(dirname "$NODE22")"
GLOBNM="$(cd "$NODE22_BIN_DIR/../lib/node_modules" 2>/dev/null && pwd || true)"

# The wrapper resolves @tobilu/qmd via NODE_PATH; its bare-`qmd` fallback needs the
# Node-22 bin on PATH (the package's exports field doesn't expose the dist subpath).
exec env NODE_PATH="${GLOBNM:-}" PATH="$NODE22_BIN_DIR:$PATH" "$NODE22" "$QMD_MCP"
