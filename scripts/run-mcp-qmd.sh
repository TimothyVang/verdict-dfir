#!/usr/bin/env bash
# run-mcp-qmd.sh — optional launcher for a local obsidian-mind QMD memory MCP
# server. The public release does not ship the vault; if an operator has one at
# ./obsidian-mind, this wrapper lets .mcp.json expose mcp__qmd__query without a
# per-machine `claude mcp add`.
#
# It resolves Node 22 via nvm (the vault QMD machinery needs --experimental-strip-types
# + the global @tobilu/qmd) and runs the vault's qmd-mcp.mjs.
#
# Set FINDEVIL_ENABLE_QMD=1 to enable it. If Node 22 / QMD isn't installed, the
# server simply doesn't start — the product is unaffected. This is an OPERATOR
# memory server: NOT in the audit chain, never touches evidence, and emits no
# Findings.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
QMD_MCP="$REPO/obsidian-mind/.claude/scripts/qmd-mcp.mjs"
[ "${FINDEVIL_ENABLE_QMD:-0}" = "1" ] || { echo "qmd memory server: set FINDEVIL_ENABLE_QMD=1 to enable (skipping)" >&2; exit 0; }
for qmd_path in "$REPO/obsidian-mind" "$REPO/obsidian-mind/.claude" "$REPO/obsidian-mind/.claude/scripts" "$QMD_MCP"; do
  [ ! -L "$qmd_path" ] || { echo "qmd memory server: symlinked vault path rejected: $qmd_path" >&2; exit 0; }
done
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
