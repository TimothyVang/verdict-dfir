#!/usr/bin/env bash
# run-mcp-n8n.sh — launch the n8n-mcp convenience server with all of its npm/npx
# bytes contained inside the project (.project-local/npm). Operator convenience
# only: never in the audit chain, never bundled in the release (the package is
# fetched at runtime into the gitignored project-local cache).
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/project-env.sh
source "${REPO}/scripts/lib/project-env.sh"
export MCP_MODE=stdio LOG_LEVEL=error DISABLE_CONSOLE_OUTPUT=true
export N8N_API_URL="${N8N_API_URL:-http://localhost:5678}"
export N8N_API_KEY="${N8N_API_KEY:-}"
exec npx -y n8n-mcp
