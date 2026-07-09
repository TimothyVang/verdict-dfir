#!/usr/bin/env bash
# run-mcp-puppeteer.sh — launch the Puppeteer MCP server with its npm cache and
# Chromium download contained inside the project (.project-local/npm +
# .project-local/puppeteer). Operator convenience only; never bundled.
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/project-env.sh
source "${REPO}/scripts/lib/project-env.sh"
exec npx -y "@modelcontextprotocol/server-puppeteer"
