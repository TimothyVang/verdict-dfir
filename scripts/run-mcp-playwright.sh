#!/usr/bin/env bash
# run-mcp-playwright.sh — launch the Playwright MCP server with its npm cache and
# browser downloads contained inside the project (.project-local/npm +
# .project-local/ms-playwright). Operator convenience only; never bundled.
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/project-env.sh
source "${REPO}/scripts/lib/project-env.sh"
exec npx -y "@playwright/mcp@latest"
