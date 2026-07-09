#!/usr/bin/env bash
set -euo pipefail
export PATH="$HOME/.local/bin:$PATH"
# Path-agnostic: derive the repo root from this script's location so the launcher
# works regardless of the caller's CWD (not just when spawned from the repo root).
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Contain all runtime state (tmp, case store, memory.sqlite, caches) in-project.
# shellcheck source=lib/project-env.sh
source "${REPO_ROOT}/scripts/lib/project-env.sh"
exec uv run --directory "${REPO_ROOT}/services/agent_mcp" python -m findevil_agent_mcp.server
