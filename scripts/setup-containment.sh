#!/usr/bin/env bash
# setup-containment.sh - make the agent-level containment portable.
#
# Everything else in this project derives the project root at runtime
# (scripts/lib/project-env.sh, the run-mcp-*.sh launchers, scripts/verdict, the
# hooks) so they already work from any CWD and stay inside this folder. The one
# piece that can't self-derive is Claude Code's `env` block in
# .claude/settings.local.json: it must hold absolute paths, and Claude Code does
# NOT expand variables there.
#
# This script regenerates that env block from project-env.sh for wherever the
# folder currently lives. Run it once after you clone or move the project:
#
#     bash scripts/setup-containment.sh
#
# It is itself path-agnostic (derives the repo from its own location) and writes
# nothing outside the project. Re-running is idempotent.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# project-env.sh honours pre-set values (${VAR:-default}) so an operator can
# override any single path. But THIS script must always re-root to the folder it
# actually lives in — otherwise a stale value inherited from the parent shell
# (e.g. a previously-loaded project's env) would be copied verbatim and the
# regenerated block would point at the wrong place. So unset the derived vars
# first, forcing project-env.sh to compute them fresh from ${REPO}.
unset PROJECT_LOCAL TMPDIR XDG_DATA_HOME XDG_STATE_HOME XDG_CACHE_HOME \
  FINDEVIL_HOME HAYABUSA_RULES_BASE npm_config_cache PLAYWRIGHT_BROWSERS_PATH \
  PUPPETEER_CACHE_DIR CARGO_HOME RUSTUP_HOME UV_CACHE_DIR UV_PYTHON_INSTALL_DIR \
  PNPM_HOME TOOLCHAIN
# Source the single source of truth so the env block can never drift from it.
# shellcheck source=lib/project-env.sh
source "${REPO}/scripts/lib/project-env.sh"

SETTINGS="${REPO}/.claude/settings.local.json"
mkdir -p "${REPO}/.claude"

# Hand the resolved values to python via the environment (already exported by
# project-env.sh) and let it merge them into the JSON, preserving every other key.
REPO="${REPO}" SETTINGS="${SETTINGS}" python3 - <<'PY'
import json, os, pathlib

settings = pathlib.Path(os.environ["SETTINGS"])
data = {}
if settings.exists():
    try:
        data = json.loads(settings.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        raise SystemExit(f"refusing to overwrite invalid JSON: {settings}")

# The containment variables project-env.sh exports — read their resolved values
# straight from the environment so this list has ONE source of truth.
VARS = [
    "PROJECT_LOCAL", "TMPDIR", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME",
    "FINDEVIL_HOME", "HAYABUSA_RULES_BASE", "npm_config_cache",
    "PLAYWRIGHT_BROWSERS_PATH", "PUPPETEER_CACHE_DIR",
    "CARGO_HOME", "RUSTUP_HOME", "UV_CACHE_DIR", "UV_PYTHON_INSTALL_DIR", "PNPM_HOME",
]
env = {v: os.environ[v] for v in VARS if v in os.environ}

data["env"] = env
settings.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
print(f"updated {settings} env block -> {len(env)} vars rooted at {os.environ['PROJECT_LOCAL']}")
PY

# --- opencode credential visibility (optional, local-only) -----------------
# Containment redirects XDG_DATA_HOME into .project-local/share, and opencode
# resolves its credential file from $XDG_DATA_HOME/opencode/auth.json. So a
# contained opencode never sees the operator's global OAuth at
# ~/.local/share/opencode/auth.json and fails with "OpenAI API key is missing".
# Symlink the project-local auth file to the global one so the existing login is
# visible here and token refreshes stay in sync. We only ever LINK (never copy
# secret contents), only when a global credential already exists, and never
# clobber a real local credential file. .project-local/ is gitignored, so the
# link is local-only and the credential is never committed.
OPENCODE_GLOBAL_AUTH="${HOME}/.local/share/opencode/auth.json"
OPENCODE_LOCAL_AUTH="${XDG_DATA_HOME}/opencode/auth.json"
if [ -e "${OPENCODE_GLOBAL_AUTH}" ]; then
  if [ -s "${OPENCODE_LOCAL_AUTH}" ] && [ ! -L "${OPENCODE_LOCAL_AUTH}" ]; then
    echo "opencode: leaving existing local auth.json alone (not a symlink)"
  else
    mkdir -p "$(dirname "${OPENCODE_LOCAL_AUTH}")"
    ln -sfn "${OPENCODE_GLOBAL_AUTH}" "${OPENCODE_LOCAL_AUTH}"
    echo "opencode: linked ${OPENCODE_LOCAL_AUTH} -> ${OPENCODE_GLOBAL_AUTH}"
  fi
else
  echo "opencode: no global auth.json found; skipping (run 'opencode auth login' if needed)"
fi

echo "done. The agent env now points at this folder. Restart Claude Code to load it."
