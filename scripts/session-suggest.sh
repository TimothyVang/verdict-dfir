#!/usr/bin/env bash
# session-suggest.sh — SessionStart hook. Inspects evidence/ and injects a short,
# project-specific suggestion block so Claude opens the session with the right next
# prompts: setup prompts when no evidence is uploaded, run prompts when it is.
#
# Intended for a local Claude Code hooks.SessionStart entry. Writes nothing to the
# evidence/audit trail — it only emits additionalContext on stdout. Always exit 0;
# never block the session.

set -euo pipefail
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EVIDENCE_DIR="${REPO_ROOT}/evidence"
# findevil-mcp is a cargo *workspace* member, so the release binary lands in the
# workspace-root target/, not services/mcp/target/. Checking the per-crate path
# made a built binary read as "not built".
MCP_BIN="${REPO_ROOT}/target/release/findevil-mcp"

# Extensions that mark a real evidence image. Mirrors scripts/install.sh; case /
# Velociraptor .zip is excluded so dependency archives don't get surfaced.
EVIDENCE_EXTS='E01|dd|raw|img|mem|vmem|aff4|aff|evtx|pcap|pcapng|vhd|vhdx'

# newest non-placeholder evidence entry (file OR case folder); empty if none.
#   1. canonical evidence/ — anything dropped there counts; same README/.gitkeep
#      filter as scripts/verdict:104-108 so "evidence present" means one thing.
#   2. fallback: tmp/evidence/ (a download or prior-run working dir) filtered to
#      real image extensions, so an image there isn't read as "no evidence".
newest_evidence() {
  local hit
  hit="$(ls -dt "${EVIDENCE_DIR}"/* 2>/dev/null | grep -vE '/(README\.md|\.gitkeep)$' | head -1 || true)"
  if [[ -z "${hit}" && -d "${REPO_ROOT}/tmp/evidence" ]]; then
    hit="$(ls -dt "${REPO_ROOT}/tmp/evidence"/* 2>/dev/null | grep -iE "\.(${EVIDENCE_EXTS})\$" | head -1 || true)"
  fi
  printf '%s\n' "${hit}"
}

EVIDENCE="$(newest_evidence)"

# Visible launch banner — printed to stderr so it shows in the terminal at launch
# without polluting the JSON additionalContext on stdout that Claude Code consumes.
# Banner text is shared with the claude wrapper via scripts/verdict-banner.sh.
bash "${REPO_ROOT}/scripts/verdict-banner.sh" >&2 || true

if [[ -n "${EVIDENCE}" ]]; then
  CONTEXT="VERDICT session: evidence is already uploaded at \`${EVIDENCE}\`. Open your first reply with a short suggestion block offering these prompts: (1) \`investigate ${EVIDENCE}\` to run the full DFIR pipeline interactively, or (2) \`bash scripts/verdict ${EVIDENCE}\` for the headless end-to-end run. Mention the live dashboard at http://localhost:3000. Keep it to a few lines."
else
  SETUP_HINT=""
  [[ ! -x "${MCP_BIN}" ]] && SETUP_HINT=" The MCP server binary is not built yet, so suggest \`bash scripts/install.sh\` first."
  CONTEXT="VERDICT session: no evidence is uploaded yet (evidence/ holds only placeholders). Open your first reply with a short suggestion block to get the user set up: drop an evidence file (pcap / memory / disk / .evtx / mixed case folder) into the \`evidence/\` directory, or run \`bash scripts/verdict --watch\` to wait for a drop, then \`investigate <path>\`.${SETUP_HINT} Keep it to a few lines."
fi

python3 - "$CONTEXT" <<'PY'
import json, sys
print(json.dumps({
    "hookSpecificOutput": {
        "hookEventName": "SessionStart",
        "additionalContext": sys.argv[1],
    }
}))
PY

exit 0
