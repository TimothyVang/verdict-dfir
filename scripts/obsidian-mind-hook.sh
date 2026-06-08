#!/usr/bin/env bash
# obsidian-mind-hook.sh — runner that wires the obsidian-mind memory layer into the
# MAIN repo so the vault works WITHOUT switching folders
# (docs/runbooks/obsidian-mind-memory.md). Two modes:
#
#   bash scripts/obsidian-mind-hook.sh session-start
#       SessionStart: inject the vault's North Star + brain-topic index into the
#       session. SKIPPED during headless investigations (FIND_EVIL_LOCAL) so a
#       `scripts/verdict` run is never polluted with dev memory.
#
#   bash scripts/obsidian-mind-hook.sh <hook-file.ts>
#       PostToolUse(Write|Edit): run the vault hook (validate-write / qmd-refresh)
#       ONLY when the edited file is under obsidian-mind/, so normal repo edits are
#       never validated or blocked.
#
# Inert by default: the vault hooks need Node 22; if it isn't installed this exits 0
# (no-op), so the committed config is harmless on a fresh clone / for a judge.
# Never blocks a tool call or session — every failure path is a clean exit 0.
# Boundary: injects context / reindexes the vault only — never writes to a case
# audit chain, never touches evidence.
set -euo pipefail

MODE="${1:-}"
[ -n "$MODE" ] || exit 0

REPO="$(cd "$(dirname "$0")/.." && pwd)"
VAULT="$REPO/obsidian-mind"

# Resolve Node 22 via nvm; absent → memory layer not installed → no-op.
export NVM_DIR="${NVM_DIR:-$HOME/.nvm}"
# shellcheck disable=SC1091
[ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh" >/dev/null 2>&1 || exit 0
NODE22="$(nvm which 22 2>/dev/null || true)"
[ -n "$NODE22" ] && [ -x "$NODE22" ] || exit 0
NODE22_BIN_DIR="$(dirname "$NODE22")"
GLOBNM="$(cd "$NODE22_BIN_DIR/../lib/node_modules" 2>/dev/null && pwd || true)"

# Run a vault hook with the vault as CLAUDE_PROJECT_DIR; stdin forwarded, stdout passes through.
run_vault_hook() {  # $1 = absolute hook path
  CLAUDE_PROJECT_DIR="$VAULT" NODE_PATH="${GLOBNM:-}" PATH="$NODE22_BIN_DIR:$PATH" \
    "$NODE22" --disable-warning=ExperimentalWarning --experimental-strip-types "$1" 2>/dev/null || exit 0
}

# --- SessionStart mode: inject vault context (interactive dev sessions only) ---
if [ "$MODE" = "session-start" ]; then
  # Investigation gate: never inject dev memory into a headless verdict run.
  [ -n "${FIND_EVIL_LOCAL:-}" ] && exit 0
  [ -n "${FINDEVIL_NO_MEMORY_HOOK:-}" ] && exit 0
  HOOK_PATH="$VAULT/.claude/scripts/session-start.ts"
  [ -f "$HOOK_PATH" ] || exit 0
  cat | run_vault_hook "$HOOK_PATH"   # stdout (injected context) passes through to the session
  exit 0
fi

# --- PostToolUse mode: $MODE is a hook file under the vault's .claude/scripts/ ---
HOOK_PATH="$VAULT/.claude/scripts/$MODE"
[ -f "$HOOK_PATH" ] || exit 0
INPUT="$(cat)"

# Path-scope guard: only act on writes under obsidian-mind/.
FP="$(printf '%s' "$INPUT" | "$NODE22" -e 'let d="";process.stdin.on("data",c=>d+=c);process.stdin.on("end",()=>{try{const j=JSON.parse(d);process.stdout.write(String((j.tool_input&&(j.tool_input.file_path||j.tool_input.path))||""))}catch{process.stdout.write("")}})' 2>/dev/null || true)"
case "$FP" in
  *"/obsidian-mind/"* | "obsidian-mind/"*) : ;;  # inside the vault → proceed
  *) exit 0 ;;                                    # anywhere else → no-op
esac

printf '%s' "$INPUT" | run_vault_hook "$HOOK_PATH"
exit 0
