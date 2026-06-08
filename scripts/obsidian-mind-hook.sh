#!/usr/bin/env bash
# obsidian-mind-hook.sh — vault-scoped, inert-by-default runner for the
# obsidian-mind memory-layer lifecycle hooks (docs/runbooks/obsidian-mind-memory.md).
#
# Why this wrapper exists:
#   * The memory layer is an OPT-IN dev/operator convenience (like Engram / n8n),
#     never part of the DFIR product or the audit chain. It must not break the
#     repo for anyone who hasn't installed it.
#   * obsidian-mind's PostToolUse hook validates frontmatter + reindexes QMD on
#     every .md write. Run unguarded in this repo it would fire on Rust/Python/docs
#     edits too. This wrapper runs the vault hook ONLY when the edited file is under
#     obsidian-mind/, so normal repo edits are never touched.
#   * The vault hooks need Node 22 (--experimental-strip-types). This wrapper
#     resolves it via nvm and EXITS 0 (no-op) if it isn't installed, so the
#     committed config stays machine-independent and harmless on a fresh clone.
#
# Usage (from a hook command):  bash scripts/obsidian-mind-hook.sh <hook-file.ts>
# Never blocks a tool call: every failure path is a clean exit 0.
set -euo pipefail

HOOK_FILE="${1:-}"
[ -n "$HOOK_FILE" ] || exit 0

REPO="$(cd "$(dirname "$0")/.." && pwd)"
VAULT="$REPO/obsidian-mind"
HOOK_PATH="$VAULT/.claude/scripts/$HOOK_FILE"
[ -f "$HOOK_PATH" ] || exit 0

# Resolve Node 22 via nvm; absent → memory layer not installed → no-op.
export NVM_DIR="${NVM_DIR:-$HOME/.nvm}"
# shellcheck disable=SC1091
[ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh" >/dev/null 2>&1 || exit 0
NODE22="$(nvm which 22 2>/dev/null || true)"
[ -n "$NODE22" ] && [ -x "$NODE22" ] || exit 0
NODE22_BIN_DIR="$(dirname "$NODE22")"
GLOBNM="$(cd "$NODE22_BIN_DIR/../lib/node_modules" 2>/dev/null && pwd || true)"

INPUT="$(cat)"

# Path-scope guard: only act on writes under obsidian-mind/.
FP="$(printf '%s' "$INPUT" | "$NODE22" -e 'let d="";process.stdin.on("data",c=>d+=c);process.stdin.on("end",()=>{try{const j=JSON.parse(d);process.stdout.write(String((j.tool_input&&(j.tool_input.file_path||j.tool_input.path))||""))}catch{process.stdout.write("")}})' 2>/dev/null || true)"
case "$FP" in
  *"/obsidian-mind/"* | "obsidian-mind/"*) : ;;  # inside the vault → proceed
  *) exit 0 ;;                                    # anywhere else → no-op
esac

printf '%s' "$INPUT" | CLAUDE_PROJECT_DIR="$VAULT" NODE_PATH="${GLOBNM:-}" PATH="$NODE22_BIN_DIR:$PATH" \
  "$NODE22" --disable-warning=ExperimentalWarning --experimental-strip-types "$HOOK_PATH" 2>/dev/null || exit 0
