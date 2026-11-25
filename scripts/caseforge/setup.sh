#!/usr/bin/env bash
#
# setup.sh — clone + build everything caseforge needs on a fresh box.
#
# Builds three repos as siblings of this one:
#   verdict-opencode        -> the `verdict` agent binary (needs: bun)
#   verdict-dfir-community   -> the forensic MCP tools     (needs: cargo, uv)
#   caseforge-core (this)    -> the harness                (needs: node>=20, npm)
#
# Native builds: run this ON the box that will run the agent (correct arch —
# important on ARM64 boxes like a DGX Spark). Idempotent: re-run to update.
set -euo pipefail

CASEFORGE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(dirname "$CASEFORGE_ROOT")"
GH="https://github.com/TimothyVang"

say()  { printf '\n=== %s ===\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

say "prerequisite check"
missing=0
for tool in git node npm; do have "$tool" && echo "  [ok] $tool" || { echo "  [MISS] $tool (required)"; missing=1; }; done
have bun   && echo "  [ok] bun"   || { echo "  [MISS] bun — needed to build the verdict binary (https://bun.sh)"; missing=1; }
have cargo && echo "  [ok] cargo" || { echo "  [MISS] cargo/rust — needed to build findevil-mcp (https://rustup.rs)"; missing=1; }
have uv    && echo "  [ok] uv"    || { echo "  [MISS] uv — needed for the Python forensic MCP (https://docs.astral.sh/uv/)"; missing=1; }
[ "$missing" = 0 ] || { echo; echo "Install the [MISS] tools above, then re-run."; exit 1; }

clone() { # repo
  local dir="$WORK/$1"
  if [ -d "$dir/.git" ]; then echo "  $1 present — pulling"; git -C "$dir" pull --ff-only || true
  else echo "  cloning $1"; git clone "$GH/$1.git" "$dir"; fi
}

say "1/3 verdict-opencode -> build the verdict binary"
clone verdict-opencode
( cd "$WORK/verdict-opencode" && bun install && cd packages/opencode && bun run script/build.ts --single --skip-embed-web-ui )
BIN="$(ls "$WORK"/verdict-opencode/packages/opencode/dist/*/bin/opencode 2>/dev/null | head -1 || true)"
if [ -n "$BIN" ]; then
  mkdir -p "$HOME/.local/bin"
  DEST="$HOME/.local/bin/verdict"
  rm -f "$DEST"
  install -m 755 "$BIN" "$DEST"
  echo "  installed: ~/.local/bin/verdict ($("$DEST" --version 2>/dev/null))"
else
  echo "  [warn] verdict binary not found after build"
fi

say "2/3 verdict-dfir-community -> build the forensic MCP tools"
clone verdict-dfir-community
( cd "$WORK/verdict-dfir-community" && cargo build --release -p findevil-mcp )
echo "  findevil-mcp: $([ -x "$WORK/verdict-dfir-community/target/release/findevil-mcp" ] && echo built || echo MISSING)"

say "3/3 caseforge-core -> build the harness"
( cd "$CASEFORGE_ROOT" && npm install && npm run build && node scripts/selftest.mjs )

say "done — next steps"
cat <<EOF
  export PATH="\$HOME/.local/bin:\$PATH"
  export VERDICT_DFIR_HOME="$WORK/verdict-dfir-community"
  # local model (e.g. Ollama on a DGX Spark over your LAN):
  export VERDICT_LLM_BASEURL="http://<spark-ip>:11434/v1"
  export VERDICT_LLM_MODEL="gpt-oss:20b"
  export CASEFORGE_PRIVACY="local-only"

  node "$CASEFORGE_ROOT/packages/caseforge-cli/dist/src/cli.js" doctor
  # then: caseforge investigate <case> --privacy local-only --route spark-ollama
  # see docs/DGX-SPARK.md
EOF
