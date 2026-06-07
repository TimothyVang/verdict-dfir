#!/usr/bin/env bash
# verdict-banner.sh — prints the VERDICT launch banner to stdout. Shared by the
# SessionStart hook (scripts/session-suggest.sh, which redirects it to stderr) and
# the claude wrapper (scripts/claude, which prints it before launching the CLI), so
# the banner text lives in exactly one place. Inspects evidence/ to pick setup vs
# run prompts. Writes nothing else; always exits 0.

set -euo pipefail
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EVIDENCE_DIR="${REPO_ROOT}/evidence"
MCP_BIN="${REPO_ROOT}/services/mcp/target/release/findevil-mcp"

# newest non-placeholder entry (file OR case folder) in evidence/; empty if none.
# Same filter as scripts/verdict so "evidence present" means one thing everywhere.
newest_evidence() {
  ls -dt "${EVIDENCE_DIR}"/* 2>/dev/null | grep -vE '/(README\.md|\.gitkeep)$' | head -1 || true
}

EVIDENCE="$(newest_evidence)"

if [[ -n "${EVIDENCE}" ]]; then
  printf '%s\n' \
    "" \
    "  VERDICT — DFIR at machine speed" \
    "  ───────────────────────────────────────────────" \
    "  Evidence detected: ${EVIDENCE}" \
    "    investigate ${EVIDENCE}     run the full DFIR pipeline interactively" \
    "    bash scripts/verdict ${EVIDENCE}   headless end-to-end run" \
    "  Live dashboard: http://localhost:3000" \
    ""
else
  printf '%s\n' \
    "" \
    "  VERDICT — DFIR at machine speed" \
    "  ───────────────────────────────────────────────" \
    "  No evidence uploaded yet. To get started:" \
    "    1. Drop an evidence file (pcap / memory / disk / .evtx / case folder) into evidence/" \
    "       or run: bash scripts/verdict --watch   to wait for a drop" \
    "    2. Then: investigate <path>"
  [[ ! -x "${MCP_BIN}" ]] && printf '%s\n' \
    "    Note: MCP server not built — run: bash scripts/install.sh first"
  printf '%s\n' \
    "  Type help for the full command reference." \
    ""
fi

exit 0
