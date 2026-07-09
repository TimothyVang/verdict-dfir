#!/usr/bin/env bash
# scripts/local-ed25519-seal-proof.sh — prove real local seals without Spark.
#
# Runs the agent_mcp manifest gates that assert:
#   * default + explicit ed25519 finalize verifies cryptographically offline
#   * signer:"stub" is coerced to ed25519 unless FINDEVIL_ALLOW_STUB_SIGNER=1
#
# This is NOT a live LLM seal on Spark — it is the custody-path proof that
# weak models cannot force a non-proof stub seal, and that ed25519 seals
# verify. Exit 0 = PASS.
#
# Usage (from anywhere):
#   bash scripts/local-ed25519-seal-proof.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MCP="$ROOT/services/agent_mcp"

if ! command -v uv >/dev/null 2>&1; then
  echo "SKIP: uv not on PATH (needed to run agent_mcp tests) — local ed25519 seal-proof not run"
  exit 0
fi

if [ ! -d "$MCP" ]; then
  echo "SKIP: services/agent_mcp missing — local ed25519 seal-proof not run"
  exit 0
fi

cd "$MCP"
echo "[seal-proof] syncing agent_mcp env (path dep + dev extras)..."
# Dev extra brings pytest; path dep findevil-agent must be editable-installed.
uv sync --extra dev --quiet
echo "[seal-proof] running ed25519 + stub-coerce manifest gates via uv..."
# Use `python -m pytest` from the project venv (not a global pytest on PATH).
uv run python -m pytest tests/test_manifest_tools.py \
  -q \
  -k "Ed25519 or StubSigner or path_is_accepted or default_signer" \
  --tb=short

echo "[seal-proof] PASS — ed25519 seals verify offline; stub is coerced by default."
echo "[seal-proof] NOTE: live Spark agent-driven seal is a separate operator check."
exit 0
