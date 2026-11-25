#!/usr/bin/env bash
# PLANNED (Phase 3): start the LiteLLM universal gateway.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
echo "caseforge: LiteLLM gateway is planned (Phase 3)."
echo "Template config: $ROOT/configs/llm-gateway.litellm.yaml"
echo "When implemented, this will run: litellm --config configs/llm-gateway.litellm.yaml"
exit 3
