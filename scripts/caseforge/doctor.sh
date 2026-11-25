#!/usr/bin/env bash
# Thin wrapper: build if needed, then run `caseforge doctor`.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[ -f "$ROOT/packages/caseforge-cli/dist/src/cli.js" ] || (cd "$ROOT" && npm run build)
exec node "$ROOT/packages/caseforge-cli/dist/src/cli.js" doctor
