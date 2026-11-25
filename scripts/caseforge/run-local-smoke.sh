#!/usr/bin/env bash
# Local smoke: build + self-test + doctor + a local-only privacy check.
# Does NOT contact any model (local model quality is hardware-dependent).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
[ -f packages/caseforge-cli/dist/src/cli.js ] || npm run build
node scripts/selftest.mjs
node packages/caseforge-cli/dist/src/cli.js models --privacy local-only
node packages/caseforge-cli/dist/src/cli.js doctor || true
echo "smoke complete."
