#!/usr/bin/env bash
# One-shot setup: install deps, build packages, run the self-test.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
npm install
npm run build
node scripts/selftest.mjs
echo "bootstrap complete. Next: set VERDICT_DFIR_HOME and run scripts/doctor.sh"
