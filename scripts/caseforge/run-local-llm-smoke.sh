#!/usr/bin/env bash
# Local LLM smoke: run Caseforge against the small dev evidence case.
#
# Defaults to ../dev/evidence/DE_1102_security_log_cleared.evtx, a staged
# known-good 1.1 MiB EVTX case with a single high-signal Security EID 1102
# event. Override CASEFORGE_DEV_EVIDENCE_PATH for another local case.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEFAULT_EVIDENCE="$ROOT/../dev/evidence/DE_1102_security_log_cleared.evtx"
EVIDENCE_PATH="${CASEFORGE_DEV_EVIDENCE_PATH:-$DEFAULT_EVIDENCE}"

cd "$ROOT"

if [ ! -e "$EVIDENCE_PATH" ]; then
  echo "dev evidence not found: $EVIDENCE_PATH" >&2
  echo "Set CASEFORGE_DEV_EVIDENCE_PATH to a small local evidence file or directory." >&2
  exit 2
fi
EVIDENCE_PATH="$(cd "$(dirname "$EVIDENCE_PATH")" && pwd)/$(basename "$EVIDENCE_PATH")"

npm run build
node scripts/selftest.mjs

exec node packages/caseforge-cli/dist/src/cli.js investigate "$EVIDENCE_PATH" \
  --privacy local-only \
  --evidence sensitive \
  --route "${CASEFORGE_LOCAL_ROUTE:-spark-ollama}"
