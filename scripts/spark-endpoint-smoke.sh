#!/usr/bin/env bash
# scripts/spark-endpoint-smoke.sh — soft reachability check for the Spark/Ollama LLM endpoint.
#
# GETs ${VERDICT_LLM_BASEURL:-http://10.126.60.100:11434}/api/tags with a short timeout.
# Exit 0 always:
#   * PASS + model names when the endpoint answers
#   * SKIP when unreachable or curl is missing (Spark offline must not fail CI)
#
# Usage (from anywhere):
#   bash scripts/spark-endpoint-smoke.sh
#   VERDICT_LLM_BASEURL=http://127.0.0.1:11434 bash scripts/spark-endpoint-smoke.sh
set -euo pipefail

BASE="${VERDICT_LLM_BASEURL:-http://10.126.60.100:11434}"
# Strip trailing slash so we never double-slash /api/tags.
BASE="${BASE%/}"
URL="${BASE}/api/tags"
CONNECT_TIMEOUT=2
MAX_TIME=3

if ! command -v curl >/dev/null 2>&1; then
  echo "SKIP: spark endpoint smoke — curl not on PATH"
  exit 0
fi

body=""
http_code=""
if ! body=$(curl -fsS \
  --connect-timeout "${CONNECT_TIMEOUT}" \
  --max-time "${MAX_TIME}" \
  -w "\n%{http_code}" \
  "${URL}" 2>/dev/null); then
  echo "SKIP: spark endpoint unreachable at ${URL} (offline Spark is not a CI failure)"
  exit 0
fi

# curl -w appends the status code on the last line.
http_code=$(printf '%s\n' "${body}" | tail -n1)
body=$(printf '%s\n' "${body}" | sed '$d')

if [ "${http_code}" != "200" ]; then
  echo "SKIP: spark endpoint returned HTTP ${http_code} at ${URL} (not a CI failure)"
  exit 0
fi

echo "PASS: spark endpoint reachable (${BASE})"

# Print model names when the Ollama-style {"models":[{"name":"..."}]} payload is present.
if command -v python3 >/dev/null 2>&1; then
  printf '%s' "${body}" | python3 -c '
import json, sys
try:
    data = json.load(sys.stdin)
except Exception:
    sys.exit(0)
models = data.get("models") if isinstance(data, dict) else None
if not isinstance(models, list) or not models:
    print("  (no models listed in /api/tags)")
    sys.exit(0)
print("  models:")
for m in models:
    if isinstance(m, dict):
        name = m.get("name") or m.get("model") or "?"
    else:
        name = str(m)
    print(f"    - {name}")
' || true
elif command -v jq >/dev/null 2>&1; then
  names=$(printf '%s' "${body}" | jq -r '.models[]?.name // empty' 2>/dev/null || true)
  if [ -n "${names}" ]; then
    echo "  models:"
    while IFS= read -r name; do
      [ -n "${name}" ] && echo "    - ${name}"
    done <<< "${names}"
  else
    echo "  (no models listed in /api/tags)"
  fi
else
  echo "  (response received; install python3 or jq to list model names)"
fi

exit 0
