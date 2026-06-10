#!/usr/bin/env bash
set -euo pipefail

PORT="${1:-3000}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CODEX_URL="http://localhost:${PORT}/codex"
LOG_DIR="${TMPDIR:-/tmp}/opencode"
OUT_LOG="${LOG_DIR}/findevil-codex-dashboard.out"
ERR_LOG="${LOG_DIR}/findevil-codex-dashboard.err"

mkdir -p "$LOG_DIR"

is_up() {
  python - "$CODEX_URL" <<'PY'
import sys
import urllib.request

try:
    with urllib.request.urlopen(sys.argv[1], timeout=3) as response:
        raise SystemExit(0 if response.status == 200 else 1)
except Exception:
    raise SystemExit(1)
PY
}

if ! is_up; then
  (
    cd "$REPO_ROOT"
    FINDEVIL_CODEX_UI_ENABLE=1 pnpm --filter @findevil/web dev -- --port "$PORT" >"$OUT_LOG" 2>"$ERR_LOG" &
  )

  for _ in $(seq 1 30); do
    if is_up; then
      break
    fi
    sleep 0.5
  done
fi

if ! is_up; then
  printf 'Find Evil dashboard did not start. Logs: %s %s\n' "$OUT_LOG" "$ERR_LOG" >&2
  exit 1
fi

if command -v xdg-open >/dev/null 2>&1; then
  xdg-open "$CODEX_URL" >/dev/null 2>&1 || true
elif command -v open >/dev/null 2>&1; then
  open "$CODEX_URL" >/dev/null 2>&1 || true
fi

printf 'Dashboard is running:\n'
printf -- '- Codex cockpit: %s\n' "$CODEX_URL"
printf -- '- Audit dashboard: http://localhost:%s/\n' "$PORT"
printf -- '- Debug stream: http://localhost:%s/debug\n' "$PORT"
printf -- '- Logs: %s %s\n' "$OUT_LOG" "$ERR_LOG"
