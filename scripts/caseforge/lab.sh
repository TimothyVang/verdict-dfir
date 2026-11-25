#!/usr/bin/env bash
#
# lab.sh — a tmux session preloaded to run caseforge investigations.
#
# Attach to watch/drive live, screenshot the terminal, or record with asciinema.
# Reproducible on any box (laptop, SIFT, DGX Spark). Idempotent.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SESSION="${CASEFORGE_TMUX:-caseforge-lab}"
DFIR="${VERDICT_DFIR_HOME:-$(dirname "$ROOT")/dev}"

if ! tmux has-session -t "$SESSION" 2>/dev/null; then
  tmux new-session -d -s "$SESSION" -c "$ROOT" -x 210 -y 50
  tmux setenv -t "$SESSION" COLORTERM truecolor
  # Environment for runs (edit for local/offline: VERDICT_LLM_BASEURL / VERDICT_LLM_MODEL + --route spark-ollama)
  tmux send-keys -t "$SESSION" "export PATH=\"$ROOT/bin:\$HOME/.local/bin:\$PATH\"" C-m
  tmux send-keys -t "$SESSION" "export VERDICT_DFIR_HOME=\"$DFIR\"" C-m
  tmux send-keys -t "$SESSION" "export CASEFORGE_PRIVACY=\"\${CASEFORGE_PRIVACY:-local-only}\"" C-m
  tmux send-keys -t "$SESSION" "clear; caseforge doctor" C-m
fi

cat <<EOF
caseforge lab ready — tmux session: ${SESSION}   (toolkit: ${DFIR})

  Attach:    tmux attach -t ${SESSION}          (detach: Ctrl-b then d)
  Run:       caseforge auth login --method headless
             caseforge investigate <evidence> --privacy cloud-ok --evidence synthetic --route chatgpt-oauth
             caseforge verify <run-dir>
             caseforge models   |   caseforge doctor
  Record:    asciinema rec ${ROOT}/demo.cast    (run inside the session; Ctrl-d to stop; play: asciinema play demo.cast)
  Snapshot:  tmux capture-pane -t ${SESSION} -p   (text)   ·   screenshot the terminal window (image)
  Kill:      tmux kill-session -t ${SESSION}
EOF
