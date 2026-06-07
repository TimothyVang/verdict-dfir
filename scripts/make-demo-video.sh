#!/usr/bin/env bash
# scripts/make-demo-video.sh — Generate docs/find-evil-demo.mp4 via Remotion.
#
# Stages:
#   1. TTS prep  — scripts/make-demo-video-prep.py generates beat MP3 files
#   2. Remotion  — npx remotion render produces the final MP4
#
# Usage:
#   bash scripts/make-demo-video.sh [options]
#
# Options:
#   --dry-run            Print beat plan without generating audio or video
#   --skip-tts           Skip TTS generation (use existing MP3s in src/audio/)
#   --voice NAME         edge-tts voice (default: en-US-AriaNeural)
#   --out PATH           Output MP4 path (default: docs/find-evil-demo.mp4)
#   --preview            Render first 90 frames only to /tmp/find-evil-preview.mp4
#
# Prerequisites:
#   pip install edge-tts          (TTS generation)
#   pnpm install --prefix scripts/make-demo-video  (Remotion deps, first run only)
#   # claude CLI on PATH → narration auto-enriched via `claude -p` (uses your session token)
#
# Example:
#   (no setup needed — just have `claude` on PATH)
#   bash scripts/make-demo-video.sh

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REMOTION_DIR="${REPO}/scripts/make-demo-video"
OUT="${REPO}/docs/find-evil-demo.mp4"
VOICE="en-US-AriaNeural"
DRY_RUN=false
SKIP_TTS=false
PREVIEW=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)    DRY_RUN=true ;;
    --skip-tts)   SKIP_TTS=true ;;
    --voice)      VOICE="$2"; shift ;;
    --out)        OUT="$2"; shift ;;
    --preview)    PREVIEW=true ;;
    *) echo "Unknown flag: $1"; exit 1 ;;
  esac
  shift
done

echo "[make-demo-video] SANS Find Evil! demo video builder"
echo "[make-demo-video] Output: ${OUT}"

# --- Stage 1: TTS prep ---
if $DRY_RUN; then
  python3 "${REPO}/scripts/make-demo-video-prep.py" --dry-run --voice "${VOICE}"
  echo "[make-demo-video] --dry-run complete"
  exit 0
fi

if ! $SKIP_TTS; then
  echo ""
  echo "[make-demo-video] Stage 1: TTS audio generation"
  python3 "${REPO}/scripts/make-demo-video-prep.py" --voice "${VOICE}"
else
  echo "[make-demo-video] Stage 1: --skip-tts, using existing MP3s"
fi

# --- Stage 2: Remotion install (idempotent) ---
echo ""
echo "[make-demo-video] Stage 2: Remotion dependencies"
if [[ ! -d "${REMOTION_DIR}/node_modules" ]]; then
  pnpm install --dir "${REMOTION_DIR}" --ignore-workspace
else
  echo "[make-demo-video]   node_modules present, skipping install"
fi

# --- Stage 3: Render ---
echo ""
echo "[make-demo-video] Stage 3: Remotion render"
if $PREVIEW; then
  "${REMOTION_DIR}/node_modules/.bin/remotion" render \
    "${REMOTION_DIR}/src/Root.tsx" FindEvilDemo \
    --output /tmp/find-evil-preview.mp4 \
    --codec h264 \
    --public-dir "${REMOTION_DIR}/public" \
    --frames 0-89
  echo "[make-demo-video] Preview written to /tmp/find-evil-preview.mp4"
else
  "${REMOTION_DIR}/node_modules/.bin/remotion" render \
    "${REMOTION_DIR}/src/Root.tsx" FindEvilDemo \
    --output "${OUT}" \
    --codec h264 \
    --public-dir "${REMOTION_DIR}/public"
  SIZE=$(du -sh "${OUT}" | cut -f1)
  echo ""
  echo "[make-demo-video] Done: ${OUT} (${SIZE})"
  echo ""
  echo "Next steps:"
  echo "  1. Review: vlc ${OUT}"
  echo "  2. Upload to YouTube or Vimeo"
  echo "  3. Register URL:"
  echo "       gh variable set DEMO_VIDEO_URL --body 'https://youtu.be/<id>'"
fi
