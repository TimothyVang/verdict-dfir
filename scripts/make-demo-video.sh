#!/usr/bin/env bash
# scripts/make-demo-video.sh — Render a VERDICT video via Remotion.
#
# Stages (per video):
#   1. TTS prep  — scripts/make-demo-video-tts.py generates beat MP3 files
#   2. Remotion  — npx remotion render produces the final MP4
#
# Usage:
#   bash scripts/make-demo-video.sh [options]
#
# Options:
#   --composition ID     Remotion composition to render (default: FindEvilDemo).
#                        One of: FindEvilDemo, EducationalExplainer,
#                        FeatureDeepDives, Quickstart, ContributorCall.
#   --beats-file PATH    Beats .ts file the TTS step reads (default: matches the
#                        composition; bare name resolved under src/beats/).
#   --audio-subdir NAME  public/audio/<NAME>/ subdir for this video's narration
#                        (default: matches the composition).
#   --all                Render the whole slate (showcase + 4 additional videos).
#   --dry-run            Print the plan without generating audio or video.
#   --skip-tts           Skip TTS generation (use existing MP3s).
#   --voice NAME         reserved for legacy compatibility; Piper uses PIPER_VOICE
#   --out PATH           Output MP4 path (default: derived from the composition).
#   --preview            Render first 90 frames only to /tmp/<id>-preview.mp4
#
# Prerequisites:
#   pip install piper-tts         (TTS generation)
#   pnpm install --dir scripts/make-demo-video --ignore-workspace  (first run)
#
# Examples:
#   bash scripts/make-demo-video.sh                       # the showcase
#   bash scripts/make-demo-video.sh --composition Quickstart
#   bash scripts/make-demo-video.sh --all

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REMOTION_DIR="${REPO}/scripts/make-demo-video"

COMPOSITION="FindEvilDemo"
BEATS_FILE=""
AUDIO_SUBDIR=""
OUT=""
VOICE="en-US-AriaNeural"
DRY_RUN=false
SKIP_TTS=false
PREVIEW=false
RENDER_ALL=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --composition) COMPOSITION="$2"; shift ;;
    --beats-file)  BEATS_FILE="$2"; shift ;;
    --audio-subdir) AUDIO_SUBDIR="$2"; shift ;;
    --out)         OUT="$2"; shift ;;
    --voice)       VOICE="$2"; shift ;;
    --all)         RENDER_ALL=true ;;
    --dry-run)     DRY_RUN=true ;;
    --skip-tts)    SKIP_TTS=true ;;
    --preview)     PREVIEW=true ;;
    *) echo "Unknown flag: $1"; exit 1 ;;
  esac
  shift
done

# Defaults derived from the composition id: beats file, audio subdir, output.
# Format: "composition|beats-file|audio-subdir|out-basename"
defaults_for() {
  case "$1" in
    FindEvilDemo)          echo "beats-data.ts||find-evil-demo.mp4" ;;
    EducationalExplainer)  echo "explainer-beats.ts|explainer|verdict-educational-explainer.mp4" ;;
    FeatureDeepDives)      echo "deepdive-beats.ts|deepdive|verdict-feature-deep-dives.mp4" ;;
    Quickstart)            echo "quickstart-beats.ts|quickstart|verdict-quickstart.mp4" ;;
    ContributorCall)       echo "contributor-beats.ts|contributor|verdict-contributor-call.mp4" ;;
    *) echo ""; ;;
  esac
}

ensure_remotion_deps() {
  if [[ ! -d "${REMOTION_DIR}/node_modules" ]]; then
    pnpm install --dir "${REMOTION_DIR}" --ignore-workspace
  else
    echo "[make-demo-video]   node_modules present, skipping install"
  fi
}

# render_video <composition> <beats-file> <audio-subdir> <out-path>
render_video() {
  local comp="$1" beats="$2" subdir="$3" out="$4"
  echo ""
  echo "[make-demo-video] === ${comp} ==="
  echo "[make-demo-video] Output: ${out}"

  if $DRY_RUN; then
    echo "[make-demo-video] DRY-RUN: scripts/make-demo-video-tts.py (Piper) beats=${beats:-<default>} subdir=${subdir:-<root>}"
    echo "[make-demo-video] DRY-RUN: remotion render ${comp} -> ${out}"
    return 0
  fi

  if ! $SKIP_TTS; then
    local tts_args=()
    [[ -n "$beats" ]] && tts_args+=(--beats-file "$beats")
    [[ -n "$subdir" ]] && tts_args+=(--audio-subdir "$subdir")
    if [[ "${TTS_ENGINE:-piper}" == "elevenlabs" ]]; then
      echo "[make-demo-video] Stage 1: TTS audio (ElevenLabs)"
      python3 "${REPO}/scripts/make-demo-video-tts-elevenlabs.py" "${tts_args[@]}"
    else
      echo "[make-demo-video] Stage 1: TTS audio (Piper)"
      python3 "${REPO}/scripts/make-demo-video-tts.py" "${tts_args[@]}"
    fi
  else
    echo "[make-demo-video] Stage 1: --skip-tts, using existing MP3s"
  fi

  echo "[make-demo-video] Stage 2: Remotion render"
  if $PREVIEW; then
    "${REMOTION_DIR}/node_modules/.bin/remotion" render \
      "${REMOTION_DIR}/src/Root.tsx" "${comp}" \
      --output "/tmp/${comp}-preview.mp4" \
      --codec h264 \
      --public-dir "${REMOTION_DIR}/public" \
      --frames 0-89
    echo "[make-demo-video] Preview written to /tmp/${comp}-preview.mp4"
  else
    "${REMOTION_DIR}/node_modules/.bin/remotion" render \
      "${REMOTION_DIR}/src/Root.tsx" "${comp}" \
      --output "${out}" \
      --codec h264 \
      --public-dir "${REMOTION_DIR}/public"
    local size
    size=$(du -sh "${out}" | cut -f1)
    echo "[make-demo-video] Done: ${out} (${size})"
  fi
}

echo "[make-demo-video] VERDICT demo video builder"

if ! $DRY_RUN; then
  echo "[make-demo-video] Remotion dependencies"
  ensure_remotion_deps
fi

if $RENDER_ALL; then
  for comp in FindEvilDemo EducationalExplainer FeatureDeepDives Quickstart ContributorCall; do
    IFS='|' read -r d_beats d_subdir d_out <<<"$(defaults_for "$comp")"
    render_video "$comp" "$d_beats" "$d_subdir" "${REPO}/docs/${d_out}"
  done
  echo ""
  echo "[make-demo-video] Slate complete. Outputs under ${REPO}/docs/"
  exit 0
fi

# Single composition. Fill unset args from the composition defaults.
DEFAULTS="$(defaults_for "$COMPOSITION")"
if [[ -z "$DEFAULTS" ]]; then
  echo "Unknown --composition: ${COMPOSITION}" >&2
  exit 1
fi
IFS='|' read -r D_BEATS D_SUBDIR D_OUT <<<"$DEFAULTS"
[[ -z "$BEATS_FILE" ]] && BEATS_FILE="$D_BEATS"
[[ -z "$AUDIO_SUBDIR" ]] && AUDIO_SUBDIR="$D_SUBDIR"
[[ -z "$OUT" ]] && OUT="${REPO}/docs/${D_OUT}"

render_video "$COMPOSITION" "$BEATS_FILE" "$AUDIO_SUBDIR" "$OUT"

if ! $DRY_RUN && ! $PREVIEW; then
  echo ""
  echo "Next steps:"
  echo "  1. Review: vlc ${OUT}"
  echo "  2. Upload to YouTube or Vimeo"
  echo "  3. Register URL (showcase only):"
  echo "       gh variable set DEMO_VIDEO_URL --body 'https://youtu.be/<id>'"
fi
