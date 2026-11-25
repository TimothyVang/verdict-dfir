#!/usr/bin/env python3
"""Generate the demo-video narration with Piper (local, ONNX, Apache-2.0).

Reads the canonical per-beat narration from beats-data.ts and writes one
public/audio/beat_NN.mp3 per beat using the Piper voice (default: the natural
female en_US-amy-medium). Replaces the old edge-tts path so the voiceover is a
local, human-sounding model instead of the cloud Aria voice.

Prereqs (small + easy — no PyTorch):
    pip install piper-tts          # ~14 MB package + onnxruntime
The voice model is downloaded to a local cache on first run.

Env overrides:
    PIPER_BIN     path to the piper executable (default: `piper` on PATH)
    PIPER_MODEL   path to a .onnx voice (default: cached en_US-amy-medium)
    PIPER_VOICE   HF voice id to fetch if PIPER_MODEL is unset
                  (default: en_US-amy-medium)
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BEATS_DIR = ROOT / "scripts/make-demo-video/src/beats"
BEATS_TS = BEATS_DIR / "beats-data.ts"
AUDIO_ROOT = ROOT / "scripts/make-demo-video/public/audio"
CACHE = ROOT / "scripts/make-demo-video/.tts-cache"
HF_BASE = "https://huggingface.co/rhasspy/piper-voices/resolve/main/en/en_US"
VOICE_PATHS = {  # HF id -> repo sub-path
    "en_US-amy-medium": "amy/medium/en_US-amy-medium",
    "en_US-ryan-high": "ryan/high/en_US-ryan-high",
    "en_US-lessac-high": "lessac/high/en_US-lessac-high",
    "en_US-hfc_female-medium": "hfc_female/medium/en_US-hfc_female-medium",
}


def extract_narrations(beats_ts: Path) -> list[str]:
    """Pull every narration string from a beats file in beat order."""
    text = beats_ts.read_text(encoding="utf-8")
    narrs = re.findall(r'narration:\s*"((?:[^"\\]|\\.)*)"', text, re.DOTALL)
    if not narrs:
        raise SystemExit(f"no narrations found in {beats_ts}")
    return narrs


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate per-beat narration MP3s with Piper.",
    )
    parser.add_argument(
        "--beats-file",
        default=str(BEATS_TS),
        help="TS beats file to read narration from (default: the showcase beats-data.ts). "
        "Accepts an absolute path or a name relative to src/beats/.",
    )
    parser.add_argument(
        "--audio-subdir",
        default="",
        help="Subdirectory under public/audio/ to write into (default: the showcase "
        "root). Use one per additional video, e.g. 'explainer'.",
    )
    return parser.parse_args()


def resolve_beats_file(value: str) -> Path:
    candidate = Path(value)
    if not candidate.is_absolute():
        # allow a bare filename relative to the beats directory
        rel = BEATS_DIR / value
        candidate = rel if rel.exists() else (ROOT / value)
    if not candidate.exists():
        raise SystemExit(f"beats file not found: {candidate}")
    return candidate


def resolve_piper() -> str:
    for cand in (
        os.environ.get("PIPER_BIN"),
        shutil.which("piper"),
        "/tmp/piper-venv/bin/piper",
    ):
        if cand and Path(cand).exists():
            return cand
    raise SystemExit("piper not found. Install it: pip install piper-tts")


def resolve_model() -> Path:
    env = os.environ.get("PIPER_MODEL")
    if env:
        return Path(env)
    voice = os.environ.get("PIPER_VOICE", "en_US-amy-medium")
    sub = VOICE_PATHS.get(voice)
    if not sub:
        raise SystemExit(f"unknown PIPER_VOICE {voice}; known: {list(VOICE_PATHS)}")
    CACHE.mkdir(parents=True, exist_ok=True)
    onnx = CACHE / f"{voice}.onnx"
    if not onnx.exists():
        for ext in (".onnx", ".onnx.json"):
            url = f"{HF_BASE}/{sub}{ext}"
            dst = CACHE / f"{voice}{ext}"
            print(f"  downloading {url}")
            urllib.request.urlretrieve(url, dst)
    return onnx


def main() -> int:
    args = parse_args()
    beats_ts = resolve_beats_file(args.beats_file)
    audio_out = AUDIO_ROOT / args.audio_subdir if args.audio_subdir else AUDIO_ROOT
    piper = resolve_piper()
    model = resolve_model()
    audio_out.mkdir(parents=True, exist_ok=True)
    CACHE.mkdir(parents=True, exist_ok=True)
    narrations = extract_narrations(beats_ts)
    print(
        f"piper: {piper}\nvoice: {model.name}\nbeats: {beats_ts.name} -> {audio_out}\n"
    )
    # amy speaks a touch slower than the old cloud voice; 0.9 keeps every beat
    # within its on-screen time budget. Override with PIPER_LENGTH_SCALE.
    length_scale = os.environ.get("PIPER_LENGTH_SCALE", "0.9")
    for i, narr in enumerate(narrations, 1):
        wav = CACHE / f"beat_{i:02d}.wav"
        subprocess.run(
            [piper, "-m", str(model), "--length-scale", length_scale, "-f", str(wav)],
            input=narr,
            text=True,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        mp3 = audio_out / f"beat_{i:02d}.mp3"
        subprocess.run(
            ["ffmpeg", "-y", "-loglevel", "error", "-i", str(wav), str(mp3)], check=True
        )
        dur = subprocess.run(
            [
                "ffprobe",
                "-v",
                "error",
                "-show_entries",
                "format=duration",
                "-of",
                "default=noprint_wrappers=1:nokey=1",
                str(mp3),
            ],
            capture_output=True,
            text=True,
        ).stdout.strip()
        print(f"  beat {i}: {mp3.name}  ({float(dur):.1f}s)")
    print("\ndone — re-render with: bash scripts/make-demo-video.sh --skip-tts")
    return 0


if __name__ == "__main__":
    sys.exit(main())
