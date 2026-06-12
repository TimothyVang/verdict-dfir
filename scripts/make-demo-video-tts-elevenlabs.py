#!/usr/bin/env python3
"""Generate the demo-video narration with ElevenLabs (cloud, natural voices).

A drop-in alternative to the local Piper path (make-demo-video-tts.py) when a
more natural voice is wanted. Reads the canonical per-beat narration from
beats-data.ts and writes one public/audio/beat_NN.mp3 per beat, then gently
speed-fits any beat whose audio would overrun its on-screen time budget
(startS..endS) so the render never clips the end of a line.

The API key is read from the environment ONLY — never hardcoded, never committed:
    ELEVENLABS_API_KEY    required  (export ELEVENLABS_API_KEY="$(cat ~/.elevenlabs_key)")
    ELEVENLABS_VOICE_ID   default EXAVITQu4vr4xnSDxMaL  (Sarah — mature, confident)
    ELEVENLABS_MODEL_ID   default eleven_multilingual_v2

Then render with:  bash scripts/make-demo-video.sh --skip-tts
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BEATS_TS = ROOT / "scripts/make-demo-video/src/beats/beats-data.ts"
AUDIO_OUT = ROOT / "scripts/make-demo-video/public/audio"
API = "https://api.elevenlabs.io/v1/text-to-speech"
DEFAULT_VOICE = "EXAVITQu4vr4xnSDxMaL"  # Sarah — mature, reassuring, confident
DEFAULT_MODEL = "eleven_v3"  # newest / most expressive; override with ELEVENLABS_MODEL_ID
FIT_MARGIN_S = 0.4   # leave a little headroom at the end of each beat slot
MAX_SPEEDUP = 1.6    # never rush a line faster than this (atempo)


def _beats() -> list[tuple[int, int, str]]:
    """Return (startS, endS, narration) per beat, in order, from beats-data.ts."""
    text = BEATS_TS.read_text(encoding="utf-8")
    starts = [int(x) for x in re.findall(r"\bstartS:\s*(\d+)", text)]
    ends = [int(x) for x in re.findall(r"\bendS:\s*(\d+)", text)]
    narrs = re.findall(r'narration:\s*"((?:[^"\\]|\\.)*)"', text, re.DOTALL)
    if not (len(starts) == len(ends) == len(narrs)):
        raise SystemExit(
            f"beat fields misaligned in {BEATS_TS}: "
            f"{len(starts)} startS, {len(ends)} endS, {len(narrs)} narration"
        )
    clean = [re.sub(r"\s+", " ", n.replace('\\"', '"')).strip() for n in narrs]
    return list(zip(starts, ends, clean))


def _duration_s(path: Path) -> float:
    out = subprocess.run(
        ["ffprobe", "-v", "error", "-show_entries", "format=duration",
         "-of", "default=noprint_wrappers=1:nokey=1", str(path)],
        capture_output=True, text=True,
    ).stdout.strip()
    return float(out) if out else 0.0


def _synth(text: str, voice: str, model: str, key: str, dst: Path) -> None:
    body = json.dumps({
        "text": text,
        "model_id": model,
        "voice_settings": {
            "stability": 0.5,
            "similarity_boost": 0.8,
            "style": 0.0,
            "use_speaker_boost": True,
        },
    }).encode("utf-8")
    req = urllib.request.Request(
        f"{API}/{voice}",
        data=body,
        method="POST",
        headers={
            "xi-api-key": key,
            "Content-Type": "application/json",
            "Accept": "audio/mpeg",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=180) as resp:  # noqa: S310 (fixed host)
            audio = resp.read()
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:300]
        raise SystemExit(f"ElevenLabs HTTP {exc.code}: {detail}")
    if len(audio) < 2000:
        raise SystemExit(f"suspiciously small audio ({len(audio)} bytes) for: {text[:60]!r}")
    dst.write_bytes(audio)


def _fit_to_budget(mp3: Path, budget_s: float) -> tuple[float, float | None]:
    """Speed up `mp3` in place if it overruns `budget_s`. Returns (final_dur, tempo)."""
    dur = _duration_s(mp3)
    target = budget_s - FIT_MARGIN_S
    if dur <= target or target <= 0:
        return dur, None
    tempo = min(dur / target, MAX_SPEEDUP)
    tmp = mp3.with_suffix(".fit.mp3")
    subprocess.run(
        ["ffmpeg", "-y", "-loglevel", "error", "-i", str(mp3),
         "-filter:a", f"atempo={tempo:.4f}", str(tmp)],
        check=True,
    )
    tmp.replace(mp3)
    return _duration_s(mp3), tempo


def main() -> int:
    key = os.environ.get("ELEVENLABS_API_KEY")
    if not key:
        raise SystemExit(
            "ELEVENLABS_API_KEY not set — export ELEVENLABS_API_KEY=\"$(cat ~/.elevenlabs_key)\""
        )
    voice = os.environ.get("ELEVENLABS_VOICE_ID", DEFAULT_VOICE)
    model = os.environ.get("ELEVENLABS_MODEL_ID", DEFAULT_MODEL)
    AUDIO_OUT.mkdir(parents=True, exist_ok=True)
    beats = _beats()
    print(f"elevenlabs: voice={voice} model={model}  ({len(beats)} beats)\n")
    for i, (start, end, narr) in enumerate(beats, 1):
        mp3 = AUDIO_OUT / f"beat_{i:02d}.mp3"
        _synth(narr, voice, model, key, mp3)
        dur, tempo = _fit_to_budget(mp3, float(end - start))
        fit = f"  (fit ×{tempo:.2f} to {end - start}s slot)" if tempo else ""
        print(f"  beat {i}: {mp3.name}  ({dur:.1f}s){fit}")
    print("\ndone — re-render with: bash scripts/make-demo-video.sh --skip-tts")
    return 0


if __name__ == "__main__":
    sys.exit(main())
