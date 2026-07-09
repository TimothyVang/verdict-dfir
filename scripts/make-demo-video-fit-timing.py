#!/usr/bin/env python3
"""Fit a beats file's per-beat slot timing to its narration audio.

Each beat plays its narration MP3 at the start of a fixed startS..endS slot; if
the slot is longer than the audio, the video holds in silence (dead air). This
rewrites startS/endS so every slot = ceil(audio) + TAIL seconds, contiguous from
zero — removing the long trailing silences while leaving a natural ~1s breath.

Audio is read from public/audio/<subdir>/beat_NN.mp3 (the TTS output). The .ts
file is edited in place: only integer `startS:`/`endS:` literals are touched
(the `startS: number;` interface fields use no integer, so they're never
matched).

Usage:
    python3 scripts/make-demo-video-fit-timing.py --beats-file <name.ts> \\
        --audio-subdir <prefix> [--tail 1]
"""

from __future__ import annotations

import argparse
import math
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BEATS_DIR = ROOT / "scripts/make-demo-video/src/beats"
AUDIO_ROOT = ROOT / "scripts/make-demo-video/public/audio"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--beats-file", required=True, help="name under src/beats/ or a path"
    )
    parser.add_argument(
        "--audio-subdir", required=True, help="subdir under public/audio/"
    )
    parser.add_argument(
        "--tail",
        type=float,
        default=1.0,
        help="seconds of breathing room after speech ends (default: 1.0)",
    )
    return parser.parse_args()


def resolve_beats_file(value: str) -> Path:
    candidate = Path(value)
    if not candidate.is_absolute():
        rel = BEATS_DIR / value
        candidate = rel if rel.exists() else (ROOT / value)
    if not candidate.exists():
        raise SystemExit(f"beats file not found: {candidate}")
    return candidate


def audio_duration(path: Path) -> float:
    out = subprocess.run(
        [
            "ffprobe",
            "-v",
            "error",
            "-show_entries",
            "format=duration",
            "-of",
            "default=noprint_wrappers=1:nokey=1",
            str(path),
        ],
        capture_output=True,
        text=True,
    ).stdout.strip()
    if not out:
        raise SystemExit(f"could not read duration: {path}")
    return float(out)


def main() -> int:
    args = parse_args()
    beats_ts = resolve_beats_file(args.beats_file)
    audio_dir = AUDIO_ROOT / args.audio_subdir
    text = beats_ts.read_text(encoding="utf-8")

    beat_count = len(re.findall(r"\bstartS:\s*\d+,", text))
    if beat_count == 0:
        raise SystemExit(f"no integer startS slots in {beats_ts}")

    # Measure each beat's narration and build new contiguous slots.
    starts: list[int] = []
    ends: list[int] = []
    cursor = 0
    for i in range(1, beat_count + 1):
        mp3 = audio_dir / f"beat_{i:02d}.mp3"
        if not mp3.exists():
            raise SystemExit(f"missing narration: {mp3}")
        slot = math.ceil(audio_duration(mp3) + args.tail)
        starts.append(cursor)
        cursor += slot
        ends.append(cursor)

    # Replace the integer startS:/endS: literals in document order.
    start_iter = iter(starts)
    end_iter = iter(ends)
    new_text = re.sub(
        r"\bstartS:\s*\d+,", lambda _m: f"startS: {next(start_iter)},", text
    )
    new_text = re.sub(
        r"\bendS:\s*\d+,", lambda _m: f"endS: {next(end_iter)},", new_text
    )

    beats_ts.write_text(new_text, encoding="utf-8")
    for i, (s, e) in enumerate(zip(starts, ends), 1):
        print(f"  beat {i}: {s:>4}s -> {e:>4}s  ({e - s}s slot)")
    print(f"  total: {ends[-1]}s  ({beats_ts.name})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
