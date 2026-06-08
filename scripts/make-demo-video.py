#!/usr/bin/env python3
"""Automated demo video builder for the SANS Find Evil! submission.

Generates docs/find-evil-demo.mp4 from the beat structure in
docs/demo-script-a2.md using TTS (edge-tts) + ffmpeg title cards.

Usage:
    python3 scripts/make-demo-video.py [--dry-run] [--out PATH] [--voice VOICE]

Flags:
    --dry-run     Print beat plan without invoking ffmpeg or edge-tts.
    --out PATH    Output MP4 path (default: docs/find-evil-demo.mp4).
    --voice NAME  edge-tts voice (default: en-US-AriaNeural).

Dependencies:
    - ffmpeg (system binary; checked at startup)
    - edge-tts (pip install edge-tts; checked at startup)
    - openai (optional; used only if GITHUB_TOKEN env var is set for
              narration enrichment via GitHub Models API)

If edge-tts or ffmpeg is absent the script exits with a clear message
listing the install commands — it never silently degrades.
"""

from __future__ import annotations

import argparse
import asyncio
import importlib.util
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from textwrap import wrap

REPO_ROOT = Path(__file__).resolve().parent.parent
DEMO_SCRIPT = REPO_ROOT / "docs" / "demo-script-a2.md"
DEFAULT_OUT = REPO_ROOT / "docs" / "find-evil-demo.mp4"

# Video spec (matches demo-script-a2.md Recording mechanics)
WIDTH = 1920
HEIGHT = 1080
FPS = 30
BG_COLOR = "0d1117"  # GitHub dark
TITLE_COLOR = "ffffff"
SUB_COLOR = "a0a0a0"
BADGE_COLOR = "f0883e"  # orange


@dataclass
class Beat:
    number: int
    title: str
    start_s: int
    end_s: int
    rubric: str
    narration: str

    @property
    def duration_s(self) -> int:
        return self.end_s - self.start_s


def _parse_time(t: str) -> int:
    """Convert 'M:SS' to total seconds."""
    m, s = t.split(":")
    return int(m) * 60 + int(s)


def parse_beats(text: str) -> list[Beat]:
    """Extract beats from the beat-map table + Voice-over blocks."""
    # --- parse beat-map table ---
    table_row = re.compile(
        r"^\|\s*(\d+)\s*\|\s*([\d:]+)–([\d:]+)\s*\|\s*[^|]+\|\s*([^|]+)\|\s*([^|]+)\|",
        re.MULTILINE,
    )
    meta: dict[int, tuple[int, int, str, str]] = {}
    for m in table_row.finditer(text):
        num = int(m.group(1))
        start_s = _parse_time(m.group(2).strip())
        end_s = _parse_time(m.group(3).strip())
        title = m.group(4).strip()
        rubric = m.group(5).strip()
        meta[num] = (start_s, end_s, title, rubric)

    # --- parse voice-over blocks ---
    # Pattern: ## Beat N — Title (time range)\n...**Voice-over:**\n\n> lines
    vo_block = re.compile(
        r"^## Beat (\d+)[^\n]*\n(.*?)(?=^## Beat |\Z)",
        re.MULTILINE | re.DOTALL,
    )
    narrations: dict[int, str] = {}
    for m in vo_block.finditer(text):
        num = int(m.group(1))
        block = m.group(2)
        # Extract quoted narration (> lines)
        quote_lines = re.findall(r"^>\s*(.*)", block, re.MULTILINE)
        narrations[num] = " ".join(line.strip() for line in quote_lines if line.strip())

    beats = []
    for num in sorted(meta):
        start_s, end_s, title, rubric = meta[num]
        beats.append(
            Beat(
                number=num,
                title=title,
                start_s=start_s,
                end_s=end_s,
                rubric=rubric,
                narration=narrations.get(num, title),
            )
        )
    return beats


def _enrich_narration_github_models(beats: list[Beat], token: str) -> list[Beat]:
    """Optionally rewrite each beat's narration to a punchy voiceover script
    using the GitHub Models API (OpenAI-compatible).  Falls back gracefully."""
    try:
        from openai import OpenAI
    except ImportError:
        print("[make-demo-video] openai package not found — skipping enrichment")
        return beats

    client = OpenAI(
        base_url="https://models.inference.ai.azure.com",
        api_key=token,
    )
    enriched = []
    for beat in beats:
        try:
            prompt = (
                f"Rewrite the following DFIR demo voiceover for Beat {beat.number} "
                f"({beat.title}, {beat.duration_s}s) into a tight, professional "
                f"narrator script of exactly 2-3 sentences (~{beat.duration_s * 2} words). "
                f"Keep all technical terms (DKOM, FRE 902(14), sigstore, INFERRED/CONFIRMED). "
                f"Original: {beat.narration}"
            )
            resp = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=200,
            )
            new_text = resp.choices[0].message.content.strip()
            enriched.append(
                Beat(
                    number=beat.number,
                    title=beat.title,
                    start_s=beat.start_s,
                    end_s=beat.end_s,
                    rubric=beat.rubric,
                    narration=new_text,
                )
            )
            print(f"  [enrich] Beat {beat.number} enriched via GitHub Models")
        except Exception as exc:
            print(f"  [enrich] Beat {beat.number} skipped ({exc})")
            enriched.append(beat)
    return enriched


async def _tts_beat(beat: Beat, out_path: Path, voice: str) -> None:
    """Generate TTS MP3 for a single beat using edge-tts."""
    import edge_tts  # type: ignore[import]

    communicate = edge_tts.Communicate(beat.narration, voice)
    await communicate.save(str(out_path))


def _make_slide(beat: Beat, out_path: Path) -> None:
    """Render a 1920×1080 title card for one beat using ffmpeg drawtext."""
    title_lines = wrap(f"Beat {beat.number}: {beat.title}", width=50)
    narration_lines = wrap(beat.narration, width=90)

    # Build drawtext chain
    filters = []
    y = 200
    for i, line in enumerate(title_lines):
        safe = line.replace("'", "\\'").replace(":", r"\:")
        filters.append(
            f"drawtext=text='{safe}':fontsize=64:fontcolor={TITLE_COLOR}"
            f":x=(w-text_w)/2:y={y + i * 80}"
        )
    y_badge = y + len(title_lines) * 80 + 40
    rubric_safe = beat.rubric.replace("'", "\\'").replace(":", r"\:")
    filters.append(
        f"drawtext=text='Rubric\\: {rubric_safe}':fontsize=36:fontcolor={BADGE_COLOR}"
        f":x=(w-text_w)/2:y={y_badge}"
    )
    y_narr = y_badge + 80
    for i, line in enumerate(narration_lines[:6]):  # max 6 lines visible
        safe = line.replace("'", "\\'").replace(":", r"\:")
        filters.append(
            f"drawtext=text='{safe}':fontsize=30:fontcolor={SUB_COLOR}"
            f":x=(w-text_w)/2:y={y_narr + i * 45}"
        )

    vf = ",".join(filters)
    cmd = [
        "ffmpeg",
        "-y",
        "-f",
        "lavfi",
        "-i",
        f"color=c=#{BG_COLOR}:size={WIDTH}x{HEIGHT}:rate={FPS}",
        "-vf",
        vf,
        "-t",
        str(beat.duration_s),
        "-c:v",
        "libx264",
        "-preset",
        "fast",
        "-crf",
        "23",
        str(out_path),
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[ffmpeg] slide {beat.number} stderr:\n{result.stderr[-500:]}")
        raise RuntimeError(f"ffmpeg slide failed for beat {beat.number}")


def _mux_beat(video: Path, audio: Path, out: Path) -> None:
    """Combine video slide + TTS audio, trimming to the shorter duration."""
    cmd = [
        "ffmpeg",
        "-y",
        "-i",
        str(video),
        "-i",
        str(audio),
        "-shortest",
        "-c:v",
        "copy",
        "-c:a",
        "aac",
        "-b:a",
        "192k",
        str(out),
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(
            f"ffmpeg mux failed for {video.name}:\n{result.stderr[-300:]}"
        )


def _concat_beats(beat_files: list[Path], out: Path) -> None:
    """Concatenate all per-beat MP4s into the final video."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as flist:
        for bf in beat_files:
            flist.write(f"file '{bf.resolve()}'\n")
        flist_path = flist.name
    try:
        cmd = [
            "ffmpeg",
            "-y",
            "-f",
            "concat",
            "-safe",
            "0",
            "-i",
            flist_path,
            "-c",
            "copy",
            str(out),
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"ffmpeg concat failed:\n{result.stderr[-400:]}")
    finally:
        Path(flist_path).unlink(missing_ok=True)


def _check_deps() -> list[str]:
    """Return list of missing required dependencies."""
    missing = []
    if not shutil.which("ffmpeg"):
        missing.append("ffmpeg  →  sudo apt install ffmpeg  (or brew install ffmpeg)")
    if importlib.util.find_spec("edge_tts") is None:
        missing.append(
            "edge-tts  →  pip install edge-tts  (or uv pip install edge-tts)"
        )
    return missing


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate demo video from demo-script-a2.md"
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Print plan without generating"
    )
    parser.add_argument("--out", default=str(DEFAULT_OUT), help="Output MP4 path")
    parser.add_argument(
        "--voice", default="en-US-AriaNeural", help="edge-tts voice name"
    )
    args = parser.parse_args(argv)

    text = DEMO_SCRIPT.read_text(encoding="utf-8")
    beats = parse_beats(text)

    if not beats:
        print("[make-demo-video] ERROR: no beats parsed from demo-script-a2.md")
        return 1

    total_s = sum(b.duration_s for b in beats)
    print(f"[make-demo-video] Parsed {len(beats)} beats, total {total_s}s")
    for b in beats:
        print(f"  Beat {b.number:2d}  {b.duration_s:3d}s  {b.title}")

    if args.dry_run:
        print("\n[make-demo-video] --dry-run: stopping before TTS/ffmpeg invocation")
        return 0

    missing = _check_deps()
    if missing:
        print("[make-demo-video] Missing dependencies:")
        for m in missing:
            print(f"  {m}")
        return 1

    # Optionally enrich narrations via GitHub Models
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if token:
        print(
            "[make-demo-video] GITHUB_TOKEN found — enriching narrations via GitHub Models"
        )
        beats = _enrich_narration_github_models(beats, token)
    else:
        print("[make-demo-video] GITHUB_TOKEN not set — using raw narration text")

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="findevil-demo-") as td:
        tmp = Path(td)
        beat_av_files: list[Path] = []

        for beat in beats:
            print(f"\n[make-demo-video] Beat {beat.number}: TTS...")
            audio_path = tmp / f"beat_{beat.number:02d}.mp3"
            asyncio.run(_tts_beat(beat, audio_path, args.voice))

            print(f"[make-demo-video] Beat {beat.number}: slide...")
            video_path = tmp / f"beat_{beat.number:02d}_slide.mp4"
            _make_slide(beat, video_path)

            print(f"[make-demo-video] Beat {beat.number}: mux...")
            av_path = tmp / f"beat_{beat.number:02d}_av.mp4"
            _mux_beat(video_path, audio_path, av_path)
            beat_av_files.append(av_path)

        print(f"\n[make-demo-video] Concatenating {len(beat_av_files)} beats...")
        _concat_beats(beat_av_files, out_path)

    size_mb = out_path.stat().st_size / 1_048_576
    print(f"\n[make-demo-video] Done: {out_path} ({size_mb:.1f} MB)")
    print("\nNext steps:")
    print("  1. Review the video: vlc docs/find-evil-demo.mp4")
    print("  2. Upload to YouTube or Vimeo")
    print("  3. Set the URL:")
    print("       gh variable set DEMO_VIDEO_URL --body 'https://youtu.be/<id>'")
    return 0


if __name__ == "__main__":
    sys.exit(main())
