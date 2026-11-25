#!/usr/bin/env python3
"""Break-then-catch demo of VERDICT's fact-fidelity (entailment) layer.

Exercises the REAL production path — the registry-persistence emitter, the
deterministic entailment check, and the verifier — to show two things:

  1. an HONEST finding is APPROVED, and the verifier records the value it
     re-extracted from the evidence (server-read, not model-transcribed);
  2. the SAME finding with one misread value (the reproducible fault
     ``FIND_EVIL_FAULT_INJECT=entailment_misread_once``) is REJECTED, so it
     never reaches the verdict.

The tool re-run is stubbed with the recorded output (MockMcpClient) so the demo
runs with no Rust MCP and no evidence; every decision shown comes from the real
verifier + entailment code.

Usage:
  python3 scripts/entailment-demo.py              # print the demo (ANSI)
  python3 scripts/entailment-demo.py --render out.mp4   # render a video clip
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT / "scripts"))
sys.path.insert(0, str(_ROOT / "services" / "agent"))

import find_evil_auto as fea  # noqa: E402
from findevil_agent.events import Finding  # noqa: E402
from findevil_agent.mcp_client import MockMcpClient  # noqa: E402
from findevil_agent.verifier import reverify_finding  # noqa: E402

_RUN_KEY = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
_TARGET = "C:\\Users\\bob\\AppData\\Roaming\\evil.exe"

# What registry_query returns — and re-returns, byte-identical, on replay.
REGISTRY_OUTPUT = {
    "entries": [
        {
            "key_path": _RUN_KEY,
            "last_write_time_iso": "2018-09-06T19:00:00Z",
            "values": [{"name": "Updater", "value_type": "RegSz", "data_str": _TARGET}],
        }
    ],
    "keys_visited": 1,
    "parse_errors": 0,
}


def _canonical_sha(payload: dict) -> str:
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _verify(finding_dict: dict):
    mcp = MockMcpClient()
    mcp.register("registry_query", REGISTRY_OUTPUT)
    index = {
        "tc-1": {
            "tool_name": "registry_query",
            "arguments": {"hive_path": "/evidence/SOFTWARE", "key_path": _RUN_KEY},
            "output_sha256": _canonical_sha(REGISTRY_OUTPUT),
        }
    }
    finding = Finding.model_validate(fea.finding_for_verifier(finding_dict))
    action, _replay = reverify_finding(finding, mcp=mcp, tool_call_index=index)
    return action


def build_steps() -> list[tuple[str, str]]:
    """Run the real demo and return (style, text) lines, single-sourced so the
    live print and the rendered clip show the identical, real results."""
    inv = fea.Investigation("memory.img", unattended=True, with_report=False)
    inv.handle = {"id": "demo-case"}
    cand = {
        "kind": "run_key",
        "value_name": "Updater",
        "target": _TARGET,
        "hive_key": _RUN_KEY,
        "last_write_time_iso": "2018-09-06T19:00:00Z",
    }
    inv._emit_registry_persistence_findings(
        [cand], "/evidence/SOFTWARE", _RUN_KEY, "tc-1", {}
    )
    finding = inv.findings_pool_a[0]

    honest = _verify(finding)
    faulted = fea.fault_inject_misread(finding)
    misread = _verify(faulted)

    faulted_claim = json.loads(faulted["asserted_values"][0]["expected"]).get(
        "name", "?"
    )

    steps: list[tuple[str, str]] = [
        ("title", "VERDICT  ·  fact-fidelity (entailment) check"),
        ("dim", "the verifier re-reads the evidence itself. no model in the loop."),
        ("dim", "break it on purpose, watch the deterministic check catch it."),
        ("blank", ""),
        ("cmd", "$ verdict investigate ./evidence    # registry Run-key persistence"),
        ("blank", ""),
        ("finding", f"CONFIRMED  {finding['finding_id']}   T1547.001"),
        ("dim", "   claims:  Run value 'Updater'  ->  ...\\AppData\\Roaming\\evil.exe"),
        ("dim", "   asserts (record): name=Updater AND data_str~evil.exe  [same row]"),
        ("blank", ""),
        ("step", "(1) honest finding  ->  verifier re-extracts the asserted value"),
        (
            "pass",
            f"    {honest.action.upper()}   value re-read from evidence: name=Updater, data_str=...evil.exe",
        ),
        ("blank", ""),
        (
            "step",
            "(2) inject a misread   FIND_EVIL_FAULT_INJECT=entailment_misread_once",
        ),
        ("dim", f"    model now claims name='{faulted_claim}'  (not in the evidence)"),
        (
            "fail",
            f"    {misread.action.upper()}   asserted value not found in the cited output",
        ),
        ("blank", ""),
        (
            "verdict",
            "the misread is dropped before it can count  ->  verdict stays honest",
        ),
        ("good", "the AI cannot record a structured fact that isn't in the evidence."),
    ]
    # Sanity: the demo is only meaningful if the real verifier agrees.
    assert honest.action == "approved", honest.action
    assert misread.action == "rejected", misread.action
    return steps


# --- live terminal output ----------------------------------------------------

_ANSI = {
    "title": "\033[1;38;5;75m",
    "dim": "\033[38;5;245m",
    "cmd": "\033[1;38;5;252m",
    "finding": "\033[1;38;5;177m",
    "step": "\033[1;38;5;221m",
    "pass": "\033[1;38;5;78m",
    "fail": "\033[1;38;5;203m",
    "verdict": "\033[1;38;5;81m",
    "good": "\033[1;38;5;78m",
    "blank": "",
}
_RST = "\033[0m"


def print_steps(steps: list[tuple[str, str]]) -> None:
    for style, text in steps:
        print(f"{_ANSI.get(style, '')}{text}{_RST}")


# --- video rendering ---------------------------------------------------------

_RGB = {
    "title": (88, 166, 255),
    "dim": (125, 133, 144),
    "cmd": (201, 209, 217),
    "finding": (210, 168, 255),
    "step": (236, 205, 90),
    "pass": (63, 185, 80),
    "fail": (248, 81, 73),
    "verdict": (121, 192, 255),
    "good": (86, 211, 100),
    "blank": (201, 209, 217),
}
_BG = (13, 17, 23)
_BAR = (28, 33, 40)


def _font(size: int, bold: bool = False):
    from PIL import ImageFont

    base = Path("/usr/share/fonts/truetype/dejavu")
    path = base / ("DejaVuSansMono-Bold.ttf" if bold else "DejaVuSansMono.ttf")
    if not path.exists():
        path = base / "DejaVuSansMono.ttf"
    return ImageFont.truetype(str(path), size)


def render_clip(steps: list[tuple[str, str]], out_path: Path) -> None:
    from PIL import Image, ImageDraw

    pad_x, top = 46, 84
    line_h = 34
    bar_h = 44
    fps = 24
    font = _font(24)
    font_b = _font(24, bold=True)
    title_font = _font(16, bold=True)
    bold_styles = {"title", "pass", "fail", "finding", "step", "good"}

    # Size the canvas to the content — no dead margin on the right or bottom.
    _probe = ImageDraw.Draw(Image.new("RGB", (8, 8)))

    def _line_w(style: str, text: str) -> float:
        return _probe.textlength(text, font=font_b if style in bold_styles else font)

    W = max(760, int(max((_line_w(s, t) for s, t in steps), default=600)) + pad_x * 2)
    H = top + len(steps) * line_h + 26

    def base_canvas() -> "Image.Image":
        img = Image.new("RGB", (W, H), _BG)
        d = ImageDraw.Draw(img)
        d.rectangle([0, 0, W, bar_h], fill=_BAR)
        for i, col in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
            d.ellipse([22 + i * 24, 15, 35 + i * 24, 28], fill=col)
        d.text(
            (W // 2 - 118, 13),
            "verdict — entailment demo",
            font=title_font,
            fill=(139, 148, 158),
        )
        return img

    def draw_state(shown, cursor_on, flash_idx=-1, flash=0.0) -> "Image.Image":
        img = base_canvas()
        d = ImageDraw.Draw(img)
        y = top
        for i, (style, text, ncols) in enumerate(shown):
            flashing = i == flash_idx and flash > 0.0
            if flashing:
                band = (
                    int(40 + 95 * flash),
                    int(13 + 17 * flash),
                    int(11 + 13 * flash),
                )
                d.rectangle(
                    [pad_x - 14, y - 5, W - pad_x + 14, y + line_h - 6], fill=band
                )
            rgb = (255, 214, 205) if flashing else _RGB.get(style, (201, 209, 217))
            f = font_b if style in bold_styles else font
            d.text((pad_x, y), text[:ncols], font=f, fill=rgb)
            if cursor_on and ncols < len(text):
                cx = pad_x + d.textlength(text[:ncols], font=f)
                d.rectangle([cx, y + 5, cx + 12, y + 27], fill=(201, 209, 217))
            y += line_h
        if cursor_on:
            d.rectangle([pad_x, y + 5, pad_x + 12, y + 27], fill=(86, 211, 100))
        return img

    frames: list = []
    shown: list[list] = []
    typing_styles = {"cmd", "pass", "fail", "good"}

    for style, text in steps:
        shown.append([style, text, 0])
        idx = len(shown) - 1
        if style in typing_styles and text:
            # type the line out, ~3 chars/frame
            n = 0
            while n < len(text):
                n = min(len(text), n + 3)
                shown[-1][2] = n
                frames.append(draw_state(shown, (len(frames) // 6) % 2 == 0))
            hold = int(fps * 0.45)
        else:
            shown[-1][2] = len(text)
            hold = int(fps * 0.42)
        if style == "pass":
            hold = int(fps * 1.5)
        if style == "fail":
            # ~1s pulsing red flash on the REJECTED line, then a steady beat
            for fr in range(fps):
                inten = 0.5 + 0.5 * ((fr // 3) % 2)
                frames.append(draw_state(shown, True, flash_idx=idx, flash=inten))
            hold = int(fps * 0.9)
        if style == "good":
            hold = int(fps * 2.4)
        for h in range(hold):
            frames.append(draw_state(shown, (h // 6) % 2 == 0))

    # tail hold
    for h in range(int(fps * 1.6)):
        frames.append(draw_state(shown, (h // 6) % 2 == 0))

    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        for i, fr in enumerate(frames):
            fr.save(tdp / f"f{i:05d}.png")
        out_path = out_path.resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        cmd = [
            "ffmpeg",
            "-y",
            "-loglevel",
            "error",
            "-framerate",
            str(fps),
            "-i",
            str(tdp / "f%05d.png"),
            "-c:v",
            "libx264",
            "-pix_fmt",
            "yuv420p",
            "-vf",
            "scale=trunc(iw/2)*2:trunc(ih/2)*2",
            str(out_path),
        ]
        subprocess.run(cmd, check=True)
        # also a gif (handy for posts)
        gif = out_path.with_suffix(".gif")
        palette = tdp / "pal.png"
        subprocess.run(
            [
                "ffmpeg",
                "-y",
                "-loglevel",
                "error",
                "-framerate",
                str(fps),
                "-i",
                str(tdp / "f%05d.png"),
                "-vf",
                "fps=12,scale=900:-1:flags=lanczos,palettegen",
                str(palette),
            ],
            check=True,
        )
        subprocess.run(
            [
                "ffmpeg",
                "-y",
                "-loglevel",
                "error",
                "-framerate",
                str(fps),
                "-i",
                str(tdp / "f%05d.png"),
                "-i",
                str(palette),
                "-lavfi",
                "fps=12,scale=900:-1:flags=lanczos[x];[x][1:v]paletteuse",
                str(gif),
            ],
            check=True,
        )
    print(f"wrote {out_path}  ({len(frames)} frames @ {fps}fps)")
    print(f"wrote {out_path.with_suffix('.gif')}")


def main(argv: list[str]) -> int:
    steps = build_steps()
    if len(argv) >= 2 and argv[0] == "--render":
        render_clip(steps, Path(argv[1]))
    else:
        print_steps(steps)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
