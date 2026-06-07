#!/usr/bin/env python3
"""TTS prep step for the Remotion demo video.

Generates MP3 audio files for each beat and writes them to
scripts/make-demo-video/src/audio/beat_NN.mp3 where Remotion's
<Audio src={staticFile(...)}> can pick them up.

Optionally rewrites narration via `claude -p` (uses your Claude Code session
token / ANTHROPIC_API_KEY — whatever `claude` is already configured with)
before feeding the text to edge-tts.

Usage:
    python3 scripts/make-demo-video-prep.py [--dry-run] [--voice VOICE]
"""
from __future__ import annotations

import argparse
import asyncio
import importlib.util
import os
import subprocess
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
AUDIO_OUT = REPO_ROOT / "scripts" / "make-demo-video" / "public" / "audio"

# Beat metadata mirrored from beats-data.ts (single source of truth is the TS
# file for the video; this mirrors it for TTS generation purposes only).
@dataclass
class Beat:
    number: int
    title: str
    duration_s: int
    narration: str


BEATS: list[Beat] = [
    Beat(1, "Cold open + problem framing", 25,
         "Modern attackers move at machine speed — the median ransomware dwell time is now "
         "measured in hours, not days. The question: can an agent reproduce "
         "a forensic investigator's work fast enough to keep up — and prove what it did. "
         "VERDICT says yes, and gives the analyst a sigstore-backed signature on every "
         "finding, verifiable offline."),
    Beat(2, "Architecture", 25,
         "Five trust boundaries. Evidence vault — read-only. SIFT tools as subprocesses, never "
         "linked, so we stay license-clean for AGPL code. Two MCP servers — Rust for forensic "
         "tools, Python for the crypto chain. Claude Code as the orchestrator. Every Finding "
         "cites a tool-call ID; every tool call hashes its output. There is no execute_shell "
         "tool — by design."),
    Beat(3, "Single-host investigation", 45,
         "One command, fully autonomous. The agent opens the case, hashes the image, walks the active "
         "process list with Volatility pslist, then signature-scans EPROCESS pool memory with "
         "psscan — and the two disagree. That divergence can be a DKOM rootkit signature, but on "
         "this image the agent spots the acquisition-smear tells (core OS singletons recovered only "
         "by psscan, duplicate System EPROCESS) and labels it a HYPOTHESIS, not a confirmed rootkit, "
         "refusing to assert T1014 without a second artifact class. It does not over-claim CONFIRMED. "
         "That epistemic discipline is non-negotiable."),
    Beat(4, "Live ACH disagreement", 60,
         "Heuer's Analysis of Competing Hypotheses, applied at agent architecture. Two pools "
         "investigate the same evidence with opposing priors. They will disagree — and that "
         "disagreement is not a bug. We surface it before reconciliation, named, in the audit "
         "trail. The judge merges with credibility weighting. The analyst sees both arguments "
         "and the reconciliation. No consensus-seeking single agent can give them that."),
    Beat(5, "Crypto chain-of-custody", 35,
         "Every audit record, every tool output, every Finding — all hash-chained. At "
         "investigation end, we Merkle-tree the chain and sign the root with sigstore, whose "
         "Rekor transparency log records the signature as an independent third party. This "
         "supports a Federal Rule of Evidence 902-14 self-authenticating-evidence claim. A judge "
         "in a literal court can verify this case's integrity from the manifest alone, "
         "three years from now, without trusting us."),
    Beat(6, "22-host fleet investigation", 50,
         "Single-host is the demo; fleet investigation is the use case. Twenty-two memory "
         "images, eighty-four gigabytes total, investigated end-to-end with one command. The "
         "orchestrator persists progress after every host so a crash doesn't cost you the run. "
         "Every host gets its own signed manifest; the fleet rollup adds cross-host "
         "correlation on top."),
    Beat(7, "Cross-host APT signal", 30,
         "This is what makes fleet correlation worth the cost. Six hosts ran Autoruns at the "
         "exact same second — that is not natural system behavior, that is a PsExec sweep or "
         "an SCCM push. Four different hosts ran rubyw — Ruby for Windows isn't enterprise "
         "tooling. These are correlations no single-host investigation would surface. The agent "
         "surfaces them as HYPOTHESIS and names the threshold. The analyst confirms."),
    Beat(8, "Signed verdict", 20,
         "When the investigation closes, VERDICT writes a signed verdict — the finding, its "
         "confidence, the MITRE technique, and the tool calls that prove it — sealed in the same "
         "Merkle tree as the audit chain and signed by sigstore. One file, verifiable offline, "
         "years from now, without trusting us."),
    Beat(9, "Outro — repo URL + license", 10,
         "Source is open. License is Apache-2.0. Build is green. Cut evidence in. "
         "Get a signed verdict out. Thank you."),
]


def _enrich_via_claude(beats: list[Beat]) -> list[Beat]:
    """Rewrite narrations using `claude -p` (uses your Claude Code session token)."""
    enriched = []
    for beat in beats:
        prompt = (
            f"Rewrite this DFIR demo voiceover for a {beat.duration_s}-second beat "
            f"(~{beat.duration_s * 2} words) into a tight, professional narrator script. "
            f"Return ONLY the rewritten narration text — no preamble, no quotes. "
            f"Keep all technical terms exactly: DKOM, FRE 902(14), sigstore, "
            f"INFERRED, CONFIRMED, HYPOTHESIS, manifest_finalize. "
            f"Beat title: {beat.title}. "
            f"Original: {beat.narration}"
        )
        try:
            result = subprocess.run(
                ["claude", "-p", prompt],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0 and result.stdout.strip():
                text = result.stdout.strip()
                print(f"  [enrich] Beat {beat.number} enriched via claude -p")
                enriched.append(Beat(beat.number, beat.title, beat.duration_s, text))
            else:
                print(f"  [enrich] Beat {beat.number} skipped (claude exit {result.returncode})")
                enriched.append(beat)
        except Exception as exc:
            print(f"  [enrich] Beat {beat.number} skipped: {exc}")
            enriched.append(beat)
    return enriched


async def _generate_tts(beat: Beat, voice: str, out_dir: Path) -> None:
    import edge_tts  # type: ignore[import]

    out_path = out_dir / f"beat_{beat.number:02d}.mp3"
    communicate = edge_tts.Communicate(beat.narration, voice)
    await communicate.save(str(out_path))
    print(f"  [tts] Beat {beat.number} → {out_path.name}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate TTS audio for Remotion video beats")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--voice", default="en-US-AriaNeural")
    args = parser.parse_args()

    total_s = sum(b.duration_s for b in BEATS)
    print(f"[make-demo-video-prep] {len(BEATS)} beats, total {total_s}s")
    for b in BEATS:
        print(f"  Beat {b.number:2d}  {b.duration_s:3d}s  {b.title}")

    if args.dry_run:
        print("\n[make-demo-video-prep] --dry-run: stopping before TTS generation")
        return 0

    if importlib.util.find_spec("edge_tts") is None:
        print("\n[make-demo-video-prep] edge-tts not installed.")
        print("  Install with:  pip install edge-tts")
        return 1

    beats = BEATS
    if shutil.which("claude"):
        print("\n[make-demo-video-prep] claude CLI found — enriching narrations via claude -p")
        beats = _enrich_via_claude(beats)
    else:
        print("\n[make-demo-video-prep] claude CLI not on PATH — using raw narration text")

    AUDIO_OUT.mkdir(parents=True, exist_ok=True)
    print(f"\n[make-demo-video-prep] Generating TTS → {AUDIO_OUT}")

    async def run_all() -> None:
        for beat in beats:
            await _generate_tts(beat, args.voice, AUDIO_OUT)

    asyncio.run(run_all())
    print(f"\n[make-demo-video-prep] Done. {len(beats)} MP3 files in {AUDIO_OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
