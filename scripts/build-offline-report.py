#!/usr/bin/env python3
"""Build a self-contained offline report.html for release artifacts.

The web dashboard is live/operator UI. Devpost also needs a static HTML artifact
that can be opened offline, so this script renders the committed showcase report
into a compact standalone page with a verdict card and cryptographic attestation
summary. It deliberately avoids network resources and extra dependencies.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from html import escape
from pathlib import Path
import re

REPO = Path(__file__).resolve().parent.parent
DEFAULT_SOURCE = REPO / "docs" / "reports" / "2026-04-26-srl2018-dc-investigation.md"


def parse_front_matter(text: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for key in (
        "Case ID",
        "Run ID",
        "Started",
        "Finalized",
        "Investigator",
        "Evidence corpus",
    ):
        match = re.search(rf"^\*\*{re.escape(key)}:\*\*\s*(.+)$", text, re.MULTILINE)
        if match:
            fields[key] = match.group(1).strip().strip("`")
    for key, pattern in {
        "Merkle root": r"Merkle root `([^`]+)`",
        "Audit log final hash": r"Audit log final hash `([^`]+)`",
        "Signature SHA-256": r"(?:Sigstore signature|Ed25519 signature|Signature \([^`]+\)) SHA-256 `([^`]+)`",
        "Cert fingerprint": r"Cert fingerprint `([^`]+)`",
    }.items():
        match = re.search(pattern, text)
        if match:
            fields[key] = match.group(1)
    return fields


def extract_section(text: str, heading: str, *, max_chars: int = 2200) -> str:
    pattern = rf"^##\s+{re.escape(heading)}\s*$"
    match = re.search(pattern, text, re.MULTILINE)
    if not match:
        return ""
    start = match.end()
    next_heading = re.search(r"^##\s+", text[start:], re.MULTILINE)
    end = start + next_heading.start() if next_heading else len(text)
    section = text[start:end].strip()
    return section[:max_chars].strip()


def markdown_to_plain_blocks(markdown: str) -> list[str]:
    blocks: list[str] = []
    current: list[str] = []
    in_code = False
    for raw_line in markdown.splitlines():
        line = raw_line.rstrip()
        if line.startswith("```"):
            in_code = not in_code
            continue
        if in_code or not line.strip() or line.strip() == "---":
            if current:
                blocks.append(" ".join(current))
                current = []
            continue
        if line.startswith("![") or line.startswith("[^"):
            continue
        line = re.sub(r"\[([^\]]+)\]\([^\)]+\)", r"\1", line)
        line = re.sub(r"`([^`]+)`", r"\1", line)
        line = line.replace("**", "").replace("*", "")
        line = line.lstrip("-0123456789. ")
        current.append(line.strip())
    if current:
        blocks.append(" ".join(current))
    return [block for block in blocks if block]


def build_html(source: Path) -> str:
    text = source.read_text(encoding="utf-8")
    fields = parse_front_matter(text)
    summary = markdown_to_plain_blocks(extract_section(text, "Executive summary"))
    methodology = markdown_to_plain_blocks(
        extract_section(text, "2. Methodology", max_chars=1600)
    )
    generated_at = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )

    cards = [
        ("Case", fields.get("Case ID", "unknown")),
        ("Run", fields.get("Run ID", "unknown")),
        ("Evidence", fields.get("Evidence corpus", "SANS HACKATHON-2026 corpus")),
        (
            "Verdict",
            "SUSPICIOUS / DKOM process-hiding lead corroborated by process-view divergence",
        ),
    ]
    crypto = [
        ("Merkle root", fields.get("Merkle root", "not recorded")),
        ("Audit final hash", fields.get("Audit log final hash", "not recorded")),
        (
            "Manifest signature",
            fields.get("Signature SHA-256", "not recorded"),
        ),
        ("Certificate", fields.get("Cert fingerprint", "not recorded")),
    ]

    def paragraph(block: str) -> str:
        return f"<p>{escape(block)}</p>"

    card_html = "\n".join(
        f"<div class='card'><span>{escape(label)}</span><strong>{escape(value)}</strong></div>"
        for label, value in cards
    )
    crypto_html = "\n".join(
        f"<tr><th>{escape(label)}</th><td><code>{escape(value)}</code></td></tr>"
        for label, value in crypto
    )
    summary_html = "\n".join(paragraph(block) for block in summary[:6])
    methodology_html = "\n".join(paragraph(block) for block in methodology[:3])

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Find Evil Offline Report</title>
  <style>
    :root {{ color-scheme: dark; font-family: Inter, ui-sans-serif, system-ui, sans-serif; }}
    body {{ margin: 0; background: #0f172a; color: #e2e8f0; }}
    main {{ max-width: 1080px; margin: 0 auto; padding: 48px 24px; }}
    h1 {{ font-size: clamp(2rem, 4vw, 4rem); line-height: 0.95; margin: 0 0 16px; }}
    h2 {{ margin-top: 36px; color: #67e8f9; }}
    p {{ line-height: 1.7; color: #cbd5e1; }}
    .eyebrow {{ color: #22d3ee; font-weight: 800; letter-spacing: .18em; text-transform: uppercase; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin: 28px 0; }}
    .card {{ border: 1px solid #334155; border-radius: 20px; padding: 18px; background: #111827; }}
    .card span {{ display: block; color: #94a3b8; font-size: .85rem; text-transform: uppercase; letter-spacing: .08em; }}
    .card strong {{ display: block; margin-top: 8px; color: white; }}
    table {{ border-collapse: collapse; width: 100%; overflow-wrap: anywhere; background: #111827; border-radius: 20px; overflow: hidden; }}
    th, td {{ border-bottom: 1px solid #334155; padding: 14px; text-align: left; vertical-align: top; }}
    th {{ color: #67e8f9; width: 220px; }}
    code {{ color: #bae6fd; }}
    .note {{ border-left: 4px solid #22d3ee; padding: 12px 16px; background: #082f49; }}
  </style>
</head>
<body>
  <main data-findevil-report="offline-release">
    <p class="eyebrow">Find Evil Offline Report</p>
    <h1>Cryptographically verifiable DFIR investigation</h1>
    <p class="note">Generated {escape(generated_at)} from {escape(source.relative_to(REPO).as_posix())}. This artifact is self-contained and requires no network access.</p>
    <section aria-label="Verdict card" id="verdict-card">
      <h2>Verdict Card</h2>
      <div class="grid">{card_html}</div>
    </section>
    <section>
      <h2>Executive Summary</h2>
      {summary_html}
    </section>
    <section>
      <h2>Cryptographic Attestation</h2>
      <table>{crypto_html}</table>
    </section>
    <section>
      <h2>Methodology</h2>
      {methodology_html}
    </section>
  </main>
</body>
</html>
"""


def main() -> int:
    parser = argparse.ArgumentParser(description="Build offline release report.html")
    parser.add_argument(
        "--source", default=str(DEFAULT_SOURCE), help="source markdown report"
    )
    parser.add_argument("--out", required=True, help="output report.html path")
    args = parser.parse_args()

    source = Path(args.source)
    if not source.is_absolute():
        source = REPO / source
    out = Path(args.out)
    if not out.is_absolute():
        out = Path.cwd() / out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(build_html(source), encoding="utf-8")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
