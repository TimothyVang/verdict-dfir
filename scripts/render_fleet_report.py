#!/usr/bin/env python3
"""render_fleet_report — render a fleet-level investigation report.

Reads the fleet correlation output (fleet_correlation.json) plus per-host
verdicts, generates fleet-wide visualizations, builds a polished
Markdown report, renders to HTML + PDF.

Usage:
    python scripts/render_fleet_report.py [<fleet-dir>]

If no arg, uses the most recent fleet under tmp/fleet-runs/.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.patches as mpatches  # noqa: E402
import matplotlib.pyplot as plt  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent


def _resolve_bin(env_var: str, names: list[str], win_fallback: str) -> str:
    """Resolve a tool: $ENV override, then PATH (Linux/macOS), then the
    Windows install path the script was originally written for."""
    import os
    import shutil

    if os.environ.get(env_var):
        return os.environ[env_var]
    for n in names:
        found = shutil.which(n)
        if found:
            return found
    return win_fallback


PANDOC = _resolve_bin("PANDOC_BIN", ["pandoc"], r"C:\Program Files\Pandoc\pandoc.exe")
CHROME = _resolve_bin(
    "CHROME_BIN",
    ["google-chrome", "google-chrome-stable", "chromium", "chromium-browser"],
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
)

# --------------------------------------------------------------------------- #
# Design tokens — the dark "forensic case file" theme, in sync with
# scripts/_report_style.css so the figures sit flush inside the dark report
# (white-background charts looked out of place against the cream-on-near-black
# paper). Editorial / threat-intel-briefing figure language.
# --------------------------------------------------------------------------- #
PAPER = "#0e0c10"
SURFACE = "#161318"
INSET = "#0b0a0d"
INK = "#ece6da"
MUTED = "#8c8576"
FAINT = "#544f48"
HAIRLINE = "#2b2620"
ACCENT = "#9b59b6"  # purple brand
ACCENT_LIGHT = "#b98fce"
ALERT = "#d6452f"  # red — strongest signal
INFERRED = "#c79a4a"  # amber
HYPOTHESIS = "#6f93b8"  # blue
CONFIRMED = "#7fae6e"  # green
FIG_BG = SURFACE  # margins included, so the PNG is dark to the edge

SANS = "DejaVu Sans"
MONO = "DejaVu Sans Mono"

plt.rcParams.update(
    {
        "font.family": SANS,
        "font.size": 11,
        "text.color": INK,
        "axes.edgecolor": HAIRLINE,
        "axes.labelcolor": INK,
        "xtick.color": MUTED,
        "ytick.color": MUTED,
        "savefig.dpi": 150,
        "savefig.bbox": "tight",
        "figure.facecolor": FIG_BG,
        "axes.facecolor": FIG_BG,
        "savefig.facecolor": FIG_BG,
    }
)

import matplotlib.font_manager as _fm  # noqa: E402


def _mono() -> _fm.FontProperties:
    return _fm.FontProperties(family=MONO)


def _severity_color(host_count: int) -> str:
    """>=10 hosts alert-red, 5-9 amber, 2-4 hypothesis-blue."""
    if host_count >= 10:
        return ALERT
    if host_count >= 5:
        return INFERRED
    return HYPOTHESIS


def _verdict_color(word: str) -> str:
    w = (word or "").upper()
    if w.startswith("SUSP") or w == "EVIL":
        return ALERT
    if w.startswith("NO_") or w == "CLEAN":
        return CONFIRMED
    return INFERRED  # INDETERMINATE / unknown -> amber


_VERDICT_GLOSS = {
    "INDETERMINATE": "leads seen, not yet corroborated — triage when convenient",
    "SUSPICIOUS": "found something — triage now",
    "NO_EVIL": "scoped-clean within what was examined — never 'definitely safe'",
}


def _cross_host_counts(corr: dict) -> list[tuple[str, int]]:
    chp = corr.get("cross_host_processes", {})
    counts = {n: len({e["host"] for e in ev}) for n, ev in chp.items()}
    return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))


def _kicker(fig, x, y, text):
    fig.text(
        x,
        y,
        text.upper(),
        color=ACCENT_LIGHT,
        fontsize=9.5,
        fontweight="bold",
        family=SANS,
        ha="left",
        va="baseline",
    )


def _headline(fig, x, y, text, size=23):
    fig.text(
        x,
        y,
        text,
        color=INK,
        fontsize=size,
        fontweight="bold",
        family=SANS,
        ha="left",
        va="baseline",
    )


def _caption(fig, x, y, text, size=9.5, color=MUTED, ha="left"):
    fig.text(x, y, text, color=color, fontsize=size, family=SANS, ha=ha, va="baseline")


def _rule(fig, x0, x1, y, color=HAIRLINE, lw=0.8):
    fig.add_artist(
        plt.Line2D(
            [x0, x1],
            [y, y],
            color=color,
            lw=lw,
            transform=fig.transFigure,
            solid_capstyle="butt",
        )
    )


def _save(fig, fig_path: Path) -> None:
    fig.savefig(
        fig_path, dpi=150, bbox_inches="tight", facecolor=FIG_BG, edgecolor="none"
    )
    plt.close(fig)


def latest_fleet_dir() -> Path | None:
    base = REPO_ROOT / "tmp" / "fleet-runs"
    if not base.is_dir():
        return None
    candidates = sorted(
        base.glob("fleet-*"), key=lambda p: p.stat().st_mtime, reverse=True
    )
    return candidates[0] if candidates else None


# ---------------------------------------------------------------------------
# Figures
# ---------------------------------------------------------------------------


def fig_verdict_distribution(corr: dict, fig_path: Path) -> None:
    """Big-number callout + proportional segmented strip. Reads intentionally
    even for a single verdict category (no absurd full-width single bar)."""
    dist = corr.get("verdict_distribution", {})
    if not dist:
        return
    host_count = corr.get("host_count", sum(dist.values()) or 1)
    total = sum(dist.values()) or 1
    items = sorted(dist.items(), key=lambda kv: -kv[1])

    fig = plt.figure(figsize=(11, 4.6))
    fig.patch.set_facecolor(FIG_BG)
    _kicker(fig, 0.055, 0.86, "Fleet verdict")
    _headline(fig, 0.055, 0.74, "What the fleet concluded", size=24)
    _caption(
        fig,
        0.055,
        0.665,
        f"{host_count} hosts examined  ·  verdict per host, merged fleet-wide",
    )

    dominant_word, dominant_n = items[0]
    dcolor = _verdict_color(dominant_word)
    fig.text(
        0.055,
        0.305,
        f"{dominant_n}",
        color=dcolor,
        fontsize=104,
        fontweight="bold",
        family=SANS,
        ha="left",
        va="baseline",
    )
    fig.text(
        0.26,
        0.40,
        f"/ {total}",
        color=MUTED,
        fontsize=20,
        family=MONO,
        ha="left",
        va="baseline",
    )
    fig.text(
        0.26,
        0.305,
        "hosts",
        color=MUTED,
        fontsize=12.5,
        family=SANS,
        ha="left",
        va="baseline",
    )
    fig.text(
        0.057,
        0.205,
        dominant_word.upper(),
        color=dcolor,
        fontsize=19,
        fontweight="bold",
        family=SANS,
        ha="left",
        va="baseline",
    )

    strip_x0, strip_x1 = 0.40, 0.945
    strip_y, strip_h = 0.36, 0.135
    width = strip_x1 - strip_x0
    fig.add_artist(
        mpatches.FancyBboxPatch(
            (strip_x0, strip_y),
            width,
            strip_h,
            boxstyle="round,pad=0,rounding_size=0.012",
            transform=fig.transFigure,
            facecolor=INSET,
            edgecolor=HAIRLINE,
            lw=0.8,
            mutation_aspect=2.4,
        )
    )
    gap = 0.004 if len(items) > 1 else 0.0
    cx = strip_x0
    for i, (word, n) in enumerate(items):
        seg_w = width * (n / total)
        if i == len(items) - 1:
            seg_w = (strip_x0 + width) - cx
        fig.add_artist(
            mpatches.FancyBboxPatch(
                (cx + (gap if i else 0), strip_y + 0.012),
                max(seg_w - gap, 0.001),
                strip_h - 0.024,
                boxstyle="round,pad=0,rounding_size=0.010",
                transform=fig.transFigure,
                facecolor=_verdict_color(word),
                edgecolor="none",
                mutation_aspect=2.4,
                alpha=0.92,
            )
        )
        if seg_w > 0.06:
            fig.text(
                cx + seg_w / 2,
                strip_y + strip_h / 2,
                word.upper(),
                color=INSET,
                fontsize=11.5,
                fontweight="bold",
                family=SANS,
                ha="center",
                va="center",
            )
        cx += seg_w

    pct = 100.0 * dominant_n / total
    gloss = _VERDICT_GLOSS.get(dominant_word.upper(), "")
    _caption(
        fig,
        strip_x0,
        strip_y - 0.085,
        f"{pct:.0f}% {dominant_word.upper()}" + (f"  —  {gloss}" if gloss else ""),
        color=MUTED,
    )
    _caption(
        fig,
        strip_x0,
        strip_y - 0.165,
        "Each host's verdict is independently signed; this is the merged view.",
        color=FAINT,
        size=8.8,
    )
    _rule(fig, 0.055, 0.945, 0.07)
    _caption(fig, 0.055, 0.035, "VERDICT  ·  fleet correlation", color=FAINT, size=8.2)
    _save(fig, fig_path)


# Offline ATT&CK technique labels so a tile can carry a human name with no
# network dependency. Extend as new techniques surface in fleet runs.
_MITRE_NAMES = {
    "T1003": "OS Credential Dumping",
    "T1014": "Rootkit",
    "T1021": "Remote Services",
    "T1047": "Windows Management Instrumentation",
    "T1053": "Scheduled Task / Job",
    "T1055": "Process Injection",
    "T1059": "Command & Scripting Interpreter",
    "T1078": "Valid Accounts",
    "T1105": "Ingress Tool Transfer",
    "T1543": "Create or Modify System Process",
    "T1547": "Boot or Logon Autostart Execution",
    "T1569": "System Services",
}


def fig_mitre_density(corr: dict, fig_path: Path) -> None:
    """Compact severity-tiled technique row (one tile per technique); reads
    intentionally even for a single technique."""
    density = corr.get("mitre_technique_density", {})
    if not density:
        return
    host_count = corr.get("host_count", 22)
    items = sorted(density.items(), key=lambda kv: -kv[1])
    n = len(items)

    fig = plt.figure(figsize=(11, 3.9))
    fig.patch.set_facecolor(FIG_BG)
    _kicker(fig, 0.055, 0.86, "ATT&CK technique density")
    _headline(fig, 0.055, 0.72, "Where the fleet's evil concentrates", size=22)
    _caption(
        fig,
        0.055,
        0.645,
        f"distinct hosts exhibiting each technique · {n} "
        f"technique{'s' if n != 1 else ''} observed",
    )

    left, right, gap, max_tile = 0.055, 0.945, 0.022, 0.30
    tile_w = min(max_tile, ((right - left) - gap * (n - 1)) / max(n, 1))
    tiles_total = tile_w * n + gap * (n - 1)
    tile_y, tile_h = 0.16, 0.34

    for i, (tid, hosts) in enumerate(items):
        tx = left + i * (tile_w + gap)
        col = _severity_color(hosts)
        fig.add_artist(
            mpatches.FancyBboxPatch(
                (tx, tile_y),
                tile_w,
                tile_h,
                boxstyle="round,pad=0,rounding_size=0.012",
                transform=fig.transFigure,
                facecolor=INSET,
                edgecolor=HAIRLINE,
                lw=0.9,
            )
        )
        fig.add_artist(
            mpatches.FancyBboxPatch(
                (tx, tile_y),
                0.008,
                tile_h,
                boxstyle="round,pad=0,rounding_size=0.004",
                transform=fig.transFigure,
                facecolor=col,
                edgecolor="none",
            )
        )
        pad = 0.028
        fig.text(
            tx + pad,
            tile_y + tile_h * 0.52,
            f"{hosts}",
            color=col,
            fontsize=46,
            fontweight="bold",
            family=SANS,
            ha="left",
            va="center",
        )
        fig.text(
            tx + pad + 0.072,
            tile_y + tile_h * 0.62,
            f"/ {host_count}",
            color=MUTED,
            fontsize=13,
            family=MONO,
            ha="left",
            va="center",
        )
        fig.text(
            tx + pad + 0.072,
            tile_y + tile_h * 0.42,
            "hosts",
            color=MUTED,
            fontsize=10,
            family=SANS,
            ha="left",
            va="center",
        )
        fig.text(
            tx + pad,
            tile_y + tile_h - 0.045,
            tid,
            color=INK,
            fontsize=13.5,
            fontweight="bold",
            family=MONO,
            ha="left",
            va="top",
        )
        fig.text(
            tx + pad,
            tile_y + 0.052,
            _MITRE_NAMES.get(tid, "technique"),
            color=MUTED,
            fontsize=9.6,
            family=SANS,
            ha="left",
            va="baseline",
        )

    if n <= 2:
        note_x = left + tiles_total + 0.05
        if note_x < right:
            lead_tid, lead_hosts = items[0]
            fig.text(
                note_x,
                tile_y + tile_h * 0.68,
                "Single dominant technique.",
                color=INK,
                fontsize=12.5,
                fontweight="bold",
                family=SANS,
                ha="left",
                va="center",
            )
            fig.text(
                note_x,
                tile_y + tile_h * 0.30,
                f"{_MITRE_NAMES.get(lead_tid, lead_tid)} appears on {lead_hosts}\n"
                f"of {host_count} hosts — a focused, not\nscattered, signature.",
                color=MUTED,
                fontsize=9.8,
                family=SANS,
                ha="left",
                va="center",
                linespacing=1.4,
            )

    _rule(fig, 0.055, 0.945, 0.075)
    _caption(
        fig, 0.055, 0.035, "MITRE ATT&CK  ·  fleet correlation", color=FAINT, size=8.2
    )
    _caption(
        fig,
        0.945,
        0.035,
        "severity: red ≥10  ·  amber 5–9  ·  blue 2–4",
        color=FAINT,
        size=8.2,
        ha="right",
    )
    _save(fig, fig_path)


def fig_cross_host_processes(corr: dict, fig_path: Path) -> None:
    """Editorial horizontal bars — the single most-shared image dominates and
    carries an annotation callout; the rest are thinner + muted."""
    counts = _cross_host_counts(corr)
    if not counts:
        return
    host_count = corr.get("host_count", 22)
    top_n = 10
    rows = list(reversed(counts[:top_n]))  # largest at top after barh
    names = [r[0] for r in rows]
    vals = [r[1] for r in rows]
    lead_name, lead_val = counts[0]

    fig = plt.figure(figsize=(11, 7.4))
    fig.patch.set_facecolor(FIG_BG)
    _kicker(fig, 0.055, 0.945, "Cross-host process reuse")
    _headline(fig, 0.055, 0.875, "One image, almost the whole fleet", size=23)
    _caption(
        fig,
        0.055,
        0.825,
        f"distinct hosts running each image · top {min(top_n, len(counts))} of "
        f"{len(counts)} shared images · {host_count} hosts total",
    )

    ax = fig.add_axes([0.30, 0.085, 0.63, 0.66])
    ax.set_facecolor(FIG_BG)
    for s in ("top", "right", "left", "bottom"):
        ax.spines[s].set_visible(False)
    ax.tick_params(length=0)
    ax.set_axisbelow(True)
    for gx in range(0, host_count + 1, 5):
        ax.axvline(gx, color=HAIRLINE, lw=0.7, zorder=0)

    is_lead = [n == lead_name for n in names]
    for yi, (val, lead) in enumerate(zip(vals, is_lead)):
        col = _severity_color(val)
        ax.barh(
            yi,
            val,
            height=(0.74 if lead else 0.46),
            color=col,
            alpha=(1.0 if lead else 0.62),
            edgecolor="none",
            zorder=3,
        )
        ax.text(
            val + 0.35,
            yi,
            f"{val}",
            va="center",
            ha="left",
            color=(INK if lead else MUTED),
            fontsize=(15 if lead else 11),
            fontweight=("bold" if lead else "normal"),
            family=MONO,
            zorder=4,
        )

    ax.set_yticks(range(len(rows)))
    ax.set_yticklabels(names, fontproperties=_mono())
    for tick, lead in zip(ax.get_yticklabels(), is_lead):
        tick.set_color(INK if lead else MUTED)
        tick.set_fontsize(12.5 if lead else 10.5)
        if lead:
            tick.set_fontweight("bold")

    ax.set_xlim(0, host_count + 2.5)
    ax.set_ylim(-0.7, len(rows) - 0.3)
    ax.set_xticks(range(0, host_count + 1, 5))
    ax.set_xticklabels([str(t) for t in range(0, host_count + 1, 5)], fontsize=9.5)
    ax.set_xlabel("distinct hosts", color=MUTED, fontsize=10, labelpad=8)

    lead_yi = names.index(lead_name)
    ax.annotate(
        f"{lead_val}/{host_count} hosts — fleet-wide\n{lead_name} is the dominant\n"
        "shared image across the estate",
        xy=(lead_val * 0.62, lead_yi - 0.28),
        xytext=(lead_val * 0.46, lead_yi - 1.55),
        fontsize=11,
        color=INK,
        family=SANS,
        va="top",
        ha="left",
        bbox=dict(boxstyle="round,pad=0.6", facecolor=INSET, edgecolor=ACCENT, lw=1.1),
        arrowprops=dict(
            arrowstyle="-|>",
            color=ACCENT,
            lw=1.4,
            connectionstyle="arc3,rad=-0.18",
            shrinkA=4,
            shrinkB=6,
        ),
        zorder=6,
    )

    lx, leg_y = 0.55, 0.775
    _caption(fig, lx - 0.045, leg_y, "severity", color=FAINT, size=8.5)
    for label, col in ((">=10 hosts", ALERT), ("5–9", INFERRED), ("2–4", HYPOTHESIS)):
        fig.add_artist(
            mpatches.FancyBboxPatch(
                (lx, leg_y - 0.004),
                0.016,
                0.014,
                boxstyle="round,pad=0,rounding_size=0.004",
                transform=fig.transFigure,
                facecolor=col,
                edgecolor="none",
            )
        )
        fig.text(
            lx + 0.022,
            leg_y,
            label,
            color=MUTED,
            fontsize=8.8,
            family=SANS,
            va="baseline",
        )
        lx += 0.022 + 0.012 * len(label) + 0.02

    _rule(fig, 0.055, 0.945, 0.79)
    _caption(
        fig, 0.055, 0.03, "CROSS-HOST  ·  fleet correlation", color=FAINT, size=8.2
    )
    _save(fig, fig_path)
    plt.close(fig)


def _temporal_band_color(hosts: int) -> str:
    """Per-panel host band (cluster host_count tops out low): >=5 red, 3-4 amber, 2 blue."""
    if hosts >= 5:
        return ALERT
    if hosts >= 3:
        return INFERRED
    return HYPOTHESIS


def _dense_month_window(rows: list[dict]):
    """Maximal contiguous run of months around the busiest one. Returns
    (count_in_window, label, {month_keys}) or None."""
    from collections import Counter

    def mkey(dt):
        return (dt.year, dt.month)

    months = sorted({mkey(r["start"]) for r in rows})
    if not months:
        return None
    mc = Counter(mkey(r["start"]) for r in rows)
    peak = max(mc, key=lambda k: mc[k])
    idx = months.index(peak)
    thr = max(1, mc[peak] * 0.2)

    def adj(a, b):
        return (b[0] - a[0]) * 12 + (b[1] - a[1]) == 1

    lo = hi = idx
    while lo - 1 >= 0 and adj(months[lo - 1], months[lo]) and mc[months[lo - 1]] >= thr:
        lo -= 1
    while (
        hi + 1 < len(months)
        and adj(months[hi], months[hi + 1])
        and mc[months[hi + 1]] >= thr
    ):
        hi += 1
    win = set(months[lo : hi + 1])
    cnt = sum(1 for r in rows if mkey(r["start"]) in win)
    a = datetime(months[lo][0], months[lo][1], 1).strftime("%b")
    b = datetime(months[hi][0], months[hi][1], 1).strftime("%b %Y")
    return cnt, (b if months[lo] == months[hi] else f"{a}–{b}"), win


def fig_temporal_clusters(corr: dict, fig_path: Path) -> None:
    """Single timeline ribbon — marker size = processes in the wave, color =
    hosts touched; the heaviest wave and the densest window are annotated."""
    clusters = corr.get("temporal_clusters", [])
    if not clusters:
        return
    rows = []
    for c in clusters:
        fe = c.get("first_event")
        if not fe:
            continue
        try:
            start = datetime.fromisoformat(fe)
        except ValueError:
            continue
        rows.append(
            {
                "start": start,
                "hosts": c.get("host_count", 0),
                "procs": len(c.get("events", [])),
                "dur": float(c.get("duration_seconds", 0.0)),
            }
        )
    if not rows:
        return
    rows.sort(key=lambda r: r["start"])
    n = len(rows)
    total_procs = sum(r["procs"] for r in rows)
    headline_row = max(rows, key=lambda r: r["procs"])
    max_procs = max(r["procs"] for r in rows) or 1

    fig = plt.figure(figsize=(11.4, 6.0))
    fig.patch.set_facecolor(FIG_BG)
    _kicker(fig, 0.05, 0.94, "Temporal clustering")
    _headline(fig, 0.05, 0.865, "Waves of near-simultaneous process creation", size=22)
    _caption(
        fig,
        0.05,
        0.81,
        f"{n} clusters · {total_procs} processes · each mark = one wave "
        "(≥2 hosts, seconds apart)",
    )

    ax = fig.add_axes([0.05, 0.40, 0.90, 0.30])
    ax.set_facecolor(FIG_BG)
    for s in ("top", "right", "left"):
        ax.spines[s].set_visible(False)
    ax.spines["bottom"].set_color(HAIRLINE)
    ax.spines["bottom"].set_linewidth(0.9)

    xs = [r["start"] for r in rows]
    x0, x1 = min(xs), max(xs)
    span = (x1 - x0).total_seconds() or 1.0

    def fx(t):
        return (t - x0).total_seconds() / span

    ribbon_y = 0.5
    ax.axhline(ribbon_y, color=HAIRLINE, lw=1.0, zorder=1)
    for r in rows:
        lead = r is headline_row
        ax.scatter(
            fx(r["start"]),
            ribbon_y,
            s=18 + 340 * (r["procs"] / max_procs) ** 0.62,
            color=(ACCENT if lead else _temporal_band_color(r["hosts"])),
            alpha=(1.0 if lead else 0.6),
            edgecolors=(ACCENT_LIGHT if lead else "none"),
            linewidths=(1.4 if lead else 0),
            zorder=(6 if lead else 3),
        )

    ax.set_xlim(-0.03, 1.03)
    ax.set_ylim(0, 1)
    ax.set_yticks([])
    seen, month_ticks = set(), []
    for r in rows:
        key = (r["start"].year, r["start"].month)
        if key not in seen:
            seen.add(key)
            month_ticks.append((fx(r["start"]), r["start"].strftime("%b %Y")))
    ax.set_xticks([t[0] for t in month_ticks])
    ax.set_xticklabels([t[1] for t in month_ticks], fontsize=9.5, color=MUTED)
    ax.tick_params(length=0, pad=10)

    hx = fx(headline_row["start"])
    ax.annotate(
        f"{headline_row['hosts']} hosts · {headline_row['procs']} procs · "
        f"{int(headline_row['dur'])}s\nheaviest synchronized burst\nlateral-movement wave",
        xy=(hx, ribbon_y - 0.07),
        xytext=(0.045, ribbon_y - 0.82),
        fontsize=11,
        color=INK,
        family=SANS,
        va="top",
        ha="left",
        bbox=dict(boxstyle="round,pad=0.6", facecolor=INSET, edgecolor=ACCENT, lw=1.1),
        arrowprops=dict(
            arrowstyle="-|>",
            color=ACCENT,
            lw=1.4,
            connectionstyle="arc3,rad=0.25",
            shrinkA=6,
            shrinkB=8,
        ),
        annotation_clip=False,
        zorder=7,
    )

    window = _dense_month_window(rows)
    if window and window[0] > 1:
        cnt, label, win = window
        band_rows = [r for r in rows if (r["start"].year, r["start"].month) in win]
        band_x = sum(fx(r["start"]) for r in band_rows) / len(band_rows)
        ax.annotate(
            f"{cnt} of {n} clusters fall in the\n{label} operational window",
            xy=(band_x, ribbon_y - 0.06),
            xytext=(band_x - 0.10, ribbon_y - 1.15),
            fontsize=9.8,
            color=MUTED,
            family=SANS,
            va="top",
            ha="center",
            arrowprops=dict(arrowstyle="-", color=FAINT, lw=0.9),
            annotation_clip=False,
            zorder=5,
        )

    leg_y = 0.10
    fig.text(
        0.05,
        leg_y,
        "marker size → processes in wave",
        color=FAINT,
        fontsize=8.8,
        family=SANS,
        va="baseline",
    )
    lx = 0.45
    fig.text(
        lx,
        leg_y,
        "hosts involved:",
        color=FAINT,
        fontsize=8.8,
        family=SANS,
        va="baseline",
    )
    lx += 0.105
    for lbl, col in (("≥5", ALERT), ("3–4", INFERRED), ("2", HYPOTHESIS)):
        fig.add_artist(
            mpatches.Circle(
                (lx, leg_y + 0.005),
                0.006,
                transform=fig.transFigure,
                facecolor=col,
                edgecolor="none",
            )
        )
        fig.text(
            lx + 0.013,
            leg_y,
            lbl,
            color=MUTED,
            fontsize=8.8,
            family=SANS,
            va="baseline",
        )
        lx += 0.013 + 0.012 * len(lbl) + 0.03

    _rule(fig, 0.05, 0.95, 0.145)
    _caption(fig, 0.05, 0.04, "TEMPORAL  ·  fleet correlation", color=FAINT, size=8.2)
    _save(fig, fig_path)


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------


def write_markdown(fleet_dir: Path, corr: dict, has_temporal: bool) -> Path:
    md = fleet_dir / "FLEET_REPORT.md"
    h = corr.get("host_count", 0)
    distrib = corr.get("verdict_distribution", {})
    cross = corr.get("cross_host_processes", {})
    clusters = corr.get("temporal_clusters", [])
    crypto = corr.get("cryptographic_attestation", {})

    susp = distrib.get("SUSPICIOUS", 0)
    indet = distrib.get("INDETERMINATE", 0)
    no_evil = distrib.get("NO_EVIL", 0)

    susp_pct = 100.0 * susp / max(1, h)

    cross_high = [
        (n, len({hh["host"] for hh in hits}))
        for n, hits in cross.items()
        if len({hh["host"] for hh in hits}) >= 4
    ]
    cross_high.sort(key=lambda kv: -kv[1])

    out = []
    out.append(f"# Fleet investigation report — {fleet_dir.name}")
    out.append("")
    out.append(f"**Hosts investigated:** {h}")
    out.append(
        f"**SUSPICIOUS:** {susp} ({susp_pct:.0f}%)  "
        f"**INDETERMINATE:** {indet}  "
        f"**NO_EVIL:** {no_evil}"
    )
    out.append(f"**Cross-host process correlations:** {len(cross)}")
    out.append(f"**Multi-host temporal clusters:** {len(clusters)}")
    if crypto:
        out.append(
            f"**Cryptographic integrity:** "
            f"{crypto.get('unique_merkle_roots', 0)}/"
            f"{crypto.get('total_merkle_roots', 0)} unique Merkle roots "
            f"({'OK — all manifests independent' if crypto.get('all_unique') else 'WARN — duplicate roots'})"
        )
    out.append("")
    out.append("---")
    out.append("")

    out.append("## Executive summary")
    out.append("")
    out.append(
        f"This is a fleet-level rollup of {h} per-host investigations "
        f"executed by `find-evil-auto` against the SRL-2018 SANS HACKATHON-2026 "
        f"dataset. {susp} of {h} hosts ({susp_pct:.0f}%) returned the "
        f"`SUSPICIOUS` verdict — they are the analyst's priority queue."
    )
    out.append("")
    out.append(
        "Each per-host investigation produced its own `run.manifest.json`, "
        "audit chain, and verdict; this report is a derivative summary, "
        "not a replacement for those primary artifacts. A judge or "
        "counter-party who wants to verify must verify each per-host "
        "manifest individually via `manifest_verify`."
    )
    out.append("")

    out.append("## Verdict distribution")
    out.append("")
    out.append("![Verdict distribution](figures/verdict_distribution.png)")
    out.append("")

    out.append("## MITRE ATT&CK technique density")
    out.append("")
    mitre = corr.get("mitre_technique_density", {})
    if mitre:
        out.append("![MITRE technique density](figures/mitre_density.png)")
        out.append("")
        # If a T1014 / enumeration-divergence pattern covers most hosts,
        # surface it — but a HIGH fleet prevalence argues AGAINST a
        # coordinated rootkit (which would have to unlink every core OS
        # process per host without crashing it) and FOR a shared
        # acquisition-smear / kernel-global read failure. Report as a
        # HYPOTHESIS, not N confirmed rootkits. (Post-smear-detection,
        # find_evil_auto tags smeared hosts mitre=None, so this count
        # reflects only genuine-DKOM hosts.)
        t1014 = mitre.get("T1014", 0)
        if t1014 >= max(2, h // 3):
            out.append(
                f"> **{t1014} hosts** show the `pslist`=0 / `psscan`>0 "
                f"process-enumeration divergence. Treat this as a "
                f"**HYPOTHESIS**, not {t1014} confirmed rootkits: a high "
                f"fleet prevalence is more consistent with a shared "
                f"acquisition-smear / kernel-global read failure than with a "
                f"coordinated DKOM rootkit. Confirm or dismiss per host via "
                f"on-disk service/driver artifacts (≥2 artifact classes) "
                f"before asserting T1014."
            )
            out.append("")

    out.append("## Cross-host process correlations")
    out.append("")
    out.append(
        "*hypothesis: the same uncommon process image name appearing on "
        "multiple hosts is a much stronger lateral-movement signal than the "
        "same name on one host alone — a lead for an analyst to confirm. "
        "Below: image names appearing on ≥2 hosts.*"
    )
    out.append("")
    out.append("![Cross-host process correlation](figures/cross_host_processes.png)")
    out.append("")
    if cross_high:
        out.append(
            f"**{len(cross_high)} image names appear on ≥4 hosts.** "
            "Pull the corresponding binary off the disk image of any of these "
            "hosts and YARA-scan against YARA-Forge core rules:"
        )
        out.append("")
        for name, count in cross_high[:15]:
            out.append(f"- `{name}` ({count} hosts)")
        out.append("")

    out.append("## Multi-host temporal clusters (lateral-movement candidates)")
    out.append("")
    if has_temporal:
        out.append("![Temporal clusters](figures/temporal_clusters.png)")
        out.append("")
    if clusters:
        out.append(
            f"hypothesis: {len(clusters)} clusters detected. Each cluster is "
            f"a group of process creations across ≥2 hosts within a 60-second "
            f"window — the temporal fingerprint of automated tradecraft "
            f"(PsExec waves, WMI execution chains, scheduled-task pivots) — "
            f"leads for an analyst to confirm, not conclusions."
        )
        out.append("")
        out.append("**Top clusters (by host count):**")
        out.append("")
        sorted_clusters = sorted(clusters, key=lambda c: -c["host_count"])[:5]
        for i, cl in enumerate(sorted_clusters, 1):
            out.append(
                f"### Cluster {i}: {cl['host_count']} hosts in "
                f"{cl['duration_seconds']:.0f}s"
            )
            out.append("")
            out.append(f"- First event: `{cl['first_event']}`")
            out.append(f"- Last event:  `{cl['last_event']}`")
            out.append("- Sample events:")
            for ev in cl["events"][:8]:
                out.append(
                    f"  - `{ev['host']}` PID {ev['pid']} `{ev['name']}` "
                    f"at {ev['create_time']}"
                )
            out.append("")

    out.append("## Cryptographic attestation")
    out.append("")
    if crypto:
        all_unique = crypto.get("all_unique", False)
        unique = crypto.get("unique_merkle_roots", 0)
        total = crypto.get("total_merkle_roots", 0)
        if all_unique:
            out.append(
                f"All {total} per-host manifests have **unique Merkle roots** "
                f"({unique}/{total}) — chain integrity intact. Each "
                f"`run.manifest.json` is independently verifiable via "
                f"`manifest_verify`."
            )
        else:
            out.append(
                f"WARNING: {total - unique} duplicate Merkle root(s) "
                f"detected ({unique} unique of {total} total). "
                "Investigate immediately — duplicate roots indicate either "
                "a tampering attempt or a tool bug."
            )
    out.append("")

    out.append("## Recommended analyst priorities")
    out.append("")
    out.append(
        "1. **Triage SUSPICIOUS hosts first** — pull each one's "
        "`verdict.json` and `REPORT.pdf` from its case directory."
    )
    out.append(
        "2. **Investigate the top cross-host process names** (≥4 hosts). "
        "Pull the binary off any of those hosts' disk images, YARA-scan, "
        "compute SHA-256, check against threat-intel feeds."
    )
    out.append(
        "3. **Trace temporal clusters back to patient zero**. The first "
        "host in each cluster is the entry point candidate — focus deeper "
        "analysis (registry, MFT timeline, EVTX 4624/4688) on that host."
    )
    out.append(
        "4. **For T1014 hosts: check `\\Windows\\System32\\drivers\\` on "
        "their disk images** for unsigned or non-Microsoft .sys files "
        "modified in the suspected compromise window."
    )
    out.append(
        "5. **Cross-reference timestamps with EVTX logon events** — "
        "lateral-movement clusters should align with Logon Type 3 "
        "(Network) or Type 10 (RDP) events on the destination hosts."
    )
    out.append("")
    out.append("---")
    out.append("")
    out.append(
        f"*Produced by `render_fleet_report.py` on "
        f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}. The "
        f"authoritative evidence is the per-host `run.manifest.json` "
        f"in each case directory; this report is a derivative summary.*"
    )

    md.write_text("\n".join(out), encoding="utf-8")
    return md


# ---------------------------------------------------------------------------
# HTML / PDF render
# ---------------------------------------------------------------------------


def render_html_pdf(md_path: Path) -> tuple[Path, Path | None]:
    fleet_dir = md_path.parent
    html = fleet_dir / "FLEET_REPORT.html"
    pdf = fleet_dir / "FLEET_REPORT.pdf"

    style_path = REPO_ROOT / "scripts" / "_report_style.css"
    if not style_path.exists():
        return html, None

    subprocess.run(
        [
            PANDOC,
            str(md_path),
            "--standalone",
            "--embed-resources",
            "--css",
            str(style_path),
            "-o",
            str(html),
        ],
        check=True,
        capture_output=True,
    )

    pdf_out: Path | None = None
    if Path(CHROME).exists():
        # Render to a sibling .new.pdf first; rename atomically so a PDF
        # locked by a viewer doesn't lose the new render. See
        # render_report.py for the same pattern.
        pdf_tmp = pdf.with_suffix(".new.pdf")
        try:
            html_url = "file:///" + str(html).replace("\\", "/")
            subprocess.run(
                [
                    CHROME,
                    "--headless",
                    "--disable-gpu",
                    "--no-sandbox",
                    "--print-to-pdf=" + str(pdf_tmp),
                    "--print-to-pdf-no-header",
                    "--virtual-time-budget=10000",
                    html_url,
                ],
                capture_output=True,
                timeout=120,
            )
            if pdf_tmp.exists() and pdf_tmp.stat().st_size > 1000:
                try:
                    pdf_tmp.replace(pdf)
                    pdf_out = pdf
                except OSError:
                    print(
                        f"  WARN: could not overwrite {pdf} (likely open "
                        f"in a viewer); rendered output left at {pdf_tmp}"
                    )
                    pdf_out = pdf_tmp
        except Exception:
            pass
    return html, pdf_out


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("fleet_dir", nargs="?", default=None)
    args = p.parse_args()

    fleet_dir = Path(args.fleet_dir) if args.fleet_dir else latest_fleet_dir()
    if fleet_dir is None or not fleet_dir.is_dir():
        print("no fleet directory found")
        return 1

    corr_path = fleet_dir / "fleet_correlation.json"
    if not corr_path.exists():
        print(f"correlation file missing — run fleet_correlate.py first: {corr_path}")
        return 1
    corr = json.loads(corr_path.read_text(encoding="utf-8"))

    fig_dir = fleet_dir / "figures"
    fig_dir.mkdir(parents=True, exist_ok=True)

    fig_verdict_distribution(corr, fig_dir / "verdict_distribution.png")
    fig_mitre_density(corr, fig_dir / "mitre_density.png")
    fig_cross_host_processes(corr, fig_dir / "cross_host_processes.png")
    has_temporal = bool(corr.get("temporal_clusters"))
    if has_temporal:
        fig_temporal_clusters(corr, fig_dir / "temporal_clusters.png")

    md = write_markdown(fleet_dir, corr, has_temporal)
    html, pdf = render_html_pdf(md)

    print(f"  -> {md}")
    print(f"  -> {html}")
    if pdf:
        print(f"  -> {pdf}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
