#!/usr/bin/env python3
"""Render an investigation report from a finished case dir.

Called by find_evil_auto.py at the end of an investigation. Generates
figures (matplotlib) + Markdown (templated) + HTML + PDF (Chrome
headless) inside the case's local directory.

Self-contained: can also be run standalone against any case dir that
has the required artifacts:

    python scripts/render_report.py /path/to/case-dir/
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime
from html import escape
from pathlib import Path, PurePosixPath
from typing import Any

import matplotlib

matplotlib.use("Agg")  # headless
import matplotlib.dates as mdates  # noqa: E402
import matplotlib.patches as mpatches  # noqa: E402
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch  # noqa: E402


def _resolve_tool(env_var: str, *fallback_names: str) -> str | None:
    override = os.environ.get(env_var, "").strip()
    if override and Path(override).exists():
        return override
    for name in fallback_names:
        found = shutil.which(name)
        if found:
            return found
    return None


PANDOC: str | None = _resolve_tool("PANDOC_BIN", "pandoc")
CHROME: str | None = _resolve_tool(
    "CHROME_BIN",
    "google-chrome",
    "google-chrome-stable",
    "chromium",
    "chromium-browser",
    "chrome",
)

# VERDICT v2 figure palette. Figures remain light "mounted exhibits" on the dark
# report, but semantic strokes/fills match the v2 brand-bible colors.
V_PURPLE = "#4D5DFF"  # legacy name: Electric Cobalt brand/info
V_GREEN = "#73D9C2"  # Seafoam verified/pass
V_AMBER = "#FFD76A"  # Butter Yellow review/attention
V_BLUE = "#4D5DFF"  # Electric Cobalt hypothesis/info
V_RED = "#FF6257"  # Signal Coral rejected/flagged
V_INK = "#101426"
V_MUTED = "#7F789C"


def display_artifact_path(value: Any) -> str:
    """Return a report-safe artifact label without operator-local paths."""

    raw = str(value or "").strip()
    if not raw or raw == "n/a":
        return "n/a"

    normalized = raw.replace("\\", "/")
    if "/extracted/disk/" in normalized:
        return "case-extracted://" + normalized.split("/extracted/disk/", 1)[1]

    if "/.findevil/cases/" in normalized:
        case_tail = normalized.split("/.findevil/cases/", 1)[1]
        if "/" in case_tail:
            return "case://" + case_tail.split("/", 1)[1]
        return "case://artifact"

    if normalized.startswith("/") or re.match(r"^[A-Za-z]:/", normalized):
        return PurePosixPath(normalized).name or "artifact"

    return raw


plt.rcParams.update(
    {
        "font.family": "DejaVu Sans",
        "font.size": 10,
        "axes.titlesize": 12,
        "axes.titleweight": "bold",
        "savefig.dpi": 150,
        "savefig.bbox": "tight",
        "figure.facecolor": "#fbfaf6",
        "axes.facecolor": "#fbfaf6",
        "savefig.facecolor": "#fbfaf6",
        "text.color": V_INK,
        "axes.edgecolor": "#cfc8ba",
        "axes.labelcolor": V_INK,
        "axes.titlecolor": V_INK,
        "xtick.color": V_MUTED,
        "ytick.color": V_MUTED,
        "grid.color": "#e6e0d4",
    }
)


# ---------------------------------------------------------------------------
# Figure generators (produce PNGs in <case_dir>/figures/)
# ---------------------------------------------------------------------------


def fig_audit_chain(
    audit: list[dict[str, Any]], manifest: dict[str, Any], out: Path
) -> None:
    fig, ax = plt.subplots(figsize=(11, 6))
    ax.axis("off")
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 6)

    def box(x, y, w, h, txt, color="#eef0ff", border=V_PURPLE, fs=9):
        p = FancyBboxPatch(
            (x, y),
            w,
            h,
            boxstyle="round,pad=0.05",
            facecolor=color,
            edgecolor=border,
            linewidth=1.2,
        )
        ax.add_patch(p)
        ax.text(
            x + w / 2,
            y + h / 2,
            txt,
            ha="center",
            va="center",
            fontsize=fs,
            family="monospace",
        )

    def arrow(x1, y1, x2, y2):
        ax.add_patch(
            FancyArrowPatch(
                (x1, y1),
                (x2, y2),
                arrowstyle="-|>",
                mutation_scale=12,
                color=V_PURPLE,
                linewidth=1.2,
            )
        )

    ax.text(
        5,
        5.6,
        "Cryptographic chain of custody — manifest_finalize output",
        ha="center",
        fontsize=12,
        fontweight="bold",
    )

    ax.text(
        0.2,
        5.0,
        "audit.jsonl (hash-chained)",
        fontsize=9,
        fontweight="bold",
        color=V_PURPLE,
    )
    for i, rec in enumerate(audit[:5]):
        ph = rec.get("prev_hash", "") or "<genesis>"
        box(
            0.2,
            4.4 - i * 0.55,
            3.6,
            0.45,
            f"seq={rec['seq']} kind={rec['kind'][:14]}\nprev_hash={ph[:14]}…",
            color="#eef0ff",
            border=V_PURPLE,
            fs=7,
        )

    box(
        0.2,
        1.2,
        3.6,
        0.5,
        f"audit_log_final_hash:\n{manifest['audit_log_final_hash'][:32]}…",
        color="#fff8dd",
        border=V_AMBER,
    )

    ax.text(
        5.5,
        5.0,
        "Merkle leaves (per tool_call_output)",
        fontsize=9,
        fontweight="bold",
        color=V_PURPLE,
    )
    for i in range(min(manifest["leaf_count"], 4)):
        box(
            5.5,
            4.4 - i * 0.55,
            3.6,
            0.45,
            f"leaf {i}: tool_call output_hash digest",
            color="#eef0ff",
            border=V_PURPLE,
            fs=8,
        )

    box(
        5.5,
        1.2,
        3.6,
        0.5,
        f"merkle_root_hex:\n{manifest['merkle_root_hex'][:32]}…",
        color="#fff8dd",
        border=V_AMBER,
    )

    sig_sha = manifest["signature"]["payload_sha256"]
    sig_kind = str(manifest["signature"].get("kind") or "stub")
    box(
        2,
        0.2,
        6,
        0.7,
        f"run.manifest.json (signature tier: {sig_kind})\n"
        f"signature_payload_sha256: {sig_sha[:32]}…",
        color="#e8fbf7",
        border=V_GREEN,
        fs=8,
    )

    arrow(2.0, 1.2, 4.5, 0.9)
    arrow(8.0, 1.2, 5.5, 0.9)

    fig.savefig(out)
    plt.close(fig)


def fig_psscan_timeline(psscan: list[dict[str, Any]], out: Path) -> None:
    """Process creation timeline from psscan output."""
    common = {
        n.lower()
        for n in {
            "System",
            "smss.exe",
            "csrss.exe",
            "winlogon.exe",
            "lsass.exe",
            "services.exe",
            "svchost.exe",
            "explorer.exe",
            "vmtoolsd.exe",
            "WmiPrvSE.exe",
            "spoolsv.exe",
            "lsm.exe",
            "wininit.exe",
            "dllhost.exe",
            "conhost.exe",
            "wmiprvse.exe",
            "taskhost.exe",
            "taskhostw.exe",
            "RuntimeBroker.exe",
        }
    }
    events = []
    for p in psscan:
        ts = p.get("CreateTime")
        if not ts:
            continue
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except Exception:
            continue
        events.append(
            {
                "dt": dt,
                "pid": p["PID"],
                "ppid": p["PPID"],
                "name": p["ImageFileName"],
                "threads": p.get("Threads", 0),
            }
        )
    events.sort(key=lambda e: e["dt"])
    if not events:
        return
    fig, ax = plt.subplots(figsize=(12, 6))
    times = [e["dt"] for e in events]
    pids = [e["pid"] for e in events]
    sizes = [max(20, min(200, e["threads"] * 3)) for e in events]
    colors = [V_RED if e["name"].lower() not in common else V_PURPLE for e in events]
    ax.scatter(
        times, pids, c=colors, s=sizes, alpha=0.7, edgecolors="black", linewidths=0.5
    )
    ax.set_xlabel("Process creation time (UTC)")
    ax.set_ylabel("PID")
    ax.set_title(
        f"Process creation timeline ({len(events)} processes via psscan)\n"
        "Coral = uncommon image name; Cobalt = standard Windows process"
    )
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%Y-%m-%d %H:%M"))
    plt.setp(ax.xaxis.get_majorticklabels(), rotation=30, ha="right")
    ax.grid(True, alpha=0.3)
    ax.legend(
        handles=[
            mpatches.Patch(color=V_PURPLE, label="Standard Windows process"),
            mpatches.Patch(color=V_RED, label="Uncommon image name"),
        ],
        loc="upper left",
        fontsize=8,
    )
    fig.tight_layout()
    fig.savefig(out)
    plt.close(fig)


def _parse_event_time(event: dict[str, Any]) -> datetime | None:
    value = event.get("timestamp_utc") or event.get("ts")
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def fig_timeline_overview(events: list[dict[str, Any]], out: Path) -> bool:
    parsed = []
    for event in events:
        dt = _parse_event_time(event)
        if dt is None:
            continue
        parsed.append(
            {
                "dt": dt,
                "artifact_class": event.get("artifact_class") or "unknown",
                "significance": event.get("significance") or "context",
            }
        )
    fig, ax = plt.subplots(figsize=(12, 4.8))
    if not parsed:
        ax.axis("off")
        ax.text(
            0.5,
            0.5,
            "No normalized timeline events available",
            ha="center",
            va="center",
            fontsize=11,
            color="#777",
        )
        fig.savefig(out)
        plt.close(fig)
        return False

    classes = sorted({row["artifact_class"] for row in parsed})
    class_to_y = {name: i for i, name in enumerate(classes)}
    colors = {
        "context": V_PURPLE,
        "triage_lead": V_AMBER,
        "finding_support": V_RED,
    }
    for row in parsed:
        ax.scatter(
            row["dt"],
            class_to_y[row["artifact_class"]],
            s=55,
            color=colors.get(row["significance"], V_PURPLE),
            edgecolor="black",
            linewidth=0.4,
            alpha=0.8,
        )
    ax.set_yticks(list(class_to_y.values()), list(class_to_y.keys()))
    ax.set_xlabel("UTC time")
    ax.set_title(f"Normalized timeline overview ({len(parsed)} timestamped events)")
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%Y-%m-%d %H:%M"))
    plt.setp(ax.xaxis.get_majorticklabels(), rotation=30, ha="right")
    ax.grid(True, axis="x", alpha=0.3)
    ax.legend(
        handles=[
            mpatches.Patch(color=V_PURPLE, label="Context"),
            mpatches.Patch(color=V_AMBER, label="Triage lead"),
            mpatches.Patch(color=V_RED, label="Finding support"),
        ],
        loc="upper left",
        fontsize=8,
    )
    fig.tight_layout()
    fig.savefig(out)
    plt.close(fig)
    return True


def fig_entity_timeline(events: list[dict[str, Any]], out: Path) -> bool:
    """Swimlane: events grouped by actor/host down the y-axis, time across x."""
    rows = []
    for event in events:
        dt = _parse_event_time(event)
        if dt is None:
            continue
        entities = event.get("entities") or {}
        actor = (
            _format_account_display(entities)
            or entities.get("host")
            or entities.get("workstation")
            or entities.get("process")
        )
        if not actor:
            continue
        rows.append(
            {
                "dt": dt,
                "actor": str(actor)[:34],
                "significance": event.get("significance") or "context",
            }
        )
    if not rows:
        return False

    counts: dict[str, int] = {}
    for row in rows:
        counts[row["actor"]] = counts.get(row["actor"], 0) + 1
    top = set(sorted(counts, key=lambda a: (-counts[a], a))[:14])
    rows = [row for row in rows if row["actor"] in top]
    actors = sorted(top)
    actor_to_y = {name: i for i, name in enumerate(actors)}
    colors = {
        "context": V_PURPLE,
        "triage_lead": V_AMBER,
        "finding_support": V_RED,
    }
    fig, ax = plt.subplots(figsize=(12, 1.6 + 0.42 * len(actors)))
    for row in rows:
        ax.scatter(
            row["dt"],
            actor_to_y[row["actor"]],
            s=60,
            color=colors.get(row["significance"], V_PURPLE),
            edgecolor="black",
            linewidth=0.4,
            alpha=0.85,
        )
    ax.set_yticks(list(actor_to_y.values()), list(actor_to_y.keys()))
    ax.set_xlabel("UTC time")
    ax.set_title(f"Entity timeline — events by actor / host ({len(rows)} events)")
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%Y-%m-%d %H:%M"))
    plt.setp(ax.xaxis.get_majorticklabels(), rotation=30, ha="right")
    ax.grid(True, axis="x", alpha=0.3)
    ax.legend(
        handles=[
            mpatches.Patch(color=V_PURPLE, label="Context"),
            mpatches.Patch(color=V_AMBER, label="Triage lead"),
            mpatches.Patch(color=V_RED, label="Finding support"),
        ],
        loc="upper left",
        fontsize=8,
    )
    fig.tight_layout()
    fig.savefig(out)
    plt.close(fig)
    return True


def fig_attack_story_timeline(attack_story: dict[str, Any], out: Path) -> bool:
    beats = attack_story.get("attack_chain", []) if attack_story else []
    fig, ax = plt.subplots(figsize=(12, 1.8 + 0.6 * max(1, len(beats))))
    ax.axis("off")
    if not beats:
        ax.text(
            0.5,
            0.5,
            "No finding-backed attack-story beats available",
            ha="center",
            va="center",
            fontsize=11,
            color="#777",
        )
        fig.savefig(out)
        plt.close(fig)
        return False

    ax.set_xlim(0, 10)
    ax.set_ylim(0, len(beats) + 1)
    colors = {
        "CONFIRMED": V_GREEN,
        "INFERRED": V_AMBER,
        "HYPOTHESIS": V_BLUE,
    }
    for idx, beat in enumerate(beats[:8], 1):
        y = len(beats[:8]) - idx + 0.6
        confidence = str(beat.get("confidence") or "HYPOTHESIS")
        color = colors.get(confidence, V_BLUE)
        ax.scatter(0.7, y, s=180, color=color, edgecolor="black", linewidth=0.6)
        ax.text(
            0.7,
            y,
            str(beat.get("order") or idx),
            ha="center",
            va="center",
            color=V_INK if confidence in {"CONFIRMED", "INFERRED"} else "white",
            fontsize=8,
            fontweight="bold",
        )
        title = _short_title(
            beat.get("title") or beat.get("summary") or "Finding-backed story beat"
        )
        tcid = beat.get("tool_call_id") or "?"
        mitre = beat.get("mitre_technique") or "n/a"
        ts = _fmt_ts(beat.get("timestamp_utc")) or "time not normalized"
        ax.text(
            1.1, y + 0.13, title, ha="left", va="center", fontsize=9, fontweight="bold"
        )
        ax.text(
            1.1,
            y - 0.17,
            f"{confidence} | {mitre} | {tcid} | {ts}",
            ha="left",
            va="center",
            fontsize=8,
            color="#444",
        )
    ax.set_title("How they got hacked - evidence-bound attack story")
    fig.tight_layout()
    fig.savefig(out)
    plt.close(fig)
    return True


def fig_process_view_comparison(tool_calls: list[dict[str, Any]], out: Path) -> bool:
    rows = []
    for tool in ("vol_pslist", "vol_psscan", "vol_psxview"):
        matches = [tc for tc in tool_calls if tc.get("tool") == tool]
        if not matches:
            continue
        tc = matches[-1]
        count = tc.get("processes_seen", tc.get("processes_returned", 0))
        try:
            count_int = int(count)
        except (TypeError, ValueError):
            count_int = 0
        rows.append((tool, count_int, tc.get("tool_call_id", "?")))
    if not rows:
        return False
    fig, ax = plt.subplots(figsize=(8.5, 4.5))
    tools = [row[0] for row in rows]
    counts = [row[1] for row in rows]
    colors = [V_PURPLE, V_AMBER, V_RED][: len(rows)]
    ax.bar(tools, counts, color=colors, edgecolor="black", linewidth=0.6)
    for i, (_, count, tcid) in enumerate(rows):
        ax.text(i, count, f"{count}\n{tcid}", ha="center", va="bottom", fontsize=8)
    ax.set_ylabel("Process rows / objects seen")
    ax.set_title("Memory process-view comparison by typed tool output")
    ax.grid(True, axis="y", alpha=0.25)
    fig.tight_layout()
    fig.savefig(out)
    plt.close(fig)
    return True


# ---------------------------------------------------------------------------
# Markdown report template
# ---------------------------------------------------------------------------


_TS_DISPLAY_RE = re.compile(
    r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.\d+)?(Z|[+-]\d{2}:?\d{2})?$"
)


def _fmt_ts(value: Any) -> str:
    """Trim sub-second precision from an ISO timestamp for table display.

    Microsecond precision is column-width noise in the report; the full-precision
    timestamps remain in `timeline.csv`/`timeline.json`.
    """
    text = str(value or "")
    match = _TS_DISPLAY_RE.match(text)
    return match.group(1) + (match.group(2) or "Z") if match else text


def md_cell(value: Any) -> str:
    if isinstance(value, list):
        value = ", ".join(str(v) for v in value)
    text = escape(str(value or ""), quote=False)
    for old, new in (
        ("\\", "\\\\"),
        ("`", "'"),
        ("\r", " "),
        ("\n", " "),
        ("|", "\\|"),
        ("[", "\\["),
        ("]", "\\]"),
        ("(", "\\("),
        (")", "\\)"),
    ):
        text = text.replace(old, new)
    return text


def _short_title(description: Any, mitre: Any = None) -> str:
    """A clean, word-boundary-safe title from a finding/event description.

    Takes the leading clause (up to the first em-dash / colon / open-paren /
    sentence end), trims to <=80 chars on a word boundary with an ellipsis, and
    optionally prefixes the MITRE technique. Never cuts mid-word.
    """
    text = str(description or "").strip()
    if not text:
        return "Finding"
    clause = re.split(r"\s*[—:(]\s*|\.\s", text, maxsplit=1)[0].strip() or text
    if len(clause) > 80:
        clause = clause[:77].rsplit(" ", 1)[0].rstrip() + "…"
    technique = str(mitre or "").strip()
    if technique and technique.lower() not in ("", "n/a", "none"):
        return f"{technique}: {clause}"
    return clause


# Friendly display names for analysis-coverage domain lane keys (the lane row
# also carries a "label", which takes precedence when present).
_DOMAIN_LABELS: dict[str, str] = {
    "endpoint_host": "Host & Endpoint Forensics",
    "memory": "Memory Forensics",
    "windows_event": "Windows Event & Account Analysis",
    "network": "Network Forensics",
    "malware": "Malware Analysis & Triage",
    "live_response": "Endpoint Telemetry & Live Response",
}


def _lane_label(lane_key: str, row: dict[str, Any]) -> str:
    return row.get("label") or _DOMAIN_LABELS.get(
        lane_key, lane_key.replace("_", " ").title()
    )


def _format_account_display(entities: dict[str, Any]) -> str:
    account = str(entities.get("account") or "").strip()
    if not account:
        return ""
    domain = str(entities.get("domain") or "").strip()
    if domain and domain not in ("-", account):
        return f"{domain}\\{account}"
    return account


def _entity_cell(entities: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = entities.get(key)
        if value not in (None, "", "-"):
            return str(value)
    return ""


def safe_visual_asset(case_dir: Path, asset: Any) -> str | None:
    asset_s = str(asset or "").replace("\\", "/")
    path = PurePosixPath(asset_s)
    if (
        len(path.parts) != 2
        or path.parts[0] != "figures"
        or path.suffix.lower() != ".png"
        or any(part in {"", ".."} for part in path.parts)
    ):
        return None
    local = (case_dir / path.parts[0] / path.parts[1]).resolve()
    figures_dir = (case_dir / "figures").resolve()
    if not local.is_relative_to(figures_dir) or not local.exists():
        return None
    return asset_s


def build_false_positive_caveats(
    merged: list[dict[str, Any]],
    completeness: dict[str, Any] | None,
    attack_coverage: dict[str, Any] | None,
) -> list[str]:
    caveats = [
        "Sigma/Hayabusa rule hits, if present, are triage leads that require raw EVTX review, tuning, and corroboration before compromise claims.",
    ]
    targets = attack_coverage.get("targets", []) if attack_coverage else []
    if any(row.get("status") == "covered_no_finding" for row in targets):
        caveats.append(
            "ATT&CK `covered_no_finding` means scoped tools ran without qualifying evidence; it is not environment-wide assurance about that technique."
        )
    checks = {
        c.get("artifact_class"): c for c in (completeness or {}).get("checks", [])
    }
    if not checks.get("network", {}).get("touched"):
        caveats.append(
            "Network telemetry was not touched in this run, so exfiltration and C2 cannot be assessed from these artifacts."
        )
    if not checks.get("disk/filesystem", {}).get("touched"):
        caveats.append(
            "Disk/filesystem artifacts were not deeply parsed in this run; memory-only or EVTX-only observations do not prove execution."
        )
    if any(f.get("confidence") == "HYPOTHESIS" for f in merged):
        caveats.append(
            "HYPOTHESIS findings are single-source or speculative leads and should not drive response actions without further artifact corroboration."
        )
    return caveats


def _artifact_check(
    completeness: dict[str, Any] | None, artifact_class: str
) -> dict[str, Any]:
    for check in (completeness or {}).get("checks", []):
        if check.get("artifact_class") == artifact_class:
            return check
    return {}


def _format_tools(tools: Any) -> str:
    if isinstance(tools, list):
        return ", ".join(str(tool) for tool in tools) or "none recorded"
    return str(tools or "none recorded")


def build_scope_interpretation_section(
    completeness: dict[str, Any] | None,
    attack_coverage: dict[str, Any] | None,
) -> str:
    network = _artifact_check(completeness, "network")
    disk = _artifact_check(completeness, "disk/filesystem")
    coverage_targets = (attack_coverage or {}).get("targets", [])
    exfil_targets = [
        row
        for row in coverage_targets
        if row.get("technique_id") in {"T1041", "T1048", "T1020"}
        or "exfil" in str(row.get("technique_name", "")).lower()
    ]

    network_touched = bool(network.get("touched"))
    network_available = bool(network.get("available"))
    disk_touched = bool(disk.get("touched"))
    disk_available = bool(disk.get("available"))
    network_proves = (
        "Typed network telemetry was parsed by the listed tools, so network-derived leads can be tied to those tool outputs."
        if network_touched
        else "Network telemetry was not parsed by typed network tools in this run."
    )
    network_not_prove = (
        "It does not by itself prove exfiltration, C2, or environment-wide network scope; those claims require finding-specific collection/staging plus network, tool, or data-movement evidence."
        if network_touched
        else "It does not evaluate C2 or exfiltration from network artifacts, and it must not be read as network assurance."
    )
    disk_proves = (
        "Disk/filesystem artifacts were parsed by the listed tools, so persistence, file, registry, Prefetch, or timeline statements can cite those outputs when Findings do so."
        if disk_touched
        else "Disk evidence, if supplied, is represented only as availability/custody unless mounted or extracted artifacts were parsed by typed tools."
    )
    disk_not_prove = (
        "It does not by itself prove execution; execution claims still require at least two artifact classes, not Amcache/ShimCache-style presence alone."
        if disk_touched
        else "It does not support disk-content conclusions, execution conclusions, or persistence conclusions without extracted/mounted artifact output."
    )
    exfil_status = (
        ", ".join(
            f"{row.get('technique_id')}={row.get('status')}"
            for row in exfil_targets[:3]
        )
        or "no exfiltration-specific ATT&CK target recorded"
    )

    lines = [
        "\n## Scope & Coverage Caveats\n",
        "This section states what the rendered coverage can and cannot prove. Limited coverage is not customer assurance about unexamined systems, techniques, or artifact classes.\n",
        "### Network Evidence Summary\n",
        f"* Available from supplied evidence: `{network_available}`",
        f"* Parsed/touched by typed tools: `{network_touched}`",
        f"* Tools: `{md_cell(_format_tools(network.get('tools')))}`",
        f"* Confidence impact: {md_cell(network.get('confidence_impact', 'network coverage not recorded'))}",
        f"* Exfiltration coverage target status: {md_cell(exfil_status)}",
        f"* **What this proves:** {network_proves}",
        f"* **What this does not prove:** {network_not_prove}",
        "\n### Disk Artifact Coverage Summary\n",
        f"* Available from supplied evidence: `{disk_available}`",
        f"* Parsed/touched by typed tools: `{disk_touched}`",
        f"* Tools: `{md_cell(_format_tools(disk.get('tools')))}`",
        f"* Confidence impact: {md_cell(disk.get('confidence_impact', 'disk/filesystem coverage not recorded'))}",
        f"* **What this proves:** {disk_proves}",
        f"* **What this does not prove:** {disk_not_prove}",
        "",
    ]
    return "\n".join(lines)


def build_readiness_section(
    report_qa: dict[str, Any] | None,
    release_gate: dict[str, Any] | None,
) -> str:
    if not report_qa and not release_gate:
        return ""
    failed = (release_gate or {}).get("failed_checks", []) or [
        check.get("check_id")
        for check in (report_qa or {}).get("checks", [])
        if check.get("status") == "FAIL"
    ]
    warnings = (release_gate or {}).get("warning_checks", []) or [
        check.get("check_id")
        for check in (report_qa or {}).get("checks", [])
        if check.get("status") == "WARN"
    ]
    blockers = (release_gate or {}).get("release_blockers") or (report_qa or {}).get(
        "customer_release_blockers", []
    )
    expert_decision = (release_gate or {}).get(
        "expert_decision", (report_qa or {}).get("expert_decision", "pending")
    )
    packet_state = (release_gate or {}).get(
        "packet_state", (report_qa or {}).get("packet_state", "unknown")
    )
    customer_releasable = (release_gate or {}).get(
        "customer_releasable", (report_qa or {}).get("customer_releasable", False)
    )
    ready_for_expert = (report_qa or {}).get("ready_for_expert_signoff", False)
    ready_for_pdf = (release_gate or {}).get(
        "ready_for_customer_pdf", (report_qa or {}).get("ready_for_customer_pdf", False)
    )
    blocker_lines = "\n".join(f"* {md_cell(item)}" for item in blockers)
    warning_lines = "\n".join(f"* {md_cell(item)}" for item in warnings)
    failed_lines = "\n".join(f"* {md_cell(item)}" for item in failed)
    return (
        "\n## Readiness State\n\n"
        f"* Packet state: `{md_cell(packet_state)}`\n"
        f"* Ready for expert review/signoff: `{ready_for_expert}`\n"
        f"* Expert-review status: `{md_cell(expert_decision)}`\n"
        f"* Ready for customer PDF: `{ready_for_pdf}`\n"
        f"* Customer releasable: `{customer_releasable}`\n\n"
        "### Blockers\n\n"
        + (blocker_lines or "* No release blockers were recorded by the QA gate.")
        + "\n\n### Failed Checks\n\n"
        + (failed_lines or "* No failed checks were recorded by the QA gate.")
        + "\n\n### Warnings\n\n"
        + (warning_lines or "* No warning checks were recorded by the QA gate.")
        + "\n\n"
    )


def build_coverage_manifest_section(coverage_manifest: dict[str, Any] | None) -> str:
    if not coverage_manifest:
        return ""
    summary = coverage_manifest.get("summary") or {}
    rows = [
        "| Artifact Class | Status | Available | Attempted | Parsed | Failed | Unsupported | Not Supplied | Parse Errors | Records Seen | Rows Returned | Tools |",
        "|---|---|:---:|:---:|:---:|:---:|:---:|:---:|---:|---:|---:|---|",
    ]
    for row in coverage_manifest.get("artifact_classes", []):
        rows.append(
            "| {artifact_class} | `{status}` | {available} | {attempted} | {parsed} | {failed} | {unsupported} | {not_supplied} | {parse_errors} | {records_seen} | {rows_returned} | `{tools}` |".format(
                artifact_class=md_cell(row.get("artifact_class", "?")),
                status=md_cell(row.get("status", "")),
                available="yes" if row.get("available") else "no",
                attempted="yes" if row.get("attempted") else "no",
                parsed="yes" if row.get("parsed") else "no",
                failed="yes" if row.get("failed") else "no",
                unsupported="yes" if row.get("unsupported") else "no",
                not_supplied="yes" if row.get("not_supplied") else "no",
                parse_errors=md_cell(row.get("parse_errors", 0)),
                records_seen=md_cell(row.get("records_seen", 0)),
                rows_returned=md_cell(row.get("rows_returned", 0)),
                tools=md_cell(row.get("tools_attempted", [])),
            )
        )
    status_counts = summary.get("status_counts", {})
    unsupported_samples: list[str] = []
    for row in coverage_manifest.get("artifact_classes", []):
        if not isinstance(row, dict) or not row.get("unsupported"):
            continue
        for sample in row.get("sample_paths") or []:
            if len(unsupported_samples) >= 20:
                break
            if sample:
                unsupported_samples.append(str(sample))
    unsupported_samples_section = ""
    if unsupported_samples:
        unsupported_samples_section = (
            "\n### Unsupported Artifact Samples\n\n"
            "These paths were inventoried or observed but no typed parser processed "
            "them in this run.\n\n"
            + "\n".join(f"* `{md_cell(sample)}`" for sample in unsupported_samples)
            + "\n\n"
        )
    return (
        "\n## Coverage Manifest\n\n"
        f"{md_cell(coverage_manifest.get('truth_boundary', ''))}\n\n"
        "This table is the explicit anti-overclaim record for the run. "
        "`not_supplied`, `unsupported`, `failed`, and `partial` rows are scope gaps, not clean findings.\n\n"
        f"* Artifact classes recorded: `{summary.get('artifact_classes_recorded', 0)}`\n"
        f"* Attempted: `{summary.get('attempted', 0)}`; parsed: `{summary.get('parsed', 0)}`; failed: `{summary.get('failed', 0)}`\n"
        f"* Unsupported: `{summary.get('unsupported', 0)}`; not supplied: `{summary.get('not_supplied', 0)}`\n"
        f"* ATT&CK blind spots: `{summary.get('attack_blind_spot_count', 0)}`\n"
        f"* Status counts: `{md_cell(status_counts)}`\n\n"
        + "\n".join(rows)
        + "\n\n"
        + unsupported_samples_section
    )


# ---------------------------------------------------------------------------
# Native HTML/CSS figures — authored as bespoke, VERDICT-themed markup and
# injected into REPORT.html post-pandoc (see _inject_figures). Vector-crisp,
# rendered by the same Chrome pass that prints the PDF; no charting library.
# ---------------------------------------------------------------------------

EVENT_ID_LABELS: dict[str, str] = {
    "1102": "Log clearing",
    "1116": "Defender detection",
    "4624": "Logon",
    "4625": "Failed logon",
    "4634": "Logoff",
    "4648": "Explicit-credential logon",
    "4663": "File/handle access",
    "4672": "Special privileges",
    "4688": "Process created",
    "4698": "Scheduled task created",
    "4720": "User account created",
    "4732": "Added to local group",
    "4768": "Kerberos TGT",
    "4769": "Kerberos service ticket",
    "4776": "Credential validation",
    "5140": "Share accessed",
    "5156": "Network allowed",
    "7045": "Service installed",
}
CRITICAL_EVENT_IDS: set[str] = {"1102", "1116", "4720", "4728", "4732", "7045", "4698"}


def _h(value: Any) -> str:
    """HTML-escape a data value for safe injection into the report figures."""
    return escape(str(value if value is not None else ""), quote=True)


def _event_id_from_ref(ref: Any) -> str:
    match = re.search(r"event_id=(\d+)", str(ref or ""))
    return match.group(1) if match else ""


def html_scorecard(
    verdict: str,
    attack_story: dict[str, Any] | None,
    merged: list[dict[str, Any]],
) -> str:
    """At-a-glance verdict card: verdict tier, headline, key entity/technique, counts."""
    tier = {
        "SUSPICIOUS": "alert",
        "NO_EVIL": "confirmed",
        "INDETERMINATE": "inferred",
    }.get(verdict, "inferred")
    story = attack_story or {}
    certainty = str(story.get("certainty") or "")
    certainty_word = certainty.split()[0].rstrip(".") if certainty else "—"
    beat = (story.get("attack_chain") or [{}])[0] if story.get("attack_chain") else {}
    meta = [
        _h(v)
        for v in (
            beat.get("actor"),
            beat.get("host"),
            beat.get("mitre_technique"),
        )
        if v
    ]
    counts = {"CONFIRMED": 0, "INFERRED": 0, "HYPOTHESIS": 0}
    for finding in merged:
        c = finding.get("confidence")
        if c in counts:
            counts[c] += 1
    chips = "".join(
        f'<span class="vchip vchip-{name.lower()}">{counts[name]} {name.title()}</span>'
        for name in ("CONFIRMED", "INFERRED", "HYPOTHESIS")
        if counts[name]
    )
    return (
        f'<div class="vfig vsc vsc-{tier}">'
        f'<div class="vsc-rail"></div>'
        f'<div class="vsc-body">'
        f'<div class="vsc-top"><span class="vsc-verdict vsc-verdict-{tier}">{_h(verdict)}</span>'
        f'<span class="vsc-cert">Certainty&nbsp;·&nbsp;{_h(certainty_word)}</span></div>'
        f'<div class="vsc-headline">{_h(story.get("headline", ""))}</div>'
        f'<div class="vsc-meta">{" &nbsp;·&nbsp; ".join(meta)}</div>'
        f'<div class="vsc-chips">{chips}</div>'
        f"</div></div>"
    )


def html_event_composition(evtx_summary: dict[str, Any] | None) -> str:
    """Horizontal bars: what the evidence contains, critical event IDs flagged."""
    if not evtx_summary:
        return ""
    top = evtx_summary.get("top_event_ids") or []
    if not top:
        return ""
    counts = [int(row.get("count", 0) or 0) for row in top]
    total = evtx_summary.get("records_seen") or sum(counts)
    peak = max(counts, default=1) or 1
    rows = []
    for row in top[:8]:
        eid = str(row.get("event_id"))
        count = int(row.get("count", 0) or 0)
        label = EVENT_ID_LABELS.get(eid, "Event")
        critical = eid in CRITICAL_EVENT_IDS
        pct = max(4, round(100 * count / peak))
        flag = ' <span class="vcomp-flag">⚠</span>' if critical else ""
        rows.append(
            f'<div class="vcomp-row{" vcomp-crit" if critical else ""}">'
            f'<span class="vcomp-label">{_h(eid)}&nbsp;·&nbsp;{_h(label)}</span>'
            f'<span class="vcomp-track"><span class="vcomp-fill" style="width:{pct}%"></span></span>'
            f'<span class="vcomp-count">{count}{flag}</span></div>'
        )
    return (
        '<div class="vfig vcomp">'
        f'<div class="vfig-title">What the evidence contains '
        f'<span class="vfig-sub">{_h(total)} records</span></div>'
        f"{''.join(rows)}</div>"
    )


def html_event_sequence(events: list[dict[str, Any]]) -> str:
    """Vertical story-strip: key events in order, the cited finding(s) flagged."""
    key_events = _select_key_events(events)
    if not key_events:
        return ""
    rows = []
    for event in key_events:
        entities = event.get("entities") or {}
        critical = (
            _event_id_from_ref(event.get("source_record_ref")) in CRITICAL_EVENT_IDS
        )
        kind = "vseq-evil" if critical else "vseq-ctx"
        who = _format_account_display(entities) or _entity_cell(
            entities, "host", "workstation"
        )
        tcid = event.get("tool_call_id") or ""
        flag = (
            '<span class="vseq-flag">⚠ finding</span>'
            if critical
            else '<span class="vseq-tag">context</span>'
        )
        sub = " &nbsp;·&nbsp; ".join(_h(v) for v in (who, tcid) if v)
        rows.append(
            f'<li class="vseq-item {kind}"><span class="vseq-dot"></span>'
            f'<span class="vseq-time">{_h(_fmt_ts(event.get("timestamp_utc")) or "—")}</span>'
            f'<div class="vseq-body"><div class="vseq-action">{_h((event.get("summary") or "")[:130])} {flag}</div>'
            f'<div class="vseq-who">{sub}</div></div></li>'
        )
    return (
        '<div class="vfig vseq">'
        '<div class="vfig-title">What happened — key events</div>'
        f'<ol class="vseq-list">{"".join(rows)}</ol>'
        '<div class="vfig-note">⚠ marks a cited finding; other rows are surrounding '
        "context, not findings.</div></div>"
    )


def build_bluf_section(
    attack_story: dict[str, Any] | None,
    verdict: str,
    merged: list[dict[str, Any]],
    host_groups: list[dict[str, Any]] | None = None,
) -> str:
    """Bottom Line Up Front: verdict + one-line story + the top next step."""
    story = attack_story or {}
    counts = {"CONFIRMED": 0, "INFERRED": 0, "HYPOTHESIS": 0}
    for finding in merged:
        confidence = finding.get("confidence")
        if confidence in counts:
            counts[confidence] += 1
    decisions = story.get("recommended_next_decisions") or []
    top = decisions[0] if decisions else "Expert review before customer release."
    parts = [
        "\n## Bottom Line Up Front\n\n",
        '::: {.report-fig data-fig="scorecard"}\n:::\n\n',
        f"**Verdict: {md_cell(verdict)}.** {md_cell(story.get('headline', ''))}\n\n",
        f"{md_cell(story.get('customer_summary', ''))}\n\n",
    ]
    # Scope honesty: when findings span more than one host, name them and say the
    # evidence does not establish them as a single incident.
    groups = host_groups or []
    if len(groups) > 1:
        spans = "; ".join(
            f"{g.get('host')} ({str(g.get('top_confidence', '')).lower()})"
            for g in groups
        )
        parts.append(
            f"**Scope:** findings span {len(groups)} hosts — {md_cell(spans)}. Each is "
            "assessed separately below; the evidence does not establish them as one "
            "incident.\n\n"
        )
    if story.get("assessment"):
        parts.append(f"**Assessment:** {md_cell(story['assessment'])}\n\n")
    if story.get("certainty"):
        parts.append(f"**Certainty:** {md_cell(story['certainty'])}\n\n")
    key_findings = story.get("what_we_can_say") or []
    if key_findings:
        parts.append(
            "**Key findings:**\n\n"
            + "\n".join(f"* {md_cell(item)}" for item in key_findings)
            + "\n\n"
        )
    parts.append(
        f"* Findings: {len(merged)} total — {counts['CONFIRMED']} confirmed, "
        f"{counts['INFERRED']} inferred, {counts['HYPOTHESIS']} hypothesis.\n"
        f"* Most important next step: {md_cell(top)}\n\n"
    )
    return "".join(parts)


def _fmt_window(first: Any, last: Any) -> str:
    start, end = _fmt_ts(first), _fmt_ts(last)
    if start and end and start != end:
        return f"{start} → {end}"
    return start or end or "time not recorded"


def build_host_sections(
    host_groups: list[dict[str, Any]] | None,
    attack_story: dict[str, Any] | None,
    normalized_timeline: dict[str, Any] | None,
) -> str:
    """Per-host analyst narrative.

    Each host gets its findings as a phase-ordered chain (named technique, CVE,
    analyst note, next pivot) plus that host's key events. A multi-host case is
    presented per host so unrelated hosts are not narrated as one incident.
    """
    groups = host_groups or []
    if not groups:
        return ""
    beats = (attack_story or {}).get("attack_chain", []) or []
    beats_by_host: dict[str, list[dict[str, Any]]] = {}
    for beat in beats:
        beats_by_host.setdefault(str(beat.get("host") or ""), []).append(beat)
    all_events = (normalized_timeline or {}).get("events", []) or []

    parts = ["\n## Host Analysis\n\n"]
    if len(groups) > 1:
        parts.append(
            "Findings span more than one host; each is assessed on its own "
            "evidence below. The evidence does not establish them as a single "
            "incident.\n\n"
        )
    for group in groups:
        host = str(group.get("host") or "unknown host")
        host_beats = beats_by_host.get(host, [])
        counts = group.get("by_confidence", {})
        srcs = ", ".join(group.get("evidence_sources", []) or [])
        parts.append(f"### {md_cell(host)}\n\n")
        parts.append(
            f"*{group.get('finding_count', len(host_beats))} finding(s) — "
            f"{counts.get('CONFIRMED', 0)} confirmed, {counts.get('INFERRED', 0)} "
            f"inferred, {counts.get('HYPOTHESIS', 0)} hypothesis · "
            f"{group.get('event_count', 0)} events · "
            f"{_fmt_window(group.get('first_seen'), group.get('last_seen'))}"
            + (f" · source: {md_cell(srcs)}" if srcs else "")
            + "*\n\n"
        )
        if not host_beats:
            parts.append("No findings attributed to this host.\n\n")
        for beat in host_beats:
            named = (
                beat.get("named_technique") or beat.get("mitre_technique") or "Finding"
            )
            cves = beat.get("cves") or []
            cve_txt = f" — {', '.join(cves)}" if cves else ""
            parts.append(
                f"**{md_cell(beat.get('phase', 'Finding'))}: {md_cell(named)}"
                f"{md_cell(cve_txt)}** `[{md_cell(beat.get('confidence', ''))}]` "
                f"`{md_cell(beat.get('tool_call_id', ''))}`\n\n"
            )
            if beat.get("analyst_note"):
                parts.append(f"{md_cell(beat['analyst_note'])}\n\n")
            if beat.get("next_pivot"):
                parts.append(f"*Next:* {md_cell(beat['next_pivot'])}\n\n")
            if beat.get("hunt"):
                parts.append(f"*Hunt:* `{beat['hunt']}`\n\n")
        finding_ids = {str(fid) for fid in (group.get("finding_ids", []) or [])}
        host_events = [
            event
            for event in all_events
            if str(
                (event.get("entities") or {}).get("host")
                or (event.get("entities") or {}).get("workstation")
                or ""
            )
            == host
            or any(
                str(fid) in finding_ids
                for fid in (event.get("linked_finding_ids") or [])
            )
        ]
        key_events = _select_key_events(host_events, cap=8)
        if key_events:
            parts.append(
                "| Time (UTC) | Event | Account | Tool Call |\n|---|---|---|---|\n"
            )
            for event in key_events:
                ent = event.get("entities") or {}
                parts.append(
                    f"| {md_cell(_fmt_ts(event.get('timestamp_utc')))} "
                    f"| {md_cell((event.get('summary') or '')[:80])} "
                    f"| {md_cell(_format_account_display(ent) or '—')} "
                    f"| `{md_cell(event.get('tool_call_id', ''))}` |\n"
                )
            parts.append("\n")
    return "".join(parts)


def _select_key_events(
    events: list[dict[str, Any]], cap: int = 12
) -> list[dict[str, Any]]:
    """Pick the pivotal, entity-bearing events for the Tier-1 timeline."""

    def priority(event: dict[str, Any]) -> int:
        entities = event.get("entities") or {}
        if any(
            entities.get(key)
            for key in ("account", "source_ip", "service_name", "logon_type_label")
        ):
            return 0
        if event.get("significance") == "triage_lead":
            return 1
        return 2

    candidates: list[dict[str, Any]] = []
    seen: set[Any] = set()
    for event in events:
        entities = event.get("entities") or {}
        interesting = event.get("significance") in (
            "finding_support",
            "triage_lead",
        ) or any(
            entities.get(key)
            for key in ("account", "source_ip", "service_name", "logon_type_label")
        )
        if not interesting:
            continue
        # Collapse repeated identical events so distinct ones surface.
        key = event.get("summary")
        if key in seen:
            continue
        seen.add(key)
        candidates.append(event)
    candidates.sort(key=lambda e: (priority(e), e.get("timestamp_utc") or ""))
    selected = candidates[:cap]
    selected.sort(key=lambda e: e.get("timestamp_utc") or "")
    return selected


def build_timeline_of_events_section(
    normalized_timeline: dict[str, Any] | None,
    event_narratives: list[dict[str, Any]] | None,
    has_entity_fig: bool,
    has_timeline_fig: bool,
) -> str:
    """Tier-1 timeline: figures + a key-events table (no prose narrative)."""
    events = (normalized_timeline or {}).get("events", []) or []
    if not events:
        return ""
    figs = (
        '::: {.report-fig data-fig="sequence"}\n:::\n\n'
        '::: {.report-fig data-fig="composition"}\n:::\n\n'
    )
    narrative_block = ""
    table_block = ""
    key_events = _select_key_events(events)
    if key_events:
        rows = [
            "| UTC Time | Event | Account | Host | Source IP | Tool Call |",
            "|---|---|---|---|---|---|",
        ]
        for event in key_events:
            entities = event.get("entities") or {}
            rows.append(
                "| {ts} | {ev} | {acct} | {host} | {ip} | `{tcid}` |".format(
                    ts=md_cell(_fmt_ts(event.get("timestamp_utc")) or "?"),
                    ev=md_cell((event.get("summary") or "")[:90]),
                    acct=md_cell(_format_account_display(entities) or "—"),
                    host=md_cell(_entity_cell(entities, "host", "workstation") or "—"),
                    ip=md_cell(
                        _entity_cell(entities, "source_ip", "destination_ip") or "—"
                    ),
                    tcid=md_cell(event.get("tool_call_id") or "?"),
                )
            )
        table_block = "### Key Events\n\n" + "\n".join(rows) + "\n\n"
    return (
        "\n## Timeline\n\n"
        "Key events in chronological order, traceable by account, host, and address; "
        "each cites the tool call that produced it. The full event ledger is in the "
        "technical report below.\n\n" + figs + narrative_block + table_block
    )


def build_detailed_event_timeline_section(
    timeline: list[dict[str, Any]] | None,
    timeline_csv_exists: bool,
    has_timeline_fig: bool,
) -> str:
    """Tier-2 full event ledger with entity columns."""
    if not timeline:
        return ""
    exports = "`timeline.json`"
    if timeline_csv_exists:
        exports += " and analyst-friendly `timeline.csv`"
    rows = [
        "| UTC Time | Artifact | Event | Account | Host | Source IP | Logon | "
        "Process/PID | Conf. | Tool Call |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]

    def _content_key(ev: dict[str, Any]) -> tuple:
        ent = ev.get("entities") or {}
        return (
            (ev.get("summary") or ev.get("description") or "")[:110],
            _format_account_display(ent) or "",
            _entity_cell(ent, "host", "workstation") or "",
            _entity_cell(ent, "source_ip", "destination_ip") or "",
            _entity_cell(ent, "process") or "",
            str(ev.get("tool_call_id") or ""),
            bool(ev.get("linked_finding_ids")),
        )

    # Collapse consecutive same-content events (e.g. an object-access 4663 burst
    # with distinct sub-second timestamps) into one row with an [Nx] count, so the
    # preview keeps distinct events visible. Finding-backed events never collapse
    # into context (the key includes linked_finding_ids). Full data is in the CSV.
    collapsed: list[dict[str, Any]] = []
    for event in timeline:
        if collapsed and _content_key(collapsed[-1]["ev"]) == _content_key(event):
            collapsed[-1]["count"] += 1
        else:
            collapsed.append({"ev": event, "count": 1})

    shown = collapsed[:40]
    for entry in shown:
        event = entry["ev"]
        count = entry["count"]
        entities = event.get("entities") or {}
        process = _entity_cell(entities, "process")
        pid = _entity_cell(entities, "pid")
        process_pid = (
            f"{process} ({pid})" if process and pid else (process or pid or "")
        )
        summary = (event.get("summary") or event.get("description") or "")[:110]
        if count > 1:
            summary = f"[{count}x] {summary}"
        rows.append(
            "| {ts} | {ac} | {ev} | {acct} | {host} | {ip} | {logon} | {pp} | "
            "{conf} | `{tcid}` |".format(
                ts=md_cell(
                    _fmt_ts(event.get("timestamp_utc") or event.get("ts")) or "?"
                ),
                ac=md_cell(event.get("artifact_class", "?")),
                ev=md_cell(summary),
                acct=md_cell(_format_account_display(entities) or "—"),
                host=md_cell(_entity_cell(entities, "host", "workstation") or "—"),
                ip=md_cell(
                    _entity_cell(entities, "source_ip", "destination_ip") or "—"
                ),
                logon=md_cell(
                    _entity_cell(entities, "logon_type_label", "logon_type") or "—"
                ),
                pp=md_cell(process_pid or "—"),
                # Confidence is a Finding attribute: show it only for events that
                # actually back a Finding; pure context events show "—".
                conf=md_cell(
                    event.get("confidence", "")
                    if event.get("linked_finding_ids")
                    else "—"
                ),
                tcid=md_cell(event.get("tool_call_id", "?")),
            )
        )
    fig_block = ""
    collapsed_note = (
        " (consecutive identical events collapsed with an [Nx] count)"
        if len(collapsed) < len(timeline)
        else ""
    )
    return (
        "\n## Full Event Timeline\n\n"
        f"Normalized timeline events: {len(timeline)}. First {len(shown)} rows shown "
        f"below{collapsed_note}; full data is in {exports}.\n\n"
        + fig_block
        + "\n".join(rows)
        + "\n\n"
    )


def build_cast_of_characters_section(entity_index: dict[str, Any] | None) -> str:
    """Tier-2 entity rollup: trace each account/host/IP/process across the case."""
    if not entity_index:
        return ""
    buckets = [
        ("accounts", "Accounts"),
        ("hosts", "Hosts"),
        ("workstations", "Workstations"),
        ("source_ips", "Source IPs"),
        ("destination_ips", "Destination IPs"),
        ("processes", "Processes"),
        ("services", "Services"),
    ]
    blocks: list[str] = []
    for key, label in buckets:
        rows = entity_index.get(key) or []
        if not rows:
            continue
        lines = [
            f"### {label}",
            "",
            "| Value | Events | First Seen | Last Seen | Findings |",
            "|---|---:|---|---|---|",
        ]
        for row in rows[:20]:
            lines.append(
                "| {value} | {count} | {first} | {last} | {findings} |".format(
                    value=md_cell(row.get("value", "")),
                    count=row.get("event_count", 0),
                    first=md_cell(_fmt_ts(row.get("first_seen")) or "—"),
                    last=md_cell(_fmt_ts(row.get("last_seen")) or "—"),
                    findings=md_cell(row.get("linked_finding_ids") or []) or "—",
                )
            )
        blocks.append("\n".join(lines))
    if not blocks:
        return ""
    return (
        "\n## Observed Hosts, Accounts & Processes\n\n"
        "Every account, host, address, and process observed across the timeline, with "
        "where it first and last appears and which findings cite it.\n\n"
        + "\n\n".join(blocks)
        + "\n\n"
    )


def build_indicators_section(indicators: dict[str, Any] | None) -> str:
    """Tier-2 indicators appendix for detection engineering / threat hunting."""
    if not indicators:
        return ""
    groups = [
        ("accounts", "Accounts"),
        ("hosts", "Hosts / Workstations"),
        ("ip_addresses", "IP addresses"),
        ("domains", "Domains"),
        ("urls", "URLs"),
        ("processes", "Processes"),
        ("services", "Services"),
        ("registry_values", "Registry values"),
        ("file_paths", "File paths"),
        ("hashes", "Hashes"),
    ]
    rows = ["| Type | Values |", "|---|---|"]
    has_values = False
    for key, label in groups:
        values = indicators.get(key) or []
        if not values:
            continue
        has_values = True
        rows.append(f"| {label} | {md_cell(values)} |")
    if not has_values:
        return ""
    note = indicators.get("note", "")
    return (
        "\n## Indicators of Compromise (IOCs)\n\n"
        + (f"{md_cell(note)}\n\n" if note else "")
        + "\n".join(rows)
        + "\n\n"
    )


def write_markdown(
    case_dir: Path,
    manifest: dict[str, Any],
    merged: list[dict[str, Any]],
    contras: int,
    kept: int,
    downgraded: int,
    evidence: str,
    verdict: str,
    has_psscan: bool,
    audit: list[dict[str, Any]] | None = None,
    completeness: dict[str, Any] | None = None,
    coverage_manifest: dict[str, Any] | None = None,
    attack_coverage: dict[str, Any] | None = None,
    next_actions: list[dict[str, Any]] | None = None,
    timeline: list[dict[str, Any]] | None = None,
    timeline_csv_exists: bool = False,
    evtx_summary: dict[str, Any] | None = None,
    practitioner_coverage: dict[str, Any] | None = None,
    malware_triage: dict[str, Any] | None = None,
    analysis_limitations: list[str] | None = None,
    evidence_cards: list[dict[str, Any]] | None = None,
    bibliography: list[dict[str, Any]] | None = None,
    attack_story: dict[str, Any] | None = None,
    report_qa: dict[str, Any] | None = None,
    expert_doctrine: dict[str, Any] | None = None,
    release_gate: dict[str, Any] | None = None,
    normalized_timeline: dict[str, Any] | None = None,
    entity_index: dict[str, Any] | None = None,
    indicators: dict[str, Any] | None = None,
    event_narratives: list[dict[str, Any]] | None = None,
    has_timeline_fig: bool = False,
    has_attack_story_fig: bool = False,
    has_process_view_fig: bool = False,
    has_entity_timeline_fig: bool = False,
    rejected_finding_leads: list[dict[str, Any]] | None = None,
    verdict_revisions: list[dict[str, Any]] | None = None,
    host_groups: list[dict[str, Any]] | None = None,
) -> Path:
    md = case_dir / "REPORT.md"
    fa = manifest["audit_log_final_hash"]
    mr = manifest["merkle_root_hex"]
    sig = manifest["signature"]["payload_sha256"]
    cf = manifest["signature"]["cert_fingerprint"]
    sig_kind = str(manifest["signature"].get("kind") or "stub")
    sig_label = {
        "sigstore": "Sigstore signature",
        "ed25519": "Ed25519 signature",
    }.get(sig_kind, f"Signature ({sig_kind})")

    # The executive narrative (headline / summary / assessment / certainty / key
    # findings) lives entirely in the Bottom Line Up Front above. This block only
    # produces the Recommendations list and captures the justified unknowns for
    # the single merged ## Limitations section below.
    beats_section = ""  # removed: redundant with Detailed Findings + Timeline
    decisions_section = ""
    cannot_say: list[str] = []
    if attack_story:
        cannot_say = attack_story.get("what_we_cannot_say", []) or []
        decisions = attack_story.get("recommended_next_decisions", []) or []
        decisions_section = (
            "\n## Recommendations\n\n"
            + (
                "\n".join(f"* {md_cell(item)}" for item in decisions)
                or "* Expert review before customer release."
            )
            + "\n\n"
        )

    qa_section = ""
    if report_qa:
        rows = ["| Check | Status | Summary |", "|---|---|---|"]
        for check in report_qa.get("checks", []):
            rows.append(
                f"| `{md_cell(check.get('check_id', ''))}` | "
                f"{md_cell(check.get('status', ''))} | "
                f"{md_cell(check.get('summary', ''))} |"
            )
        qa_section = (
            "\n## QA / Expert Signoff\n\n"
            f"* Overall QA status: `{report_qa.get('status', '?')}`\n"
            f"* Packet state: `{report_qa.get('packet_state', 'unknown')}`\n"
            f"* Ready for expert signoff: `{report_qa.get('ready_for_expert_signoff', False)}`\n"
            f"* Customer-release candidate from automated QA: `{report_qa.get('customer_release_candidate', False)}`\n"
            f"* Customer releasable after expert approval: `{report_qa.get('customer_releasable', False)}`\n"
            f"* Expert decision: `{report_qa.get('expert_decision', 'pending')}`\n"
            f"* Expert review estimate: `{report_qa.get('recommended_expert_review_time', 'unknown')}`\n"
            "* Signoff question: `Would I send this report to a company without rewriting it?`\n\n"
            + "\n".join(rows)
            + "\n\n"
        )

    expert_section = ""
    if expert_doctrine:
        rules = expert_doctrine.get("claim_rules", [])
        rows = ["| Rule | Severity | Requirement |", "|---|---|---|"]
        for rule in rules[:8]:
            rows.append(
                f"| `{md_cell(rule.get('id', ''))}` | "
                f"{md_cell(rule.get('severity', ''))} | "
                f"{md_cell(rule.get('requirement', ''))} |"
            )
        expert_section = (
            "\n## Analysis Doctrine\n\n"
            f"{md_cell(expert_doctrine.get('operating_model', ''))}\n\n"
            + "\n".join(rows)
            + "\n\n"
        )

    release_gate_section = ""
    if release_gate:
        blockers = release_gate.get("release_blockers", []) or []
        blocker_lines = "\n".join(f"* {md_cell(item)}" for item in blockers)
        release_gate_section = (
            "\n## Customer Release Gate\n\n"
            "This gate is written after `manifest_finalize` and `manifest_verify`; "
            "it is a post-finalize linkage artifact, not a replacement for the "
            "audited `verdict.json` hash committed before manifest finalization.\n\n"
            f"* QA status: `{md_cell(release_gate.get('qa_status', 'unknown'))}`\n"
            f"* Packet state: `{md_cell(release_gate.get('packet_state', 'unknown'))}`\n"
            f"* Manifest verified: `{release_gate.get('manifest_verified', False)}`\n"
            f"* Manifest signature present: `{release_gate.get('manifest_signature_present', False)}`\n"
            f"* Signer: `{md_cell(release_gate.get('signer', 'unknown'))}`\n"
            f"* Expert approved: `{release_gate.get('expert_approved', False)}`\n"
            f"* Customer releasable: `{release_gate.get('customer_releasable', False)}`\n"
            "\n### Release Blockers\n\n"
            + (blocker_lines or "* No release blockers recorded.")
            + "\n\n"
        )

    findings_md_lines = []
    replay_rows = [
        "| Finding | Tool | Drift class | Match | Expected SHA | Actual SHA |",
        "|---|---|---|:---:|---|---|",
    ]
    for i, f in enumerate(merged, 1):
        replay_artifact = f.get("replay_artifact") or {}
        replay_chip = ""
        if replay_artifact:
            replay_chip = (
                f", replay: {replay_artifact.get('drift_class', 'unknown')}"
                f" ({'match' if replay_artifact.get('matched') else 'no match'})"
            )
            replay_rows.append(
                "| {finding} | `{tool}` | `{drift}` | {matched} | `{expected}` | `{actual}` |".format(
                    finding=md_cell(f.get("finding_id", f"#{i}")),
                    tool=md_cell(replay_artifact.get("tool_name", "")),
                    drift=md_cell(replay_artifact.get("drift_class", "")),
                    matched="yes" if replay_artifact.get("matched") else "no",
                    expected=md_cell(
                        str(replay_artifact.get("expected_sha256") or "")[:12]
                    ),
                    actual=md_cell(
                        str(replay_artifact.get("actual_sha256") or "")[:12]
                    ),
                )
            )
        for corr in f.get("corroboration_replays") or []:
            # A CONFIRMED execution finding cites two artifact classes; this row
            # attests the replay of the corroborating (e.g. UserAssist) class so the
            # appendix is not "2-class claim, 1 replay".
            replay_rows.append(
                "| {finding} | `{tool}` | `{drift}` | {matched} | `{expected}` | `{actual}` |".format(
                    finding=md_cell(
                        str(f.get("finding_id", f"#{i}")) + " (corroboration)"
                    ),
                    tool=md_cell(corr.get("tool_name", "")),
                    drift=md_cell(corr.get("drift_class", "")),
                    matched="yes" if corr.get("matched") else "no",
                    expected=md_cell(str(corr.get("expected_sha256") or "")[:12]),
                    actual=md_cell(str(corr.get("actual_sha256") or "")[:12]),
                )
            )
        findings_md_lines.append(
            f"### Finding {i} — confidence: {f.get('confidence', '?')}, "
            f"pool: {f.get('pool_origin', '?')}, "
            f"MITRE: {f.get('mitre_technique') or 'n/a'}{replay_chip}"
        )
        findings_md_lines.append("")
        findings_md_lines.append(md_cell(f.get("description", "")) + "\n")
        findings_md_lines.append(
            f"- `tool_call_id`: `{md_cell(f.get('tool_call_id', 'n/a'))}`"
        )
        findings_md_lines.append(
            f"- artifact: `{md_cell(display_artifact_path(f.get('artifact_path')))}`"
        )
        caveat = {
            "CONFIRMED": "Confirmed — the cited tool output is reproducible; this does "
            "not imply attribution or complete scope.",
            "INFERRED": "Inferred — derived from corroborated facts; confirm before acting.",
            "HYPOTHESIS": "Hypothesis — a single-source triage lead; corroborate before "
            "any response action.",
        }.get(f.get("confidence"), "")
        if caveat:
            findings_md_lines.append(f"- confidence: {caveat}")
        findings_md_lines.append("")
    findings_section = (
        "\n".join(findings_md_lines) if findings_md_lines else "*No merged findings.*"
    )
    if merged:
        findings_summary_rows = [
            "| Confidence | Pool | MITRE | Finding |",
            "|---|---|---|---|",
        ]
        for finding in merged:
            # The Confidence column already states the tier, so strip the doctrinal
            # "hypothesis:" prose prefix here to avoid saying it twice in one row.
            desc = str(finding.get("description", ""))
            if desc.lower().startswith("hypothesis:"):
                desc = desc[len("hypothesis:") :].lstrip()
            findings_summary_rows.append(
                f"| {md_cell(finding.get('confidence', ''))} "
                f"| {md_cell(finding.get('pool_origin', ''))} "
                f"| {md_cell(finding.get('mitre_technique', '') or '—')} "
                f"| {md_cell(desc)} |"
            )
        findings_summary_table = "\n".join(findings_summary_rows)
    else:
        findings_summary_table = "*No merged findings.*"
    replay_appendix = ""
    if len(replay_rows) > 2:
        replay_appendix = (
            "\n## Reproducibility Appendix\n\n"
            "Verifier replay artifacts record whether each cited tool call reproduced "
            "the audited output hash. They do not change Track 3b severity policy.\n\n"
            + "\n".join(replay_rows)
            + "\n"
        )

    rejected_leads = [
        lead for lead in (rejected_finding_leads or []) if isinstance(lead, dict)
    ]
    rejected_leads_section = ""
    if rejected_leads:
        rows = [
            "| Finding | Tool Call | Confidence | MITRE | Description | Verifier Reason | Effect | Analyst Action |",
            "|---|---|---|---|---|---|---|---|",
        ]
        for lead in rejected_leads[:20]:
            rows.append(
                "| {finding} | `{tool}` | `{confidence}` | `{mitre}` | {description} | "
                "{reason} | `{effect}` | {action} |".format(
                    finding=md_cell(lead.get("finding_id", "")),
                    tool=md_cell(lead.get("tool_call_id", "")),
                    confidence=md_cell(lead.get("confidence", "")),
                    mitre=md_cell(lead.get("mitre_technique", "") or "n/a"),
                    description=md_cell(lead.get("description", "")),
                    reason=md_cell(lead.get("verifier_reason", "")),
                    effect=md_cell(
                        lead.get("verdict_effect", "excluded_from_final_findings")
                    ),
                    action=md_cell(lead.get("analyst_action", "")),
                )
            )
        omitted = ""
        if len(rejected_leads) > 20:
            omitted = (
                f"\n\n*{len(rejected_leads) - 20} additional rejected lead(s) are "
                "recorded in `verdict.json`.*"
            )
        rejected_leads_section = (
            "\n## Verifier-Rejected Leads\n\n"
            "These entries failed verifier replay after re-dispatch and are preserved "
            "for analyst review only. They are excluded from final Findings, do not "
            "support the verdict, and must not be treated as evidence unless replay "
            "succeeds in a later run.\n\n" + "\n".join(rows) + omitted + "\n\n"
        )

    revisions = [rev for rev in (verdict_revisions or []) if isinstance(rev, dict)]
    self_correction_section = ""
    if revisions:
        mechanism_label = {
            "verify_hash_drift": "verifier replayed the cited tool call and its "
            "output hash drifted",
            "correlation_downgrade": "the SOUL.md >=2-artifact-class rule was applied "
            "during correlation",
            "tool_failure_resequence": "a tool failure forced a re-sequence of the "
            "Finding",
        }
        blocks: list[str] = []
        for rev in revisions[:20]:
            from_v = md_cell(rev.get("from_verdict", "?"))
            to_v = md_cell(rev.get("to_verdict", "?"))
            trigger = md_cell(rev.get("trigger_tool_call_id", "n/a"))
            mechanism = rev.get("mechanism", "")
            verification = mechanism_label.get(
                mechanism, md_cell(str(mechanism) or "an audited self-check")
            )
            reason = md_cell(rev.get("reason", "")) or "no per-flip reason recorded"
            finding = md_cell(rev.get("finding_id", "n/a"))
            blocks.append(
                f"### Self-Correction — Finding `{finding}`\n\n"
                f"* **Initial Finding:** held at `{from_v}` confidence before the "
                "self-check below.\n"
                f"* **Verification Action:** {verification} (trigger "
                f"`tool_call_id`: `{trigger}`).\n"
                f"* **What It Revealed:** {reason}\n"
                f"* **Correction Applied:** confidence revised `{from_v}` -> `{to_v}` "
                f"via `{md_cell(str(mechanism))}`.\n"
            )
        omitted_rev = ""
        if len(revisions) > 20:
            omitted_rev = (
                f"\n*{len(revisions) - 20} additional self-correction(s) are "
                "recorded in `verdict.json`.*\n"
            )
        self_correction_section = (
            "\n## Self-Correction\n\n"
            "Each entry is a committed conclusion flip: a Finding whose confidence "
            "tier the run lowered as its own verification machinery reasoned about it. "
            "These revisions ride the hash-chained audit log (each cites the trigger "
            "`tool_call_id`) and are offline-verifiable via `manifest_verify` chain "
            "replay — they are the audited record of VERDICT correcting itself, not a "
            "narrative claim.\n\n" + "\n".join(blocks) + omitted_rev + "\n"
        )

    psscan_fig_block = ""
    if has_psscan:
        psscan_fig_block = (
            "\n### Process creation timeline\n\n"
            "![Process creation timeline](figures/psscan_timeline.png)\n"
        )

    completeness_section = ""
    if completeness:
        rows = [
            "| Artifact Class | Available | Touched | Tools | Confidence Impact |",
            "|---|:---:|:---:|---|---|",
        ]
        for check in completeness.get("checks", []):
            rows.append(
                "| {artifact_class} | {available} | {touched} | `{tools}` | {impact} |".format(
                    artifact_class=check.get("artifact_class", "?"),
                    available="yes" if check.get("available") else "no",
                    touched="yes" if check.get("touched") else "no",
                    tools=", ".join(check.get("tools", [])) or "none",
                    impact=check.get("confidence_impact", ""),
                )
            )
        completeness_section = (
            "\n## Evidence Coverage\n\n"
            f"{completeness.get('summary', '')}\n\n" + "\n".join(rows) + "\n\n"
        )

    attack_section = ""
    if attack_coverage:
        rows = [
            "| Technique | Tactic | Status | Tools Observed | Gap / Analyst Value |",
            "|---|---|---|---|---|",
        ]
        status_label = {
            "finding": "finding",
            "covered_no_finding": "covered, no finding (limited)",
            "available_not_examined": "available, not examined",
            "blind_spot": "blind spot",
        }
        for row in attack_coverage.get("targets", []):
            technique = (
                f"{row.get('technique_id', '?')} "
                f"{row.get('technique_name', '')}".strip()
            )
            if row.get("finding_confidence"):
                status = (
                    f"{status_label.get(row.get('status'), row.get('status'))} "
                    f"({row.get('finding_confidence')})"
                )
            else:
                status = status_label.get(row.get("status"), row.get("status", "?"))
            tools = ", ".join(row.get("tools_observed") or []) or "none"
            gap = row.get("gap") or row.get("analyst_value", "")
            rows.append(
                f"| {md_cell(technique)} | {md_cell(row.get('tactic', ''))} | "
                f"{md_cell(status)} | `{md_cell(tools)}` | {md_cell(gap)} |"
            )
        attack_section = (
            "\n## MITRE ATT&CK Coverage\n\n"
            f"{attack_coverage.get('summary', '')}\n\n" + "\n".join(rows) + "\n\n"
        )

    practitioner_section = ""
    if practitioner_coverage:
        lanes = practitioner_coverage.get("lanes", {})
        rows = [
            "| Domain | Status | Artifacts Seen | Tools Run | Data Sources | Gaps |",
            "|---|---|---|---|---|---|",
        ]
        for lane, row in lanes.items():
            rows.append(
                f"| {md_cell(_lane_label(lane, row))} | "
                f"{md_cell(row.get('status', ''))} | "
                f"{md_cell(row.get('artifact_classes_seen', [])) or 'none'} | "
                f"`{md_cell(row.get('tools_run', [])) or 'none'}` | "
                f"{md_cell(row.get('attck_data_sources_seen', [])) or 'none'} | "
                f"{md_cell(row.get('coverage_gaps', [])) or 'none'} |"
            )
        guardrails = practitioner_coverage.get("overclaim_guardrails_applied", [])
        practitioner_section = (
            "\n## Analysis Coverage by Domain\n\n"
            "This table shows which DFIR analysis domains the typed tools "
            "exercised on the supplied evidence. Coverage is scope, not assurance.\n\n"
            + "\n".join(rows)
            + "\n\n"
            + "**Overclaim guardrails applied:** "
            + (md_cell(guardrails) if guardrails else "none")
            + "\n\n"
        )

    malware_section = ""
    if malware_triage:
        summary = malware_triage.get("summary", {})
        observables = malware_triage.get("observables", [])
        aggregate_iocs = malware_triage.get("aggregate_iocs", {})
        rows = [
            "| Observable | Process | Region | Labels | Tool Call |",
            "|---|---|---|---|---|",
        ]
        for observable in observables[:10]:
            process = observable.get("process", {})
            region = observable.get("memory_region", {})
            rows.append(
                f"| `{md_cell(observable.get('observable_id', ''))}` | "
                f"{md_cell(process.get('image_name', ''))} pid={md_cell(process.get('pid', ''))} | "
                f"{md_cell(region.get('vad_start_hex', ''))}-{md_cell(region.get('vad_end_hex', ''))} {md_cell(region.get('protection', ''))} | "
                f"{md_cell(observable.get('labels', []))} | "
                f"`{md_cell(observable.get('tool_call_id', ''))}` |"
            )
        ioc_rows = ["| Type | Values |", "|---|---|"]
        for key, values in aggregate_iocs.items():
            if values:
                ioc_rows.append(f"| {md_cell(key)} | `{md_cell(values[:10])}` |")
        ioc_table = (
            "\n".join(ioc_rows)
            if len(ioc_rows) > 2
            else "*No IOCs extracted from previews.*"
        )
        malware_section = (
            "\n## Malware Triage\n\n"
            "This section is malware triage only. It does not identify who operated the code, execution, or intent. Single-source malfind/YARA/string indicators require corroboration before response claims.\n\n"
            f"* Scope: `{malware_triage.get('scope', 'triage_only')}`\n"
            f"* Observables: {summary.get('observable_count', 0)}\n"
            f"* IOCs extracted: {summary.get('ioc_count', 0)}\n"
            f"* malfind injections: {summary.get('malfind_injection_count', 0)}\n"
            f"* YARA matches: {summary.get('yara_match_count', 0)}\n"
            f"* Verdict contribution: `{summary.get('verdict_contribution', 'none')}`\n\n"
            + "\n".join(rows)
            + "\n\n### Extracted IOC Leads\n\n"
            + ioc_table
            + "\n\n"
        )

    evtx_section = ""
    if evtx_summary:
        top = (
            ", ".join(
                f"EID {row.get('event_id')} x{row.get('count')}"
                for row in evtx_summary.get("top_event_ids", [])[:5]
            )
            or "none"
        )
        channels = ", ".join(evtx_summary.get("channels", [])) or "none"
        evtx_section = (
            "\n## Windows Event Log Summary\n\n"
            f"* Records seen: {evtx_summary.get('records_seen', 0)}\n"
            f"* Rows returned: {evtx_summary.get('row_count', 0)}\n"
            f"* Parse errors: {evtx_summary.get('parse_errors', 0)}\n"
            f"* Channels: {channels}\n"
            f"* Top Event IDs: {top}\n"
            f"* Verdict contribution: {evtx_summary.get('verdict_contribution', 'none')} — {evtx_summary.get('reason', '')}\n\n"
        )

    actions_section = ""
    if next_actions:
        rows = [
            "| Priority | Action | Why | Based On | Expected Evidence |",
            "|---|---|---|---|---|",
        ]
        for item in next_actions[:5]:
            rows.append(
                f"| {md_cell(item.get('priority', ''))} | "
                f"{md_cell(item.get('action', ''))} | "
                f"{md_cell(item.get('why', ''))} | "
                f"{md_cell(item.get('based_on', []))} | "
                f"{md_cell(item.get('expected_evidence', ''))} |"
            )
        actions_section = (
            "\n## Recommended Analyst Actions\n\n" + "\n".join(rows) + "\n\n"
        )

    # Single authoritative Limitations section: the justified unknowns (from the
    # attack story's what_we_cannot_say) plus any run-specific analysis limitations,
    # de-duplicated so an item that appears in both lists renders only once.
    limitation_items: list[str] = []
    _seen_limitations: set[str] = set()
    for item in list(cannot_say) + list(analysis_limitations or []):
        key = str(item)
        if key not in _seen_limitations:
            _seen_limitations.add(key)
            limitation_items.append(item)
    limitations_section = ""
    if limitation_items:
        limitations_section = (
            "\n## Limitations\n\n"
            "What the supplied evidence cannot establish, and how to resolve it.\n\n"
            + "\n".join(f"* {md_cell(item)}" for item in limitation_items)
            + "\n\n"
        )

    bluf_section = build_bluf_section(attack_story, verdict, merged, host_groups)
    timeline_of_events_section = build_timeline_of_events_section(
        normalized_timeline,
        event_narratives,
        has_entity_timeline_fig,
        has_timeline_fig,
    )
    # Analyst-first lead: per-host narrative when the case is host-grouped; fall
    # back to the curated timeline + findings table otherwise.
    host_sections = build_host_sections(host_groups, attack_story, normalized_timeline)
    if host_sections:
        analysis_section = host_sections
    else:
        analysis_section = (
            timeline_of_events_section
            + "\n## Findings Summary\n\n"
            + findings_summary_table
            + "\n"
        )
    detailed_timeline_section = build_detailed_event_timeline_section(
        timeline, timeline_csv_exists, has_timeline_fig
    )
    cast_section = build_cast_of_characters_section(entity_index)
    indicators_section = build_indicators_section(indicators)
    coverage_manifest_section = build_coverage_manifest_section(coverage_manifest)

    visual_section = ""
    if evidence_cards:
        lines = [
            "\n## Figures\n",
            "Visual exhibits are generated from parsed tool outputs. They support cited findings but do not replace `tool_call_id`-backed evidence or upgrade confidence by themselves.\n",
        ]
        rendered_assets: set[str] = set()
        if has_process_view_fig and not any(
            card.get("visual_asset") == "figures/process_view_comparison.png"
            for card in evidence_cards
        ):
            lines.append(
                "![Process-view comparison](figures/process_view_comparison.png)\n"
            )
            rendered_assets.add("figures/process_view_comparison.png")
        for card in evidence_cards[:10]:
            asset = safe_visual_asset(case_dir, card.get("visual_asset"))
            if asset and str(asset) not in rendered_assets:
                lines.append(
                    f"![{md_cell(card.get('title', 'Evidence card'))}]({asset})\n"
                )
                rendered_assets.add(str(asset))
            lines.extend(
                [
                    f"### {md_cell(card.get('title', 'Evidence card'))}",
                    f"* Card: `{md_cell(card.get('card_id', '?'))}`",
                    f"* Linked findings: `{md_cell(card.get('linked_finding_ids', []))}`",
                    f"* Tool call: `{md_cell(card.get('tool_call_id', '?'))}`",
                    f"* Source records: `{md_cell(card.get('source_record_refs', []))}`",
                    f"* Confidence: `{md_cell(card.get('confidence', '?'))}`",
                    f"* Citations: `{md_cell(card.get('citation_ids', []))}`",
                    f"* Why suspicious/relevant: {md_cell(card.get('why_suspicious', ''))}",
                    f"* Snippet: `{md_cell(card.get('snippet', ''))}`",
                    f"* Caveats: {md_cell(card.get('caveats', []))}",
                    "",
                ]
            )
        visual_section = "\n".join(lines) + "\n"

    sources_section = ""
    if bibliography:
        rows = [
            "| Citation ID | Title | URL | Supports |",
            "|---|---|---|---|",
        ]
        for source in bibliography:
            rows.append(
                f"| `{md_cell(source.get('citation_id', ''))}` | "
                f"{md_cell(source.get('title', ''))} | "
                f"{md_cell(source.get('url', ''))} | "
                f"{md_cell(source.get('supports', []))} |"
            )
        sources_section = "\n## References\n\n" + "\n".join(rows) + "\n\n"

    # "False-Positive Considerations" and "Scope & Coverage Caveats" were generic
    # boilerplate that restated the coverage tables and the Limitations section in
    # every run. They are omitted so the report stays focused on case-specific
    # findings; the one case-relevant false-positive note (e.g. log clearing also
    # occurs during legitimate administration) is carried in the BLUF assessment.
    caveat_section = ""
    scope_interpretation_section = ""
    readiness_section = build_readiness_section(report_qa, release_gate)

    # Display-safe evidence label for the customer report header: keep only the
    # basename so an operator's absolute /home path never leaks into REPORT.md /
    # .html / .pdf. The full path is preserved in verdict.json for operational use.
    evidence_display = Path(evidence).name if evidence and evidence != "?" else evidence

    md.write_text(
        f"""[VERDICT · DFIR Case File]{{.kicker}}

# VERDICT — Forensic Investigation Report

[Show Me the Evidence · signed, replayable chain of custody]{{.tagline}}

**Case ID:** `{manifest["case_id"]}`
**Run ID:** `{manifest["run_id"]}`
**Started:** {manifest["started_at"]}
**Finalized:** {manifest["finalized_at"]}
**Evidence:** `{md_cell(evidence_display)}`
**Verdict:** **{verdict}**

> **Cryptographic attestation:**
> Merkle root `{mr}`
> Audit log final hash `{fa}`
> {sig_label} SHA-256 `{sig}`
> Cert fingerprint `{cf}`

---

{bluf_section}

{analysis_section}

{decisions_section}

{limitations_section}

# Technical Report {{.tier-break}}

The sections below are the full analyst-grade record: every finding with its
`tool_call_id` and confidence, the complete event timeline, the entity rollup
and indicators, coverage matrices, triage, sources, and the reproducibility and
chain-of-custody appendices.

## Case Summary

* **Total merged findings:** {len(merged)}
* **By confidence:**
  - CONFIRMED: {sum(1 for m in merged if m.get("confidence") == "CONFIRMED")}
  - INFERRED:  {sum(1 for m in merged if m.get("confidence") == "INFERRED")}
  - HYPOTHESIS: {sum(1 for m in merged if m.get("confidence") == "HYPOTHESIS")}
* **Contradictions surfaced (Pool A vs Pool B):** {contras}
* **SOUL.md correlator:** {kept} kept, {downgraded} downgraded

{coverage_manifest_section}

## Detailed Findings

{findings_section}

{rejected_leads_section}

{self_correction_section}

{beats_section}

{detailed_timeline_section}

{cast_section}

{indicators_section}

{attack_section}

{completeness_section}

{scope_interpretation_section}

{practitioner_section}

{malware_section}

{evtx_section}

{visual_section}

{sources_section}

{caveat_section}

{actions_section}

{replay_appendix}

---

## Chain of Custody

![Chain of custody](figures/chain_of_custody.png)
{psscan_fig_block}
---

## Integrity Verification

This investigation produced a `run.manifest.json` that any third party can
verify offline from the VERDICT repository using the manifest verification
library or the `manifest_verify` MCP tool. There is no standalone
`manifest_verify` shell command in this repo.

```bash
uv run --directory services/agent python -c "from pathlib import Path; from findevil_agent.crypto.manifest import verify_manifest; print(verify_manifest(Path('PATH/TO/run.manifest.json'), audit_log_path=Path('PATH/TO/audit.jsonl')))"
# returns overall=True if the audit chain, Merkle root, leaf count, and signature presence validate
```

The verifier rebuilds:
1. The audit chain by walking `prev_hash` SHA-256 links (catches backdated edits).
2. The Merkle tree from the manifest's `leaves[]` array (catches selective redaction).
3. The signature bundle recorded in the manifest. Ed25519 signatures verify
   offline in `manifest_verify`; Sigstore bundles are recorded for
   identity-policy-aware verification by a party that supplies the expected
   signer identity.

A tamper test against this manifest's `merkle_root_hex` was not run automatically.
To execute it, copy the manifest, overwrite `merkle_root_hex` with `ff` repeated
32 times, then run the same Python verification command against the tampered copy.

```bash
python -c "import shutil;shutil.copyfile('run.manifest.json','run.manifest.tamper.json')"
python -c "import json,pathlib;p=pathlib.Path('run.manifest.tamper.json');d=json.loads(p.read_text());d['merkle_root_hex']='ff'*32;p.write_text(json.dumps(d,indent=2,sort_keys=True))"
uv run --directory services/agent python -c "from pathlib import Path; from findevil_agent.crypto.manifest import verify_manifest; print(verify_manifest(Path('PATH/TO/run.manifest.tamper.json'), audit_log_path=Path('PATH/TO/audit.jsonl')))"
```

---

*Produced by `find-evil-auto` (the VERDICT automated investigation orchestrator).
The cryptographic attestation values shown are the actual outputs of this run; every
quantitative claim above is independently verifiable from the artifacts in this
directory (`audit.jsonl`, `run.manifest.json`, `verdict.json`). The automated
QA / expert-signoff gates for this run are in the companion `REPORT-internal` packet.*
""",
        encoding="utf-8",
    )

    # The QA / expert-signoff gates are the product's internal expert-review packet,
    # not customer narrative — they ship as a companion file so the shared report
    # ends with the forensic content.
    internal_md = case_dir / "REPORT-internal.md"
    internal_md.write_text(
        f"""[VERDICT · Internal QA & Release Gates]{{.kicker}}

# VERDICT — Internal QA & Release Gates

[Expert-signoff packet · not customer narrative]{{.tagline}}

**Case ID:** `{md_cell(manifest.get("case_id", "unknown"))}`
**Run ID:** `{md_cell(manifest.get("run_id", "unknown"))}`
**Verdict:** **{md_cell(verdict)}**

> These sections are the automated expert-review packet's internal gates. They are
> not part of the customer report (`REPORT.html`); they exist so a human expert can
> see the machine QA status, release blockers, and the doctrine the engine enforced
> before approving customer release.

---
{expert_section}
{qa_section}
{release_gate_section}
{readiness_section}
""",
        encoding="utf-8",
    )
    return md


# ---------------------------------------------------------------------------
# Pandoc + Chrome render
# ---------------------------------------------------------------------------


_CONF_CLASS = {
    "CONFIRMED": "conf-confirmed",
    "INFERRED": "conf-inferred",
    "HYPOTHESIS": "conf-hypothesis",
}
_VERDICT_CLASS = {
    "SUSPICIOUS": "verdict-alert",
    "INDETERMINATE": "verdict-inferred",
    "NO_EVIL": "verdict-confirmed",
}


def _colorize_html(html_text: str) -> str:
    """Wrap confidence + verdict keywords in semantic-colored spans, operating only
    on text nodes inside <body> (never tag internals, <style>/<script>, or code)."""
    lower = html_text.lower()
    start = lower.find("<body")
    end = lower.rfind("</body>")
    if start == -1 or end == -1:
        return html_text
    body_open_end = html_text.find(">", start)
    if body_open_end == -1:
        return html_text
    head = html_text[: body_open_end + 1]
    body = html_text[body_open_end + 1 : end]
    tail = html_text[end:]

    mapping = {**_CONF_CLASS, **_VERDICT_CLASS}
    pattern = re.compile(r"(?<![\w-])(" + "|".join(mapping) + r")(?![\w-])")
    segments = re.split(r"(<[^>]+>)", body)
    skip = False
    out: list[str] = []
    for i, seg in enumerate(segments):
        if i % 2 == 1:  # an HTML tag
            tag = seg.lower()
            if tag.startswith(("<style", "<script", "<code", "<pre")):
                skip = True
            elif tag.startswith(("</style", "</script", "</code", "</pre")):
                skip = False
            out.append(seg)
            continue
        if skip or not seg:
            out.append(seg)
            continue
        out.append(
            pattern.sub(
                lambda m: f'<span class="{mapping[m.group(1)]}">{m.group(1)}</span>',
                seg,
            )
        )
    return head + "".join(out) + tail


def _inject_figures(html_text: str, figures: dict[str, str]) -> str:
    """Replace pandoc figure-placeholder divs with bespoke, pre-escaped figure HTML."""
    for name, markup in (figures or {}).items():
        if not markup:
            continue
        pattern = re.compile(
            r'<div[^>]*\bdata-fig="' + re.escape(name) + r'"[^>]*>.*?</div>',
            re.DOTALL,
        )
        html_text = pattern.sub(lambda _m, m=markup: m, html_text, count=1)
    return html_text


def render_html_pdf(
    md_path: Path, figures: dict[str, str] | None = None
) -> tuple[Path, Path | None]:
    case_dir = md_path.parent
    html = case_dir / f"{md_path.stem}.html"
    pdf = case_dir / f"{md_path.stem}.pdf"

    style_path = Path(__file__).resolve().parent / "_report_style.css"
    if not style_path.exists():
        style_path.write_text(_DEFAULT_CSS, encoding="utf-8")

    if PANDOC is None:
        print(
            "  WARN: pandoc not found (set PANDOC_BIN or install pandoc); skipping HTML render"
        )
        return html, None

    subprocess.run(
        [
            PANDOC,
            str(md_path),
            "--from",
            "markdown-raw_html-raw_tex",
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

    # Inject bespoke figure HTML into the placeholder divs, then color-code the
    # confidence/verdict keywords (both best-effort, never fatal to the render).
    try:
        text = html.read_text(encoding="utf-8")
        if figures:
            text = _inject_figures(text, figures)
        html.write_text(_colorize_html(text), encoding="utf-8")
    except Exception:
        pass

    pdf_out: Path | None = None
    if CHROME is not None:
        # Chrome can't overwrite a PDF that's open in a viewer (Windows
        # locks the file). Render to a sibling .new.pdf first; if the
        # final rename fails, the rendered output still survives and
        # the user gets a clear message naming both paths.
        pdf_tmp = pdf.with_suffix(".new.pdf")
        try:
            html_url = html.resolve().as_uri()
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
                    # Target locked (likely open in a viewer). Keep the
                    # rendered .new.pdf so the operator can see it.
                    print(
                        f"  WARN: could not overwrite {pdf} (likely open "
                        f"in a viewer); rendered output left at {pdf_tmp}"
                    )
                    pdf_out = pdf_tmp
        except Exception:
            pass
    return html, pdf_out


_DEFAULT_CSS = """
@import url('https://fonts.googleapis.com/css2?family=Archivo:wght@500;600;700;800;900&family=JetBrains+Mono:wght@400;500;700&display=swap');
:root { --paper:#101426; --surface:#12131a; --inset:#0c1020; --ink:#f5f1e8;
  --muted:#b8a8ff; --faint:#7f789c; --hairline:#27304a; --accent:#4d5dff;
  --accent-light:#b8a8ff; --alert:#ff6257; --confirmed:#73d9c2; --inferred:#ffd76a;
  --hypothesis:#4d5dff; --mono:"JetBrains Mono","Courier New",monospace;
  --serif:"Archivo",Impact,system-ui,sans-serif; --grotesk:"Archivo",system-ui,sans-serif; }
@page { margin: 0; }
html { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
body { background:#101426; color:var(--ink); font-family:var(--mono); font-size:13px;
  line-height:1.7; max-width:1040px; margin:0 auto; padding:1.5cm 1.6cm 2cm;
  -webkit-print-color-adjust:exact; print-color-adjust:exact;
  background-image:linear-gradient(rgba(245,241,232,0.026) 1px,transparent 1px),
    linear-gradient(90deg,rgba(245,241,232,0.026) 1px,transparent 1px);
  background-size:56px 56px; }
h1 { font-family:var(--serif); font-weight:900; color:var(--ink); font-size:2.5em;
  letter-spacing:-0.5px; line-height:1.05; margin:0 0 0.35em; border:none; }
h1.tier-break { page-break-before:always; font-family:var(--grotesk);
  text-transform:uppercase; letter-spacing:4px; font-size:1.15em; font-weight:700;
  color:var(--ink); background:linear-gradient(90deg,rgba(77,93,255,0.24),rgba(184,168,255,0.06));
  border:none; border-left:3px solid var(--accent); border-radius:4px;
  padding:0.65em 0.9em; margin:0 0 1.4em; }
h2 { font-family:var(--grotesk); text-transform:uppercase; letter-spacing:2.5px;
  font-size:1.02em; font-weight:600; color:var(--accent-light); margin:2.6em 0 1em;
  padding-bottom:0.5em; border-bottom:1px solid var(--hairline); }
h3 { font-family:var(--grotesk); text-transform:uppercase; letter-spacing:1.5px;
  font-size:0.9em; font-weight:600; color:var(--muted); margin:1.8em 0 0.7em; }
p, li { color:var(--ink); }
a { color:var(--accent-light); text-decoration:none; border-bottom:1px solid rgba(77,93,255,0.45); }
strong { color:var(--ink); font-weight:700; }
em { color:var(--muted); }
img { max-width:100%; display:block; margin:1.8em auto; background:#fbfaf6;
  border:1px solid var(--hairline); border-radius:6px; padding:10px;
  box-shadow:0 6px 26px rgba(0,0,0,0.5); }
code { background:var(--inset); color:var(--accent-light); padding:0.12em 0.45em;
  border-radius:4px; border:1px solid var(--hairline); font-family:var(--mono); font-size:0.9em; }
pre { background:var(--inset); color:var(--ink); padding:1.1em 1.4em; border-radius:8px;
  border:1px solid var(--hairline); overflow-x:auto; }
pre code { background:none; border:none; padding:0; color:inherit; }
blockquote { font-family:var(--mono); color:var(--ink); margin:1.4em 0;
  background:rgba(77,93,255,0.1); border:1px solid rgba(77,93,255,0.45);
  border-left:3px solid var(--accent); border-radius:0 6px 6px 0; padding:0.9em 1.3em; }
blockquote strong { color:var(--accent-light); }
table { border-collapse:collapse; margin:1.3em 0; width:100%; font-size:0.84em;
  background:var(--surface); border:1px solid var(--hairline); }
th { background:rgba(77,93,255,0.16); color:var(--accent-light); font-family:var(--grotesk);
  text-transform:uppercase; letter-spacing:0.4px; font-weight:600; font-size:0.95em;
  padding:0.55em 0.8em; border:1px solid var(--hairline); text-align:left; }
td { padding:0.5em 0.8em; border:1px solid var(--hairline); color:var(--ink); vertical-align:top; }
th, td { overflow-wrap:anywhere; word-break:break-word; }
tr:nth-child(even) td { background:rgba(245,241,232,0.025); }
hr { border:none; border-top:1px solid var(--hairline); margin:2.4em 0; }
.kicker { font-family:var(--grotesk); text-transform:uppercase; letter-spacing:5px;
  font-size:0.72em; font-weight:600; color:var(--accent); }
.tagline { font-family:var(--mono); color:var(--muted); letter-spacing:1px; font-size:0.86em; }
.conf-confirmed, .verdict-confirmed { color:var(--confirmed); font-weight:700; }
.conf-inferred, .verdict-inferred { color:var(--inferred); font-weight:700; }
.conf-hypothesis { color:var(--accent-light); font-weight:700; }
.verdict-alert { color:var(--alert); font-weight:700; }
"""


# ---------------------------------------------------------------------------
# Public entrypoint (called from find_evil_auto.py)
# ---------------------------------------------------------------------------


def render_report(
    case_dir: Path,
    manifest: dict[str, Any],
    merged: list[dict[str, Any]],
    contras: int,
    kept: int,
    downgraded: int,
    evidence: str,
    verdict: str,
) -> Path:
    case_dir = Path(case_dir)
    fig_dir = case_dir / "figures"
    fig_dir.mkdir(parents=True, exist_ok=True)

    audit = []
    audit_path = case_dir / "audit.jsonl"
    if audit_path.exists():
        for line in audit_path.read_text().splitlines():
            line = line.strip()
            if line:
                try:
                    audit.append(json.loads(line))
                except json.JSONDecodeError:
                    pass

    fig_audit_chain(audit, manifest, fig_dir / "chain_of_custody.png")

    has_psscan = False
    psscan_path = case_dir / "psscan.json"
    if psscan_path.exists():
        try:
            psscan = json.loads(psscan_path.read_text())
            if isinstance(psscan, list) and psscan:
                fig_psscan_timeline(psscan, fig_dir / "psscan_timeline.png")
                has_psscan = True
        except json.JSONDecodeError:
            pass

    verdict_obj = {}
    verdict_path = case_dir / "verdict.json"
    if verdict_path.exists():
        try:
            verdict_obj = json.loads(verdict_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            verdict_obj = {}

    final_release_gate = {}
    final_gate_path = case_dir / "customer_release_gate.final.json"
    if final_gate_path.exists():
        try:
            final_release_gate = json.loads(final_gate_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            final_release_gate = {}

    coverage_manifest = verdict_obj.get("coverage_manifest", {})
    if not coverage_manifest:
        coverage_manifest_path = case_dir / "coverage_manifest.json"
        if coverage_manifest_path.exists():
            try:
                loaded = json.loads(coverage_manifest_path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    coverage_manifest = loaded
            except json.JSONDecodeError:
                coverage_manifest = {}

    practitioner_coverage = verdict_obj.get("attck_practitioner_coverage", {})
    has_process_view_fig = fig_process_view_comparison(
        verdict_obj.get("tool_calls", []),
        fig_dir / "process_view_comparison.png",
    )
    attack_story = verdict_obj.get("attack_story", {})
    # Clean any mid-word-truncated beat titles from the full description text.
    for beat in attack_story.get("attack_chain", []) or []:
        if isinstance(beat, dict):
            beat["title"] = _short_title(
                beat.get("summary") or beat.get("title"),
                beat.get("mitre_technique"),
            )
    has_attack_story_fig = fig_attack_story_timeline(
        attack_story,
        fig_dir / "attack_story_timeline.png",
    )
    entity_index = verdict_obj.get("entity_index", {})
    indicators = verdict_obj.get("indicators", {})
    event_narratives = verdict_obj.get("event_narratives", [])
    evidence_cards = verdict_obj.get("report_evidence_cards", []) or []
    for card in evidence_cards:
        if isinstance(card, dict):
            card["title"] = _short_title(card.get("snippet") or card.get("title"))

    timeline = []
    normalized_timeline = verdict_obj.get("normalized_timeline", {})
    if isinstance(normalized_timeline, dict) and isinstance(
        normalized_timeline.get("events"), list
    ):
        timeline = normalized_timeline["events"]
    else:
        timeline_path = case_dir / "timeline.json"
        if timeline_path.exists():
            try:
                loaded_timeline = json.loads(timeline_path.read_text(encoding="utf-8"))
                if isinstance(loaded_timeline, list):
                    timeline = loaded_timeline
                elif isinstance(loaded_timeline, dict) and isinstance(
                    loaded_timeline.get("events"), list
                ):
                    timeline = loaded_timeline["events"]
            except json.JSONDecodeError:
                timeline = []
    timeline_csv_exists = (case_dir / "timeline.csv").exists()
    # The time-scatter figures are replaced by native HTML/CSS figures (built
    # below and injected into REPORT.html); no longer generated.
    has_timeline_fig = False
    has_entity_timeline_fig = False

    # Bespoke, vector HTML/CSS figures injected into the report post-pandoc.
    figures_html = {
        "scorecard": html_scorecard(verdict, attack_story, merged),
        "sequence": html_event_sequence(timeline),
        "composition": html_event_composition(verdict_obj.get("evtx_summary")),
    }

    md = write_markdown(
        case_dir,
        manifest,
        merged,
        contras,
        kept,
        downgraded,
        evidence,
        verdict,
        has_psscan,
        audit=audit,
        completeness=verdict_obj.get("case_completeness", {}),
        coverage_manifest=coverage_manifest,
        attack_coverage=verdict_obj.get("attack_coverage", {}),
        next_actions=verdict_obj.get("next_actions", []),
        timeline=timeline,
        timeline_csv_exists=timeline_csv_exists,
        evtx_summary=verdict_obj.get("evtx_summary"),
        practitioner_coverage=practitioner_coverage,
        malware_triage=verdict_obj.get("malware_triage"),
        analysis_limitations=verdict_obj.get("analysis_limitations", []),
        evidence_cards=evidence_cards,
        bibliography=verdict_obj.get("source_bibliography", []),
        attack_story=attack_story,
        report_qa=verdict_obj.get("report_qa", {}),
        expert_doctrine=verdict_obj.get("expert_doctrine", {}),
        release_gate=final_release_gate or verdict_obj.get("release_gate", {}),
        normalized_timeline={"events": timeline},
        entity_index=entity_index,
        indicators=indicators,
        event_narratives=event_narratives,
        has_timeline_fig=has_timeline_fig,
        has_attack_story_fig=has_attack_story_fig,
        has_process_view_fig=has_process_view_fig,
        has_entity_timeline_fig=has_entity_timeline_fig,
        rejected_finding_leads=verdict_obj.get("rejected_finding_leads", []),
        verdict_revisions=verdict_obj.get("verdict_revisions", []),
        host_groups=verdict_obj.get("host_groups", []),
    )
    html, pdf = render_html_pdf(md, figures=figures_html)
    # Render the companion internal QA/signoff packet (no figure placeholders).
    internal_md = case_dir / "REPORT-internal.md"
    if internal_md.is_file():
        render_html_pdf(internal_md)
    return pdf if pdf else html


def main() -> int:
    p = argparse.ArgumentParser(description="Render report for a finished case dir")
    p.add_argument(
        "case_dir",
        help="Directory containing audit.jsonl + run.manifest.json + verdict.json",
    )
    args = p.parse_args()
    case_dir = Path(args.case_dir)
    manifest = json.loads((case_dir / "run.manifest.json").read_text())
    verdict_obj = json.loads((case_dir / "verdict.json").read_text())
    merged = verdict_obj.get("findings", [])
    summary = verdict_obj.get("findings_summary", {})
    out = render_report(
        case_dir,
        manifest,
        merged,
        summary.get("contradictions_surfaced", 0),
        summary.get("soul_md_kept", 0),
        summary.get("soul_md_downgraded", 0),
        verdict_obj.get("evidence_path", "?"),
        verdict_obj.get("verdict", "?"),
    )
    print(f"rendered: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
