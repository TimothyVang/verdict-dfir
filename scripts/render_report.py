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

plt.rcParams.update(
    {
        "font.family": "DejaVu Sans",
        "font.size": 10,
        "axes.titlesize": 12,
        "axes.titleweight": "bold",
        "savefig.dpi": 140,
        "savefig.bbox": "tight",
        "figure.facecolor": "white",
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

    def box(x, y, w, h, txt, color="#e3f2fd", border="#1565c0", fs=9):
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
                color="#1565c0",
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
        color="#6a1b9a",
    )
    for i, rec in enumerate(audit[:5]):
        ph = rec.get("prev_hash", "") or "<genesis>"
        box(
            0.2,
            4.4 - i * 0.55,
            3.6,
            0.45,
            f"seq={rec['seq']} kind={rec['kind'][:14]}\nprev_hash={ph[:14]}…",
            color="#f3e5f5",
            border="#6a1b9a",
            fs=7,
        )

    box(
        0.2,
        1.2,
        3.6,
        0.5,
        f"audit_log_final_hash:\n{manifest['audit_log_final_hash'][:32]}…",
        color="#fff3e0",
        border="#ef6c00",
    )

    ax.text(
        5.5,
        5.0,
        "Merkle leaves (per tool_call_output)",
        fontsize=9,
        fontweight="bold",
        color="#1565c0",
    )
    for i in range(min(manifest["leaf_count"], 4)):
        box(
            5.5,
            4.4 - i * 0.55,
            3.6,
            0.45,
            f"leaf {i}: tool_call output_hash digest",
            color="#e3f2fd",
            border="#1565c0",
            fs=8,
        )

    box(
        5.5,
        1.2,
        3.6,
        0.5,
        f"merkle_root_hex:\n{manifest['merkle_root_hex'][:32]}…",
        color="#fffde7",
        border="#f9a825",
    )

    sig_sha = manifest["signature"]["payload_sha256"]
    box(
        2,
        0.2,
        6,
        0.7,
        f"run.manifest.json (signed via sigstore StubSigner)\n"
        f"signature_payload_sha256: {sig_sha[:32]}…",
        color="#e8f5e9",
        border="#2e7d32",
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
    colors = [
        "#c62828" if e["name"].lower() not in common else "#1565c0" for e in events
    ]
    ax.scatter(
        times, pids, c=colors, s=sizes, alpha=0.7, edgecolors="black", linewidths=0.5
    )
    ax.set_xlabel("Process creation time (UTC)")
    ax.set_ylabel("PID")
    ax.set_title(
        f"Process creation timeline ({len(events)} processes via psscan)\n"
        "Red = uncommon image name; Blue = standard Windows process"
    )
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%Y-%m-%d %H:%M"))
    plt.setp(ax.xaxis.get_majorticklabels(), rotation=30, ha="right")
    ax.grid(True, alpha=0.3)
    ax.legend(
        handles=[
            mpatches.Patch(color="#1565c0", label="Standard Windows process"),
            mpatches.Patch(color="#c62828", label="Uncommon image name"),
        ],
        loc="upper left",
        fontsize=8,
    )
    fig.tight_layout()
    fig.savefig(out)
    plt.close(fig)


def fig_findings_table(findings: list[dict[str, Any]], out: Path) -> None:
    fig, ax = plt.subplots(figsize=(12, 0.5 + 0.4 * max(1, len(findings))))
    ax.axis("off")
    if not findings:
        ax.text(
            0.5,
            0.5,
            "No merged findings",
            ha="center",
            va="center",
            fontsize=11,
            color="#777",
        )
        fig.savefig(out)
        plt.close(fig)
        return
    table_data = [["Conf.", "Pool", "MITRE", "Description"]]
    for f in findings[:20]:
        table_data.append(
            [
                f.get("confidence", "?")[:9],
                f.get("pool_origin", "?")[:1],
                (f.get("mitre_technique") or "—")[:10],
                (f.get("description", ""))[:90],
            ]
        )
    table = ax.table(
        cellText=table_data,
        loc="center",
        cellLoc="left",
        colWidths=[0.10, 0.05, 0.10, 0.75],
    )
    table.auto_set_font_size(False)
    table.set_fontsize(8)
    table.scale(1, 1.4)
    for i in range(len(table_data[0])):
        cell = table[(0, i)]
        cell.set_facecolor("#1565c0")
        cell.set_text_props(color="white", fontweight="bold")
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
        "context": "#1565c0",
        "triage_lead": "#ef6c00",
        "finding_support": "#c62828",
    }
    for row in parsed:
        ax.scatter(
            row["dt"],
            class_to_y[row["artifact_class"]],
            s=55,
            color=colors.get(row["significance"], "#1565c0"),
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
            mpatches.Patch(color="#1565c0", label="Context"),
            mpatches.Patch(color="#ef6c00", label="Triage lead"),
            mpatches.Patch(color="#c62828", label="Finding support"),
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
        "CONFIRMED": "#c62828",
        "INFERRED": "#ef6c00",
        "HYPOTHESIS": "#6a1b9a",
    }
    for idx, beat in enumerate(beats[:8], 1):
        y = len(beats[:8]) - idx + 0.6
        confidence = str(beat.get("confidence") or "HYPOTHESIS")
        color = colors.get(confidence, "#1565c0")
        ax.scatter(0.7, y, s=180, color=color, edgecolor="black", linewidth=0.6)
        ax.text(
            0.7,
            y,
            str(beat.get("order") or idx),
            ha="center",
            va="center",
            color="white",
            fontsize=8,
            fontweight="bold",
        )
        title = str(beat.get("title") or "Finding-backed story beat")[:85]
        tcid = beat.get("tool_call_id") or "?"
        mitre = beat.get("mitre_technique") or "n/a"
        ts = beat.get("timestamp_utc") or "time not normalized"
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


def fig_practitioner_coverage(coverage: dict[str, Any], out: Path) -> bool:
    lanes = coverage.get("lanes", {}) if coverage else {}
    fig, ax = plt.subplots(figsize=(12, 2.4 + 0.35 * max(1, len(lanes))))
    ax.axis("off")
    if not lanes:
        ax.text(
            0.5,
            0.5,
            "No practitioner coverage data available",
            ha="center",
            va="center",
            fontsize=11,
            color="#777",
        )
        fig.savefig(out)
        plt.close(fig)
        return False
    table_data = [["Lane", "Status", "Artifacts Seen", "Tools", "ATT&CK Data Sources"]]
    for lane, row in lanes.items():
        table_data.append(
            [
                lane.replace("_", " "),
                row.get("status", "?"),
                ", ".join(row.get("artifact_classes_seen") or []) or "none",
                ", ".join(row.get("tools_run") or []) or "none",
                ", ".join(row.get("attck_data_sources_seen") or []) or "none",
            ]
        )
    table = ax.table(
        cellText=table_data,
        loc="center",
        cellLoc="left",
        colWidths=[0.17, 0.13, 0.20, 0.25, 0.25],
    )
    table.auto_set_font_size(False)
    table.set_fontsize(7.5)
    table.scale(1, 1.35)
    for i in range(len(table_data[0])):
        cell = table[(0, i)]
        cell.set_facecolor("#1565c0")
        cell.set_text_props(color="white", fontweight="bold")
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
    colors = ["#1565c0", "#ef6c00", "#c62828"][: len(rows)]
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
        "\n## Evidence Scope Interpretation\n",
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
    why_not_ready = (report_qa or {}).get("why_not_ready", [])
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
    why_lines = "\n".join(f"* {md_cell(item)}" for item in why_not_ready)
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
        + "\n\n### Why This Is Not Ready, If Applicable\n\n"
        + (why_lines or "* No additional readiness caveats were recorded.")
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
    has_timeline_fig: bool = False,
    has_attack_story_fig: bool = False,
    has_practitioner_fig: bool = False,
    has_process_view_fig: bool = False,
) -> Path:
    md = case_dir / "REPORT.md"
    fa = manifest["audit_log_final_hash"]
    mr = manifest["merkle_root_hex"]
    sig = manifest["signature"]["payload_sha256"]
    cf = manifest["signature"]["cert_fingerprint"]

    attack_story_section = ""
    if attack_story:
        fig_block = (
            "![How they got hacked timeline](figures/attack_story_timeline.png)\n\n"
            if has_attack_story_fig
            else ""
        )
        can_say = attack_story.get("what_we_can_say", []) or []
        cannot_say = attack_story.get("what_we_cannot_say", []) or []
        decisions = attack_story.get("recommended_next_decisions", []) or []
        beats = attack_story.get("attack_chain", []) or []
        beat_lines = []
        for beat in beats[:8]:
            beat_lines.extend(
                [
                    f"### Beat {beat.get('order', '?')}: {md_cell(beat.get('title', 'Finding-backed story beat'))}",
                    f"* Time: `{md_cell(beat.get('timestamp_utc') or 'not normalized')}`",
                    f"* Confidence: `{md_cell(beat.get('confidence', ''))}`",
                    f"* MITRE: `{md_cell(beat.get('mitre_technique') or 'n/a')}`",
                    f"* Tool call: `{md_cell(beat.get('tool_call_id') or 'n/a')}`",
                    f"* Artifact classes: `{md_cell(beat.get('artifact_classes', []))}`",
                    f"* Caveat: {md_cell(beat.get('caveat', 'Expert review required.'))}",
                    "",
                ]
            )
        if not beat_lines:
            beat_lines.append(
                "*No finding-backed attack-story beats were produced in this run.*\n"
            )
        attack_story_section = (
            "\n## Executive Attack Story\n\n"
            f"**Headline:** {md_cell(attack_story.get('headline', ''))}\n\n"
            f"{md_cell(attack_story.get('customer_summary', ''))}\n\n"
            f"**How they got in:** {md_cell(attack_story.get('how_they_got_in', ''))}\n\n"
            f"**Root cause:** {md_cell(attack_story.get('root_cause', ''))}\n\n"
            f"**Business impact:** {md_cell(attack_story.get('business_impact', ''))}\n\n"
            + fig_block
            + "### What We Can Say\n\n"
            + "\n".join(f"* {md_cell(item)}" for item in can_say)
            + "\n\n### What We Cannot Prove\n\n"
            + "\n".join(f"* {md_cell(item)}" for item in cannot_say)
            + "\n\n### Recommended Next Decisions\n\n"
            + (
                "\n".join(f"* {md_cell(item)}" for item in decisions)
                or "* Expert review before customer release."
            )
            + "\n\n### Finding-Backed Story Beats\n\n"
            + "\n".join(beat_lines)
            + "\n"
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
            "\n## Expert Doctrine Applied\n\n"
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
            f"- artifact: `{md_cell(f.get('artifact_path', 'n/a'))}`"
        )
        findings_md_lines.append("")
    findings_section = (
        "\n".join(findings_md_lines) if findings_md_lines else "*No merged findings.*"
    )
    replay_appendix = ""
    if len(replay_rows) > 2:
        replay_appendix = (
            "\n## Replay Determinism Appendix\n\n"
            "Verifier replay artifacts record whether each cited tool call reproduced "
            "the audited output hash. They do not change Track 3b severity policy.\n\n"
            + "\n".join(replay_rows)
            + "\n"
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
            "\n## Case Completeness\n\n"
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
            "\n## ATT&CK Coverage\n\n"
            f"{attack_coverage.get('summary', '')}\n\n" + "\n".join(rows) + "\n\n"
        )

    practitioner_section = ""
    if practitioner_coverage:
        lanes = practitioner_coverage.get("lanes", {})
        rows = [
            "| Lane | Status | Artifacts Seen | Tools Run | Data Sources | Gaps |",
            "|---|---|---|---|---|---|",
        ]
        for lane, row in lanes.items():
            rows.append(
                f"| {md_cell(lane.replace('_', ' '))} | "
                f"{md_cell(row.get('status', ''))} | "
                f"{md_cell(row.get('artifact_classes_seen', [])) or 'none'} | "
                f"`{md_cell(row.get('tools_run', [])) or 'none'}` | "
                f"{md_cell(row.get('attck_data_sources_seen', [])) or 'none'} | "
                f"{md_cell(row.get('coverage_gaps', [])) or 'none'} |"
            )
        guardrails = practitioner_coverage.get("overclaim_guardrails_applied", [])
        fig_block = (
            "![Practitioner coverage](figures/practitioner_coverage.png)\n\n"
            if has_practitioner_fig
            else ""
        )
        practitioner_section = (
            "\n## Practitioner Coverage\n\n"
            "GCFA, GNFA, and GREM are practitioner domains and certifications; "
            "this table describes evidence-orchestration coverage only.\n\n"
            + fig_block
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
            "\n## EVTX Summary\n\n"
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
        actions_section = "\n## Next 5 Analyst Actions\n\n" + "\n".join(rows) + "\n\n"

    limitations_section = ""
    if analysis_limitations:
        limitations_section = (
            "\n## Analysis Limitations\n\n"
            + "\n".join(f"* {md_cell(item)}" for item in analysis_limitations)
            + "\n\n"
        )

    timeline_section = ""
    if timeline:
        timeline_exports = "`timeline.json`"
        if timeline_csv_exists:
            timeline_exports += " and analyst-friendly `timeline.csv`"
        rows = [
            "| UTC Time | Artifact Class | Significance | Summary | Tool Call | Source Record |",
            "|---|---|---|---|---|---|",
        ]
        for event in timeline[:25]:
            ts = event.get("timestamp_utc") or event.get("ts") or "?"
            summary = event.get("summary") or event.get("description") or ""
            significance = event.get("significance") or "context"
            rows.append(
                "| {ts} | {artifact_class} | {significance} | {summary} | `{tcid}` | `{ref}` |".format(
                    ts=md_cell(ts),
                    artifact_class=md_cell(event.get("artifact_class", "?")),
                    significance=md_cell(significance),
                    summary=md_cell(summary[:120]),
                    tcid=md_cell(event.get("tool_call_id", "?")),
                    ref=md_cell(
                        event.get("source_record_ref") or event.get("source") or "?"
                    ),
                )
            )
        fig_block = (
            "![Normalized timeline overview](figures/timeline_overview.png)\n\n"
            if has_timeline_fig
            else ""
        )
        timeline_section = (
            "\n## Timeline\n\n"
            f"Normalized timeline events: {len(timeline)}. "
            f"First 25 events shown below; full data is in {timeline_exports}.\n\n"
            + fig_block
            + "\n".join(rows)
            + "\n\n"
        )

    visual_section = ""
    if evidence_cards:
        lines = [
            "\n## Visual Evidence\n",
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
        sources_section = "\n## Sources\n\n" + "\n".join(rows) + "\n\n"

    caveats = build_false_positive_caveats(merged, completeness, attack_coverage)
    caveat_section = (
        "\n## False-positive caveats\n\n"
        + "\n".join(f"* {c}" for c in caveats)
        + "\n\n"
    )
    scope_interpretation_section = build_scope_interpretation_section(
        completeness, attack_coverage
    )
    readiness_section = build_readiness_section(report_qa, release_gate)

    md.write_text(
        f"""# Find Evil! — Forensic Breach Narrative and Evidence Report

**Case ID:** `{manifest['case_id']}`
**Run ID:** `{manifest['run_id']}`
**Started:** {manifest['started_at']}
**Finalized:** {manifest['finalized_at']}
**Evidence:** `{md_cell(evidence)}`
**Verdict:** **{verdict}**

> **Cryptographic attestation:**
> Merkle root `{mr}`
> Audit log final hash `{fa}`
> Sigstore signature SHA-256 `{sig}`
> Cert fingerprint `{cf}`

---

## Summary

* **Total merged findings:** {len(merged)}
* **By confidence:**
  - CONFIRMED: {sum(1 for m in merged if m.get('confidence') == 'CONFIRMED')}
  - INFERRED:  {sum(1 for m in merged if m.get('confidence') == 'INFERRED')}
  - HYPOTHESIS: {sum(1 for m in merged if m.get('confidence') == 'HYPOTHESIS')}
* **Contradictions surfaced (Pool A vs Pool B):** {contras}
* **SOUL.md correlator:** {kept} kept, {downgraded} downgraded

---

{attack_story_section}

{qa_section}

{release_gate_section}

{readiness_section}

## Findings overview

![Findings table](figures/findings_table.png)

{actions_section}

{completeness_section}

{scope_interpretation_section}

{practitioner_section}

{attack_section}

{evtx_section}

{limitations_section}

{timeline_section}

{malware_section}

{visual_section}

{sources_section}

{caveat_section}

{expert_section}

## Findings detail

{findings_section}

{replay_appendix}

---

## Cryptographic chain of custody

![Cryptographic chain of custody](figures/chain_of_custody.png)
{psscan_fig_block}
---

## Verification

This investigation produced a `run.manifest.json` that any third party can
verify offline from the Find Evil repository using the manifest verification
library or the `manifest_verify` MCP tool. There is no standalone
`manifest_verify` shell command in this repo.

```bash
uv run --directory services/agent python -c "from pathlib import Path; from findevil_agent.crypto.manifest import verify_manifest; print(verify_manifest(Path('PATH/TO/run.manifest.json'), audit_log_path=Path('PATH/TO/audit.jsonl')).model_dump_json(indent=2))"
# returns overall=true if the audit chain and Merkle root validate and signature metadata is present
```

The verifier rebuilds:
1. The audit chain by walking `prev_hash` SHA-256 links (catches backdated edits).
2. The Merkle tree from the manifest's `leaves[]` array (catches selective redaction).
3. The signature bundle metadata recorded in the manifest. Full signature and
   transparency-log validation must be performed separately when a non-stub signer
   is used.

A tamper test against this manifest's `merkle_root_hex` was not run automatically.
To execute it, copy the manifest, overwrite `merkle_root_hex` with `ff` repeated
32 times, then run the same Python verification command against the tampered copy.

```bash
python -c "import shutil;shutil.copyfile('run.manifest.json','run.manifest.tamper.json')"
python -c "import json,pathlib;p=pathlib.Path('run.manifest.tamper.json');d=json.loads(p.read_text());d['merkle_root_hex']='ff'*32;p.write_text(json.dumps(d,indent=2,sort_keys=True))"
uv run --directory services/agent python -c "from pathlib import Path; from findevil_agent.crypto.manifest import verify_manifest; print(verify_manifest(Path('PATH/TO/run.manifest.tamper.json'), audit_log_path=Path('PATH/TO/audit.jsonl')).model_dump_json(indent=2))"
```

---

*Produced by `find-evil-auto` (the Find Evil! automated investigation orchestrator).
The cryptographic attestation values shown are the actual outputs of this run; every
quantitative claim above is independently verifiable from the artifacts in this
directory (`audit.jsonl`, `run.manifest.json`, `verdict.json`).*
""",
        encoding="utf-8",
    )
    return md


# ---------------------------------------------------------------------------
# Pandoc + Chrome render
# ---------------------------------------------------------------------------


def render_html_pdf(md_path: Path) -> tuple[Path, Path | None]:
    case_dir = md_path.parent
    html = case_dir / "REPORT.html"
    pdf = case_dir / "REPORT.pdf"

    style_path = Path(__file__).resolve().parent / "_report_style.css"
    if not style_path.exists():
        style_path.write_text(_DEFAULT_CSS, encoding="utf-8")

    if PANDOC is None:
        print("  WARN: pandoc not found (set PANDOC_BIN or install pandoc); skipping HTML render")
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
body { font-family: -apple-system, "Segoe UI", Roboto, Arial, sans-serif;
       max-width: 980px; margin: 2em auto; padding: 0 2.5em; line-height: 1.65;
       color: #222; background: #fafafa; }
h1 { color: #1565c0; border-bottom: 3px solid #1565c0; padding-bottom: 0.4em; font-size: 2em; }
h2 { color: #1565c0; border-bottom: 1px solid #ccc; padding-bottom: 0.25em; margin-top: 2.5em; font-size: 1.4em; }
h3 { color: #6a1b9a; margin-top: 1.6em; font-size: 1.15em; }
img { max-width: 100%; display: block; margin: 2em auto; border: 1px solid #ddd;
      box-shadow: 0 4px 12px rgba(0,0,0,0.08); border-radius: 4px;
      background: white; padding: 8px; }
code { background: #eef2f5; padding: 0.1em 0.4em; border-radius: 3px;
       font-family: "Consolas", monospace; font-size: 0.92em; color: #c62828; }
pre { background: #2c3e50; color: #ecf0f1; padding: 1em 1.4em; border-radius: 4px; overflow-x: auto; }
pre code { background: none; padding: 0; color: inherit; }
blockquote { border-left: 4px solid #1565c0; padding: 0.7em 1.2em; margin: 1.2em 0;
             background: #e3f2fd; border-radius: 0 4px 4px 0; }
table { border-collapse: collapse; margin: 1.2em 0; width: 100%; }
th, td { padding: 0.55em 0.9em; border: 1px solid #ddd; text-align: left; }
th { background: #1565c0; color: white; font-weight: 600; }
tr:nth-child(even) td { background: #f5f7fa; }
strong { color: #1565c0; }
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
    fig_findings_table(merged, fig_dir / "findings_table.png")

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

    practitioner_coverage = verdict_obj.get("attck_practitioner_coverage", {})
    has_practitioner_fig = fig_practitioner_coverage(
        practitioner_coverage,
        fig_dir / "practitioner_coverage.png",
    )
    has_process_view_fig = fig_process_view_comparison(
        verdict_obj.get("tool_calls", []),
        fig_dir / "process_view_comparison.png",
    )
    attack_story = verdict_obj.get("attack_story", {})
    has_attack_story_fig = fig_attack_story_timeline(
        attack_story,
        fig_dir / "attack_story_timeline.png",
    )

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
    has_timeline_fig = fig_timeline_overview(
        timeline, fig_dir / "timeline_overview.png"
    )

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
        attack_coverage=verdict_obj.get("attack_coverage", {}),
        next_actions=verdict_obj.get("next_actions", []),
        timeline=timeline,
        timeline_csv_exists=timeline_csv_exists,
        evtx_summary=verdict_obj.get("evtx_summary"),
        practitioner_coverage=practitioner_coverage,
        malware_triage=verdict_obj.get("malware_triage"),
        analysis_limitations=verdict_obj.get("analysis_limitations", []),
        evidence_cards=verdict_obj.get("report_evidence_cards", []),
        bibliography=verdict_obj.get("source_bibliography", []),
        attack_story=attack_story,
        report_qa=verdict_obj.get("report_qa", {}),
        expert_doctrine=verdict_obj.get("expert_doctrine", {}),
        release_gate=final_release_gate or verdict_obj.get("release_gate", {}),
        has_timeline_fig=has_timeline_fig,
        has_attack_story_fig=has_attack_story_fig,
        has_practitioner_fig=has_practitioner_fig,
        has_process_view_fig=has_process_view_fig,
    )
    html, pdf = render_html_pdf(md)
    return pdf if pdf else html


def main() -> int:
    p = argparse.ArgumentParser(description="Render report for a finished case dir")
    p.add_argument(
        "case_dir",
        help="Directory containing audit.jsonl + " "run.manifest.json + verdict.json",
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
