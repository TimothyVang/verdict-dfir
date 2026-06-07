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
import matplotlib.dates as mdates  # noqa: E402
import matplotlib.patches as mpatches  # noqa: E402
import matplotlib.pyplot as plt  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
PANDOC = r"C:\Program Files\Pandoc\pandoc.exe"
CHROME = r"C:\Program Files\Google\Chrome\Application\chrome.exe"

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
    distrib = corr.get("verdict_distribution", {})
    if not distrib:
        return
    fig, ax = plt.subplots(figsize=(8, 4.5))
    labels = list(distrib.keys())
    counts = [distrib[k] for k in labels]
    palette = {
        "SUSPICIOUS": "#c62828",
        "INDETERMINATE": "#ef6c00",
        "NO_EVIL": "#2e7d32",
    }
    colors = [palette.get(label, "#546e7a") for label in labels]
    ax.bar(labels, counts, color=colors, edgecolor="black", linewidth=0.5)
    ax.set_ylabel("Hosts")
    ax.set_title(
        f"Fleet verdict distribution ({sum(counts)} hosts)\n"
        "SUSPICIOUS hosts are the analyst's priority queue"
    )
    for i, c in enumerate(counts):
        ax.text(i, c + 0.05, str(c), ha="center", fontweight="bold", fontsize=12)
    ax.set_ylim(0, max(counts) * 1.15)
    ax.grid(True, axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(fig_path)
    plt.close(fig)


def fig_mitre_density(corr: dict, fig_path: Path) -> None:
    mitre = corr.get("mitre_technique_density", {})
    if not mitre:
        return
    fig, ax = plt.subplots(figsize=(9, max(3, 0.4 * len(mitre) + 1.5)))
    items = sorted(mitre.items(), key=lambda kv: -kv[1])
    techniques = [t for t, _ in items]
    counts = [c for _, c in items]
    ax.barh(
        techniques,
        counts,
        color=[
            "#c62828" if c >= 3 else "#ef6c00" if c >= 2 else "#1565c0" for c in counts
        ],
        edgecolor="black",
        linewidth=0.4,
    )
    ax.invert_yaxis()
    ax.set_xlabel("Distinct hosts where this technique was observed")
    host_count = corr.get("host_count", 0)
    ax.set_title(
        f"MITRE ATT&CK technique density across the fleet\n"
        f"{len(techniques)} techniques observed across {host_count} hosts "
        "(bars show distinct-host count per technique)"
    )
    for i, c in enumerate(counts):
        ax.text(c + 0.1, i, str(c), va="center", fontsize=9)
    fig.tight_layout()
    fig.savefig(fig_path)
    plt.close(fig)


def fig_cross_host_processes(corr: dict, fig_path: Path) -> None:
    procs = corr.get("cross_host_processes", {})
    if not procs:
        return
    by_host_count = sorted(
        procs.items(),
        key=lambda kv: -len({h["host"] for h in kv[1]}),
    )[:25]
    if not by_host_count:
        return
    fig, ax = plt.subplots(figsize=(11, max(4, 0.35 * len(by_host_count) + 1.5)))
    names = [n for n, _ in by_host_count]
    counts = [len({h["host"] for h in hits}) for _, hits in by_host_count]
    colors = [
        "#c62828" if c >= 5 else "#ef6c00" if c >= 3 else "#1565c0" for c in counts
    ]
    ax.barh(names, counts, color=colors, edgecolor="black", linewidth=0.4)
    ax.invert_yaxis()
    ax.set_xlabel("Distinct hosts where this image name appears")
    ax.set_title(
        "Cross-host process-name correlation (top 25)\n"
        "Red = ≥5 hosts (very strong lateral-movement signal); "
        "Orange = 3-4 hosts; Blue = 2 hosts"
    )
    for i, c in enumerate(counts):
        ax.text(c + 0.05, i, str(c), va="center", fontsize=8)
    plt.setp(ax.get_yticklabels(), fontfamily="monospace", fontsize=8)
    fig.tight_layout()
    fig.savefig(fig_path)
    plt.close(fig)


def fig_temporal_clusters(corr: dict, fig_path: Path) -> None:
    clusters = corr.get("temporal_clusters", [])
    if not clusters:
        return
    fig, ax = plt.subplots(figsize=(12, 6))
    # Plot each event as a point, x=time, y=cluster index, color by host
    all_hosts = sorted({ev["host"] for cl in clusters for ev in cl["events"]})
    host_color = {h: plt.cm.tab20(i % 20) for i, h in enumerate(all_hosts)}
    for ci, cl in enumerate(clusters):
        for ev in cl["events"]:
            try:
                dt = datetime.fromisoformat(ev["create_time"])
            except ValueError:
                continue
            ax.scatter(
                dt,
                ci,
                color=host_color[ev["host"]],
                s=80,
                edgecolor="black",
                linewidth=0.4,
                alpha=0.85,
            )
    ax.set_yticks(range(len(clusters)))
    ax.set_yticklabels(
        [
            f"Cluster {i + 1}\n({cl['host_count']} hosts, "
            f"{cl['duration_seconds']:.0f}s)"
            for i, cl in enumerate(clusters)
        ],
        fontsize=8,
    )
    ax.invert_yaxis()
    ax.set_xlabel("Process creation time (UTC)")
    ax.set_title(
        "Multi-host temporal clusters — possible lateral-movement waves\n"
        "Each row is a cluster of process creations on ≥2 hosts within 60s; "
        "color-coded by host"
    )
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%Y-%m-%d %H:%M:%S"))
    plt.setp(ax.xaxis.get_majorticklabels(), rotation=30, ha="right")
    ax.grid(True, alpha=0.3)
    handles = [mpatches.Patch(color=host_color[h], label=h) for h in all_hosts[:12]]
    if handles:
        ax.legend(
            handles=handles,
            fontsize=7,
            loc="upper left",
            ncol=2,
            framealpha=0.9,
            title="Hosts (first 12)",
        )
    fig.tight_layout()
    fig.savefig(fig_path)
    plt.close(fig)


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
        "*The same uncommon process image name appearing on multiple "
        "hosts is a much stronger lateral-movement signal than the same "
        "name on one host alone. Below: image names appearing on ≥2 hosts.*"
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
            f"{len(clusters)} clusters detected. Each cluster is a group "
            f"of process creations across ≥2 hosts within a 60-second "
            f"window — the temporal fingerprint of automated tradecraft "
            f"(PsExec waves, WMI execution chains, scheduled-task pivots)."
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

    out.append("## Judge self-score (fleet aggregate)")
    out.append("")
    sa = corr.get("selfscore_aggregate", {})
    sa_hosts = sa.get("hosts_with_selfscore", 0)
    sa_total = sa.get("hosts_total", h)
    if sa_hosts == 0:
        out.append(
            "*No host emitted `kind=judge_selfscore` audit records. This "
            "fleet predates the selfscore wiring (`find-evil-auto` commit "
            "94c08dd / `render_report.py` commit 7729cfc). Re-run any "
            "host with the current orchestrator and the records will "
            "appear in `audit.jsonl` and the per-case `REPORT.pdf`.*"
        )
    else:
        out.append(
            f"{sa_hosts} of {sa_total} hosts emitted self-score records. "
            f"Modal answer per criterion shown below; the score on each "
            f"host is part of that host's cryptographic attestation, so "
            f"verifying the manifest verifies the score."
        )
        out.append("")
        out.append("| # | Modal answer | Hosts agreeing | Distinct answers |")
        out.append("|---:|---|---:|---:|")
        for crit in sorted(sa.get("by_criterion", {}), key=int):
            entry = sa["by_criterion"][crit]
            out.append(
                f"| {crit} | `{entry['modal_answer']}` | "
                f"{entry['modal_share']}/{entry['host_count']} | "
                f"{entry['distinct_answers']} |"
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
        print(
            f"correlation file missing — run fleet_correlate.py first: " f"{corr_path}"
        )
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
