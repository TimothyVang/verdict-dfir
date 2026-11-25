#!/usr/bin/env python3
"""fleet_correlate — cross-host pattern detection over a finished fleet run.

Reads tmp/fleet-runs/<fleet-id>/fleet.json plus each per-host
verdict.json + run.manifest.json + (psscan.json if present), produces:

  - fleet_correlation.json   structured cross-host findings
  - fleet_correlation.md     human-readable report

Cross-host signals it looks for:

  * Process-name correlation:  the same uncommon process name on N≥2 hosts
                               is much more interesting than 1.
  * Temporal correlation:      processes created at near-identical UTC
                               timestamps across multiple hosts (lateral
                               movement signal — attacker hits multiple
                               machines within a short window).
  * MITRE technique density:   how many hosts surface T1014/T1055 etc.
  * Verdict cluster:            verdict distribution; the SUSPICIOUS hosts
                               are the priority queue for the analyst.
  * Cryptographic integrity:   every per-host manifest's Merkle root is
                               unique and individually verifiable.

Usage:
  python scripts/fleet_correlate.py [<fleet-dir>]

If no arg given, uses the most recent fleet under tmp/fleet-runs/.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent

# Same definition as the orchestrator — keep in sync if tuning.
#
# Volatility's `ImageFileName` field on EPROCESS is 16 bytes including
# null padding, so binaries with names longer than 14 chars get
# truncated in pslist/psscan output (e.g. "VGAuthService." for
# VGAuthService.exe, "ManagementAgen" for ManagementAgent.exe). The
# normalize_image_name() helper below truncates both sides to 14
# chars before comparison so the truncated-vs-untruncated case
# matches cleanly.
_RAW_COMMON_PROCS: set[str] = {
    # Core Windows
    "System",
    "Idle",
    "smss.exe",
    "csrss.exe",
    "winlogon.exe",
    "lsass.exe",
    "services.exe",
    "svchost.exe",
    "explorer.exe",
    "spoolsv.exe",
    "lsm.exe",
    "wininit.exe",
    "dllhost.exe",
    "conhost.exe",
    "wmiprvse.exe",
    "WmiPrvSE.exe",
    "taskhost.exe",
    "taskhostw.exe",
    "RuntimeBroker.exe",
    "MsMpEng.exe",
    "msdtc.exe",
    "dwm.exe",
    "LogonUI.exe",
    "fontdrvhost.exe",
    "SearchUI.exe",
    "SearchIndexer.exe",
    "SearchProtocolHost.exe",
    "SearchFilterHost.exe",
    "ShellExperienceHost.exe",
    "sihost.exe",
    "ctfmon.exe",
    "audiodg.exe",
    "smartscreen.exe",
    "SecurityHealthService.exe",
    "SecurityHealthSystray.exe",
    "ApplicationFrameHost.exe",
    "backgroundTaskHost.exe",
    "TrustedInstaller.exe",
    "userinit.exe",
    "MemCompression",
    "SystemSettings.exe",
    "Registry",
    "Memory Compression",
    "rdpclip.exe",
    "tabtip.exe",
    "wermgr.exe",
    "wsqmcons.exe",
    "WUDFHost.exe",
    "spoolsv.exe",
    "ssh-agent.exe",
    # VMware Tools (common across the SRL-2018 fleet which is virtualized)
    "vmtoolsd.exe",
    "VGAuthService.exe",
    "vm3dservice.exe",
    "vmacthlp.exe",
    # McAfee / Trellix endpoint stack — the SRL-2018 fleet ships this
    # by default; on 18+/22 hosts otherwise it triggers false-positive
    # cross-host correlations.
    "masvc.exe",
    "macmnsvc.exe",
    "macompatsvc.exe",
    "ManagementAgent.exe",
    "ManagementAgentHost.exe",
    "mfemactl.exe",
    "mfemms.exe",
    "mfevtps.exe",
    "FireSvc.exe",
    "FireTray.exe",
    "ProtectedModuleHost.exe",
    "DLPAgent.exe",
    "DLPAgentService.exe",
    "HipMgmt.exe",
    "VsTskMgr.exe",
    "mcshield.exe",
    "mfeann.exe",
    "mfefire.exe",
    "mfehcs.exe",
    "mfetp.exe",
    "UpdaterUI.exe",
    "scriptproxy.exe",
    "shstat.exe",
    "naPrdMgr.exe",
    "FrameworkService.exe",
    "mctray.exe",
    "MSASCuiL.exe",
    "MpCmdRun.exe",
    "NisSrv.exe",
    # Symantec / Norton (also seen in some SANS fixtures)
    "ccSvcHst.exe",
    "smcgui.exe",
    "smc.exe",
    "rtvscan.exe",
    # Carbon Black, CrowdStrike, SentinelOne (modern EDR — not in this
    # fleet, but listed for forward-compat with future investigations)
    "CarbonBlackClientSetup.exe",
    "csagent.exe",
    "CSFalconService.exe",
    "SentinelAgent.exe",
    "SentinelAgentWorker.exe",
    "SentinelHelperService.exe",
    # Microsoft Office (background services common in enterprise builds)
    "MSOSYNC.EXE",
    "OfficeClickToRun.exe",
    "OneDrive.exe",
    # Sysinternals tools — pre-deployed on SRL-2018 admin/IR machines
    # and run from default Sysinternals locations. Showing up on
    # multiple hosts at once is more often "the IR team ran Autoruns
    # everywhere" than attacker tooling — but flag it so the analyst
    # double-checks rather than dismissing.
    # (Intentionally NOT in COMMON_WIN_PROCS so cross-host runs of
    # Autorunsc, PsExec, etc., still surface as suspicious.)
}

COMMON_WIN_PROCS: set[str] = {n.lower() for n in _RAW_COMMON_PROCS}


def normalize_image_name(name: str) -> str:
    """Lowercase + truncate to 14 chars (Volatility EPROCESS field
    width). Used for comparison against COMMON_WIN_PROCS entries that
    may have been recorded as truncated strings in psscan output."""
    return name.strip().lower()[:14]


_COMMON_TRUNCATED: set[str] = {normalize_image_name(n) for n in _RAW_COMMON_PROCS}


def latest_fleet_dir() -> Path | None:
    base = REPO_ROOT / "tmp" / "fleet-runs"
    if not base.is_dir():
        return None
    candidates = sorted(
        base.glob("fleet-*"), key=lambda p: p.stat().st_mtime, reverse=True
    )
    return candidates[0] if candidates else None


def load_verdicts(fleet_dir: Path) -> list[dict[str, Any]]:
    fleet_json = fleet_dir / "fleet.json"
    if not fleet_json.is_file():
        return []
    fleet = json.loads(fleet_json.read_text(encoding="utf-8"))
    out = []
    for r in fleet.get("results", []):
        host = r.get("host", "?")
        case_dir = r.get("case_dir")
        if not case_dir:
            continue
        case_path = Path(case_dir)
        verdict_file = case_path / "verdict.json"
        if not verdict_file.is_file():
            continue
        try:
            v = json.loads(verdict_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        v["_host"] = host
        v["_case_dir"] = str(case_path)
        # Pick up psscan if it exists
        psscan_file = case_path / "psscan.json"
        if psscan_file.is_file():
            try:
                v["_psscan"] = json.loads(psscan_file.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                v["_psscan"] = []
        else:
            v["_psscan"] = []
        # Pick up judge_selfscore audit records if present (added 2026-04-26
        # commit 94c08dd; older runs simply won't have any).
        audit_file = case_path / "audit.jsonl"
        v["_selfscores"] = []
        if audit_file.is_file():
            for line in audit_file.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if rec.get("kind") == "judge_selfscore":
                    v["_selfscores"].append(rec.get("payload", {}))
        out.append(v)
    return out


def selfscore_aggregate(verdicts: list[dict[str, Any]]) -> dict[str, Any]:
    """Roll up the per-host kind=judge_selfscore audit records into a
    fleet-level summary. Each criterion's `answer` is a short string
    (e.g. "C=0% I=100% H=0% (n=2)" for criterion 2); we group by
    criterion number and report the modal answer plus per-host
    breakdown for analyst inspection."""
    by_criterion: dict[int, list[tuple[str, str]]] = defaultdict(list)
    hosts_with_selfscore = 0
    for v in verdicts:
        scores = v.get("_selfscores") or []
        if scores:
            hosts_with_selfscore += 1
        host = v.get("_host", "?")
        for p in scores:
            crit = p.get("criterion")
            answer = p.get("answer", "")
            if isinstance(crit, int):
                by_criterion[crit].append((host, answer))
    summary: dict[str, Any] = {
        "hosts_total": len(verdicts),
        "hosts_with_selfscore": hosts_with_selfscore,
        "by_criterion": {},
    }
    for crit in sorted(by_criterion):
        entries = by_criterion[crit]
        ans_counts = Counter(a for _, a in entries)
        modal_ans, modal_n = ans_counts.most_common(1)[0]
        summary["by_criterion"][str(crit)] = {
            "host_count": len(entries),
            "modal_answer": modal_ans,
            "modal_share": modal_n,
            "distinct_answers": len(ans_counts),
        }
    return summary


# psscan row accessors. The Rust `findevil-mcp` emits snake_case rows
# (image_name/pid/ppid/create_time_iso); older/raw Volatility output used
# PascalCase (ImageFileName/PID/PPID/CreateTime). Read either so the correlator
# works regardless of which producer wrote psscan.json.
def _proc_name(p: dict) -> str:
    return (p.get("image_name") or p.get("ImageFileName") or "").strip()


def _proc_pid(p: dict):
    return p.get("pid", p.get("PID"))


def _proc_ppid(p: dict):
    return p.get("ppid", p.get("PPID"))


def _proc_ctime(p: dict):
    return p.get("create_time_iso") or p.get("CreateTime")


def cross_host_processes(verdicts: list[dict[str, Any]]) -> dict[str, list[dict]]:
    """Return {process_name: [{host, pid, create_time}, ...]} for any
    uncommon name that appears on ≥2 hosts.

    Uses normalize_image_name() (lowercase + 14-char truncation) on
    both sides so a Volatility-truncated psscan name like
    "VGAuthService." matches the canonical "VGAuthService.exe" entry
    in COMMON_WIN_PROCS without manual aliasing."""
    by_name: dict[str, list[dict]] = defaultdict(list)
    for v in verdicts:
        host = v["_host"]
        for p in v.get("_psscan", []):
            name = _proc_name(p)
            if not name:
                continue
            if normalize_image_name(name) in _COMMON_TRUNCATED:
                continue
            by_name[name].append(
                {
                    "host": host,
                    "pid": _proc_pid(p),
                    "ppid": _proc_ppid(p),
                    "create_time": _proc_ctime(p),
                    # SOUL.md epistemic vocabulary: a cross-host correlation
                    # is a lead for an analyst to confirm, never a conclusion.
                    "epistemic_label": "HYPOTHESIS",
                }
            )
    return {
        n: hits for n, hits in by_name.items() if len({h["host"] for h in hits}) >= 2
    }


def temporal_clusters(
    verdicts: list[dict[str, Any]], window_seconds: int = 60
) -> list[dict[str, Any]]:
    """Return clusters of process creations across hosts that fall
    within a window_seconds-second window. Lateral-movement signal."""
    events: list[tuple[datetime, str, dict]] = []
    for v in verdicts:
        host = v["_host"]
        for p in v.get("_psscan", []):
            ct = _proc_ctime(p)
            if not ct:
                continue
            try:
                dt = datetime.fromisoformat(ct.replace("Z", "+00:00"))
            except ValueError:
                continue
            events.append((dt, host, p))
    events.sort(key=lambda e: e[0])
    if not events:
        return []
    clusters: list[dict[str, Any]] = []
    cur: list[tuple[datetime, str, dict]] = [events[0]]
    for ev in events[1:]:
        if ev[0] - cur[-1][0] <= timedelta(seconds=window_seconds):
            cur.append(ev)
        else:
            if len({h for _, h, _ in cur}) >= 2:
                clusters.append(_cluster_to_dict(cur))
            cur = [ev]
    if len({h for _, h, _ in cur}) >= 2:
        clusters.append(_cluster_to_dict(cur))
    return clusters


def _cluster_to_dict(cluster: list[tuple[datetime, str, dict]]) -> dict[str, Any]:
    return {
        "first_event": cluster[0][0].isoformat(),
        "last_event": cluster[-1][0].isoformat(),
        "duration_seconds": (cluster[-1][0] - cluster[0][0]).total_seconds(),
        "host_count": len({h for _, h, _ in cluster}),
        # A temporal cluster is a lateral-movement LEAD (SOUL.md: HYPOTHESIS
        # tier) — the analyst confirms or kills it; the fleet never concludes.
        "epistemic_label": "HYPOTHESIS",
        "events": [
            {
                "host": h,
                "create_time": dt.isoformat(),
                "pid": _proc_pid(p),
                "name": _proc_name(p),
            }
            for dt, h, p in cluster
        ],
    }


def mitre_density(verdicts: list[dict[str, Any]]) -> Counter:
    """Count *distinct hosts* per MITRE technique (not findings).

    A host that emits T1014 from both Pool A and Pool B should still
    count once — what the analyst cares about is "how many hosts
    show this technique," not "how loud the agents were on each one."

    `load_verdicts` decorates each verdict with `_host`; fall back to
    `host` for callers that already pass a host-tagged dict.
    """
    by_technique: dict[str, set[str]] = {}
    for v in verdicts:
        host = v.get("_host") or v.get("host") or "?"
        techniques_on_host = {
            f.get("mitre_technique")
            for f in v.get("findings", [])
            if f.get("mitre_technique")
        }
        for mt in techniques_on_host:
            by_technique.setdefault(mt, set()).add(host)
    return Counter({mt: len(hosts) for mt, hosts in by_technique.items()})


def verdict_distribution(verdicts: list[dict[str, Any]]) -> Counter:
    return Counter(v.get("verdict", "?") for v in verdicts)


def _host_merkle_root(verdict: dict[str, Any]) -> str | None:
    """The per-host Merkle root, from verdict.json or its run.manifest.json.

    manifest_finalize usually runs AFTER verdict.json is written, so the root
    lives only in run.manifest.json. Read the verdict's embedded value first,
    then fall back to the host's manifest beside it.
    """
    root = verdict.get("cryptographic_attestation", {}).get("merkle_root_hex")
    if root:
        return root
    case_dir = verdict.get("_case_dir")
    if not case_dir:
        return None
    manifest = Path(case_dir) / "run.manifest.json"
    if not manifest.is_file():
        return None
    try:
        return json.loads(manifest.read_text(encoding="utf-8")).get("merkle_root_hex")
    except (json.JSONDecodeError, OSError):
        return None


def merkle_uniqueness(verdicts: list[dict[str, Any]]) -> tuple[int, int]:
    roots = [r for r in (_host_merkle_root(v) for v in verdicts) if r]
    return len(set(roots)), len(roots)


def write_outputs(
    fleet_dir: Path,
    verdicts: list[dict[str, Any]],
    cross_procs: dict[str, list[dict]],
    clusters: list[dict[str, Any]],
    mitre: Counter,
    distrib: Counter,
    unique_roots: tuple[int, int],
) -> None:
    structured = {
        "fleet_dir": str(fleet_dir),
        "host_count": len(verdicts),
        "verdict_distribution": dict(distrib),
        "mitre_technique_density": dict(mitre),
        "cryptographic_attestation": {
            "unique_merkle_roots": unique_roots[0],
            "total_merkle_roots": unique_roots[1],
            "all_unique": unique_roots[0] == unique_roots[1],
        },
        "selfscore_aggregate": selfscore_aggregate(verdicts),
        "cross_host_processes": cross_procs,
        "temporal_clusters": clusters,
    }
    (fleet_dir / "fleet_correlation.json").write_text(
        json.dumps(structured, indent=2, sort_keys=True), encoding="utf-8"
    )

    md = ["# Fleet correlation report", ""]
    md.append(f"**Fleet dir:** `{fleet_dir.name}`")
    md.append(f"**Host count:** {len(verdicts)}")
    md.append("")
    md.append("## Verdict distribution")
    md.append("")
    md.append("| Verdict | Count |")
    md.append("|---|---:|")
    for verdict, count in distrib.most_common():
        md.append(f"| **{verdict}** | {count} |")
    md.append("")

    md.append("## MITRE ATT&CK technique density across the fleet")
    md.append("")
    if mitre:
        md.append("| Technique | Hosts |")
        md.append("|---|---:|")
        for t, c in mitre.most_common():
            md.append(f"| {t} | {c} |")
    else:
        md.append("*No MITRE techniques cited.*")
    md.append("")

    md.append("## Cross-host process-name correlation")
    md.append("")
    md.append(
        "*hypothesis: uncommon process names that appear on ≥2 hosts. "
        "Same name across multiple hosts is a much stronger lateral-movement "
        "signal than the same name on one host alone — a lead for an analyst "
        "to confirm, not a conclusion.*"
    )
    md.append("")
    if cross_procs:
        md.append("| Image name | Host count | Hosts (first 5) |")
        md.append("|---|---:|---|")
        for name, hits in sorted(
            cross_procs.items(), key=lambda kv: -len({h["host"] for h in kv[1]})
        ):
            host_set = sorted({h["host"] for h in hits})
            md.append(f"| `{name}` | {len(host_set)} | {', '.join(host_set[:5])} |")
    else:
        md.append("*No cross-host process correlations found.*")
    md.append("")

    md.append("## Temporal clusters")
    md.append("")
    md.append(
        "*hypothesis: groups of process creations across multiple hosts that "
        "fall within a 60-second window. Tight time clusters spanning ≥2 hosts "
        "are a hallmark of automated lateral movement (PsExec waves, "
        "WMI execution, scheduled-task chains) — leads for an analyst to "
        "confirm, not conclusions.*"
    )
    md.append("")
    if clusters:
        for i, cl in enumerate(clusters[:10], 1):
            md.append(
                f"### Cluster {i}: {cl['host_count']} hosts in "
                f"{cl['duration_seconds']:.1f}s "
                f"({cl['first_event']} → {cl['last_event']})"
            )
            md.append("")
            md.append("| Host | Time | PID | Image name |")
            md.append("|---|---|---:|---|")
            for ev in cl["events"][:20]:
                md.append(
                    f"| `{ev['host']}` | {ev['create_time']} | {ev['pid']} | `{ev['name']}` |"
                )
            md.append("")
    else:
        md.append("*No multi-host temporal clusters within the 60s window.*")
    md.append("")

    md.append("## Cryptographic attestation across the fleet")
    md.append("")
    md.append(
        f"All {unique_roots[1]} per-host manifests have Merkle roots; "
        f"**{unique_roots[0]} unique values** "
        f"({'all unique — chain integrity intact' if unique_roots[0] == unique_roots[1] else 'duplicate roots — investigate'})."
    )
    md.append("")
    md.append(
        "Each per-host manifest is independently verifiable via "
        "`manifest_verify`. The fleet correlation report (this file) is "
        "**derivative**, not authoritative — it summarizes the per-host "
        "manifests but doesn't replace them. A judge / counter-party who "
        "wants to verify must verify each `run.manifest.json` individually."
    )
    md.append("")

    md.append("## Recommended next steps for the analyst")
    md.append("")
    md.append("1. Triage the SUSPICIOUS-tier hosts first (verdict distribution above).")
    md.append(
        "2. For any cross-host process appearing on ≥3 hosts, pull the "
        "binary off disk (via the corresponding host's E01) and YARA-scan it."
    )
    md.append(
        "3. For temporal clusters spanning ≥3 hosts, build a timeline "
        "of the cluster's events and look for the *first* host in the "
        "cluster — that's the patient zero candidate."
    )
    md.append(
        "4. Cross-reference any T1014 (Rootkit) hosts against the disk "
        "image's `\\Windows\\System32\\drivers\\` for unsigned drivers."
    )
    md.append("")
    md.append("---")
    md.append("")
    md.append("## Judge self-score (fleet aggregate)")
    md.append("")
    sa = selfscore_aggregate(verdicts)
    if sa["hosts_with_selfscore"] == 0:
        md.append(
            "*No host emitted `kind=judge_selfscore` audit records. This "
            "fleet predates commit 94c08dd which wired the selfscore step "
            "into find-evil-auto. Re-run any host with the current "
            "orchestrator and the records will appear in audit.jsonl + "
            "the per-case REPORT.pdf.*"
        )
    else:
        md.append(
            f"{sa['hosts_with_selfscore']} of {sa['hosts_total']} hosts "
            f"emitted self-score records (per-criterion modal answer "
            f"shown below; full per-host breakdown is in the audit.jsonl "
            f"of each case dir). The score on each host is part of that "
            f"host's cryptographic attestation."
        )
        md.append("")
        md.append("| # | Modal answer | Host count | Distinct answers |")
        md.append("|---:|---|---:|---:|")
        for crit in sorted(sa["by_criterion"]):
            entry = sa["by_criterion"][crit]
            md.append(
                f"| {crit} | `{entry['modal_answer']}` | "
                f"{entry['modal_share']}/{entry['host_count']} | "
                f"{entry['distinct_answers']} |"
            )
    md.append("")
    md.append("---")
    md.append("")
    md.append(
        "*This report was produced by `fleet_correlate.py` as a derivative "
        "summary of the fleet's per-host investigations. The authoritative "
        "evidence is the set of per-host `run.manifest.json` files in each "
        "case directory.*"
    )
    (fleet_dir / "fleet_correlation.md").write_text("\n".join(md), encoding="utf-8")


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument(
        "fleet_dir",
        nargs="?",
        default=None,
        help="Fleet directory (defaults to most recent under tmp/fleet-runs/)",
    )
    p.add_argument(
        "--temporal-window",
        type=int,
        default=60,
        help="Seconds; cluster window for temporal correlation (default 60)",
    )
    args = p.parse_args()

    fleet_dir = Path(args.fleet_dir) if args.fleet_dir else latest_fleet_dir()
    if fleet_dir is None or not fleet_dir.is_dir():
        print("no fleet directory found")
        return 1
    print(f"correlating fleet: {fleet_dir.name}")

    verdicts = load_verdicts(fleet_dir)
    if not verdicts:
        print(f"  no verdicts loaded from {fleet_dir}")
        return 1
    print(f"  loaded {len(verdicts)} per-host verdicts")

    cross = cross_host_processes(verdicts)
    print(f"  cross-host process correlations: {len(cross)}")

    clusters = temporal_clusters(verdicts, args.temporal_window)
    print(f"  multi-host temporal clusters: {len(clusters)}")

    mitre = mitre_density(verdicts)
    distrib = verdict_distribution(verdicts)
    unique_roots = merkle_uniqueness(verdicts)

    write_outputs(fleet_dir, verdicts, cross, clusters, mitre, distrib, unique_roots)
    print(f"  -> {fleet_dir / 'fleet_correlation.md'}")
    print(f"  -> {fleet_dir / 'fleet_correlation.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
