#!/usr/bin/env python3
"""Per-finding >=2-artifact-class corroboration check (Provability R4).

Companion to ``scripts/score-overclaim.py``, which computes only a *case-level*
artifact-class breadth and explicitly defers per-finding R4 to "the judge's class
accounting." This script answers the per-finding question, offline, from a
finished case directory — and is scrupulous about *which* of two faithful
derivations it is reporting, because neither is a textual heuristic dressed up as
the real check.

R4 (from ``agent-config/SOUL.md`` / CLAUDE.md): an EXECUTION or EXFILTRATION claim
must be backed by >=2 distinct artifact classes (registry, evtx, memory,
filesystem, network, prefetch, ...) or it must not stand at CONFIRMED.

What the committed artifacts actually carry
-------------------------------------------
The ``Finding`` model in ``services/agent/findevil_agent/events.py`` has NO
structured "artifact classes corroborating this finding" field. The judge/
correlate stage (``services/agent/findevil_agent/correlator.py``) decides R4 by
*regex-matching the finding's own ``description`` prose* for a prefetch+registry
pair or EDR-tier wording — it never emits a per-finding class list or count.
What lands in ``verdict.json`` is:

  - ``findings[*].tool_call_id`` + ``findings[*].derived_from`` — provenance
    pointers (tool-call ids), which map to ONE citing tool each;
  - ``findings_summary.correlation_outcomes[*]`` — the judge's per-finding
    ``action`` ("kept" / "downgraded") and a free-text ``reason``, but NOT the
    class count it used.

So two FAITHFUL derivations are possible, and this script reports BOTH, labeled:

  [A] structural  — map each finding's cited tool-call ids (``tool_call_id`` +
      ``derived_from``) to artifact classes via the same ``_TOOL_CLASS`` table
      ``score-overclaim.py`` uses, and count DISTINCT classes per finding. This
      is the real "how many artifact classes is this finding mechanically tied
      to" number. It does not read prose.

  [B] replay-of-judge — re-run the exact correlator predicate
      (``is_execution_claim`` + the prefetch/registry/EDR description regex) on
      the committed findings and confirm it reproduces the committed
      ``correlation_outcomes`` actions. This attests that the R4 gate the run
      *claims* it applied is the one in source.

Honesty boundary: [A] is the structural class count; [B] is a replay of the
shipped gate (which is itself a description-text gate — that is the system's
design, stated plainly, not this script's heuristic). Where they disagree it is
reported, not smoothed over.

Usage:
    python scripts/check-corroboration.py [<case-dir>]   # default: newest run with findings
    python scripts/check-corroboration.py <case-dir> --json
"""

from __future__ import annotations

import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

# Canonical cited-tool -> artifact-class map. Kept byte-identical to the table in
# scripts/score-overclaim.py so the two scorers never disagree on what class a
# tool belongs to. (Single source would be nicer; duplicated deliberately to keep
# each scorer a standalone offline read with no shared import.)
_TOOL_CLASS = {
    "registry_query": "registry",
    "evtx_query": "evtx",
    "hayabusa_scan": "evtx",
    "vol_pslist": "memory",
    "vol_psscan": "memory",
    "vol_psxview": "memory",
    "vol_malfind": "memory",
    "vol_run": "memory",
    "mft_timeline": "filesystem",
    "usnjrnl_query": "filesystem",
    "indx_parse": "filesystem",
    "prefetch_parse": "prefetch",
    "yara_scan": "yara",
    "browser_history": "browser",
    "pcap_triage": "network",
    "zeek_summary": "network",
    "suricata_eve": "network",
    "nfdump_query": "network",
    "sysmon_network_query": "network",
}

# --- [B] mirror of the shipped execution-claim + corroboration gate ----------
# Kept byte-identical to services/agent/findevil_agent/execution_claim.py and
# correlator.py so this replay attests the SHIPPED gate, not a re-imagined one.
_EXEC_MITRE_PREFIXES = (
    "T1059",
    "T1106",
    "T1129",
    "T1203",
    "T1543",
    "T1547",
    "T1053",
)
_EXEC_TOKENS = (
    r"\bexecut(?:ed|ion|ing)\b",
    r"\bran\b",
    r"\brun count\b",
    r"\bprocess creation\b",
    r"\binvok(?:ed|ation|ing)\b",
    r"\blaunch(?:ed|ing)\b",
    r"\bspawn(?:ed|ing)\b",
    r"\bstarted\b",
)
_EXEC_RE = re.compile("|".join(_EXEC_TOKENS), re.IGNORECASE)
_AMCACHE_RE = re.compile(r"\bamcache\b", re.IGNORECASE)
_PREFETCH_RE = re.compile(r"\bprefetch\b", re.IGNORECASE)
_SHIMCACHE_RE = re.compile(r"\b(?:shimcache|appcompatcache)\b", re.IGNORECASE)
_USERASSIST_RE = re.compile(r"\buserassist\b", re.IGNORECASE)
_EDR_RE = re.compile(r"\b(?:sysmon|edr|carbon[\s-]?black|crowdstrike)\b", re.IGNORECASE)


def _is_execution_claim(description: str | None, mitre: str | None) -> bool:
    if description and _EXEC_RE.search(description):
        return True
    return bool(mitre and mitre.startswith(_EXEC_MITRE_PREFIXES))


def _replay_correlator_action(description: str, mitre: str | None) -> tuple[str, str]:
    """Reproduce correlator.correlate()'s per-finding (action, reason)."""
    if not _is_execution_claim(description, mitre):
        return "kept", "non-execution claim"
    text = description.lower()
    has_strong = (
        _PREFETCH_RE.search(text)
        and (
            _AMCACHE_RE.search(text)
            or _SHIMCACHE_RE.search(text)
            or _USERASSIST_RE.search(text)
        )
    ) or _EDR_RE.search(text) is not None
    amcache_only = (
        _AMCACHE_RE.search(text)
        and not _PREFETCH_RE.search(text)
        and not _SHIMCACHE_RE.search(text)
        and not _EDR_RE.search(text)
    )
    if amcache_only:
        return (
            "downgraded",
            "Amcache LastModified is catalog-registration, not execution",
        )
    if has_strong:
        return (
            "kept",
            "execution corroborated in-finding by prefetch+registry pair or EDR telemetry",
        )
    return (
        "downgraded",
        "execution claim from a single artifact class without prefetch/EDR corroboration",
    )


def _newest_case_with_findings() -> Path | None:
    root = Path("tmp/auto-runs")
    if not root.is_dir():
        return None
    cands: list[tuple[float, Path]] = []
    for d in root.iterdir():
        vp = d / "verdict.json"
        if not vp.is_file():
            continue
        try:
            doc = json.loads(vp.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        if doc.get("findings"):
            cands.append((vp.stat().st_mtime, d))
    return max(cands, key=lambda t: t[0])[1] if cands else None


def _tool_call_index(verdict: dict[str, Any]) -> dict[str, str]:
    """Map tool_call_id -> tool name from the committed tool_calls list."""
    idx: dict[str, str] = {}
    for tc in verdict.get("tool_calls", []) or []:
        tid = tc.get("tool_call_id")
        name = tc.get("tool")
        if tid and name:
            idx[tid] = name
    return idx


def _finding_classes(finding: dict[str, Any], tc_index: dict[str, str]) -> set[str]:
    """[A] distinct artifact classes a finding is mechanically tied to.

    Source: its own tool_call_id plus any derived_from tool-call ids, mapped
    through _TOOL_CLASS. prior_observations are excluded by design (per the
    Finding model they NEVER count toward the >=2-class rule).
    """
    ids: set[str] = set()
    if finding.get("tool_call_id"):
        ids.add(finding["tool_call_id"])
    for d in finding.get("derived_from") or []:
        if isinstance(d, str):
            ids.add(d)
    classes: set[str] = set()
    for cid in ids:
        tool = tc_index.get(cid)
        if tool and tool in _TOOL_CLASS:
            classes.add(_TOOL_CLASS[tool])
    return classes


def analyze(case_dir: Path) -> dict[str, Any]:
    verdict = json.loads((case_dir / "verdict.json").read_text(encoding="utf-8"))
    findings = verdict.get("findings", []) or []
    tc_index = _tool_call_index(verdict)
    committed_outcomes = {
        # last-write-wins on duplicated finding_ids mirrors how a reader keys them;
        # we also surface duplicates separately below.
        o["finding_id"]: o
        for o in verdict.get("findings_summary", {}).get("correlation_outcomes", [])
        or []
    }

    rows: list[dict[str, Any]] = []
    for f in findings:
        desc = f.get("description") or ""
        mitre = f.get("mitre_technique")
        classes = sorted(_finding_classes(f, tc_index))
        is_exec = _is_execution_claim(desc, mitre)
        replay_action, replay_reason = _replay_correlator_action(desc, mitre)
        committed = committed_outcomes.get(f.get("finding_id"))
        rows.append(
            {
                "finding_id": f.get("finding_id"),
                "confidence": f.get("confidence"),
                "mitre_technique": mitre,
                "is_execution_claim": is_exec,
                "structural_classes": classes,  # [A]
                "structural_class_count": len(classes),
                "meets_2class_structural": len(classes) >= 2,
                "replay_action": replay_action,  # [B]
                "replay_reason": replay_reason,
                "committed_action": (committed or {}).get("action"),
                "committed_reason": (committed or {}).get("reason"),
            }
        )

    # --- [B] replay fidelity: does our mirror reproduce committed outcomes? ----
    # Compare per finding-object (committed_outcomes is keyed by id, so a duplicated
    # finding_id collapses; compare against the per-id committed action we resolved).
    replay_checked = [r for r in rows if r["committed_action"] is not None]
    replay_matches = sum(
        1 for r in replay_checked if r["replay_action"] == r["committed_action"]
    )

    # --- [A] structural R4 over CONFIRMED execution claims --------------------
    confirmed = [r for r in rows if r["confidence"] == "CONFIRMED"]
    confirmed_exec = [r for r in confirmed if r["is_execution_claim"]]
    confirmed_exec_2class = [r for r in confirmed_exec if r["meets_2class_structural"]]
    confirmed_exec_1class = [
        r for r in confirmed_exec if not r["meets_2class_structural"]
    ]

    # Also report over ALL execution-claim findings (any confidence), since the
    # gate runs before the tier is finalized.
    all_exec = [r for r in rows if r["is_execution_claim"]]
    all_exec_2class = [r for r in all_exec if r["meets_2class_structural"]]

    return {
        "case_dir": str(case_dir),
        "case_id": verdict.get("case_id"),
        "verdict": verdict.get("verdict"),
        "n_findings": len(findings),
        "n_unique_finding_ids": len({f.get("finding_id") for f in findings}),
        "tool_call_index_size": len(tc_index),
        "structural_R4": {
            "confirmed_total": len(confirmed),
            "confirmed_execution_claims": len(confirmed_exec),
            "confirmed_exec_meets_2class": len(confirmed_exec_2class),
            "confirmed_exec_single_class": len(confirmed_exec_1class),
            "all_execution_claims": len(all_exec),
            "all_exec_meets_2class": len(all_exec_2class),
            "class_count_histogram": dict(
                sorted(Counter(r["structural_class_count"] for r in all_exec).items())
            ),
        },
        "judge_replay_R4": {
            "outcomes_compared": len(replay_checked),
            "replay_matches_committed": replay_matches,
            "replay_fidelity": (
                round(replay_matches / len(replay_checked), 4)
                if replay_checked
                else None
            ),
            "committed_action_breakdown": dict(
                Counter(r["committed_action"] for r in replay_checked)
            ),
        },
        "rows": rows,
    }


def _print_human(report: dict[str, Any]) -> None:
    s = report["structural_R4"]
    j = report["judge_replay_R4"]
    print(f"VERDICT R4 per-finding corroboration check — {report['case_id']}")
    print(f"  case: {report['case_dir']}")
    print(
        f"  verdict: {report['verdict']}   findings: {report['n_findings']} "
        f"({report['n_unique_finding_ids']} unique ids)"
    )
    print()
    print("[A] STRUCTURAL  (distinct artifact classes from cited tool-call ids):")
    print(
        f"      CONFIRMED execution-claim findings        : {s['confirmed_execution_claims']}"
    )
    print(
        f"        meeting >=2 distinct classes            : {s['confirmed_exec_meets_2class']}"
    )
    print(
        f"        backed by a SINGLE class                : {s['confirmed_exec_single_class']}"
    )
    print(
        f"      ALL execution-claim findings (any tier)   : {s['all_execution_claims']}"
    )
    print(
        f"        meeting >=2 distinct classes            : {s['all_exec_meets_2class']}"
    )
    print(
        f"      class-count histogram (exec claims)       : {s['class_count_histogram']}"
    )
    print()
    print("[B] JUDGE REPLAY  (re-run shipped correlator gate vs committed outcomes):")
    print(f"      outcomes compared                         : {j['outcomes_compared']}")
    print(
        f"      replay reproduces committed action        : {j['replay_matches_committed']}"
        f"  (fidelity {j['replay_fidelity']})"
    )
    print(
        f"      committed action breakdown                : {j['committed_action_breakdown']}"
    )
    print()
    print("Honesty boundary: [A] is the mechanical class count from tool provenance;")
    print(
        "[B] replays the shipped gate, which decides R4 by matching the finding's own"
    )
    print("description prose (prefetch+registry / EDR) — that is the product's design,")
    print("not a heuristic introduced here. Neither asserts interpretive correctness.")


def main(argv: list[str]) -> int:
    args = [a for a in argv if a != "--json"]
    as_json = "--json" in argv
    if args:
        case_dir = Path(args[0])
    else:
        nc = _newest_case_with_findings()
        if nc is None:
            print("no case dir with findings under tmp/auto-runs", file=sys.stderr)
            return 2
        case_dir = nc
    if not (case_dir / "verdict.json").is_file():
        print(f"no verdict.json under {case_dir}", file=sys.stderr)
        return 2
    report = analyze(case_dir)
    if as_json:
        print(json.dumps(report, indent=2))
    else:
        _print_human(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
