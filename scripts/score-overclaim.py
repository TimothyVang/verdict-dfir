#!/usr/bin/env python3
"""VERDICT overclaim / trust scorer — the discipline axis recall ignores.

Companion to ``scripts/score-recall.py`` (which answers "did the run find the
ground truth?"). This answers the opposite, harder question from
``docs/trust-benchmark.md``: **did the run over-claim — assert more than the
evidence and the verifier support, and is every finding checkable?**

It is an offline, after-the-fact read of a finished case directory. It does NOT
touch the sealed audit chain. From ``verdict.json`` + ``manifest_verify.json`` it
computes the *mechanically derivable* trust-benchmark metrics:

  - citation_coverage  : fraction of findings that cite a ``tool_call_id``        (Provability R1)
  - replay_pass_rate   : fraction whose verifier replay reproduced the output hash (R2)
  - custody_ok         : manifest_verify ``overall`` (+ chain / merkle / signature) (R7)
  - confidence_tiers   : CONFIRMED / INFERRED / HYPOTHESIS distribution             (R5)
  - verifier_actions   : approved / rejected / downgraded — the system catching itself
  - overclaim signals  : findings APPROVED despite a failed/absent replay = snuck-through over-claims

What it deliberately does NOT score (honesty boundary, see docs/trust-benchmark.md):
  - full entailment / value-fidelity (R3) — lives in the entailment check on ``master``;
  - per-finding >=2-artifact-class corroboration (R4) — needs the judge's class accounting;
  - interpretive correctness — no deterministic oracle; stays human-judged.

These are reported under ``not_measured`` so a clean scorecard is never mistaken
for "provably correct." A high score means *disciplined and checkable*, not *right*.

Usage:
    python scripts/score-overclaim.py <case-dir>      # or newest run with findings
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


# Map a cited tool to its artifact CLASS, for the R4 corroboration-breadth signal.
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


# The 32 audit-chained Rust DFIR product tools (the ``findevil-mcp`` surface, per
# CLAUDE.md / docs/reference/mcp-and-tools.md). This is the evidence-analysis
# surface a Case may choose to exercise — it is the denominator for the
# "allowed-but-not-run" untested-surface table. The 13 Python custody/ACH tools
# in ``findevil-agent-mcp`` (verify/judge/correlate/manifest …) are the pipeline
# spine that runs on every Case, not a per-Case analysis choice, so they are
# deliberately not in this set.
_PRODUCT_DFIR_TOOLS = frozenset(
    {
        "case_open",
        "disk_mount",
        "disk_extract_artifacts",
        "disk_unmount",
        "evtx_query",
        "prefetch_parse",
        "mft_timeline",
        "registry_query",
        "yara_scan",
        "usnjrnl_query",
        "hayabusa_scan",
        "sysmon_network_query",
        "zeek_summary",
        "pcap_triage",
        "vol_pslist",
        "vol_malfind",
        "vol_psscan",
        "vol_psxview",
        "vol_run",
        "ez_parse",
        "oe_dbx_parse",
        "plaso_parse",
        "mac_triage",
        "cloud_audit",
        "journalctl_query",
        "login_accounting",
        "ausearch",
        "nfdump_query",
        "suricata_eve",
        "indx_parse",
        "vel_collect",
        "browser_history",
    }
)

# Keywords that mark a verifier rejection as a fact-fidelity / entailment veto
# (the SHA replay reproduced, but an asserted value was not entailed) rather than
# a hash-drift / replay failure. See docs/fact-fidelity.md.
_FIDELITY_REASON_HINTS = ("entail", "fidelity", "asserted", "not supported by")


def _iter_audit(case_dir: Path) -> list[dict[str, Any]]:
    """Read-only parse of ``audit.jsonl`` into a list of records (empty if absent).

    Never touches the sealed chain — it only reads — and tolerates a truncated
    final line so a half-flushed run dir still yields what it has.
    """
    path = case_dir / "audit.jsonl"
    if not path.is_file():
        return []
    records: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return records


def _suppression_funnel(
    case_dir: Path,
    audit: list[dict[str, Any]],
    reported_n: int,
    verdict_doc: dict[str, Any],
) -> dict[str, Any]:
    """Deterministic raw-candidate -> reported funnel by named suppression class.

    Prefers the hash-chained ``audit.jsonl`` (``verifier_action`` +
    ``correlation_outcomes`` records); falls back to the ``verdict.json`` mirror
    (``rejected_finding_leads`` + ``findings_summary.correlation_outcomes``) when
    no audit log is present. Read-only — it derives counts, it never mutates the
    chain or the scoring math.
    """
    verifier_rejected = 0
    fact_fidelity_vetoed = 0
    correlator_downgraded = 0
    below_confidence_leads_only = 0

    if audit:
        source = "audit.jsonl"
        for rec in audit:
            kind = rec.get("kind")
            payload = rec.get("payload") or {}
            if kind == "verifier_action":
                action = str(payload.get("action") or "").lower()
                if action == "rejected":
                    reason = str(payload.get("reason") or "").lower()
                    if payload.get("replay_matched") is not False and any(
                        h in reason for h in _FIDELITY_REASON_HINTS
                    ):
                        fact_fidelity_vetoed += 1
                    else:
                        verifier_rejected += 1
            elif kind == "correlation_outcomes":
                for outcome in payload.get("outcomes") or []:
                    action = str(outcome.get("action") or "").lower()
                    if action == "downgraded":
                        correlator_downgraded += 1
                    elif action in ("rejected", "dropped", "suppressed"):
                        below_confidence_leads_only += 1
    else:
        source = "verdict.json"
        leads = verdict_doc.get("rejected_finding_leads") or []
        verifier_rejected = len(leads)
        summary = verdict_doc.get("findings_summary") or {}
        for outcome in summary.get("correlation_outcomes") or []:
            action = str(outcome.get("action") or "").lower()
            if action == "downgraded":
                correlator_downgraded += 1
            elif action in ("rejected", "dropped", "suppressed"):
                below_confidence_leads_only += 1
        if not summary.get("correlation_outcomes"):
            correlator_downgraded = int(summary.get("soul_md_downgraded") or 0)

    classes = {
        "verifier_rejected": verifier_rejected,
        "fact_fidelity_vetoed": fact_fidelity_vetoed,
        "correlator_downgraded": correlator_downgraded,
        "below_confidence_leads_only": below_confidence_leads_only,
    }
    # raw = reported + the classes that REMOVE a candidate from the reported set.
    # correlator_downgraded is a tier change (the finding is still reported at a
    # lower confidence), so it is surfaced but NOT subtracted from raw.
    removed = verifier_rejected + fact_fidelity_vetoed + below_confidence_leads_only
    return {
        "reported_findings_n": reported_n,
        "raw_candidate_findings_n": reported_n + removed,
        "classes": classes,
        "source": source,
        "note": (
            "raw -> reported funnel. verifier_rejected / fact_fidelity_vetoed / "
            "below_confidence_leads_only REMOVE a candidate (counted into raw); "
            "correlator_downgraded only lowers a reported finding's tier and is NOT "
            "subtracted. Derived read-only from the run dir; not a goldens score."
        ),
    }


def _untested_surface(
    audit: list[dict[str, Any]], verdict_doc: dict[str, Any]
) -> dict[str, Any]:
    """Product DFIR tools available but never exercised in this Case.

    Exercised tools come from ``audit.jsonl`` ``tool_call_start`` records, or the
    ``verdict.json`` ``tool_calls`` mirror when no audit log is present.
    """
    exercised: set[str] = set()
    if audit:
        for rec in audit:
            if rec.get("kind") == "tool_call_start":
                tool = (rec.get("payload") or {}).get("tool")
                if tool:
                    exercised.add(str(tool))
    if not exercised:
        for call in verdict_doc.get("tool_calls") or []:
            tool = call.get("tool")
            if tool:
                exercised.add(str(tool))

    exercised_product = sorted(exercised & _PRODUCT_DFIR_TOOLS)
    allowed_not_run = sorted(_PRODUCT_DFIR_TOOLS - exercised)
    return {
        "product_dfir_tools_n": len(_PRODUCT_DFIR_TOOLS),
        "exercised_tools": exercised_product,
        "exercised_n": len(exercised_product),
        "allowed_not_run": allowed_not_run,
        "allowed_not_run_n": len(allowed_not_run),
        "note": (
            "Product MCP DFIR tools (findevil-mcp) available but not exercised in "
            "this Case. Untested surface is coverage context, not a defect — many "
            "tools do not apply to a given evidence type."
        ),
    }


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
        except json.JSONDecodeError:
            continue
        if doc.get("findings"):
            cands.append((vp.stat().st_mtime, d))
    return max(cands, key=lambda t: t[0])[1] if cands else None


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}


def _frac(num: int, den: int) -> float:
    return round(num / den, 4) if den else 1.0


def score(case_dir: Path) -> dict[str, Any]:
    verdict_doc = _load(case_dir / "verdict.json")
    manifest = _load(case_dir / "manifest_verify.json")

    findings: list[dict[str, Any]] = verdict_doc.get("findings") or []
    n = len(findings)

    audit = _iter_audit(case_dir)
    suppression_funnel = _suppression_funnel(case_dir, audit, n, verdict_doc)
    untested_surface = _untested_surface(audit, verdict_doc)

    cited = [f for f in findings if f.get("tool_call_id")]
    replay_attempted = [f for f in findings if f.get("replay_matched") is not None]
    replay_passed = [f for f in replay_attempted if f.get("replay_matched") is True]

    tiers = Counter((f.get("confidence") or "UNSPECIFIED").upper() for f in findings)
    actions = Counter((f.get("verifier_action") or "none").lower() for f in findings)

    # The headline over-claim signal: a finding the verifier APPROVED whose cited
    # tool-call replay did NOT reproduce (or was never replayed). If the verifier
    # works, this set is empty — an approved finding always carries a matching replay.
    snuck_through = [
        {
            "finding_id": f.get("finding_id"),
            "tool": f.get("replay_tool_name"),
            "replay_matched": f.get("replay_matched"),
            "replay_error": f.get("replay_error"),
            "description": (f.get("description") or "")[:160],
        }
        for f in findings
        if (f.get("verifier_action") or "").lower() == "approved"
        and f.get("replay_matched") is not True
    ]

    custody_ok = bool(manifest.get("overall")) if manifest else None
    # `overall` can be true on a STUB (dev/offline placeholder) signature, so report
    # the signature status separately — a green custody must not hide an unverified sig.
    signature_verified = manifest.get("signature_verified")
    signature_kind = manifest.get("signature_kind")

    # R3 — value-fidelity. The R3-scored subset is ONLY findings that declare a
    # NON-EMPTY `asserted_values`; an empty/absent `asserted_values` is not an R3
    # finding (every finding carries the key, often empty). The pass signal is
    # RUN-LEVEL — `manifest_verify.json` `entailment_ok` — NOT per-finding (the
    # per-finding `entailment`/`entailment_ok` fields are null on these runs). A
    # per-finding `entailment_ok is False` is still honored as a miss if one appears.
    asserted_findings = [f for f in findings if f.get("asserted_values")]
    if asserted_findings:
        run_entailment_ok = bool(manifest.get("entailment_ok")) if manifest else False
        per_finding_miss = any(
            f.get("entailment_ok") is False for f in asserted_findings
        )
        all_entailed = run_entailment_ok and not per_finding_miss
        ok_n = len(asserted_findings) if all_entailed else 0
        r3 = {
            "available": True,
            "scored_n": len(asserted_findings),
            "fidelity_pass_rate": _frac(ok_n, len(asserted_findings)),
            "signal": "manifest_verify.entailment_ok",
            "run_entailment_ok": run_entailment_ok,
        }
    else:
        r3 = {
            "available": False,
            "reason": "run produced without the master entailment check — no asserted_values to re-check",
        }

    # R4 — corroboration BREADTH for the case (a signal, NOT the per-finding check).
    classes = sorted(
        {
            _TOOL_CLASS.get(f.get("replay_tool_name"), "other")
            for f in findings
            if f.get("replay_tool_name")
        }
    )
    r4 = {
        "artifact_classes_present": classes,
        "distinct_class_count": len(classes),
        "confirmed_findings_n": tiers.get("CONFIRMED", 0),
        "note": (
            "case-level artifact-class breadth. Per-finding >=2-class corroboration (Provability R4) "
            "is enforced upstream by the judge and is NOT re-derivable from verdict.json — see the "
            "honesty boundary."
        ),
    }

    return {
        "case_id": verdict_doc.get("case_id"),
        "case_dir": str(case_dir),
        "verdict": verdict_doc.get("verdict"),
        "findings_n": n,
        # --- Provability metrics (mechanically derivable) -------------------
        "citation_coverage": _frac(len(cited), n),  # R1
        "uncited_findings_n": n - len(cited),
        "replay_pass_rate": _frac(len(replay_passed), len(replay_attempted)),  # R2
        "replay_attempted_n": len(replay_attempted),
        "not_replayed_n": n - len(replay_attempted),
        "custody_ok": custody_ok,  # R7
        "custody_detail": {
            k: manifest.get(k)
            for k in ("audit_chain_ok", "merkle_root_ok", "signature_verified")
            if k in manifest
        },
        "signature_verified": signature_verified,
        "signature_kind": signature_kind,
        "custody_cryptographically_signed": signature_verified is True,
        "confidence_tiers": dict(tiers),  # R5
        "verifier_actions": dict(actions),
        # --- Over-claim ----------------------------------------------------
        "overclaim_snuck_through_n": len(snuck_through),
        "overclaim_snuck_through": snuck_through,
        "r3_fidelity": r3,
        "r4_corroboration": r4,
        # --- Discipline funnel + untested surface (goldens-free) -----------
        "suppression_funnel": suppression_funnel,
        "untested_surface": untested_surface,
        # --- Honesty boundary ---------------------------------------------
        "not_measured": [
            "value-fidelity / entailment (Provability R3) — the entailment check on master",
            "per-finding >=2-artifact-class corroboration (R4) — needs judge class accounting",
            "interpretive correctness — no deterministic oracle; human-judged",
        ],
        "note": (
            "A clean scorecard means disciplined + checkable, NOT provably correct. "
            "Pair with score-recall.py for recall/precision and run the benign baseline "
            "for the false-positive floor."
        ),
    }


def _print_report(r: dict[str, Any]) -> None:
    print(f"=== VERDICT overclaim / trust score — {r['case_id']} ===")
    print(f"  case_dir : {r['case_dir']}")
    print(f"  verdict  : {r['verdict']}  ({r['findings_n']} findings)")
    print(
        f"  citation : {r['citation_coverage'] * 100:.0f}% cite a tool_call_id "
        f"({r['uncited_findings_n']} uncited)"
    )
    print(
        f"  replay   : {r['replay_pass_rate'] * 100:.0f}% of {r['replay_attempted_n']} "
        f"replayed findings reproduced the output hash ({r['not_replayed_n']} not replayed)"
    )
    sig = (
        "ed25519 verified"
        if r.get("custody_cryptographically_signed")
        else f"{r.get('signature_kind')} — NOT cryptographically verified"
    )
    print(f"  custody  : overall={r['custody_ok']}; signature={sig}")
    print(f"  tiers    : {r['confidence_tiers']}")
    print(f"  verifier : {r['verifier_actions']}")
    print(
        f"  OVERCLAIM: {r['overclaim_snuck_through_n']} finding(s) approved despite a "
        f"failed/absent replay  ({'CLEAN' if r['overclaim_snuck_through_n'] == 0 else 'INVESTIGATE'})"
    )
    for s in r["overclaim_snuck_through"][:5]:
        print(
            f"    - {s['finding_id']} [{s['tool']}] matched={s['replay_matched']}: {s['description']}"
        )
    r3 = r["r3_fidelity"]
    if r3.get("available"):
        pass_n = round(r3["fidelity_pass_rate"] * r3["scored_n"])
        print(
            f"  R3 fidel.: {r3['fidelity_pass_rate'] * 100:.0f}% on the asserted subset "
            f"({pass_n}/{r3['scored_n']} re-extracted; signal=manifest entailment_ok={r3['run_entailment_ok']})"
        )
    else:
        print(f"  R3 fidel.: n/a ({r3['reason']})")
    r4 = r["r4_corroboration"]
    print(
        f"  R4 breadth: {r4['distinct_class_count']} artifact classes {r4['artifact_classes_present']}; "
        f"{r4['confirmed_findings_n']} CONFIRMED (per-finding >=2-class enforced upstream, not re-derived)"
    )
    sf = r["suppression_funnel"]
    sc = sf["classes"]
    print(
        f"  funnel   : {sf['raw_candidate_findings_n']} raw -> {sf['reported_findings_n']} reported "
        f"(verifier_rejected={sc['verifier_rejected']}, fidelity_vetoed={sc['fact_fidelity_vetoed']}, "
        f"correlator_downgraded={sc['correlator_downgraded']}, leads_only={sc['below_confidence_leads_only']}; "
        f"src={sf['source']})"
    )
    us = r["untested_surface"]
    print(
        f"  surface  : {us['exercised_n']}/{us['product_dfir_tools_n']} DFIR tools exercised; "
        f"{us['allowed_not_run_n']} allowed-but-not-run"
    )


def main(argv: list[str]) -> int:
    args = [a for a in argv[1:] if not a.startswith("--")]
    case_dir = Path(args[0]) if args else _newest_case_with_findings()
    if case_dir is None or not (case_dir / "verdict.json").is_file():
        print("usage: python scripts/score-overclaim.py <case-dir>", file=sys.stderr)
        print(
            "  (no case dir given and no run with findings under tmp/auto-runs/)",
            file=sys.stderr,
        )
        return 2

    result = score(case_dir)
    if "--quiet" not in argv:
        _print_report(result)
    out = case_dir / "overclaim-score.json"
    out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    if "--quiet" not in argv:
        print(f"\nwrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
