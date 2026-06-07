#!/usr/bin/env python3
"""ground_verdict.py — post-verdict grounding helper (Phase 1, keyless).

Reads a finished Case's `verdict.json`, collects every MITRE technique the verdict
references (techniques asserted by findings / the attack story, plus coverage
targets), asks the self-hosted `findevil-grounding` n8n workflow to research each
one against MITRE ATT&CK, and writes the UNJUDGED research bundle to
`<case>/grounding_research.json`.

This helper does NOT judge. Claude Code reads the bundle and judges each claim
(supported/unsupported/contradicted/unknown) per `agent-config/GROUNDING.md`, then
writes `<case>/grounding.json`. There is no LLM and no API key in this path.

BOUNDARY (agent-config/GROUNDING.md): the output is a post-verdict operator aid —
never evidence, never a tool_call_id, never appended to `audit.jsonl` or the signed
`run.manifest.json`. This helper only ever writes `grounding_research.json`.

Usage:
    python3 scripts/ground_verdict.py <case-dir | verdict.json | case-id>
    GROUNDING_WEBHOOK=http://127.0.0.1:5678/webhook/findevil-grounding  (override)
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
AUTO_RUNS = ROOT / "tmp" / "auto-runs"
WEBHOOK = os.environ.get(
    "GROUNDING_WEBHOOK", "http://127.0.0.1:5678/webhook/findevil-grounding"
)
RESEARCH_FILENAME = "grounding_research.json"
HTTP_TIMEOUT_S = 240


def resolve_case_dir(arg: str) -> Path:
    """Accept a case dir, a path to verdict.json, or a bare case-id."""
    p = Path(arg)
    if p.is_file() and p.name == "verdict.json":
        return p.parent
    if p.is_dir():
        return p
    candidate = AUTO_RUNS / arg
    if candidate.is_dir():
        return candidate
    raise SystemExit(f"error: cannot resolve a case directory from {arg!r}")


def _touch(techs: dict[str, dict[str, Any]], tid: str) -> dict[str, Any]:
    key = tid.strip().upper()
    return techs.setdefault(
        key,
        {
            "technique_id": key,
            "claimed": False,
            "claimed_by": [],
            "finding_confidences": [],
            "names": [],
            "claim_snippets": [],
            "coverage_status": None,
        },
    )


def _add_unique(seq: list[Any], value: Any) -> None:
    if value and value not in seq:
        seq.append(value)


def collect_techniques(verdict: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Union of every MITRE technique the verdict references, with provenance.

    Asserted techniques (findings + attack-story chain) are real claims to judge;
    coverage-only targets are playbook entries (claimed=False).
    """
    techs: dict[str, dict[str, Any]] = {}

    for f in verdict.get("findings") or []:
        mt = f.get("mitre_technique")
        if not mt:
            continue
        e = _touch(techs, mt)
        e["claimed"] = True
        _add_unique(e["claimed_by"], f.get("finding_id") or f.get("id"))
        _add_unique(e["finding_confidences"], f.get("confidence"))
        _add_unique(e["claim_snippets"], (f.get("description") or "").strip()[:240])

    story = verdict.get("attack_story") or {}
    for s in story.get("attack_chain") or []:
        mt = s.get("mitre_technique")
        if not mt:
            continue
        e = _touch(techs, mt)
        e["claimed"] = True
        _add_unique(e["claimed_by"], s.get("finding_id"))
        _add_unique(e["finding_confidences"], s.get("confidence"))
        _add_unique(
            e["claim_snippets"],
            (s.get("summary") or s.get("title") or "").strip()[:240],
        )

    coverage = verdict.get("attack_coverage") or {}
    for t in coverage.get("targets") or []:
        tid = t.get("technique_id")
        if not tid:
            continue
        e = _touch(techs, tid)
        _add_unique(e["names"], t.get("technique_name"))
        e["coverage_status"] = t.get("status")
    for tid in coverage.get("observed_techniques") or []:
        _touch(techs, tid)

    return techs


def claim_for(entry: dict[str, Any]) -> str:
    if entry["claim_snippets"]:
        return entry["claim_snippets"][0]
    if entry["names"]:
        return entry["names"][0]
    return "coverage target (no finding asserts this)"


def call_workflow(case_id: str, techs: dict[str, dict[str, Any]]) -> dict[str, Any]:
    payload = {
        "case_id": case_id,
        "techniques": [
            {"id": e["technique_id"], "claim": claim_for(e)} for e in techs.values()
        ],
    }
    req = urllib.request.Request(
        WEBHOOK, data=json.dumps(payload).encode(), method="POST"
    )
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_S) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        raise SystemExit(
            f"error: grounding webhook returned HTTP {e.code}. "
            f"Is the workflow deployed? Run: python3 scripts/setup-grounding-workflow.py"
        )
    except (urllib.error.URLError, OSError) as e:
        raise SystemExit(
            f"error: cannot reach grounding webhook at {WEBHOOK} ({e}).\n"
            f"  - start n8n + browserless (scripts/setup-n8n.py, browserless container), and\n"
            f"  - deploy the workflow: python3 scripts/setup-grounding-workflow.py"
        )


def merge_bundle(
    techs: dict[str, dict[str, Any]], research: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    by_id = {r.get("technique_id", "").upper(): r for r in research}
    merged: list[dict[str, Any]] = []
    # claimed techniques first, then by id — the asserted claims are what matter
    for key, e in sorted(techs.items(), key=lambda kv: (not kv[1]["claimed"], kv[0])):
        r = by_id.get(key, {})
        merged.append(
            {
                "technique_id": key,
                "claimed": e["claimed"],
                "claimed_by": e["claimed_by"],
                "finding_confidences": e["finding_confidences"],
                "coverage_status": e["coverage_status"],
                "found": r.get("found", False),
                "id_match": r.get("id_match", False),
                "mitre_id": r.get("mitre_id"),
                "mitre_name": r.get("mitre_name"),
                "excerpt": r.get("excerpt"),
                "sources": r.get("sources", []),
                "error": r.get("error"),
            }
        )
    return merged


# Typed IOC buckets we can reputation-enrich (from malware_triage.aggregate_iocs).
ENRICHABLE_IOC_TYPES = ("hashes", "domains", "ips", "urls")


def extract_iocs(verdict: dict[str, Any]) -> dict[str, list[str]]:
    """Pull typed IOCs from malware_triage.aggregate_iocs only.

    Deliberately NOT a regex over the verdict: every tool output is SHA-256'd
    into the crypto chain, so a blind hash regex would scoop up custody hashes
    and manufacture bogus IOCs. Only the engine's typed observables enrich.
    """
    agg = (verdict.get("malware_triage") or {}).get("aggregate_iocs") or {}
    return {k: [v for v in (agg.get(k) or []) if v] for k in ENRICHABLE_IOC_TYPES}


def run_ioc_enrichment(iocs: dict[str, list[str]]) -> dict[str, Any] | None:
    """Host-side reputation enrichment (VirusTotal). Key never enters n8n.

    Returns None when there are no IOCs to enrich; otherwise the enrichment
    block (results + availability note) for the research bundle.
    """
    if not any(iocs.values()):
        return None
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    try:
        import ioc_enrich
    except Exception as e:  # ioc_enrich is optional; never break technique grounding
        return {
            "results": [],
            "available": False,
            "note": f"ioc_enrich unavailable: {e}",
        }
    return ioc_enrich.enrich(iocs)


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print(__doc__)
        return 2
    case_dir = resolve_case_dir(argv[0])
    verdict_path = case_dir / "verdict.json"
    if not verdict_path.is_file():
        raise SystemExit(f"error: no verdict.json in {case_dir}")
    verdict = json.loads(verdict_path.read_text())
    case_id = verdict.get("case_id") or case_dir.name

    techs = collect_techniques(verdict)
    if not techs:
        raise SystemExit(
            "error: verdict references no MITRE techniques — nothing to ground."
        )
    claimed = sum(1 for e in techs.values() if e["claimed"])
    print(
        f"grounding {len(techs)} technique(s) "
        f"({claimed} asserted by findings, {len(techs) - claimed} coverage-only) "
        f"for case {case_id} via {WEBHOOK}"
    )

    response = call_workflow(case_id, techs)
    merged = merge_bundle(techs, response.get("technique_research") or [])

    iocs = extract_iocs(verdict)
    ioc_total = sum(len(v) for v in iocs.values())
    if ioc_total:
        print(f"enriching {ioc_total} IOC(s) host-side via VirusTotal…")
    ioc_block = run_ioc_enrichment(iocs)

    bundle = {
        "case_id": case_id,
        "verdict": verdict.get("verdict"),
        "generated_at": response.get("generated_at")
        or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": "n8n findevil-grounding research bundle "
        "(operator aid; not evidence, not in audit chain) — UNJUDGED",
        "note": "Claude Code judges this per agent-config/GROUNDING.md, then writes "
        "grounding.json. No technique is 'supported' without a quoted excerpt.",
        "techniques": merged,
    }
    if ioc_block is not None:
        bundle["ioc_enrichment"] = ioc_block
    out_path = case_dir / RESEARCH_FILENAME
    out_path.write_text(json.dumps(bundle, indent=2))

    for m in merged:
        tag = "claim" if m["claimed"] else "cover"
        if not m["found"]:
            mark, name = "MISS", "(not on MITRE)"
        elif not m["id_match"]:
            mark = "RENUM"
            name = f"{m['mitre_name']} -> now {m['mitre_id']}"
        else:
            mark, name = "ok   ", (m["mitre_name"] or "-")
        print(f"  [{tag}] {mark} {m['technique_id']:<12} {name}")
    if ioc_block is not None:
        if not ioc_block.get("available"):
            print(f"  [ioc] skipped — {ioc_block.get('note')}")
        else:
            for r in ioc_block.get("results", []):
                mk = "ok  " if r.get("found") else "MISS"
                prov = ",".join(r.get("providers") or []) or "-"
                print(
                    f"  [ioc] {mk} {r.get('type'):<6} mal_src={r.get('malicious_sources')} "
                    f"[{prov}] {r.get('ioc', '')[:40]}"
                )
    print(f"\nwrote {out_path}")
    print(
        "next: Claude Code judges this bundle per agent-config/GROUNDING.md "
        f"and writes {case_dir / 'grounding.json'}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
