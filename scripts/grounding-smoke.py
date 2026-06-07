#!/usr/bin/env python3
"""grounding-smoke.py — lock the post-verdict grounding contract.

Two layers:
  1. OFFLINE (always runs): ground_verdict's claim extraction + bundle merge +
     the never-evidence boundary (the helper writes only grounding_research.json,
     never audit.jsonl / run.manifest.json).
  2. LIVE (only when the findevil-grounding webhook is reachable): the
     anti-hallucination contract — a real technique grounds (found=true), a bogus
     id is rejected (found=false), a malformed id is rejected, and the response is
     structured-extract only (no raw HTML leak, bounded excerpt, tags stripped).

Exit 0 if all run checks pass (LIVE checks skip cleanly when n8n is down);
non-zero on any failure. Mirrors the other scripts/*-smoke.py gates.
"""

from __future__ import annotations

import importlib.util
import json
import os
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WEBHOOK = os.environ.get(
    "GROUNDING_WEBHOOK", "http://127.0.0.1:5678/webhook/findevil-grounding"
)
N8N_HEALTH = os.environ.get("N8N_BASE", "http://127.0.0.1:5678") + "/healthz"

ALLOWED_RESEARCH_KEYS = {
    "technique_id",
    "claim",
    "found",
    "id_match",
    "mitre_id",
    "mitre_name",
    "excerpt",
    "sources",
    "error",
}

failures: list[str] = []


def check(cond: bool, msg: str) -> None:
    if not cond:
        failures.append(msg)
        print(f"  FAIL: {msg}")
    else:
        print(f"  ok: {msg}")


def load_ground_verdict():
    spec = importlib.util.spec_from_file_location(
        "ground_verdict", ROOT / "scripts" / "ground_verdict.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def offline_checks(gv) -> None:
    print("[offline] claim extraction + merge + boundary")

    verdict = {
        "findings": [
            {
                "finding_id": "f1",
                "mitre_technique": "T1059.001",
                "confidence": "CONFIRMED",
                "description": "powershell exec",
            },
            {
                "finding_id": "f2",
                "mitre_technique": None,
                "confidence": "HYPOTHESIS",
                "description": "acquisition smear",
            },
        ],
        "attack_story": {
            "attack_chain": [
                {
                    "finding_id": "f3",
                    "mitre_technique": "t1003",
                    "confidence": "INFERRED",
                    "summary": "credential dumping",
                },
            ]
        },
        "attack_coverage": {
            "targets": [
                {
                    "technique_id": "T1547.001",
                    "technique_name": "Run Keys",
                    "status": "blind_spot",
                },
                {
                    "technique_id": "T1059.001",
                    "technique_name": "PowerShell",
                    "status": "covered_no_finding",
                },
            ],
            "observed_techniques": ["T1070.001"],
        },
    }
    techs = gv.collect_techniques(verdict)
    check(
        set(techs) == {"T1059.001", "T1003", "T1547.001", "T1070.001"},
        f"collect_techniques set == 4 expected (got {sorted(techs)})",
    )
    check(
        techs["T1059.001"]["claimed"] and "f1" in techs["T1059.001"]["claimed_by"],
        "finding-asserted technique is claimed",
    )
    check(
        techs["T1003"]["claimed"], "lowercase 't1003' from story normalized + claimed"
    )
    check(not techs["T1547.001"]["claimed"], "coverage-only technique is NOT claimed")
    check(not techs["T1070.001"]["claimed"], "observed-only technique is NOT claimed")

    research = [
        {
            "technique_id": "T1059.001",
            "found": True,
            "id_match": True,
            "mitre_id": "T1059.001",
            "mitre_name": "PowerShell",
            "excerpt": "x",
            "sources": [{"source": "mitre_attack", "url": "u", "retrieved_at": "t"}],
        },
        {
            "technique_id": "T1003",
            "found": True,
            "id_match": True,
            "mitre_id": "T1003",
            "mitre_name": "OS Credential Dumping",
            "excerpt": "y",
            "sources": [],
        },
        {
            "technique_id": "T1547.001",
            "found": False,
            "id_match": False,
            "mitre_id": None,
            "mitre_name": None,
            "excerpt": None,
            "sources": [],
        },
        {
            "technique_id": "T1070.001",
            "found": True,
            "id_match": False,
            "mitre_id": "T1685.005",
            "mitre_name": "Clear Windows Event Logs",
            "excerpt": "z",
            "sources": [],
        },
    ]
    merged = gv.merge_bundle(techs, research)
    check(
        [m["claimed"] for m in merged][:2] == [True, True],
        "claimed techniques are ordered first in merge",
    )
    by = {m["technique_id"]: m for m in merged}
    check(
        by["T1070.001"]["found"]
        and not by["T1070.001"]["id_match"]
        and by["T1070.001"]["mitre_id"] == "T1685.005",
        "renumbered technique carries served mitre_id + id_match False",
    )
    check(
        not by["T1547.001"]["found"],
        "unresolved technique stays found=False through merge",
    )

    # Boundary (behavioral): run the helper against a temp case with a stubbed
    # webhook and assert the audit/crypto chain is byte-identical afterward — the
    # helper writes ONLY the research sidecar, never evidence/audit/manifest.
    check(
        gv.RESEARCH_FILENAME == "grounding_research.json",
        "helper writes grounding_research.json (sidecar name)",
    )
    import hashlib
    import tempfile

    def sha(p: Path) -> str:
        return hashlib.sha256(p.read_bytes()).hexdigest()

    with tempfile.TemporaryDirectory() as td:
        case = Path(td)
        (case / "verdict.json").write_text(
            json.dumps(
                {
                    "case_id": "boundary-test",
                    "verdict": "INDETERMINATE",
                    "findings": [
                        {
                            "finding_id": "f1",
                            "mitre_technique": "T1014",
                            "confidence": "HYPOTHESIS",
                            "description": "rootkit lead",
                        }
                    ],
                }
            )
        )
        (case / "audit.jsonl").write_text('{"prev_hash":"abc","kind":"x"}\n')
        (case / "run.manifest.json").write_text('{"signed":true}\n')
        before = {f: sha(case / f) for f in ("audit.jsonl", "run.manifest.json")}

        orig = gv.call_workflow
        gv.call_workflow = lambda cid, techs: {
            "generated_at": "2026-01-01T00:00:00Z",
            "technique_research": [
                {
                    "technique_id": "T1014",
                    "found": True,
                    "id_match": True,
                    "mitre_id": "T1014",
                    "mitre_name": "Rootkit",
                    "excerpt": "e",
                    "sources": [
                        {"source": "mitre_attack", "url": "u", "retrieved_at": "t"}
                    ],
                }
            ],
        }
        try:
            rc = gv.main([str(case)])
        finally:
            gv.call_workflow = orig

        after = {f: sha(case / f) for f in ("audit.jsonl", "run.manifest.json")}
        check(rc == 0, "helper run returns 0 against temp case")
        check(
            before == after, "audit.jsonl + run.manifest.json byte-unchanged by helper"
        )
        check(
            (case / gv.RESEARCH_FILENAME).is_file(), "helper wrote the research sidecar"
        )
        check(
            not (case / "grounding.json").exists(),
            "helper does NOT write grounding.json (the agent judges that)",
        )


def offline_ioc_checks(gv) -> None:
    print("[offline] IOC extraction (typed only, no crypto-chain pollution)")
    verdict = {
        "malware_triage": {
            "aggregate_iocs": {
                "hashes": ["a" * 64],
                "domains": ["evil.test"],
                "ips": ["1.2.3.4"],
                "urls": ["http://x.test/p"],
                "emails": ["a@b.test"],
                "paths": ["/tmp/x"],
                "registry_keys": ["HKLM\\Run"],
                "mutex_like": [],
                "user_agents": [],
            }
        },
        # a crypto-chain hash elsewhere in the verdict that MUST NOT be extracted
        "tool_calls": [{"tool_call_id": "tc-1", "output_sha256": "b" * 64}],
    }
    iocs = gv.extract_iocs(verdict)
    check(
        set(iocs) == set(gv.ENRICHABLE_IOC_TYPES),
        "extract_iocs returns only enrichable typed buckets",
    )
    check(iocs["hashes"] == ["a" * 64], "extract_iocs reads aggregate_iocs hashes")
    check(
        "b" * 64 not in iocs["hashes"],
        "extract_iocs ignores crypto-chain hashes (no blind regex)",
    )
    check(
        gv.run_ioc_enrichment({k: [] for k in gv.ENRICHABLE_IOC_TYPES}) is None,
        "no IOCs -> enrichment skipped (None)",
    )

    spec = importlib.util.spec_from_file_location(
        "ioc_enrich", ROOT / "scripts" / "ioc_enrich.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    check(hasattr(mod, "enrich"), "ioc_enrich.enrich present")
    check(
        hasattr(mod, "vt_key") and hasattr(mod, "abusech_key"),
        "ioc_enrich exposes vt_key + abusech_key",
    )
    check(
        mod._classify("http://x") == "urls"
        and mod._classify("a" * 64) == "hashes"
        and mod._classify("1.2.3.4") == "ips"
        and mod._classify("evil.test") == "domains",
        "ioc_enrich classifies hash/domain/ip/url",
    )
    # No provider key configured (CI/offline) -> enrich reports unavailable, never crashes.
    if not mod.vt_key() and not mod.abusech_key():
        out = mod.enrich({"hashes": ["a" * 64], "domains": [], "ips": [], "urls": []})
        check(
            out.get("available") is False,
            "ioc_enrich degrades cleanly with no provider key (available=false)",
        )


def webhook_up() -> bool:
    try:
        with urllib.request.urlopen(N8N_HEALTH, timeout=4) as r:
            return r.status == 200
    except (urllib.error.URLError, OSError):
        return False


def live_checks() -> None:
    print(f"[live] anti-hallucination contract via {WEBHOOK}")
    payload = {
        "case_id": "smoke",
        "techniques": [
            {"id": "T1014", "claim": "rootkit"},
            {"id": "T9999", "claim": "bogus invented technique"},
            {"id": "not-a-technique", "claim": "garbage"},
        ],
    }
    req = urllib.request.Request(
        WEBHOOK, data=json.dumps(payload).encode(), method="POST"
    )
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            data = json.loads(r.read().decode())
    except (urllib.error.URLError, OSError) as e:
        failures.append(f"webhook call failed: {e}")
        print(f"  FAIL: webhook call failed: {e}")
        return

    by = {t["technique_id"].upper(): t for t in data.get("technique_research", [])}
    check(
        "T1014" in by
        and by["T1014"]["found"]
        and by["T1014"].get("mitre_name") == "Rootkit"
        and by["T1014"].get("id_match") is True,
        "real technique T1014 grounds to found=true name=Rootkit id_match=true",
    )
    check(
        "T9999" in by and by["T9999"]["found"] is False,
        "bogus technique T9999 rejected (found=false)",
    )
    check(
        "NOT-A-TECHNIQUE" in by and by["NOT-A-TECHNIQUE"]["found"] is False,
        "malformed technique id rejected (found=false)",
    )

    for tid, t in by.items():
        extra = set(t) - ALLOWED_RESEARCH_KEYS
        check(not extra, f"{tid}: structured-extract only, no leaked fields ({extra})")
        exc = t.get("excerpt")
        check(
            exc is None or (isinstance(exc, str) and len(exc) <= 600),
            f"{tid}: excerpt is None or bounded (<=600 chars)",
        )
        check(
            exc is None or "<" not in exc,
            f"{tid}: excerpt has HTML tags stripped (untrusted markup is inert)",
        )


def main() -> int:
    gv = load_ground_verdict()
    offline_checks(gv)
    offline_ioc_checks(gv)
    if webhook_up():
        live_checks()
    else:
        print(
            f"[live] SKIP: n8n not reachable at {N8N_HEALTH} "
            "(start it + run scripts/setup-grounding-workflow.py to exercise live)"
        )
    print()
    if failures:
        print(f"GROUNDING SMOKE FAILED: {len(failures)} check(s)")
        return 1
    print("grounding smoke passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
