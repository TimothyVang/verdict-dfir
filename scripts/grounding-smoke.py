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
        gv.call_workflow = lambda cid, techs, queries=None: {
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
        # Headless: the helper writes a first-pass grounding.json (sidecar), but
        # NEVER touches evidence/audit/manifest (asserted byte-unchanged above).
        gpath = case / "grounding.json"
        check(gpath.is_file(), "helper writes a first-pass grounding.json (headless)")
        fp = json.loads(gpath.read_text())
        check(
            "first-pass" in (fp.get("judged_by") or ""),
            "headless grounding.json is labeled a deterministic first-pass",
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


def offline_openweb_checks(gv) -> None:
    print("[offline] open-web query building")
    techs = gv.collect_techniques(
        {
            "findings": [
                {
                    "finding_id": "f1",
                    "mitre_technique": "T1055",
                    "confidence": "INFERRED",
                    "description": "process injection lead",
                }
            ],
            "attack_coverage": {"targets": [{"technique_id": "T1055"}]},
        }
    )
    ioc_block = {
        "results": [
            {
                "ioc": "abc",
                "sources": [
                    {"provider": "threatfox", "malicious": True, "label": "MintsLoader"}
                ],
            }
        ]
    }
    q = gv.build_queries(techs, ioc_block)
    terms = [x["query"] for x in q]
    check(
        any("MintsLoader" in t for t in terms),
        "build_queries seeds a malware-family query",
    )
    check(
        any("T1055" in t for t in terms), "build_queries adds a claimed-technique query"
    )
    check(len(q) <= 4, "build_queries caps at 4")
    check(
        isinstance(gv.build_queries(techs, None), list),
        "build_queries works without IOCs",
    )


def offline_cve_checks(gv) -> None:
    print("[offline] CVE extraction (engine-tagged + text fallback)")
    verdict = {
        "findings": [
            {"finding_id": "f1", "cves": ["CVE-2021-34527"]},
            {
                "finding_id": "f2",
                "description": "exploited cve-2017-0144 (EternalBlue)",
            },
            {"finding_id": "f3", "description": "no cve here"},
        ]
    }
    m = gv.extract_cves(verdict)
    check("CVE-2021-34527" in m, "extract_cves reads engine-tagged finding.cves")
    check("CVE-2017-0144" in m, "extract_cves falls back to a literal text scan")
    check(m.get("CVE-2021-34527") == ["f1"], "extract_cves maps cve -> finding ids")
    check(gv.ground_cves({}) is None, "ground_cves returns None when there are no CVEs")


def offline_firstpass_checks(gv) -> None:
    print("[offline] headless first-pass grounding")
    bundle = {
        "case_id": "x",
        "verdict": "SUSPICIOUS",
        "techniques": [
            {
                "technique_id": "T1055",
                "claimed": True,
                "found": True,
                "id_match": True,
                "mitre_name": "Process Injection",
                "excerpt": "e",
                "sources": [{"url": "u"}],
            },
            {
                "technique_id": "T9999",
                "claimed": True,
                "found": False,
                "id_match": False,
            },
        ],
        "ioc_enrichment": {
            "results": [
                {
                    "ioc": "h",
                    "type": "hash",
                    "found": True,
                    "malicious_sources": 1,
                    "sources": [
                        {
                            "provider": "virustotal",
                            "found": True,
                            "url": "u",
                            "detail": "d",
                        }
                    ],
                }
            ]
        },
        "cve_research": {
            "results": [
                {
                    "cve_id": "CVE-2021-34527",
                    "found": True,
                    "cvss": 8.8,
                    "severity": "HIGH",
                    "url": "u",
                    "description": "d",
                },
                {
                    "cve_id": "CVE-9999-0000",
                    "found": False,
                    "url": "u",
                    "error": "not_found",
                },
            ]
        },
    }
    fp = gv.first_pass_grounding(bundle)
    g = {x["technique_id"]: x for x in fp["grounding"]}
    check(
        g["T1055"]["status"] == "supported", "first-pass: found technique -> supported"
    )
    check(
        g["T9999"]["status"] == "contradicted" and g["T9999"]["possible_hallucination"],
        "first-pass: not-found technique -> contradicted + possible_hallucination",
    )
    check(
        fp["ioc_grounding"][0]["status"] == "malicious",
        "first-pass: flagged IOC -> malicious",
    )
    cg = {c["cve_id"]: c for c in fp["cve_grounding"]}
    check(
        cg["CVE-2021-34527"]["status"] == "supported",
        "first-pass: found CVE -> supported",
    )
    check(
        cg["CVE-9999-0000"]["possible_hallucination"],
        "first-pass: unknown CVE -> possible_hallucination",
    )
    check(
        "first-pass" in fp["judged_by"],
        "first-pass labels judged_by as deterministic first-pass",
    )


def offline_actions_checks() -> None:
    print("[offline] grounding-aware action routing")
    spec = importlib.util.spec_from_file_location(
        "ground_actions", ROOT / "scripts" / "ground_actions.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    grounding = {
        "verdict": "SUSPICIOUS",
        "grounding": [
            {
                "technique_id": "T1055",
                "status": "supported",
                "possible_hallucination": False,
            },
            {
                "technique_id": "T9999",
                "status": "contradicted",
                "possible_hallucination": True,
            },
        ],
        "ioc_grounding": [
            {"ioc": "abc123", "status": "malicious"},
            {"ioc": "good.test", "status": "clean", "possible_overclaim": True},
        ],
    }
    actions = mod.derive_actions(grounding)
    check(
        all(a["auto"] is False for a in actions),
        "all actions are human-in-the-loop (auto=false)",
    )
    by_basis = {a["based_on"]: a for a in actions}
    check(
        by_basis.get("T1055", {}).get("route") == "act",
        "supported technique on SUSPICIOUS -> act",
    )
    check(
        by_basis.get("T9999", {}).get("route") == "review",
        "possible-hallucination technique -> review",
    )
    check(by_basis.get("abc123", {}).get("route") == "act", "malicious IOC -> act")
    check(
        by_basis.get("good.test", {}).get("route") == "review",
        "possible-overclaim IOC -> review",
    )


def offline_boundary_checks() -> None:
    print("[offline] submission boundary (judge-clean + keys/n8n excluded)")

    def read(rel: str) -> str:
        p = ROOT / rel
        return p.read_text() if p.is_file() else ""

    for doc in ("docs/architecture.md",):
        text = read(doc).lower()
        check(
            "n8n" not in text and "grounding" not in text,
            f"{doc} stays judge-clean (no n8n/grounding mention)",
        )
    gi = read(".gitignore")
    check(
        "/tmp/" in gi, ".gitignore excludes /tmp/ (keys, searxng, grounding artifacts)"
    )
    check("/n8n-references/" in gi, ".gitignore excludes /n8n-references/")
    pkg = read("scripts/package-devpost.sh").lower()
    if pkg:
        check(
            not any(t in pkg for t in ("api-keys", "grounding", "searxng")),
            "package-devpost.sh never bundles keys / grounding / searxng",
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
    offline_openweb_checks(gv)
    offline_cve_checks(gv)
    offline_firstpass_checks(gv)
    offline_actions_checks()
    offline_boundary_checks()
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
