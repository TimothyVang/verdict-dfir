#!/usr/bin/env python3
"""ioc_enrich.py — host-side IOC reputation enrichment for grounding (Phase 2).

Enriches a verdict's typed IOCs (`malware_triage.aggregate_iocs`) against
VirusTotal v3 (and, when its key is present, abuse.ch). Returns per-IOC
reputation with provenance so Claude Code can ground "malicious IOC" claims.

WHY HOST-SIDE (not in n8n): n8n persists execution inputs in its database, so
routing an API key through the webhook would leak the secret into n8n's
execution store. VirusTotal / abuse.ch are plain JSON APIs (no browser needed),
so the host calls them directly and the key never leaves the gitignored file.
n8n stays the browser-rendered-research engine (MITRE, open-web) where the value
is rendering untrusted HTML and no secret is involved.

BOUNDARY (agent-config/GROUNDING.md): enrichment is a post-verdict operator aid —
never evidence, never a tool_call_id, never in the audit/crypto chain.

Keys (gitignored): tmp/api-keys/virustotal.txt (or env VT_API_KEY).
CLI: python3 scripts/ioc_enrich.py <hash|domain|ip|url> [...]
"""

from __future__ import annotations

import base64
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
VT_KEY_FILE = ROOT / "tmp" / "api-keys" / "virustotal.txt"
VT_BASE = "https://www.virustotal.com/api/v3"
VT_GUI = "https://www.virustotal.com/gui"

# VirusTotal public tier is ~4 lookups/min. Space calls and cap total volume so a
# verdict with many IOCs can't stall or burn the daily quota; the cap is logged.
VT_RATE_DELAY_S = float(os.environ.get("VT_RATE_DELAY", "15"))
MAX_PER_TYPE = int(os.environ.get("IOC_MAX_PER_TYPE", "8"))

# IOC buckets we can enrich via reputation APIs (from aggregate_iocs).
ENRICHABLE_TYPES = ("hashes", "domains", "ips", "urls")


def vt_key() -> str | None:
    env = os.environ.get("VT_API_KEY")
    if env:
        return env.strip()
    if VT_KEY_FILE.is_file():
        return VT_KEY_FILE.read_text().strip() or None
    return None


def _vt_get(path: str, key: str) -> tuple[int, dict[str, Any]]:
    req = urllib.request.Request(f"{VT_BASE}/{path}")
    req.add_header("x-apikey", key)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode())
        except Exception:
            return e.code, {"error": {"code": str(e.code)}}
    except (urllib.error.URLError, OSError) as e:
        return 0, {"error": {"message": str(e)}}


def _vt_path(ioc: str, kind: str) -> str:
    if kind == "hashes":
        return f"files/{ioc}"
    if kind == "domains":
        return f"domains/{ioc}"
    if kind == "ips":
        return f"ip_addresses/{ioc}"
    if kind == "urls":
        url_id = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
        return f"urls/{url_id}"
    raise ValueError(f"unenrichable ioc type: {kind}")


def _gui_link(ioc: str, kind: str) -> str:
    seg = {"hashes": "file", "domains": "domain", "ips": "ip-address", "urls": "url"}[
        kind
    ]
    if kind == "urls":
        url_id = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
        return f"{VT_GUI}/url/{url_id}"
    return f"{VT_GUI}/{seg}/{ioc}"


def _enrich_one(ioc: str, kind: str, key: str) -> dict[str, Any]:
    status, body = _vt_get(_vt_path(ioc, kind), key)
    type_label = {"hashes": "hash", "domains": "domain", "ips": "ip", "urls": "url"}[
        kind
    ]
    entry: dict[str, Any] = {
        "ioc": ioc,
        "type": type_label,
        "source": "virustotal",
        "url": _gui_link(ioc, kind),
        "found": False,
        "malicious": None,
        "suspicious": None,
        "total_engines": None,
        "reputation": None,
        "names": [],
        "first_seen": None,
    }
    if status == 429:
        entry["error"] = "rate_limited"
        return entry
    if status != 200 or "data" not in body:
        err = (body.get("error") or {}).get("code") or (body.get("error") or {}).get(
            "message"
        )
        entry["error"] = err or f"not_found ({status})"
        return entry
    a = body["data"].get("attributes", {})
    stats = a.get("last_analysis_stats", {})
    entry["found"] = True
    entry["malicious"] = stats.get("malicious")
    entry["suspicious"] = stats.get("suspicious")
    entry["total_engines"] = sum(v for v in stats.values() if isinstance(v, int))
    entry["reputation"] = a.get("reputation")
    name = a.get("meaningful_name")
    names = a.get("names") or ([name] if name else [])
    entry["names"] = names[:3]
    fs = a.get("first_submission_date") or a.get("creation_date")
    if isinstance(fs, int):
        entry["first_seen"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(fs))
    return entry


def enrich(iocs: dict[str, list[str]], log: Any = None) -> dict[str, Any]:
    """Enrich typed IOC buckets via VirusTotal. Returns {results, skipped, note}."""
    key = vt_key()
    if not key:
        return {
            "results": [],
            "available": False,
            "note": "no VirusTotal key (tmp/api-keys/virustotal.txt) — run "
            "scripts/get-api-key.cjs virustotal",
        }
    results: list[dict[str, Any]] = []
    skipped: dict[str, int] = {}
    first = True
    for kind in ENRICHABLE_TYPES:
        values = [v for v in (iocs.get(kind) or []) if v]
        if len(values) > MAX_PER_TYPE:
            skipped[kind] = len(values) - MAX_PER_TYPE
            values = values[:MAX_PER_TYPE]
        for ioc in values:
            if not first:
                time.sleep(VT_RATE_DELAY_S)  # respect VT public rate limit
            first = False
            entry = _enrich_one(ioc, kind, key)
            if log:
                log(entry)
            results.append(entry)
            if entry.get("error") == "rate_limited":
                # back off: stop hammering, report what we have
                return {
                    "results": results,
                    "available": True,
                    "skipped": skipped,
                    "note": "VirusTotal rate limit hit; partial enrichment",
                }
    note = None
    if skipped:
        note = "capped per type (VT rate/quota): " + ", ".join(
            f"{k}:-{n}" for k, n in skipped.items()
        )
    return {"results": results, "available": True, "skipped": skipped, "note": note}


def _classify(ioc: str) -> str:
    s = ioc.strip()
    if s.startswith("http://") or s.startswith("https://"):
        return "urls"
    if all(c in "0123456789abcdefABCDEF" for c in s) and len(s) in (32, 40, 64):
        return "hashes"
    parts = s.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return "ips"
    return "domains"


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 2
    buckets: dict[str, list[str]] = {k: [] for k in ENRICHABLE_TYPES}
    for ioc in argv:
        buckets[_classify(ioc)].append(ioc)
    out = enrich(
        buckets,
        log=lambda e: print(
            f"  {e['type']:<6} {('ok ' if e['found'] else 'MISS')} "
            f"mal={e['malicious']}/{e['total_engines']} rep={e['reputation']} "
            f"{(e['names'][0] if e['names'] else e.get('error') or '')} {e['ioc'][:48]}"
        ),
    )
    if not out["available"]:
        print(out["note"])
        return 1
    if out.get("note"):
        print(out["note"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
