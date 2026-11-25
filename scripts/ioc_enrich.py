#!/usr/bin/env python3
"""ioc_enrich.py — host-side IOC reputation enrichment for grounding (Phase 2/3).

Enriches a verdict's typed IOCs (`malware_triage.aggregate_iocs`) against multiple
authoritative sources — VirusTotal v3 and abuse.ch (ThreatFox / MalwareBazaar /
URLhaus) — and returns, per IOC, a normalized list of provider `sources` so Claude
Code can ground "malicious IOC" claims with multi-source corroboration.

WHY HOST-SIDE (not in n8n): n8n persists execution inputs in its database, so
routing an API key through the webhook would leak the secret into n8n's execution
store. These are plain JSON APIs (no browser needed), so the host calls them
directly and keys never leave the gitignored files. n8n stays the
browser-rendered-research engine (MITRE, open-web) where no secret is involved.

BOUNDARY (agent-config/GROUNDING.md): enrichment is a post-verdict operator aid —
never evidence, never a tool_call_id, never in the audit/crypto chain.

Keys (gitignored): tmp/api-keys/virustotal.txt (or VT_API_KEY),
                   tmp/api-keys/abusech.txt   (or ABUSECH_API_KEY).
CLI: python3 scripts/ioc_enrich.py <hash|domain|ip|url> [...]
"""

from __future__ import annotations

import base64
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
KEY_DIR = ROOT / "tmp" / "api-keys"
VT_KEY_FILE = KEY_DIR / "virustotal.txt"
ABUSECH_KEY_FILE = KEY_DIR / "abusech.txt"

VT_BASE = "https://www.virustotal.com/api/v3"
VT_GUI = "https://www.virustotal.com/gui"
THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"
MALWAREBAZAAR_API = "https://mb-api.abuse.ch/api/v1/"
URLHAUS_API = "https://urlhaus-api.abuse.ch/v1"

# VirusTotal public tier is ~4 lookups/min. Space VT calls and cap total volume so
# a verdict with many IOCs can't stall or burn the daily quota; the cap is logged.
# abuse.ch has no such tight limit, so its calls are not delayed.
VT_RATE_DELAY_S = float(os.environ.get("VT_RATE_DELAY", "15"))
MAX_PER_TYPE = int(os.environ.get("IOC_MAX_PER_TYPE", "8"))

# IOC buckets we can enrich via reputation APIs (from aggregate_iocs).
ENRICHABLE_TYPES = ("hashes", "domains", "ips", "urls")
TYPE_LABEL = {"hashes": "hash", "domains": "domain", "ips": "ip", "urls": "url"}


def vt_key() -> str | None:
    env = os.environ.get("VT_API_KEY")
    if env:
        return env.strip()
    if VT_KEY_FILE.is_file():
        return VT_KEY_FILE.read_text().strip() or None
    return None


def abusech_key() -> str | None:
    env = os.environ.get("ABUSECH_API_KEY")
    if env:
        return env.strip()
    if ABUSECH_KEY_FILE.is_file():
        return ABUSECH_KEY_FILE.read_text().strip() or None
    return None


# --- HTTP helpers -------------------------------------------------------------
def _http(url: str, headers: dict[str, str], data: bytes | None) -> tuple[int, Any]:
    req = urllib.request.Request(url, data=data, method="POST" if data else "GET")
    for k, v in headers.items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            raw = r.read().decode()
            try:
                return r.status, json.loads(raw)
            except json.JSONDecodeError:
                return r.status, {"_raw": raw}
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode())
        except Exception:
            return e.code, {"error": {"code": str(e.code)}}
    except (urllib.error.URLError, OSError) as e:
        return 0, {"error": {"message": str(e)}}


# --- VirusTotal ---------------------------------------------------------------
def _vt_path(ioc: str, kind: str) -> str:
    if kind == "hashes":
        return f"files/{ioc}"
    if kind == "domains":
        return f"domains/{ioc}"
    if kind == "ips":
        return f"ip_addresses/{ioc}"
    url_id = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
    return f"urls/{url_id}"


def _vt_gui(ioc: str, kind: str) -> str:
    if kind == "urls":
        url_id = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
        return f"{VT_GUI}/url/{url_id}"
    seg = {"hashes": "file", "domains": "domain", "ips": "ip-address"}[kind]
    return f"{VT_GUI}/{seg}/{ioc}"


def _vt_source(ioc: str, kind: str, key: str) -> dict[str, Any]:
    status, body = _http(f"{VT_BASE}/{_vt_path(ioc, kind)}", {"x-apikey": key}, None)
    src: dict[str, Any] = {
        "provider": "virustotal",
        "url": _vt_gui(ioc, kind),
        "found": False,
    }
    if status == 429:
        src["error"] = "rate_limited"
        return src
    if status != 200 or "data" not in body:
        err = (body.get("error") or {}).get("code") or (body.get("error") or {}).get(
            "message"
        )
        src["error"] = err or f"not_found ({status})"
        return src
    a = body["data"].get("attributes", {})
    stats = a.get("last_analysis_stats", {})
    mal = stats.get("malicious") or 0
    total = sum(v for v in stats.values() if isinstance(v, int))
    names = a.get("names") or (
        [a.get("meaningful_name")] if a.get("meaningful_name") else []
    )
    fs = a.get("first_submission_date") or a.get("creation_date")
    src.update(
        {
            "found": True,
            "malicious": mal >= 5,  # avoid over-reading a single-vendor FP
            "label": names[0] if names else None,
            "detail": f"{mal}/{total} engines flagged malicious; reputation {a.get('reputation')}",
            "detections": f"{mal}/{total}",
            "first_seen": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(fs))
            if isinstance(fs, int)
            else None,
        }
    )
    return src


# --- abuse.ch (ThreatFox / MalwareBazaar / URLhaus) ---------------------------
def _threatfox(ioc: str, key: str) -> dict[str, Any]:
    body = json.dumps({"query": "search_ioc", "search_term": ioc}).encode()
    status, resp = _http(
        THREATFOX_API, {"Auth-Key": key, "Content-Type": "application/json"}, body
    )
    src: dict[str, Any] = {
        "provider": "threatfox",
        "url": f"https://threatfox.abuse.ch/browse.php?search=ioc%3A{urllib.parse.quote(ioc)}",
        "found": False,
    }
    if resp.get("query_status") == "ok" and resp.get("data"):
        d = resp["data"][0]
        src.update(
            {
                "found": True,
                "malicious": True,
                "label": d.get("malware_printable") or d.get("malware"),
                "detail": f"ThreatFox: {d.get('malware_printable') or d.get('malware')} "
                f"({d.get('threat_type')}); confidence {d.get('confidence_level')}%",
                "first_seen": d.get("first_seen"),
            }
        )
    else:
        src["error"] = resp.get("query_status") or f"status_{status}"
    return src


def _malwarebazaar(sha: str, key: str) -> dict[str, Any]:
    data = urllib.parse.urlencode({"query": "get_info", "hash": sha}).encode()
    status, resp = _http(
        MALWAREBAZAAR_API,
        {"Auth-Key": key, "Content-Type": "application/x-www-form-urlencoded"},
        data,
    )
    src: dict[str, Any] = {
        "provider": "malwarebazaar",
        "url": f"https://bazaar.abuse.ch/sample/{sha}/",
        "found": False,
    }
    if resp.get("query_status") == "ok" and resp.get("data"):
        d = resp["data"][0]
        tags = ", ".join(d.get("tags") or [])
        src.update(
            {
                "found": True,
                "malicious": True,
                "label": d.get("signature") or d.get("file_type"),
                "detail": f"MalwareBazaar: {d.get('signature') or 'known sample'}"
                + (f" [{tags}]" if tags else ""),
                "first_seen": d.get("first_seen"),
            }
        )
    else:
        src["error"] = resp.get("query_status") or f"status_{status}"
    return src


def _urlhaus(ioc: str, kind: str, key: str) -> dict[str, Any]:
    endpoint, field = ("url", "url") if kind == "urls" else ("host", "host")
    data = urllib.parse.urlencode({field: ioc}).encode()
    status, resp = _http(
        f"{URLHAUS_API}/{endpoint}/",
        {"Auth-Key": key, "Content-Type": "application/x-www-form-urlencoded"},
        data,
    )
    src: dict[str, Any] = {
        "provider": "urlhaus",
        "url": "https://urlhaus.abuse.ch/",
        "found": False,
    }
    if resp.get("query_status") == "ok":
        tags = ", ".join(resp.get("tags") or [])
        src.update(
            {
                "found": True,
                "malicious": True,
                "label": resp.get("threat"),
                "detail": f"URLhaus: {resp.get('threat')} status={resp.get('url_status')}"
                + (f" [{tags}]" if tags else ""),
                "url": resp.get("urlhaus_reference") or src["url"],
                "first_seen": resp.get("date_added") or resp.get("firstseen"),
            }
        )
    else:
        src["error"] = resp.get("query_status") or f"status_{status}"
    return src


def _abusech_sources(ioc: str, kind: str, key: str) -> list[dict[str, Any]]:
    out = [_threatfox(ioc, key)]  # ThreatFox covers every IOC type
    if kind == "hashes":
        out.append(_malwarebazaar(ioc, key))
    elif kind in ("urls", "domains", "ips"):
        out.append(_urlhaus(ioc, kind, key))
    return out


# --- orchestration ------------------------------------------------------------
def enrich(iocs: dict[str, list[str]], log: Any = None) -> dict[str, Any]:
    """Enrich typed IOC buckets across all configured providers.

    Each result is {ioc, type, found, malicious_sources, providers, sources[]}.
    Returns {results, available, skipped, note}; available is False only when no
    provider key is configured at all.
    """
    vk = vt_key()
    ak = abusech_key()
    if not vk and not ak:
        return {
            "results": [],
            "available": False,
            "note": "no IOC-enrichment key (tmp/api-keys/{virustotal,abusech}.txt) — "
            "run scripts/get-api-key.cjs virustotal | abusech",
        }
    results: list[dict[str, Any]] = []
    skipped: dict[str, int] = {}
    vt_calls = 0
    for kind in ENRICHABLE_TYPES:
        values = [v for v in (iocs.get(kind) or []) if v]
        if len(values) > MAX_PER_TYPE:
            skipped[kind] = len(values) - MAX_PER_TYPE
            values = values[:MAX_PER_TYPE]
        for ioc in values:
            sources: list[dict[str, Any]] = []
            if vk:
                if vt_calls > 0:
                    time.sleep(VT_RATE_DELAY_S)  # respect VT public rate limit
                vt_calls += 1
                sources.append(_vt_source(ioc, kind, vk))
            if ak:
                sources.extend(_abusech_sources(ioc, kind, ak))
            entry = {
                "ioc": ioc,
                "type": TYPE_LABEL[kind],
                "found": any(s.get("found") for s in sources),
                "malicious_sources": sum(1 for s in sources if s.get("malicious")),
                "providers": [s["provider"] for s in sources if s.get("found")],
                "sources": sources,
            }
            if log:
                log(entry)
            results.append(entry)
            if any(s.get("error") == "rate_limited" for s in sources):
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

    def _log(e: dict[str, Any]) -> None:
        mk = "ok  " if e["found"] else "MISS"
        prov = ",".join(e["providers"]) or "-"
        print(
            f"  {mk} {e['type']:<6} mal_src={e['malicious_sources']} [{prov}] {e['ioc'][:44]}"
        )
        for s in e["sources"]:
            if s.get("found"):
                print(f"        {s['provider']}: {s.get('detail')}")

    out = enrich(buckets, log=_log)
    if not out["available"]:
        print(out["note"])
        return 1
    if out.get("note"):
        print(out["note"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
