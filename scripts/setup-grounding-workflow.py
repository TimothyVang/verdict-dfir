#!/usr/bin/env python3
"""setup-grounding-workflow.py — deploy the `findevil-grounding` n8n workflow.

The ultimate post-verdict DFIR GROUNDING workflow (Phase 1, keyless): given a
case's claimed MITRE techniques, it researches each one against MITRE ATT&CK via
the self-hosted browserless renderer and returns a structured research_bundle
with provenance ({source, url, retrieved_at, excerpt}) in the webhook response.
Claude Code then reads that bundle and JUDGES each claim (supported/unsupported/
contradicted) — n8n itself contains NO LLM.

BOUNDARY: runs AFTER the verdict; output is never evidence, never a tool_call_id,
never in the audit/crypto chain (docs/runbooks/n8n-automation-integration.md).

Phase 2 (keyed) adds abuse.ch/VirusTotal IOC enrichment + open-web search; keys
via scripts/get-api-key.py (browser login).

Design notes:
- n8n 2.x disallows require('fs') in Code nodes, so n8n RETURNS the bundle in the
  webhook response; the host (scripts/ground_verdict.py) persists it.
- A single async Code node loops the techniques and calls browserless via
  this.helpers.httpRequest — avoids per-item pairing fragility of a fan-out HTTP node.

Prereqs: n8n running, API key in tmp/n8n-apikey.txt, and n8n + browserless on a
shared docker network (so http://browserless:3000 resolves). Run:
    python3 scripts/setup-grounding-workflow.py
"""

from __future__ import annotations

import json
import shutil
import subprocess
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BASE = "http://localhost:5678"
API = f"{BASE}/api/v1"
KEY = (ROOT / "tmp/n8n-apikey.txt").read_text().strip()
WF_NAME = "findevil-grounding"
WEBHOOK_PATH = "findevil-grounding"
BROWSERLESS = "http://browserless:3000"  # container-name DNS on the shared net
NET = "findevil-net"  # user-defined network so n8n resolves `browserless` by name
BROWSERLESS_IMAGE = "ghcr.io/browserless/chromium:latest"
BROWSERLESS_NAME = "browserless"
SEARXNG = "http://searxng:8080"  # container-name DNS on the shared net (open-web)
SEARXNG_IMAGE = "searxng/searxng"
SEARXNG_NAME = "searxng"
SEARXNG_SETTINGS = ROOT / "tmp" / "searxng" / "settings.yml"

# Single async Code node: loop techniques → render the MITRE page via browserless
# → extract name + short description (UNTRUSTED HTML: extract only, never execute)
# → structured fact with provenance. Returns the research_bundle for the response.
RESEARCH_JS = r"""
const body = $input.first().json.body || $input.first().json;
const caseId = body.case_id || body.caseId || 'unknown';
const techniques = Array.isArray(body.techniques) ? body.techniques : [];
const research = [];
for (const t of techniques) {
  const id = String((t && t.id) ? t.id : t).trim().toUpperCase();
  const claim = (t && t.claim) || null;
  if (!/^T\d{4}(\.\d{3})?$/.test(id)) {
    research.push({ technique_id: id, claim, found: false, mitre_name: null,
      excerpt: 'malformed technique id (not T#### / T####.###)', sources: [] });
    continue;
  }
  const parts = id.split('.');
  const url = parts.length === 2
    ? `https://attack.mitre.org/techniques/${parts[0]}/${parts[1]}/`
    : `https://attack.mitre.org/techniques/${id}/`;
  let html = '';
  let dbg = '';
  try {
    const r = await this.helpers.httpRequest({
      method: 'POST',
      url: 'http://browserless:3000/content',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, gotoOptions: { waitUntil: 'networkidle2' } }),
      returnFullResponse: true,
      timeout: 45000,
    });
    html = String((r && r.body != null) ? r.body : (typeof r === 'string' ? r : ''));
    dbg = 'status=' + (r && (r.statusCode || r.status)) + ' len=' + html.length;
  } catch (e) {
    dbg = 'ERR:' + (e && (e.message || e.toString())).slice(0, 160);
    html = '';
  }
  // MITRE's <title> carries the canonical name AND the technique id, e.g.
  // "Rootkit, Technique T1014 - Enterprise | MITRE ATT&CK®" or for a bogus id
  // just "404 | MITRE ATT&CK®". Anti-hallucination check: the title must name
  // THIS id, else the page MITRE served is not about the claimed technique.
  const decode = (s) => String(s || '')
    .replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"').replace(/&#0?39;/g, "'").replace(/&#x27;/gi, "'")
    .replace(/&nbsp;/g, ' ');
  const titleMatch = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  const title = decode(titleMatch ? titleMatch[1].replace(/\s+/g, ' ').trim() : '');
  const notFound = /page not found/i.test(html) || /^404\b/.test(title);
  // The id MITRE actually served (a deprecated id redirects to its current one).
  const servedMatch = title.match(/\b(T\d{4}(?:\.\d{3})?)\b/i);
  const servedId = servedMatch ? servedMatch[1].toUpperCase() : null;
  const found = !notFound && !!servedId;          // a real MITRE technique page rendered
  const idMatch = found && servedId === id;        // ...and it is THIS exact id (not renumbered)
  let name = null;
  if (found) {
    name = (title.split(/,\s*(?:sub-?technique|technique)\b/i)[0] || '').trim() || null;
  }
  let desc = null;
  const md = html.match(/<meta\s+name=["']description["']\s+content=["']([^"']+)["']/i);
  if (md) desc = decode(md[1]);
  if (!desc) { const p = html.match(/<p[^>]*>([\s\S]{40,600}?)<\/p>/i); if (p) desc = decode(p[1]); }
  if (desc) desc = desc.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 600);
  const entry = {
    technique_id: id, claim, found, id_match: idMatch, mitre_id: servedId,
    mitre_name: name, excerpt: desc,
    sources: [{ source: 'mitre_attack', url, retrieved_at: new Date().toISOString() }],
  };
  if (dbg && dbg.indexOf('ERR') === 0) entry.error = dbg;  // surface fetch failures, not clean hits
  research.push(entry);
}

// Open-web research (keyless): query the self-hosted SearXNG, render the top
// hits via browserless, structured-extract a short excerpt. UNTRUSTED web text:
// strip <script>/<style> + all tags, cap length; the judge treats it as inert
// DATA (lowest-trust corroboration), never authoritative.
const queries = Array.isArray(body.queries) ? body.queries.slice(0, 5) : [];
const openWeb = [];
for (const q of queries) {
  const term = String((q && q.query) ? q.query : q).trim();
  if (!term) continue;
  let hits = [];
  try {
    const sr = await this.helpers.httpRequest({
      method: 'GET',
      url: 'http://searxng:8080/search?format=json&categories=general&q=' + encodeURIComponent(term),
      returnFullResponse: true,
      timeout: 30000,
    });
    const raw = (sr && sr.body != null) ? sr.body : {};
    const data = (typeof raw === 'object') ? raw : JSON.parse(String(raw || '{}'));
    hits = Array.isArray(data.results) ? data.results.slice(0, 4) : [];
  } catch (e) {
    openWeb.push({ query: term, results: [], error: 'searxng:' + (e && (e.message || e.toString())).slice(0, 120) });
    continue;
  }
  const results = [];
  for (let i = 0; i < hits.length; i++) {
    const u = hits[i].url;
    const rec = { url: u, title: String(hits[i].title || '').slice(0, 200),
      snippet: String(hits[i].content || '').slice(0, 400), source: 'open_web' };
    if (i < 2 && u) {  // render the top 2 for a real quotable excerpt
      try {
        const rr = await this.helpers.httpRequest({
          method: 'POST', url: 'http://browserless:3000/content',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: u, gotoOptions: { waitUntil: 'domcontentloaded' } }),
          returnFullResponse: true, timeout: 30000,
        });
        const h = String((rr && rr.body) || '');
        const text = h.replace(/<script[\s\S]*?<\/script>/gi, ' ')
          .replace(/<style[\s\S]*?<\/style>/gi, ' ')
          .replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
        rec.excerpt = text.slice(0, 600);
      } catch (e) { rec.render_error = (e && (e.message || e.toString())).slice(0, 80); }
    }
    results.push(rec);
  }
  openWeb.push({ query: term, results, retrieved_at: new Date().toISOString() });
}

return [{ json: {
  case_id: caseId,
  generated_at: new Date().toISOString(),
  source: 'n8n findevil-grounding (operator aid; not evidence, not in audit chain)',
  technique_research: research,
  open_web_research: openWeb,
} }];
""".strip()

NODES = [
    {
        "id": "wh",
        "name": "Grounding webhook",
        "type": "n8n-nodes-base.webhook",
        "typeVersion": 2,
        "position": [0, 0],
        "parameters": {
            "httpMethod": "POST",
            "path": WEBHOOK_PATH,
            "responseMode": "responseNode",
        },
    },
    {
        "id": "research",
        "name": "Research techniques (MITRE via browserless)",
        "type": "n8n-nodes-base.code",
        "typeVersion": 2,
        "position": [260, 0],
        "parameters": {"language": "javaScript", "jsCode": RESEARCH_JS},
    },
    {
        "id": "resp",
        "name": "Respond",
        "type": "n8n-nodes-base.respondToWebhook",
        "typeVersion": 1.1,
        "position": [520, 0],
        "parameters": {"respondWith": "json", "responseBody": "={{ $json }}"},
    },
]

CONNECTIONS = {}
for a, b in zip(NODES, NODES[1:]):
    CONNECTIONS[a["name"]] = {
        "main": [[{"node": b["name"], "type": "main", "index": 0}]]
    }

WORKFLOW = {"name": WF_NAME, "nodes": NODES, "connections": CONNECTIONS, "settings": {}}


def req(method, url, body=None, key=True):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=data, method=method)
    r.add_header("Content-Type", "application/json")
    if key:
        r.add_header("X-N8N-API-KEY", KEY)
    try:
        with urllib.request.urlopen(r, timeout=20) as resp:
            raw = resp.read().decode()
            return resp.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        return e.code, {"error": e.read().decode()[:500]}


def _docker(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *args], check=False, capture_output=True, text=True
    )


def _running(name: str) -> bool:
    out = _docker("ps", "--filter", f"name=^{name}$", "--format", "{{.Names}}").stdout
    return name in out.split()


def _ensure_searxng() -> None:
    """Start a self-hosted SearXNG (open-web search) on the shared net.

    Public SERPs block headless browsers (anti-bot), so we run our own search
    engine: keyless, JSON output, no upstream blocking for low-volume grounding.
    Writes a settings.yml (JSON format on, limiter off, random secret) if absent.
    """
    if _running(SEARXNG_NAME):
        _docker("network", "connect", NET, SEARXNG_NAME)
        return
    if not SEARXNG_SETTINGS.is_file():
        import secrets

        SEARXNG_SETTINGS.parent.mkdir(parents=True, exist_ok=True)
        SEARXNG_SETTINGS.write_text(
            "use_default_settings: true\n"
            "server:\n"
            f'  secret_key: "{secrets.token_hex(24)}"\n'
            "  limiter: false\n"
            "  image_proxy: false\n"
            '  method: "GET"\n'
            "search:\n"
            "  safe_search: 0\n"
            "  formats:\n"
            "    - html\n"
            "    - json\n"
        )
    _docker("rm", "-f", SEARXNG_NAME)
    print(f"  starting {SEARXNG_NAME} on {NET}…")
    _docker(
        "run",
        "-d",
        "--name",
        SEARXNG_NAME,
        "--network",
        NET,
        "-p",
        "127.0.0.1:8888:8080",
        "-v",
        f"{SEARXNG_SETTINGS}:/etc/searxng/settings.yml:ro",
        SEARXNG_IMAGE,
    )


def ensure_infra() -> None:
    """Wire the shared docker network so n8n can reach browserless by name.

    Idempotent and best-effort: creates `findevil-net`, starts browserless on it
    (host-bound to 127.0.0.1:3000 for local checks), and attaches a running n8n
    container. `docker network connect` on an already-connected container errors
    harmlessly — we ignore it.
    """
    if not shutil.which("docker"):
        print(
            f"  WARN: docker not found — ensure browserless is reachable at {BROWSERLESS} "
            "and that n8n can resolve that host before triggering the workflow."
        )
        return
    _docker("network", "create", NET)
    if _running(BROWSERLESS_NAME):
        _docker("network", "connect", NET, BROWSERLESS_NAME)
    else:
        _docker("rm", "-f", BROWSERLESS_NAME)
        print(f"  starting {BROWSERLESS_NAME} on {NET}…")
        _docker(
            "run",
            "-d",
            "--name",
            BROWSERLESS_NAME,
            "--network",
            NET,
            "-p",
            "127.0.0.1:3000:3000",
            BROWSERLESS_IMAGE,
        )
    _ensure_searxng()
    if _running("n8n"):
        _docker("network", "connect", NET, "n8n")
    print(
        f"  infra ready: network {NET}, {BROWSERLESS_NAME} ({BROWSERLESS}) + "
        f"{SEARXNG_NAME} ({SEARXNG})"
    )


def main():
    ensure_infra()
    _, lst = req("GET", f"{API}/workflows")
    for w in lst.get("data", []):
        if w.get("name") == WF_NAME:
            req("DELETE", f"{API}/workflows/{w['id']}")
            print(f"  removed prior {WF_NAME} ({w['id']})")
    status, created = req("POST", f"{API}/workflows", WORKFLOW)
    if status not in (200, 201):
        print("CREATE FAILED:", status, json.dumps(created)[:600])
        return 1
    wid = created["id"]
    req("POST", f"{API}/workflows/{wid}/activate", {})
    print(f"  deployed + activated {WF_NAME} ({wid})")
    print(f"  webhook: {BASE}/webhook/{WEBHOOK_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
