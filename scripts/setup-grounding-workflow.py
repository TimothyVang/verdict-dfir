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
  $helpers.httpRequest — avoids per-item pairing fragility of a fan-out HTTP node.

Prereqs: n8n running, API key in tmp/n8n-apikey.txt, and n8n + browserless on a
shared docker network (so http://browserless:3000 resolves). Run:
    python3 scripts/setup-grounding-workflow.py
"""
from __future__ import annotations

import json
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
    const r = await $helpers.httpRequest({
      method: 'POST',
      url: 'http://browserless:3000/content',
      headers: { 'content-type': 'application/json' },
      body: { url, gotoOptions: { waitUntil: 'networkidle2' } },
      json: true,
      returnFullResponse: true,
      timeout: 45000,
    });
    html = String((r && r.body != null) ? r.body : (typeof r === 'string' ? r : ''));
    dbg = 'status=' + (r && (r.statusCode || r.status)) + ' len=' + html.length;
  } catch (e) {
    dbg = 'ERR:' + (e && (e.message || e.toString())).slice(0, 160);
    html = '';
  }
  const nameMatch = html.match(/<h1[^>]*>\s*([^<]+?)\s*<\/h1>/i);
  const name = nameMatch ? nameMatch[1].trim() : null;
  let desc = null;
  const md = html.match(/<meta\s+name=["']description["']\s+content=["']([^"']+)["']/i);
  if (md) desc = md[1];
  if (!desc) { const p = html.match(/<p[^>]*>([\s\S]{40,600}?)<\/p>/i); if (p) desc = p[1]; }
  if (desc) desc = desc.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 600);
  const found = !!name && !/Page Not Found|404 Not Found/i.test(html);
  research.push({
    technique_id: id, claim, found, mitre_name: name, excerpt: desc, _debug: dbg,
    sources: [{ source: 'mitre_attack', url, retrieved_at: new Date().toISOString() }],
  });
}
return [{ json: {
  case_id: caseId,
  generated_at: new Date().toISOString(),
  source: 'n8n findevil-grounding (operator aid; not evidence, not in audit chain)',
  technique_research: research,
} }];
""".strip()

NODES = [
    {"id": "wh", "name": "Grounding webhook", "type": "n8n-nodes-base.webhook", "typeVersion": 2,
     "position": [0, 0],
     "parameters": {"httpMethod": "POST", "path": WEBHOOK_PATH, "responseMode": "responseNode"}},
    {"id": "research", "name": "Research techniques (MITRE via browserless)", "type": "n8n-nodes-base.code",
     "typeVersion": 2, "position": [260, 0],
     "parameters": {"language": "javaScript", "jsCode": RESEARCH_JS}},
    {"id": "resp", "name": "Respond", "type": "n8n-nodes-base.respondToWebhook", "typeVersion": 1.1,
     "position": [520, 0],
     "parameters": {"respondWith": "json", "responseBody": "={{ $json }}"}},
]

CONNECTIONS = {}
for a, b in zip(NODES, NODES[1:]):
    CONNECTIONS[a["name"]] = {"main": [[{"node": b["name"], "type": "main", "index": 0}]]}

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


def main():
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
