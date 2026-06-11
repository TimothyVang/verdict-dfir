#!/usr/bin/env python3
"""setup-n8n.py — provision the optional n8n automation layer, idempotently.

Called by scripts/install.sh (best-effort, non-fatal) and runnable on its own.
It makes the post-verdict automation reproducible instead of hand-set:

  1. Ensure an n8n instance is reachable at N8N_BASE (optionally `docker run` one).
  2. Ensure an owner account exists (create it on a fresh instance, else log in).
  3. Ensure a REST API key exists (reuse a saved one, else mint one via the
     authenticated session).
  4. (No longer deploys the `findevil-finding-to-action` workflow — superseded by
     grounding-aware routing in scripts/ground_actions.py. The owner + API key
     provisioned here are what scripts/setup-grounding-workflow.py needs.)

Credentials/key are written to gitignored files under tmp/ (the same paths
scripts/n8n_post.py and the dashboard already read):
    tmp/n8n-credentials.txt   (base / email / password)
    tmp/n8n-apikey.txt        (X-N8N-API-KEY value)

BOUNDARY: n8n acts on what the audited product already proved. Its output is
never evidence, never a tool_call_id, never in the audit chain.

Env overrides:
    N8N_BASE            default http://localhost:5678
    N8N_OWNER_EMAIL     default admin@findevil.local
    N8N_OWNER_PASSWORD  default: generated and saved to tmp/n8n-credentials.txt
    N8N_AUTO_DOCKER=1   start a docker n8n if none is reachable (needs Docker)
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from http.cookiejar import CookieJar
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TMP = ROOT / "tmp"
CRED_FILE = TMP / "n8n-credentials.txt"
KEY_FILE = TMP / "n8n-apikey.txt"

BASE = os.environ.get("N8N_BASE", "http://localhost:5678").rstrip("/")
API = f"{BASE}/api/v1"
EMAIL = os.environ.get("N8N_OWNER_EMAIL", "admin@findevil.local")
WF_NAME = "findevil-finding-to-action"
WEBHOOK_PATH = "findevil-finding-to-action"


def log(msg: str) -> None:
    print(f"[setup-n8n] {msg}")


# --- minimal HTTP helpers (cookie session for /rest, api key for /api) --------
_jar = CookieJar()
_opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(_jar))


def _req(method: str, url: str, body=None, api_key: str | None = None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=data, method=method)
    r.add_header("Content-Type", "application/json")
    if api_key:
        r.add_header("X-N8N-API-KEY", api_key)
    try:
        with _opener.open(r, timeout=15) as resp:
            raw = resp.read().decode()
            return resp.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, {"error": raw[:400]}
    except urllib.error.URLError as e:
        return 0, {"error": str(e.reason)}


def ensure_reachable() -> bool:
    for _ in range(2):
        status, _ = _req("GET", f"{BASE}/healthz")
        if status == 200:
            return True
        status, _ = _req("GET", f"{BASE}/")
        if status in (200, 401):
            return True
        if os.environ.get("N8N_AUTO_DOCKER") == "1" and shutil.which("docker"):
            log("n8n not reachable — starting a docker container…")
            # Shared network so n8n resolves `browserless` by name (grounding
            # workflow). Idempotent: `network create` no-ops if it exists.
            subprocess.run(
                ["docker", "network", "create", "findevil-net"],
                check=False,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                [
                    "docker",
                    "run",
                    "-d",
                    "--name",
                    "n8n",
                    "--network",
                    "findevil-net",
                    "-p",
                    "5678:5678",
                    "-v",
                    "n8n_data:/home/node/.n8n",
                    # n8n 2.x mandates an owner login (no no-auth mode); a long JWT
                    # session means the investigator logs in once and stays in.
                    # Creds are saved to gitignored tmp/n8n-credentials.txt.
                    "-e",
                    "N8N_USER_MANAGEMENT_JWT_DURATION_HOURS=8760",
                    "docker.n8n.io/n8nio/n8n",
                ],
                check=False,
            )
            for _ in range(30):
                time.sleep(2)
                s, _ = _req("GET", f"{BASE}/")
                if s in (200, 401):
                    return True
        break
    return False


def _gen_password() -> str:
    # n8n requires 8+ chars with a number and an uppercase letter.
    return "Fe" + secrets.token_urlsafe(14).replace("-", "x").replace("_", "y") + "9A"


def ensure_owner_session() -> bool:
    """Create the owner on a fresh instance, else log in. Returns True on a
    usable authenticated session (cookie in _jar)."""
    password = (
        os.environ.get("N8N_OWNER_PASSWORD")
        or (_read_cred("password") if CRED_FILE.exists() else "")
        or _gen_password()
    )

    status, settings = _req("GET", f"{BASE}/rest/settings")
    needs_setup = bool(
        settings.get("data", {}).get("userManagement", {}).get("showSetupOnFirstLoad")
    )

    if needs_setup:
        status, _ = _req(
            "POST",
            f"{BASE}/rest/owner/setup",
            {
                "email": EMAIL,
                "firstName": "Find",
                "lastName": "Evil",
                "password": password,
            },
        )
        if status in (200, 201):
            log(f"created owner {EMAIL}")
            _write_creds(password)
            return True
        log(f"owner setup failed ({status}) — trying login")

    status, _ = _req(
        "POST",
        f"{BASE}/rest/login",
        {
            "emailOrLdapLoginId": EMAIL,
            "password": password,
        },
    )
    if status == 200:
        log(f"logged in as {EMAIL}")
        _write_creds(password)
        return True
    log(
        f"login failed ({status}); set N8N_OWNER_PASSWORD to the existing owner password"
    )
    return False


def ensure_api_key() -> str | None:
    """Reuse a working saved key, else mint one through the authed session."""
    if KEY_FILE.exists():
        key = KEY_FILE.read_text().strip()
        status, _ = _req("GET", f"{API}/workflows", api_key=key)
        if status == 200:
            log("reusing existing API key")
            return key

    status, created = _req("POST", f"{BASE}/rest/api-keys", {"label": "findevil-setup"})
    if status in (200, 201):
        d = created.get("data", created)
        key = d.get("rawApiKey") or d.get("apiKey") or d.get("key")
        if key:
            KEY_FILE.write_text(key + "\n")
            log("minted API key -> tmp/n8n-apikey.txt")
            return key
    log(
        f"could not mint API key ({status}). Create one in n8n → Settings → API "
        f"and save it to {KEY_FILE.relative_to(ROOT)}"
    )
    return None


def _read_cred(field: str) -> str:
    if not CRED_FILE.exists():
        return ""
    for line in CRED_FILE.read_text().splitlines():
        if line.startswith(f"{field}:"):
            return line.split(":", 1)[1].strip()
    return ""


def _write_creds(password: str) -> None:
    TMP.mkdir(exist_ok=True)
    CRED_FILE.write_text(
        f"n8n instance: {BASE}\nemail: {EMAIL}\npassword: {password}\n"
    )


# --- workflow definition (webhook -> route -> ticket -> respond) ---
JS_CODE = r"""
// Find Evil! finding-to-action router (operator harness; NOT evidence).
const inItem = $input.first().json;
const payload = inItem.body || inItem;
const verdict = String(payload.verdict || payload.top_verdict || 'INDETERMINATE').toUpperCase();
const caseId = payload.case_id || payload.caseId || 'unknown';
const findings = payload.findings || [];
const ACTIONS = {
  'T1014':     ['page_ir', 'velociraptor_fleet_sweep_sys_hash'],
  'T1055':     ['open_ticket', 'sandbox_injected_region', 'correlate_evtx_4688'],
  'T1547.001': ['notify', 'collect_autoruns'],
};
const DEFAULT = ['notify', 'open_ticket'];
let plan = [];
if (verdict === 'SUSPICIOUS') {
  const confirmed = findings.filter(f =>
    String(f.confidence || f.level || '').toUpperCase() === 'CONFIRMED');
  const subjects = confirmed.length ? confirmed : findings;
  plan = subjects.map(f => {
    const tech = String(f.mitre || f.technique || f.mitre_technique || '');
    const key = Object.keys(ACTIONS).find(k => tech.startsWith(k));
    return { finding: f.title || f.name || tech || 'finding', technique: tech || null,
             confidence: f.confidence || f.level || null, actions: key ? ACTIONS[key] : DEFAULT };
  });
} else if (verdict === 'INDETERMINATE') {
  plan = [{ finding: null, technique: null, actions: ['route_to_analyst_queue'] }];
} else {
  plan = [{ finding: null, technique: null, actions: ['file_scope_note'] }];
}
return [{ json: { case_id: caseId, verdict,
  note: 'n8n finding-to-action (operator harness; not evidence, not in audit chain)',
  action_plan: plan } }];
""".strip()

WRITE_JS = r"""
const fs = require('fs');
const dir = '/data/findevil-tickets';
try { fs.mkdirSync(dir, { recursive: true }); } catch (e) {}
const j = $input.first().json;
const safe = String(j.case_id || 'unknown').replace(/[^A-Za-z0-9._-]/g, '_');
const record = { case_id: j.case_id, verdict: j.verdict, written_at: new Date().toISOString(),
  source: 'n8n finding-to-action (operator harness; not evidence, not in audit chain)',
  tickets: (j.action_plan || []).map(p => ({ finding: p.finding, technique: p.technique,
    confidence: p.confidence, recommended_actions: p.actions, status: 'open' })) };
fs.writeFileSync(`${dir}/${safe}.json`, JSON.stringify(record, null, 2));
return [{ json: { ...j, ticket_file: `tmp/findevil-tickets/${safe}.json`, tickets_written: record.tickets.length } }];
""".strip()


def build_workflow() -> dict:
    nodes = [
        {
            "id": "wh",
            "name": "Verdict webhook",
            "type": "n8n-nodes-base.webhook",
            "typeVersion": 2,
            "parameters": {
                "httpMethod": "POST",
                "path": WEBHOOK_PATH,
                "responseMode": "responseNode",
            },
        },
        {
            "id": "code",
            "name": "Route + map to actions",
            "type": "n8n-nodes-base.code",
            "typeVersion": 2,
            "parameters": {"language": "javaScript", "jsCode": JS_CODE},
        },
        {
            "id": "ticket",
            "name": "Write ticket file",
            "type": "n8n-nodes-base.code",
            "typeVersion": 2,
            "parameters": {"language": "javaScript", "jsCode": WRITE_JS},
        },
    ]
    nodes.append(
        {
            "id": "resp",
            "name": "Respond",
            "type": "n8n-nodes-base.respondToWebhook",
            "typeVersion": 1.1,
            "parameters": {
                "respondWith": "json",
                "responseBody": "={{ $('Write ticket file').item.json }}",
            },
        }
    )
    for i, n in enumerate(nodes):
        n["position"] = [i * 240, 0]
    conns = {}
    for a, b in zip(nodes, nodes[1:]):
        conns[a["name"]] = {"main": [[{"node": b["name"], "type": "main", "index": 0}]]}
    return {"name": WF_NAME, "nodes": nodes, "connections": conns, "settings": {}}


def deploy_workflow(key: str) -> bool:
    _, lst = _req("GET", f"{API}/workflows", api_key=key)
    for w in lst.get("data", []):
        if w.get("name") == WF_NAME:
            _req("DELETE", f"{API}/workflows/{w['id']}", api_key=key)
            log(f"removed prior {WF_NAME} ({w['id']})")
    status, created = _req("POST", f"{API}/workflows", build_workflow(), api_key=key)
    if status not in (200, 201):
        log(f"workflow create failed ({status}): {created}")
        return False
    wid = created["id"]
    _req("POST", f"{API}/workflows/{wid}/activate", {}, api_key=key)
    log(f"deployed + activated {WF_NAME} ({wid})")
    return True


def main() -> int:
    if not ensure_reachable():
        log(
            f"no n8n at {BASE} (optional). Start one: "
            f"docker run -d --name n8n -p 5678:5678 -v n8n_data:/home/node/.n8n "
            f"docker.n8n.io/n8nio/n8n  — or set N8N_AUTO_DOCKER=1. Skipping."
        )
        return 0  # optional component — never fail the install
    if not ensure_owner_session():
        return 0
    key = ensure_api_key()
    if not key:
        return 0
    # NOTE: the `findevil-finding-to-action` workflow (deploy_workflow / WRITE_JS /
    # ACTIONS / JS_CODE below) is SUPERSEDED by grounding-aware routing in
    # scripts/ground_actions.py (host-side, written into grounding.json,
    # human-in-the-loop). Its in-node fs.writeFileSync is also disallowed on
    # n8n 2.x. We no longer deploy it; the owner + API key provisioned above are
    # what the grounding workflow (scripts/setup-grounding-workflow.py) needs.
    log(
        f"done. creds -> {CRED_FILE.relative_to(ROOT)}, key -> {KEY_FILE.relative_to(ROOT)}"
    )
    log(
        "n8n owner + API key ready. Deploy grounding: "
        "python3 scripts/setup-grounding-workflow.py"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
