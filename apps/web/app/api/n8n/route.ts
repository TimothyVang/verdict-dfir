// GET /api/n8n -> { configured, url, email, password, reachable }
//
// Surfaces the n8n owner credentials that scripts/setup-n8n.py provisions
// (gitignored tmp/n8n-credentials.txt) so the dashboard can show them — n8n 2.x
// mandates an owner login for its web UI and provides no no-auth mode, so the
// investigator needs the generated creds to open the canvas.
//
// LOCAL-ONLY: this is a single-operator localhost investigator dashboard; the
// password is returned for display on the same machine that already holds the
// gitignored creds file. Do not expose this route on a shared/remote host.

import { promises as fs } from "node:fs";
import path from "node:path";

export const dynamic = "force-dynamic";

function repoRoot(): string {
  return process.env.FINDEVIL_REPO_ROOT ?? process.cwd();
}

function field(text: string, re: RegExp): string | null {
  const m = text.match(re);
  const v = m?.[1]?.trim();
  return v && v.length > 0 ? v : null;
}

export async function GET() {
  const credFile = path.join(repoRoot(), "tmp", "n8n-credentials.txt");
  let url = "http://localhost:5678";
  let email: string | null = null;
  let password: string | null = null;

  try {
    const txt = await fs.readFile(credFile, "utf8");
    url = field(txt, /instance:\s*(.+)/) ?? url;
    email = field(txt, /email:\s*(.+)/);
    password = field(txt, /password:\s*(.+)/);
  } catch {
    // creds not provisioned yet — run scripts/setup-n8n.py
  }

  let reachable = false;
  try {
    const r = await fetch(url, { signal: AbortSignal.timeout(2500) });
    reachable = r.status < 500;
  } catch {
    reachable = false;
  }

  return Response.json({
    configured: Boolean(email && password),
    url,
    email,
    password,
    reachable,
  });
}
