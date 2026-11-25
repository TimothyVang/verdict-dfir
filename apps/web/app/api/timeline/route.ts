// Normalized-timeline endpoint — serves the authoritative event timeline the
// engine builds into a case (verdict.json.normalized_timeline / timeline.json).
// The LiveTimeline component fetches this on `manifest_finalize` to reconcile
// its provisional live dots against the engine's final, citation-backed events.
//
// Usage: GET /api/timeline?case=<dir>  ->  { version, events: [...], ... }
//
// `case` is validated against the same allow-list as /api/audit.

import { promises as fs } from "node:fs";
import path from "node:path";

import { isAllowedCasePath } from "@/lib/audit-tail";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

async function readJson(file: string): Promise<unknown | null> {
  try {
    return JSON.parse(await fs.readFile(file, "utf-8"));
  } catch {
    return null;
  }
}

export async function GET(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const caseDir = url.searchParams.get("case");
  if (!caseDir) {
    return new Response("missing required ?case=<absolute-case-dir>", { status: 400 });
  }
  const resolved = path.resolve(caseDir);
  if (!isAllowedCasePath(resolved)) {
    return new Response(
      JSON.stringify({ error: "case path not in allow-list", reason: resolved }),
      { status: 400, headers: { "Content-Type": "application/json" } },
    );
  }

  // Prefer the standalone timeline.json (the full normalized_timeline dict);
  // fall back to verdict.json.normalized_timeline.
  const timeline = await readJson(path.join(resolved, "timeline.json"));
  if (timeline && typeof timeline === "object") {
    return Response.json(timeline);
  }

  const verdict = await readJson(path.join(resolved, "verdict.json"));
  if (verdict && typeof verdict === "object") {
    const nt = (verdict as Record<string, unknown>).normalized_timeline;
    if (nt && typeof nt === "object") {
      return Response.json(nt);
    }
  }

  return new Response(
    JSON.stringify({ error: "no timeline available yet", events: [] }),
    { status: 404, headers: { "Content-Type": "application/json" } },
  );
}
