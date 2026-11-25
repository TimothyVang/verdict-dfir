// GET /api/cases -> { cases: [{ path, name, mtime }] }
//
// Lists the case directories (those containing an audit.jsonl) under the same
// allow-listed roots as /api/audit, newest-first. Powers the dashboard case
// picker so an investigator selects a case instead of pasting an absolute path.

import { listCases } from "@/lib/audit-tail";

export const dynamic = "force-dynamic";

export async function GET() {
  try {
    const cases = await listCases();
    return Response.json({ cases });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return new Response(JSON.stringify({ error: message, cases: [] }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }
}
