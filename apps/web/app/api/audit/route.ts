// SSE audit-log tail endpoint. Per A3 plan Task 4.2.
//
// Usage from the browser:
//   const es = new EventSource("/api/audit?case=" + encodeURIComponent(caseDir));
//   es.addEventListener("audit_line", (e) => {
//     const line = JSON.parse(e.data);  // AuditLine
//     ...
//   });
//
// The `case` query param is the absolute path to a case directory
// containing `audit.jsonl`. Paths are validated against the case-path
// allow-list in `lib/audit-tail.ts` (`isAllowedCasePath`) — see the
// "Path allow-list for `/api/audit`" section of apps/web/README.md
// for the default roots and the `FINDEVIL_DASHBOARD_EXTRA_ROOTS`
// override.

import path from "node:path";

import { isAllowedCasePath, tailAuditLog } from "@/lib/audit-tail";

// SSE needs a long-lived connection — Node runtime, not Edge.
export const runtime = "nodejs";
// Force dynamic so the response isn't cached by the App Router.
export const dynamic = "force-dynamic";

export async function GET(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const caseDir = url.searchParams.get("case");
  if (!caseDir) {
    return new Response("missing required ?case=<absolute-case-dir>", {
      status: 400,
    });
  }

  // Resolve the case dir first so the allow-list check sees the
  // post-traversal path (e.g. `goldens/../../etc` collapses to
  // `/etc` before comparison).
  const resolvedCaseDir = path.resolve(caseDir);
  if (!isAllowedCasePath(resolvedCaseDir)) {
    return new Response(
      JSON.stringify({
        error: "case path not in allow-list",
        reason: `${resolvedCaseDir} is not inside any allow-listed root (see apps/web/README.md "Path allow-list for /api/audit")`,
      }),
      {
        status: 400,
        headers: { "Content-Type": "application/json" },
      },
    );
  }

  // Resolve to the audit.jsonl inside the case dir.
  const auditPath = path.resolve(resolvedCaseDir, "audit.jsonl");

  const encoder = new TextEncoder();
  const stream = new ReadableStream({
    async start(controller) {
      // Keepalive comment so proxies / browsers don't close the
      // connection on idle.
      const keepalive = setInterval(() => {
        try {
          controller.enqueue(encoder.encode(": keepalive\n\n"));
        } catch {
          clearInterval(keepalive);
        }
      }, 15_000);

      try {
        for await (const line of tailAuditLog(auditPath, request.signal)) {
          // SSE event format: "event: <name>\ndata: <json>\n\n".
          // Use `audit_line` as the event name so consumers can
          // addEventListener("audit_line", …).
          const sse =
            `event: audit_line\n` +
            `data: ${JSON.stringify(line)}\n\n`;
          controller.enqueue(encoder.encode(sse));
        }
      } catch (err) {
        const errMsg =
          err instanceof Error ? err.message : String(err);
        controller.enqueue(
          encoder.encode(
            `event: error\ndata: ${JSON.stringify({ error: errMsg })}\n\n`,
          ),
        );
      } finally {
        clearInterval(keepalive);
        controller.close();
      }
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
    },
  });
}
