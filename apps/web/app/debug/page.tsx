// Dev/QA debug page: subscribe to /api/audit?case=<path> SSE stream
// from the browser and dump each `audit_line` event as a small editorial
// case-file card. This remains the raw-events QA view; the main dashboard
// renders role-state cards from the same stream.
//
// Importing the AuditLine type from `@/lib/audit-tail` would drag the
// server-only `node:fs` + chokidar imports into the client bundle, so
// we redeclare the shape here. Keep this in sync with
// `apps/web/lib/audit-tail.ts:AuditLine`.

"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import { DashboardNav } from "@/components/DashboardNav";
import {
  VERDICT,
  MONO,
  GROTESK,
  RADIUS,
  Surface,
  SectionHeading,
  confidenceColor,
} from "@/lib/verdict-ui";

interface AuditLine {
  seq: number;
  kind: string;
  ts: string;
  payload: Record<string, unknown>;
  line_hash?: string;
  raw_line: string;
}

type ConnState = "disconnected" | "connecting" | "live";

const MAX_EVENTS = 100;

export default function DebugPage() {
  const [casePath, setCasePath] = useState("");
  const [events, setEvents] = useState<AuditLine[]>([]);
  const [conn, setConn] = useState<ConnState>("disconnected");
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [showPayloads, setShowPayloads] = useState(true);
  const esRef = useRef<EventSource | null>(null);

  const disconnect = useCallback(() => {
    if (esRef.current) {
      esRef.current.close();
      esRef.current = null;
    }
    setConn("disconnected");
  }, []);

  const connect = useCallback(() => {
    if (!casePath.trim()) {
      setErrorMsg("Enter an absolute case directory path first.");
      return;
    }
    // Close any previous connection cleanly before opening a new one.
    if (esRef.current) {
      esRef.current.close();
      esRef.current = null;
    }
    setErrorMsg(null);
    setConn("connecting");

    const url = `/api/audit?case=${encodeURIComponent(casePath.trim())}`;
    const es = new EventSource(url);
    esRef.current = es;

    es.addEventListener("open", () => {
      setConn("live");
    });

    es.addEventListener("audit_line", (raw: MessageEvent) => {
      try {
        const line = JSON.parse(raw.data) as AuditLine;
        setEvents((prev) => {
          const next = [line, ...prev];
          return next.length > MAX_EVENTS ? next.slice(0, MAX_EVENTS) : next;
        });
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        setErrorMsg(`failed to parse audit_line: ${msg}`);
      }
    });

    es.addEventListener("error", (raw: Event) => {
      // SSE error events from the route handler carry a JSON body in
      // `MessageEvent.data`; native EventSource errors (network drop,
      // 400, etc.) come in as plain Events with no data. Surface
      // whatever we can get.
      const maybeMsg = (raw as MessageEvent).data;
      if (typeof maybeMsg === "string" && maybeMsg.length > 0) {
        try {
          const parsed = JSON.parse(maybeMsg) as { error?: string };
          setErrorMsg(parsed.error ?? maybeMsg);
        } catch {
          setErrorMsg(maybeMsg);
        }
      } else {
        setErrorMsg(
          "EventSource error (connection refused, 400 from API, or stream closed). Check the case path and that audit.jsonl exists.",
        );
      }
      setConn("disconnected");
      es.close();
      esRef.current = null;
    });
  }, [casePath]);

  // Tear down the EventSource on unmount so the stream doesn't leak
  // across navigations.
  useEffect(() => {
    return () => {
      if (esRef.current) {
        esRef.current.close();
        esRef.current = null;
      }
    };
  }, []);

  const clearEvents = useCallback(() => {
    setEvents([]);
  }, []);

  const dotColor =
    conn === "live"
      ? VERDICT.confirmed
      : conn === "connecting"
        ? VERDICT.inferred
        : VERDICT.alertRed;

  // Editorial buttons share a pill shape; only the accent color differs.
  const buttonBase = {
    borderRadius: RADIUS.pill,
    padding: "10px 18px",
    fontFamily: MONO,
    fontWeight: 700,
    cursor: "pointer",
  } as const;

  const connectButtonStyle: React.CSSProperties = {
    ...buttonBase,
    background: `${VERDICT.accentPurple}26`,
    border: `1px solid ${VERDICT.accentPurple}`,
    color: VERDICT.accentPurple,
  };

  const disconnectButtonStyle: React.CSSProperties = {
    ...buttonBase,
    background: `${VERDICT.alertRed}26`,
    border: `1px solid ${VERDICT.alertRed}`,
    color: VERDICT.alertRed,
  };

  const clearButtonStyle: React.CSSProperties = {
    ...buttonBase,
    background: `${VERDICT.muted}26`,
    border: `1px solid ${VERDICT.muted}`,
    color: VERDICT.muted,
    cursor: events.length === 0 ? "not-allowed" : "pointer",
    opacity: events.length === 0 ? 0.5 : 1,
  };

  return (
    <main className="min-h-screen overflow-x-hidden p-4 md:p-8">
      <DashboardNav active="debug" />
      <div className="max-w-4xl mx-auto">
        <Surface>
          <SectionHeading>RAW AUDIT STREAM</SectionHeading>
          <p style={{ fontFamily: GROTESK, fontSize: 14, color: VERDICT.muted, lineHeight: 1.6 }}>
            Dev/QA tool. Subscribe to <code style={{ fontFamily: MONO, color: VERDICT.text }}>/api/audit?case=&lt;path&gt;</code>{" "}
            and dump each <code style={{ fontFamily: MONO, color: VERDICT.text }}>audit_line</code> event raw. The main dashboard
            renders role-state cards from the same stream; this page keeps a
            low-level stream check available without <code style={{ fontFamily: MONO, color: VERDICT.text }}>curl</code>.
          </p>

          <div style={{ marginTop: 24 }}>
            <label
              htmlFor="case-path"
              style={{
                display: "block",
                fontFamily: GROTESK,
                fontSize: 13,
                fontWeight: 600,
                letterSpacing: 1,
                color: VERDICT.muted,
                marginBottom: 8,
              }}
            >
              Case directory (absolute path)
            </label>
            <input
              id="case-path"
              type="text"
              placeholder="absolute path to a case dir containing audit.jsonl"
              value={casePath}
              onChange={(e) => setCasePath(e.target.value)}
              disabled={conn !== "disconnected"}
              style={{
                background: VERDICT.surfaceInset,
                border: `1px solid ${VERDICT.border}`,
                borderRadius: RADIUS.tile,
                padding: "10px 14px",
                fontFamily: MONO,
                fontSize: 14,
                color: VERDICT.text,
                width: "100%",
              }}
            />
          </div>

          <div className="mt-4 flex flex-wrap items-center gap-3">
            {conn === "disconnected" ? (
              <button type="button" style={connectButtonStyle} onClick={connect}>
                Connect
              </button>
            ) : (
              <button type="button" style={disconnectButtonStyle} onClick={disconnect}>
                Disconnect
              </button>
            )}
            <button
              type="button"
              style={clearButtonStyle}
              onClick={clearEvents}
              disabled={events.length === 0}
            >
              Clear ({events.length})
            </button>
            <label
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: 8,
                fontFamily: GROTESK,
                fontSize: 14,
                color: VERDICT.text,
                cursor: "pointer",
              }}
            >
              <input
                type="checkbox"
                checked={showPayloads}
                onChange={(e) => setShowPayloads(e.target.checked)}
              />
              <span>Show payloads</span>
            </label>
            <span
              style={{
                marginLeft: "auto",
                display: "inline-flex",
                alignItems: "center",
                gap: 8,
                fontFamily: MONO,
                fontSize: 13,
                color: VERDICT.muted,
              }}
            >
              <span
                aria-label={`stream ${conn}`}
                style={{
                  display: "inline-block",
                  width: "0.75rem",
                  height: "0.75rem",
                  borderRadius: "9999px",
                  background: dotColor,
                  boxShadow: `0 0 6px ${dotColor}`,
                }}
              />
              <span>{conn}</span>
            </span>
          </div>

          {errorMsg ? (
            <Surface
              borderColor={VERDICT.alertRed}
              style={{ color: VERDICT.alertRed, marginTop: 16, padding: 14 }}
            >
              <p style={{ fontFamily: MONO, fontSize: 13, margin: 0 }}>
                <strong>error:</strong> {errorMsg}
              </p>
            </Surface>
          ) : null}
        </Surface>
      </div>

      <div className="max-w-4xl mx-auto mt-6 space-y-3">
        {events.length === 0 ? (
          <Surface tone="inset" style={{ padding: 14 }}>
            <p style={{ fontFamily: MONO, fontSize: 13, color: VERDICT.muted, margin: 0 }}>
              No events yet.{" "}
              {conn === "live"
                ? "Stream is live — waiting for the next audit append."
                : "Click Connect to start tailing."}
            </p>
          </Surface>
        ) : (
          events.map((line, idx) => {
            const payloadStr = JSON.stringify(line.payload);
            const truncated =
              payloadStr.length > 200
                ? payloadStr.slice(0, 200) + "…"
                : payloadStr;
            // Use seq + idx so we don't collide on bookkeeping lines
            // that happen to share a seq (e.g. -1 sentinel).
            const key = `${line.seq}-${idx}-${line.line_hash ?? ""}`;
            // Color the kind: confidence-bearing payloads map to their
            // semantic tier; everything else takes the brand accent.
            const confidence =
              typeof line.payload?.confidence === "string"
                ? line.payload.confidence
                : undefined;
            const kindColor = confidence
              ? confidenceColor(confidence)
              : VERDICT.accentPurple;
            return (
              <Surface key={key} tone="inset" style={{ padding: 14 }}>
                <p style={{ fontFamily: MONO, fontSize: 13, margin: 0, color: VERDICT.muted }}>
                  <span>[seq {line.seq}]</span>{" "}
                  <span style={{ color: VERDICT.mutedDark }}>·</span>{" "}
                  <span style={{ color: kindColor, fontWeight: 700 }}>[{line.kind}]</span>{" "}
                  <span style={{ color: VERDICT.mutedDark }}>·</span>{" "}
                  <span>[{line.ts}]</span>
                </p>
                {showPayloads ? (
                  <pre
                    style={{
                      fontFamily: MONO,
                      fontSize: 12,
                      color: VERDICT.muted,
                      whiteSpace: "pre-wrap",
                      margin: 0,
                      marginTop: 8,
                      wordBreak: "break-all",
                    }}
                  >
                    {truncated}
                  </pre>
                ) : null}
              </Surface>
            );
          })
        )}
      </div>
    </main>
  );
}
