// VERDICT live dashboard — the polished port of the demo video's
// single-host investigation scene (Beat 3) into the real product.
//
// Subscribes to /api/audit?case=<path> via EventSource, accumulates the
// audit-line stream, and feeds it to <InvestigationStreamPanel>, which
// reduces the raw stream into the terminal view + finding cards. The
// design system lives in @/lib/verdict-ui (ported 1:1 from the Remotion
// scenes). The NES.css placeholder + role-sprite grid this replaced are
// kept on disk (components/sprites/*) for the /codex + /debug views.
//
// Honest scope: this page ships the genuinely live-now panels only
// (investigation stream). ACH columns, fleet grid, cluster timeline, and
// the merkle/sigstore chain right-rail are gated behind backend routes
// that don't exist yet (see docs / workflow blueprint) and are NOT
// rendered with placeholder data.

"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import { DashboardNav } from "@/components/DashboardNav";
import { InvestigationStreamPanel } from "@/components/investigation/InvestigationStreamPanel";
import { BrandMark, GridOverlay, MONO, RadialGlow, VERDICT } from "@/lib/verdict-ui";

// Mirror /debug's local AuditLine shape — importing from @/lib/audit-tail
// would drag node:fs + chokidar into the client bundle. Keep in sync with
// `apps/web/lib/audit-tail.ts:AuditLine`.
interface AuditLine {
  seq: number;
  kind: string;
  ts: string;
  payload: Record<string, unknown>;
  line_hash?: string;
  raw_line: string;
}

type ConnState = "disconnected" | "connecting" | "live";

const MAX_EVENTS = 500;

export default function DashboardPage() {
  const [casePath, setCasePath] = useState("");
  const [events, setEvents] = useState<AuditLine[]>([]);
  const [conn, setConn] = useState<ConnState>("disconnected");
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const esRef = useRef<EventSource | null>(null);

  const disconnect = useCallback(() => {
    if (esRef.current) {
      esRef.current.close();
      esRef.current = null;
    }
    setConn("disconnected");
  }, []);

  const connect = useCallback(
    (pathArg?: string) => {
      const target = (pathArg ?? casePath).trim();
      if (!target) {
        setErrorMsg("Enter an absolute case directory path first.");
        return;
      }
      if (esRef.current) {
        esRef.current.close();
        esRef.current = null;
      }
      setErrorMsg(null);
      setConn("connecting");

      const url = `/api/audit?case=${encodeURIComponent(target)}`;
      const es = new EventSource(url);
      esRef.current = es;

      es.addEventListener("open", () => {
        setConn("live");
      });

      es.addEventListener("audit_line", (raw: MessageEvent) => {
        try {
          const line = JSON.parse(raw.data) as AuditLine;
          setEvents((prev) => {
            const next = [...prev, line];
            return next.length > MAX_EVENTS
              ? next.slice(next.length - MAX_EVENTS)
              : next;
          });
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          setErrorMsg(`failed to parse audit_line: ${msg}`);
        }
      });

      es.addEventListener("error", (raw: Event) => {
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
    },
    [casePath],
  );

  // Tear down on unmount.
  useEffect(() => {
    return () => {
      if (esRef.current) {
        esRef.current.close();
        esRef.current = null;
      }
    };
  }, []);

  // Deep link: ?case=... auto-populates and starts streaming on first mount.
  useEffect(() => {
    if (typeof window === "undefined") return;
    const params = new URLSearchParams(window.location.search);
    const c = params.get("case");
    if (c) {
      setCasePath(c);
      connect(c);
    }
    // Mount-only: fire the deep-link connect once.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const dotColor =
    conn === "live"
      ? VERDICT.confirmed
      : conn === "connecting"
        ? VERDICT.inferred
        : VERDICT.alertRed;

  // Stale-data warning (critic gap A1): the stream dropped but we still hold
  // events — surface it so a judge doesn't trust frozen data.
  const showStaleBanner = conn === "disconnected" && events.length > 0;

  return (
    <main
      style={{
        position: "relative",
        minHeight: "100vh",
        background: VERDICT.bg,
        color: VERDICT.text,
        fontFamily: MONO,
        overflowX: "hidden",
      }}
    >
      <GridOverlay opacity={0.04} />
      <RadialGlow alpha={0.1} position="50% 0%" />

      <div
        style={{
          position: "relative",
          maxWidth: 1320,
          margin: "0 auto",
          padding: "clamp(20px, 4vw, 40px)",
        }}
      >
        {/* Masthead */}
        <header
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            flexWrap: "wrap",
            gap: 20,
            marginBottom: 24,
          }}
        >
          <BrandMark size={56} withWordmark withTagline />
          <span
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: 8,
              fontSize: 13,
              color: VERDICT.muted,
            }}
          >
            <span
              aria-label={`stream ${conn}`}
              style={{
                display: "inline-block",
                width: "0.7rem",
                height: "0.7rem",
                borderRadius: "9999px",
                background: dotColor,
                boxShadow: `0 0 8px ${dotColor}`,
              }}
            />
            {conn}
          </span>
        </header>

        <DashboardNav active="audit" variant="dark" />

        {/* Connect control */}
        <section
          style={{
            background: VERDICT.surface,
            border: `1px solid ${VERDICT.border}`,
            borderRadius: 12,
            padding: 20,
            marginBottom: 24,
          }}
        >
          <label
            htmlFor="case-path"
            style={{
              display: "block",
              fontSize: 13,
              color: VERDICT.muted,
              marginBottom: 8,
            }}
          >
            Case directory (absolute path) — or append{" "}
            <code style={{ color: VERDICT.accentPurpleLight }}>
              ?case=&lt;dir&gt;
            </code>{" "}
            to deep-link
          </label>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 12 }}>
            <input
              id="case-path"
              type="text"
              placeholder="absolute path to a case dir containing audit.jsonl"
              value={casePath}
              onChange={(e) => setCasePath(e.target.value)}
              disabled={conn !== "disconnected"}
              style={{
                flex: "1 1 360px",
                background: VERDICT.bg,
                border: `1px solid ${VERDICT.border}`,
                borderRadius: 8,
                padding: "10px 14px",
                color: VERDICT.text,
                fontFamily: MONO,
                fontSize: 14,
                outline: "none",
              }}
            />
            {conn === "disconnected" ? (
              <button
                type="button"
                onClick={() => connect()}
                style={{
                  background: "rgba(155,89,182,0.15)",
                  border: `1px solid ${VERDICT.accentPurple}`,
                  color: VERDICT.accentPurpleLight,
                  borderRadius: 8,
                  padding: "10px 24px",
                  fontFamily: MONO,
                  fontWeight: 700,
                  fontSize: 14,
                  cursor: "pointer",
                }}
              >
                Connect
              </button>
            ) : (
              <button
                type="button"
                onClick={disconnect}
                style={{
                  background: "rgba(231,76,60,0.15)",
                  border: `1px solid ${VERDICT.alertRed}`,
                  color: VERDICT.alertRed,
                  borderRadius: 8,
                  padding: "10px 24px",
                  fontFamily: MONO,
                  fontWeight: 700,
                  fontSize: 14,
                  cursor: "pointer",
                }}
              >
                Disconnect
              </button>
            )}
            <span
              style={{
                alignSelf: "center",
                fontSize: 13,
                color: VERDICT.muted,
              }}
            >
              events: {events.length}
            </span>
          </div>

          {errorMsg ? (
            <div
              style={{
                marginTop: 14,
                background: "rgba(231,76,60,0.1)",
                border: `1px solid ${VERDICT.alertRed}44`,
                borderRadius: 8,
                padding: "10px 14px",
                fontSize: 13,
                color: VERDICT.alertRed,
              }}
            >
              <strong>error:</strong> {errorMsg}
            </div>
          ) : null}

          {showStaleBanner ? (
            <div
              style={{
                marginTop: 14,
                background: "rgba(243,156,18,0.1)",
                border: `1px solid ${VERDICT.inferred}44`,
                borderRadius: 8,
                padding: "10px 14px",
                fontSize: 13,
                color: VERDICT.inferred,
              }}
            >
              stream disconnected — showing {events.length} buffered events;
              data may be stale. Reconnect to resume.
            </div>
          ) : null}
        </section>

        {/* Marquee: the live single-host investigation stream */}
        <InvestigationStreamPanel events={events} />
      </div>
    </main>
  );
}
