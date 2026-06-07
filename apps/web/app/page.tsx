// Live dashboard — Phase 5 of Amendment A3.
//
// Subscribes to /api/audit?case=<path> via EventSource, accumulates
// the audit-line stream, runs `deriveRoleStates` on every update,
// and renders the 5 role sprites in a grid that mirrors the ASCII
// diagram in agent-config/AGENTS.md:
//
//        Pool A      Pool B
//             Verifier
//              Judge
//            Correlator
//
// Phase 5 ships placeholder visuals — the sprite art swap-in is
// gated on the Claude Design pass per A3 §1.2; until then the
// components render labeled NES.css containers with colored-dot
// status indicators. The /debug route remains the raw-events
// viewer one click away.

"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { CorrelatorSprite } from "@/components/sprites/CorrelatorSprite";
import { DashboardNav } from "@/components/DashboardNav";
import { JudgeSprite } from "@/components/sprites/JudgeSprite";
import { PoolASprite } from "@/components/sprites/PoolASprite";
import { PoolBSprite } from "@/components/sprites/PoolBSprite";
import { VerifierSprite } from "@/components/sprites/VerifierSprite";
import { deriveRoleStates } from "@/lib/sprite-state";

// Mirror /debug's local AuditLine shape — importing from
// @/lib/audit-tail would drag node:fs + chokidar into the client
// bundle. Keep in sync with `apps/web/lib/audit-tail.ts:AuditLine`.
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

  const roleStates = useMemo(() => deriveRoleStates(events), [events]);

  const disconnect = useCallback(() => {
    if (esRef.current) {
      esRef.current.close();
      esRef.current = null;
    }
    setConn("disconnected");
  }, []);

  const connect = useCallback((pathArg?: string) => {
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
          // Append in chronological order (events arrive in seq
          // order from the route handler), trim from the head if we
          // exceed MAX_EVENTS so memory stays bounded.
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
  }, [casePath]);

  // Tear down on unmount.
  useEffect(() => {
    return () => {
      if (esRef.current) {
        esRef.current.close();
        esRef.current = null;
      }
    };
  }, []);

  // On first mount, if the URL carries `?case=...`, auto-populate the input
  // AND start streaming — so a deep link is "open and watch", no typing.
  useEffect(() => {
    if (typeof window === "undefined") return;
    const params = new URLSearchParams(window.location.search);
    const c = params.get("case");
    if (c) {
      setCasePath(c);
      connect(c);
    }
    // Mount-only: the deep-link connect should fire once, not on every
    // connect-identity change (connect is re-memoized when casePath updates).
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const dotColor =
    conn === "live"
      ? "#22c55e"
      : conn === "connecting"
        ? "#eab308"
        : "#ef4444";

  return (
    <main className="min-h-screen overflow-x-hidden p-4 md:p-8">
      <DashboardNav active="audit" />
      <div className="nes-container with-title is-centered max-w-5xl mx-auto">
        <p className="title">Find Evil!</p>
        <p>The agent army at work — live audit stream from a case.</p>
        <p className="mt-2 text-sm">
          Append <code>?case=&lt;absolute-case-dir&gt;</code> to deep-link, or
          paste the path below and Connect.
        </p>
      </div>

      <div className="nes-container with-title is-rounded max-w-5xl mx-auto mt-6">
        <p className="title">Stream</p>
        <div className="nes-field">
          <label htmlFor="case-path">Case directory (absolute path)</label>
          <input
            id="case-path"
            type="text"
            className="nes-input"
            placeholder="absolute path to a case dir containing audit.jsonl"
            value={casePath}
            onChange={(e) => setCasePath(e.target.value)}
            disabled={conn !== "disconnected"}
          />
        </div>

        <div className="mt-4 flex flex-wrap items-center gap-3">
          {conn === "disconnected" ? (
            <button
              type="button"
              className="nes-btn is-primary"
              onClick={connect}
            >
              Connect
            </button>
          ) : (
            <button
              type="button"
              className="nes-btn is-error"
              onClick={disconnect}
            >
              Disconnect
            </button>
          )}
          <span className="text-sm">events: {events.length}</span>
          <span className="ml-auto inline-flex items-center gap-2 text-sm">
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
          <div className="nes-container is-rounded is-error mt-4">
            <p className="text-sm">
              <strong>error:</strong> {errorMsg}
            </p>
          </div>
        ) : null}
      </div>

      {/*
        Sprite grid — mirrors the AGENTS.md ASCII layout:
          row 1: Pool A | Pool B    (parallel adversarial pools)
          row 2: Verifier            (gates pool output)
          row 3: Judge               (credibility-weighted merge)
          row 4: Correlator          (>=2 artifact-class rule)
        Single-column collapse on narrow viewports; not pixel-perfect.
      */}
      <div className="max-w-5xl mx-auto mt-8">
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          <PoolASprite state={roleStates.pool_a} />
          <PoolBSprite state={roleStates.pool_b} />
        </div>
        <div className="mt-4">
          <VerifierSprite state={roleStates.verifier} />
        </div>
        <div className="mt-4">
          <JudgeSprite state={roleStates.judge} />
        </div>
        <div className="mt-4">
          <CorrelatorSprite state={roleStates.correlator} />
        </div>
      </div>

      <div className="max-w-5xl mx-auto mt-8 text-sm">
        <span className="text-xs opacity-70">
          Sprites are placeholder NES.css visuals; final art lands with the
          Claude Design pass (A3 §1.2).
        </span>
      </div>
    </main>
  );
}
