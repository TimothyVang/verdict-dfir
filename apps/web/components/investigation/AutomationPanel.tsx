// AutomationPanel — makes the post-verdict SOAR automation visible in-pane so
// the operator perceives it working without alt-tabbing to n8n.
//
// n8n lives OUTSIDE the evidentiary chain: rather than reading audit.jsonl
// (the signed hash chain), this fetches the separate `automation.json` the
// launcher writes after the verdict (scripts/n8n_post.py). Until that exists it
// shows the pipeline idle plus a link to the n8n canvas.

"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import { MONO, RADIUS, SectionHeading, VERDICT } from "@/lib/verdict-ui";

interface AutomationPanelProps {
  caseDir: string;
  manifestDone: boolean;
  n8nUrl?: string;
}

type NodeStatus = "idle" | "running" | "ok" | "error" | "skipped";

interface AutomationRecord {
  ran?: boolean;
  n8n_reachable?: boolean;
  steps?: { node: string; status: NodeStatus }[];
  slack_delivered?: boolean | null;
  ticket_file?: string | null;
  error?: string;
}

const NODE_LABELS: Record<string, string> = {
  trigger: "webhook trigger",
  route: "route → actions",
  slack: "Slack alert",
  ticket: "write ticket",
};

const FALLBACK_NODES = ["trigger", "route", "slack", "ticket"];

const STATUS_COLOR: Record<NodeStatus, string> = {
  idle: VERDICT.mutedDark,
  running: VERDICT.inferred,
  ok: VERDICT.confirmed,
  error: VERDICT.alertRed,
  skipped: VERDICT.mutedDark,
};

const STATUS_GLYPH: Record<NodeStatus, string> = {
  idle: "○",
  running: "◉",
  ok: "✓",
  error: "✕",
  skipped: "–",
};

export function AutomationPanel({ caseDir, manifestDone, n8nUrl = "http://localhost:5678" }: AutomationPanelProps) {
  const [record, setRecord] = useState<AutomationRecord | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const refresh = useCallback(async () => {
    if (!caseDir) return;
    try {
      const res = await fetch(
        `/api/report?case=${encodeURIComponent(caseDir)}&file=automation.json`,
      );
      if (!res.ok) return;
      setRecord((await res.json()) as AutomationRecord);
    } catch {
      // not ready yet
    }
  }, [caseDir]);

  useEffect(() => {
    if (!caseDir) {
      setRecord(null);
      return;
    }
    void refresh();
    if (manifestDone) {
      let ticks = 0;
      pollRef.current = setInterval(() => {
        ticks += 1;
        void refresh();
        if ((record && record.ran !== undefined) || ticks > 15) {
          if (pollRef.current) clearInterval(pollRef.current);
        }
      }, 2000);
    }
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, [caseDir, manifestDone, refresh, record]);

  const steps =
    record?.steps && record.steps.length > 0
      ? record.steps
      : FALLBACK_NODES.map((n) => ({ node: n, status: "idle" as NodeStatus }));

  const ran = Boolean(record?.ran);
  const reachable = record?.n8n_reachable;

  return (
    <section
      aria-label="Automation"
      style={{
        background: VERDICT.surface,
        border: `1px solid ${VERDICT.border}`,
        borderRadius: RADIUS.card,
        padding: 18,
      }}
    >
      <SectionHeading
        right={
          <a
            href={n8nUrl}
            target="_blank"
            rel="noopener noreferrer"
            style={{ fontFamily: MONO, fontSize: 11, color: VERDICT.hypothesis, textDecoration: "none" }}
          >
            open n8n canvas ↗
          </a>
        }
      >
        AUTOMATION
      </SectionHeading>

      <ol role="list" style={{ listStyle: "none", margin: 0, padding: 0, display: "flex", flexDirection: "column", gap: 8 }}>
        {steps.map((s) => (
          <li key={s.node} style={{ display: "flex", alignItems: "center", gap: 10, fontFamily: MONO, fontSize: 13 }}>
            <span aria-hidden style={{ width: 14, textAlign: "center", color: STATUS_COLOR[s.status] }}>
              {STATUS_GLYPH[s.status] ?? "○"}
            </span>
            <span style={{ color: s.status === "idle" ? VERDICT.mutedDark : VERDICT.text }}>
              {NODE_LABELS[s.node] ?? s.node}
            </span>
            <span style={{ marginLeft: "auto", fontSize: 11, color: STATUS_COLOR[s.status] }}>{s.status}</span>
          </li>
        ))}
      </ol>

      <div style={{ marginTop: 12, paddingTop: 12, borderTop: `1px solid ${VERDICT.borderSubtle}`, fontFamily: MONO, fontSize: 12, color: VERDICT.muted }}>
        {ran && reachable ? (
          <>
            <div>
              Slack:{" "}
              {record?.slack_delivered === true ? (
                <span style={{ color: VERDICT.confirmed }}>delivered ●</span>
              ) : record?.slack_delivered === false ? (
                <span style={{ color: VERDICT.mutedDark }}>skipped</span>
              ) : (
                "—"
              )}
            </div>
            {record?.ticket_file ? (
              <div style={{ marginTop: 4 }}>Ticket: {record.ticket_file.split("/").pop()}</div>
            ) : null}
          </>
        ) : ran && reachable === false ? (
          <span style={{ color: VERDICT.mutedDark }}>
            n8n not reachable — start it (docker start n8n) and open the canvas to wire findings → Slack + ticket.
          </span>
        ) : (
          <span style={{ color: VERDICT.mutedDark }}>
            runs after the verdict — n8n routes findings → Slack + ticket.
          </span>
        )}
      </div>
    </section>
  );
}
