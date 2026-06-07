// LiveTimeline — the headline "watch the timeline build" moment of mission
// control. A horizontal swimlane (one lane per artifact class) of event dots
// positioned by UTC time, mirroring the engine's own fig_timeline_overview so
// the in-app view and the PDF figure tell the same story.
//
// Dual-source (see lib/timeline-data.ts): provisional dots stream live from the
// audit chain's findings; on manifest_finalize it fetches the authoritative
// normalized_timeline from /api/timeline and reconciles. Motion is
// compositor-friendly (opacity/transform) and disabled under reduced-motion.

"use client";

import { useEffect, useMemo, useRef, useState } from "react";

import type { AuditLine } from "@/lib/audit-tail";
import {
  deriveProvisionalTimeline,
  layoutTimeline,
  mergeTimeline,
  normalizeAuthoritative,
  type TimelineEvent,
} from "@/lib/timeline-data";
import { MONO, RADIUS, SectionHeading, VERDICT } from "@/lib/verdict-ui";

interface LiveTimelineProps {
  events: AuditLine[];
  caseDir: string;
  manifestDone: boolean;
}

const LANE_HEIGHT = 30;
const PLOT_LEFT = 150; // px gutter for lane labels

const SIGNIFICANCE_COLOR: Record<string, string> = {
  finding_support: VERDICT.alertRed,
  triage_lead: VERDICT.inferred,
  context: VERDICT.hypothesis,
};

function significanceColor(sig: string): string {
  return SIGNIFICANCE_COLOR[sig] ?? VERDICT.muted;
}

function fmtTs(ts: number): string {
  if (!ts) return "";
  return new Date(ts).toISOString().slice(0, 16).replace("T", " ") + "Z";
}

export function LiveTimeline({ events, caseDir, manifestDone }: LiveTimelineProps) {
  const [authoritative, setAuthoritative] = useState<TimelineEvent[]>([]);
  const fetchedFor = useRef<string>("");

  const provisional = useMemo(() => deriveProvisionalTimeline(events), [events]);

  // Fetch the authoritative timeline once the run finalizes (or when a
  // completed case is opened via deep-link). Re-fetch if the case changes.
  useEffect(() => {
    if (!caseDir) return;
    const key = `${caseDir}|${manifestDone}`;
    if (fetchedFor.current === key) return;
    // Only spend a fetch once there's a reason to (finalized, or a fresh case
    // dir that may already be complete).
    fetchedFor.current = key;
    const controller = new AbortController();
    (async () => {
      try {
        const res = await fetch(`/api/timeline?case=${encodeURIComponent(caseDir)}`, {
          signal: controller.signal,
        });
        if (!res.ok) return;
        const raw = await res.json();
        setAuthoritative(normalizeAuthoritative(raw));
      } catch {
        // Timeline not ready yet — provisional dots still render.
      }
    })();
    return () => controller.abort();
  }, [caseDir, manifestDone]);

  const merged = useMemo(
    () => mergeTimeline(provisional, authoritative),
    [provisional, authoritative],
  );
  const layout = useMemo(() => layoutTimeline(merged), [merged]);

  const hasData = merged.length > 0;

  return (
    <section
      aria-label="Event timeline"
      style={{
        background: VERDICT.surface,
        border: `1px solid ${VERDICT.border}`,
        borderRadius: RADIUS.card,
        padding: 18,
        marginTop: 24,
      }}
    >
      <style>{`
        @keyframes verdictDotIn { from { opacity: 0; transform: scale(0.4); } to { opacity: 1; transform: scale(1); } }
        .verdict-tl-dot { animation: verdictDotIn 280ms cubic-bezier(0.16,1,0.3,1); }
        @media (prefers-reduced-motion: reduce) { .verdict-tl-dot { animation: none; } }
      `}</style>

      <SectionHeading
        right={
          <>
            {merged.length} event{merged.length === 1 ? "" : "s"}
            {authoritative.length > 0 ? " · normalized" : provisional.length > 0 ? " · live" : ""}
          </>
        }
      >
        EVENT TIMELINE
      </SectionHeading>

      {!hasData ? (
        <p style={{ fontFamily: MONO, fontSize: 13, color: VERDICT.mutedDark, margin: "8px 0" }}>
          timeline builds as findings land — the full normalized timeline appears when the run finalizes.
        </p>
      ) : (
        <>
          <div style={{ position: "relative" }}>
            {layout.lanes.map((lane) => {
              const laneEvents = merged.filter((e) => e.artifactClass === lane);
              return (
                <div
                  key={lane}
                  style={{
                    position: "relative",
                    height: LANE_HEIGHT,
                    borderTop: `1px solid ${VERDICT.borderSubtle}`,
                  }}
                >
                  <span
                    style={{
                      position: "absolute",
                      left: 0,
                      top: "50%",
                      transform: "translateY(-50%)",
                      width: PLOT_LEFT - 12,
                      fontFamily: MONO,
                      fontSize: 12,
                      color: VERDICT.muted,
                      whiteSpace: "nowrap",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                    }}
                  >
                    {lane}
                  </span>
                  <div
                    style={{
                      position: "absolute",
                      left: PLOT_LEFT,
                      right: 8,
                      top: 0,
                      bottom: 0,
                    }}
                  >
                    {laneEvents.map((e) => {
                      const color = significanceColor(e.significance);
                      return (
                        <span
                          key={e.id}
                          className="verdict-tl-dot"
                          title={`${fmtTs(e.ts)} · ${e.significance}${e.confidence ? " · " + e.confidence : ""}\n${e.summary}`}
                          style={{
                            position: "absolute",
                            left: `${layout.xFor(e.ts) * 100}%`,
                            top: "50%",
                            transform: "translate(-50%, -50%)",
                            width: 9,
                            height: 9,
                            borderRadius: "50%",
                            background: color,
                            border: e.provisional ? `1px dashed ${color}` : "none",
                            opacity: e.provisional ? 0.5 : 0.9,
                            boxShadow: `0 0 6px ${color}66`,
                          }}
                        />
                      );
                    })}
                  </div>
                </div>
              );
            })}
            <div style={{ borderTop: `1px solid ${VERDICT.borderSubtle}` }} />
          </div>

          {/* time axis */}
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              marginLeft: PLOT_LEFT,
              marginTop: 8,
              fontFamily: MONO,
              fontSize: 11,
              color: VERDICT.mutedDark,
            }}
          >
            <span>{fmtTs(layout.minTs)}</span>
            <span>{fmtTs(layout.maxTs)}</span>
          </div>

          {/* legend */}
          <div style={{ display: "flex", gap: 16, marginTop: 12, flexWrap: "wrap" }}>
            {[
              ["finding_support", "finding"],
              ["triage_lead", "triage lead"],
              ["context", "context"],
            ].map(([sig, label]) => (
              <span key={sig} style={{ display: "inline-flex", alignItems: "center", gap: 6, fontFamily: MONO, fontSize: 11, color: VERDICT.muted }}>
                <span style={{ width: 8, height: 8, borderRadius: "50%", background: significanceColor(sig) }} />
                {label}
              </span>
            ))}
          </div>
        </>
      )}
    </section>
  );
}
