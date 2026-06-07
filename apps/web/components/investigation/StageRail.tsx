// StageRail — the "is the machine alive, and where is it?" glance for mission
// control. Renders the investigation pipeline as a left→right row of pills that
// light up as the audit chain advances (driven by `deriveStageStates`).
//
// Pure presentational: fed `stages: Stage[]`. Motion is compositor-friendly
// (opacity/transform only) and disabled under prefers-reduced-motion. Status is
// conveyed by glyph + text, never color alone (a11y).

"use client";

import type { Stage, StageStatus } from "@/lib/stage-state";
import { GROTESK, MONO, RADIUS, VERDICT } from "@/lib/verdict-ui";

interface StageRailProps {
  stages: Stage[];
}

const GLYPH: Record<StageStatus, string> = {
  done: "✓",
  active: "◉",
  idle: "○",
};

function stageColors(status: StageStatus): { border: string; fill: string; text: string } {
  if (status === "done") {
    return { border: VERDICT.confirmed, fill: `${VERDICT.confirmed}1f`, text: VERDICT.confirmed };
  }
  if (status === "active") {
    return { border: VERDICT.inferred, fill: `${VERDICT.inferred}24`, text: VERDICT.inferred };
  }
  return { border: VERDICT.border, fill: "transparent", text: VERDICT.mutedDark };
}

function StagePill({ stage }: { stage: Stage }) {
  const c = stageColors(stage.status);
  const isActive = stage.status === "active";
  return (
    <li
      aria-current={isActive ? "step" : undefined}
      style={{
        position: "relative",
        display: "inline-flex",
        alignItems: "center",
        gap: 8,
        flex: "0 0 auto",
        padding: "8px 14px",
        borderRadius: RADIUS.pill,
        border: `1px solid ${c.border}`,
        background: c.fill,
        color: c.text,
        fontFamily: MONO,
        fontSize: 13,
        whiteSpace: "nowrap",
        transition: "color 200ms ease, border-color 200ms ease, background 200ms ease",
      }}
    >
      {isActive ? (
        <span
          aria-hidden
          className="verdict-stage-pulse"
          style={{
            position: "absolute",
            inset: -1,
            borderRadius: RADIUS.pill,
            border: `1px solid ${VERDICT.inferred}`,
            pointerEvents: "none",
          }}
        />
      ) : null}
      <span aria-hidden style={{ fontSize: 12 }}>
        {GLYPH[stage.status]}
      </span>
      <span style={{ fontFamily: GROTESK, textTransform: "uppercase", letterSpacing: 1.5 }}>
        {stage.label}
      </span>
      <span style={{ position: "absolute", width: 1, height: 1, overflow: "hidden", clip: "rect(0 0 0 0)" }}>
        {` (${stage.status})`}
      </span>
    </li>
  );
}

function Connector({ done }: { done: boolean }) {
  return (
    <span
      aria-hidden
      style={{
        flex: "0 0 auto",
        width: 18,
        height: 2,
        borderRadius: 2,
        background: done ? VERDICT.confirmed : VERDICT.border,
        transition: "background 240ms ease",
        alignSelf: "center",
      }}
    />
  );
}

export function StageRail({ stages }: StageRailProps) {
  return (
    <section
      aria-label="Investigation pipeline"
      style={{
        background: VERDICT.surface,
        border: `1px solid ${VERDICT.border}`,
        borderRadius: RADIUS.card,
        padding: "14px 18px",
        marginBottom: 24,
        overflowX: "auto",
      }}
    >
      <style>{`
        @keyframes verdictStagePulse {
          0% { opacity: 0.9; transform: scale(1); }
          70% { opacity: 0; transform: scale(1.08); }
          100% { opacity: 0; transform: scale(1.08); }
        }
        .verdict-stage-pulse { animation: verdictStagePulse 1600ms ease-out infinite; }
        @media (prefers-reduced-motion: reduce) {
          .verdict-stage-pulse { animation: none; opacity: 0.6; }
        }
      `}</style>
      <ol
        role="list"
        style={{
          display: "flex",
          alignItems: "center",
          gap: 0,
          margin: 0,
          padding: 0,
          listStyle: "none",
        }}
      >
        {stages.map((stage, i) => (
          <span key={stage.id} style={{ display: "inline-flex", alignItems: "center" }}>
            <StagePill stage={stage} />
            {i < stages.length - 1 ? (
              <Connector done={stage.status === "done"} />
            ) : null}
          </span>
        ))}
      </ol>
    </section>
  );
}
