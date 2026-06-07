import React from "react";
import {
  interpolate,
  OffthreadVideo,
  spring,
  staticFile,
  useCurrentFrame,
  useVideoConfig,
} from "remotion";
import { C, GROTESK, MARGIN, MONO } from "./shared/editorial";
import { Scene } from "./shared/Scene";
import { EvidenceTag, Kicker, KineticHeadline, PullQuote, RuleLine } from "./shared/editorial-ui";
import { spread } from "./shared/pacing";

// Beat 6 — "Watch it work." The real dashboard, shown as an exhibit: the live
// capture plays inside an editorial "browser window" frame on the right two-
// thirds, while the left column states what the operator is watching (findings
// proven in real time, tiered confirmed/inferred/hypothesis). Three callout
// labels with thin leader lines point into the window, staggered across the
// whole beat so the spread keeps building rather than freezing.

const clampOpts = { extrapolateLeft: "clamp", extrapolateRight: "clamp" } as const;

// Browser-window frame geometry (top-left anchored), right of the text column.
const WIN_X = 700;
const WIN_Y = 230;
const WIN_W = 1150;
const WIN_H = 650;
const TITLEBAR_H = 40;

// The three confidence tiers shown as evidence chips under the pull-quote.
const TIERS: string[] = ["CONFIRMED", "INFERRED", "HYPOTHESIS"];

// Editorial callouts that point into regions of the window. Each has a label, a
// raw reveal delay (remapped via spread), and the leader-line endpoints in
// absolute canvas coordinates (start = label anchor, end = point in the window).
interface Callout {
  label: string;
  raw: number;
  // label box position (top-left)
  lx: number;
  ly: number;
  // leader line: from (x1,y1) near the label to (x2,y2) the target in the window
  x1: number;
  y1: number;
  x2: number;
  y2: number;
}

const CALLOUTS: Callout[] = [
  {
    label: "live tool-call stream",
    raw: 30,
    lx: 700,
    ly: 132,
    x1: 880,
    y1: 158,
    x2: WIN_X + 250,
    y2: WIN_Y + TITLEBAR_H + 70,
  },
  {
    label: "pipeline lights up stage by stage",
    raw: 60,
    lx: 1300,
    ly: 132,
    x1: 1470,
    y1: 158,
    x2: WIN_X + WIN_W - 230,
    y2: WIN_Y + TITLEBAR_H + 60,
  },
  {
    label: "every finding cites its tool call",
    raw: 90,
    lx: 1290,
    ly: 930,
    x1: 1470,
    y1: 938,
    x2: WIN_X + WIN_W - 300,
    y2: WIN_Y + WIN_H - 90,
  },
];

export function DashboardUI() {
  const frame = useCurrentFrame();
  const { fps, durationInFrames } = useVideoConfig();

  const sd = (raw: number) => spread(raw, 0, 100, durationInFrames, 24, 200);

  // The window springs/fades in over the first ~20 frames, then holds.
  const winSpring = spring({ frame, fps, config: { damping: 18, stiffness: 110 } });
  const winOp = interpolate(frame, [0, 20], [0, 1], clampOpts);
  const winScale = 0.965 + winSpring * 0.035;
  const winRise = (1 - winSpring) * 18;

  return (
    <Scene page={6} caption="The dashboard">
      {/* Left column — what the operator is watching */}
      <div style={{ position: "absolute", left: MARGIN, top: 234, width: 520 }}>
        <Kicker frame={frame} delay={sd(2)} color={C.accent}>
          Exhibit F · Mission Control
        </Kicker>
        <div style={{ marginTop: 18 }}>
          <KineticHeadline text="Watch it" frame={frame} delay={sd(6)} size={104} />
          <KineticHeadline text="work." frame={frame} delay={sd(12)} size={104} italic />
        </div>
        <div style={{ marginTop: 30 }}>
          <RuleLine frame={frame} delay={sd(20)} width={150} color={C.accent} thickness={2} />
        </div>

        <PullQuote
          frame={frame}
          delay={sd(28)}
          size={34}
          color={C.inkMuted}
          style={{ marginTop: 34, lineHeight: 1.22, maxWidth: 500 }}
        >
          Findings appear as they're proven —{" "}
          <span style={{ color: C.confirmed }}>confirmed</span>,{" "}
          <span style={{ color: C.inferred }}>inferred</span>, or{" "}
          <span style={{ color: C.hypothesis }}>hypothesis</span>.
        </PullQuote>

        <div
          style={{
            marginTop: 40,
            display: "flex",
            flexDirection: "column",
            gap: 16,
            alignItems: "flex-start",
          }}
        >
          {TIERS.map((tier, i) => (
            <EvidenceTag
              key={tier}
              label={tier}
              tier={tier}
              frame={frame}
              delay={sd(44 + i * 10)}
            />
          ))}
        </div>
      </div>

      {/* Main — the browser window playing the real capture */}
      <div
        style={{
          position: "absolute",
          left: WIN_X,
          top: WIN_Y,
          width: WIN_W,
          height: WIN_H,
          opacity: winOp,
          transform: `translateY(${winRise}px) scale(${winScale})`,
          transformOrigin: "60% 40%",
          border: `1px solid ${C.hairline}`,
          borderRadius: 10,
          overflow: "hidden",
          background: C.surface,
          boxShadow: `0 30px 80px ${C.paperEdge}aa`,
        }}
      >
        {/* slim title bar */}
        <div
          style={{
            height: TITLEBAR_H,
            display: "flex",
            alignItems: "center",
            gap: 16,
            padding: "0 18px",
            borderBottom: `1px solid ${C.hairline}`,
            background: C.paper,
          }}
        >
          <div style={{ display: "flex", gap: 8 }}>
            {[C.inkFaint, C.inkFaint, C.inkFaint].map((dot, i) => (
              <span
                key={i}
                style={{ width: 9, height: 9, borderRadius: "50%", background: dot }}
              />
            ))}
          </div>
          <span
            style={{
              fontFamily: MONO,
              fontSize: 13,
              letterSpacing: 1,
              color: C.inkFaint,
            }}
          >
            localhost · VERDICT
          </span>
        </div>

        {/* the real capture fills the rest of the window */}
        <div style={{ position: "relative", width: "100%", height: WIN_H - TITLEBAR_H }}>
          <OffthreadVideo
            src={staticFile("ui/dashboard-live.mp4")}
            muted
            style={{ width: "100%", height: "100%", objectFit: "cover" }}
          />
        </div>
      </div>

      {/* Editorial callouts — thin leader lines + small grotesque labels */}
      <svg
        width={1920}
        height={1080}
        style={{ position: "absolute", left: 0, top: 0, pointerEvents: "none" }}
      >
        {CALLOUTS.map((c) => {
          const d = sd(c.raw);
          const draw = interpolate(frame - d, [0, 20], [0, 1], { ...clampOpts });
          const lx2 = c.x1 + (c.x2 - c.x1) * draw;
          const ly2 = c.y1 + (c.y2 - c.y1) * draw;
          const dotOp = interpolate(frame - (d + 18), [0, 8], [0, 1], clampOpts);
          return (
            <g key={c.label}>
              <line
                x1={c.x1}
                y1={c.y1}
                x2={lx2}
                y2={ly2}
                stroke={C.inkFaint}
                strokeWidth={1}
              />
              <circle cx={c.x2} cy={c.y2} r={3.5 * dotOp} fill={C.accent} />
            </g>
          );
        })}
      </svg>

      {CALLOUTS.map((c) => {
        const d = sd(c.raw);
        const op = interpolate(frame - d, [0, 12], [0, 1], clampOpts);
        const ty = interpolate(frame - d, [0, 16], [10, 0], clampOpts);
        return (
          <div
            key={c.label}
            style={{
              position: "absolute",
              left: c.lx,
              top: c.ly,
              width: 240,
              opacity: op,
              transform: `translateY(${ty}px)`,
              fontFamily: GROTESK,
              fontSize: 15,
              fontWeight: 600,
              letterSpacing: 2,
              textTransform: "uppercase",
              color: C.inkMuted,
              textAlign: c.lx > WIN_X + WIN_W / 2 ? "right" : "left",
            }}
          >
            {c.label}
          </div>
        );
      })}
    </Scene>
  );
}
