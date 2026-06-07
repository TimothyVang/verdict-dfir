import React from "react";
import { interpolate, useCurrentFrame } from "remotion";
import { C, MARGIN, MONO, SERIF } from "./shared/editorial";
import { Scene } from "./shared/Scene";
import { EvidenceTag, Kicker, KineticHeadline, PullQuote, RuleLine } from "./shared/editorial-ui";

// Beat 7 — "The pattern." Cross-host correlation rendered as an editorial
// timeline exhibit: a horizontal T+0…T+60s axis with one row per artifact,
// host-event dots, and serif-italic margin annotations. The key finding —
// six hosts running Autoruns in the same second — carries the pull-quote.

const clampOpts = { extrapolateLeft: "clamp", extrapolateRight: "clamp" } as const;

interface ArtifactRow {
  label: string;
  events: number[]; // seconds on the T+0…T+60 axis
  alert?: boolean; // the cluster that reads as evil
  note?: string; // serif-italic margin annotation
}

// Real timing preserved from the prior scene: Autoruns fires on 6 hosts in the
// same second (T+0); rubyw is scattered; svchost32 clusters then trails; the
// elevated cmd.exe walks across the whole window.
const ROWS: ArtifactRow[] = [
  { label: "Autoruns · Run key", events: [0, 0, 0, 0, 0, 0], alert: true, note: "six hosts, one second" },
  { label: "rubyw.exe", events: [1, 5, 9, 14], note: "not in baseline" },
  { label: "svchost32.exe", events: [3, 3, 3, 11], note: "masquerade" },
  { label: "cmd.exe · elevated", events: [1, 6, 12, 17, 20] },
];

// Time axis — uneven stops compress the late window editorially.
const STOPS = [0, 5, 10, 15, 20, 30, 60];
const AXIS_W = 700; // px of plotting width inside the exhibit column
const SECONDS_MAX = 60;

// Map a second onto the (piecewise) axis so the dense early window gets room.
function secondToX(sec: number): number {
  for (let i = 0; i < STOPS.length - 1; i++) {
    const a = STOPS[i];
    const b = STOPS[i + 1];
    if (sec <= b) {
      const segFrac = (sec - a) / (b - a);
      return ((i + segFrac) / (STOPS.length - 1)) * AXIS_W;
    }
  }
  return AXIS_W;
}

export function ClusterScene() {
  const frame = useCurrentFrame();

  const rowTop = 250; // top of the first artifact row inside the exhibit
  const rowGap = 92;

  return (
    <Scene page={7} caption="Cross-host correlation">
      {/* Left column — the story */}
      <div style={{ position: "absolute", left: MARGIN, top: 200, width: 660 }}>
        <Kicker frame={frame} delay={10} color={C.accent}>Exhibit G · 22 Hosts</Kicker>
        <div style={{ marginTop: 16 }}>
          <KineticHeadline text="The pattern." frame={frame} delay={20} size={108} />
        </div>
        <div style={{ marginTop: 30, marginBottom: 30 }}>
          <RuleLine frame={frame} delay={44} width={120} color={C.alert} thickness={2} />
        </div>

        <PullQuote frame={frame} delay={60} size={48} color={C.ink} style={{ maxWidth: 620 }}>
          Six hosts ran Autoruns in the&nbsp;
          <span style={{ color: C.alert }}>same second.</span>
        </PullQuote>

        <PullQuote frame={frame} delay={120} size={26} color={C.inkMuted} style={{ marginTop: 28, maxWidth: 600, fontWeight: 500 }}>
          No human types that fast on six boxes at once. A single push fanned the
          payload across the fleet — and rubyw.exe was never in the baseline.
        </PullQuote>

        <div style={{ marginTop: 40, display: "flex", flexDirection: "column", gap: 18, alignItems: "flex-start" }}>
          <EvidenceTag label="T1569.002 Service Execution" tier="HYPOTHESIS" frame={frame} delay={560} />
          <EvidenceTag label="T1059.007 JavaScript / Ruby" tier="HYPOTHESIS" frame={frame} delay={600} />
        </div>
      </div>

      {/* Right column — the timeline exhibit */}
      <div style={{ position: "absolute", right: MARGIN, top: 210, width: 880 }}>
        <div style={{ fontFamily: MONO, fontSize: 14, letterSpacing: 3, textTransform: "uppercase", color: C.inkMuted, marginBottom: 14 }}>
          Exhibit G-1 — Temporal Clustering
        </div>
        <RuleLine frame={frame} delay={70} color={C.hairline} />

        {/* The plot. Axis lives at x = AXIS_X; labels hang to its left. */}
        <svg width={880} height={rowTop + ROWS.length * rowGap - 20} style={{ display: "block", marginTop: 4 }}>
          {(() => {
            const AXIS_X = 175; // left edge of the plotting area
            const axisBottom = rowTop + (ROWS.length - 1) * rowGap + 24;
            return (
              <>
                {/* Vertical time gridlines + axis labels */}
                {STOPS.map((s, i) => {
                  const x = AXIS_X + (i / (STOPS.length - 1)) * AXIS_W;
                  const op = interpolate(frame - (80 + i * 4), [0, 12], [0, 1], clampOpts);
                  return (
                    <g key={s} opacity={op}>
                      <line
                        x1={x}
                        y1={rowTop - 36}
                        x2={x}
                        y2={axisBottom}
                        stroke={C.hairline}
                        strokeWidth={1}
                      />
                      <text
                        x={x}
                        y={axisBottom + 26}
                        textAnchor="middle"
                        fontFamily={MONO}
                        fontSize={15}
                        fill={C.inkMuted}
                        letterSpacing={1}
                      >
                        T+{s}s
                      </text>
                    </g>
                  );
                })}

                {/* Cluster band behind the Autoruns burst (the "evil" column) */}
                {(() => {
                  const op = interpolate(frame - 300, [0, 18], [0, 0.1], clampOpts);
                  const x = AXIS_X + secondToX(0);
                  return (
                    <rect
                      x={x - 16}
                      y={rowTop - 36}
                      width={32}
                      height={axisBottom - (rowTop - 36)}
                      fill={C.alert}
                      opacity={op}
                    />
                  );
                })()}

                {/* Rows */}
                {ROWS.map((row, ri) => {
                  const y = rowTop + ri * rowGap;
                  const rowDelay = 110 + ri * 22;
                  const rowOp = interpolate(frame - rowDelay, [0, 14], [0, 1], clampOpts);
                  const baseTone = row.alert ? C.alert : C.ink;
                  return (
                    <g key={row.label} opacity={rowOp}>
                      {/* Row label — grotesque, hangs left of the axis */}
                      <text
                        x={AXIS_X - 22}
                        y={y + 5}
                        textAnchor="end"
                        fontFamily={MONO}
                        fontSize={16}
                        fontWeight={600}
                        fill={row.alert ? C.alert : C.ink}
                        letterSpacing={0.5}
                      >
                        {row.label}
                      </text>

                      {/* Row baseline */}
                      <line
                        x1={AXIS_X}
                        y1={y}
                        x2={AXIS_X + AXIS_W}
                        y2={y}
                        stroke={row.alert ? `${C.alert}55` : C.hairline}
                        strokeWidth={1}
                      />

                      {/* Event dots */}
                      {row.events.map((sec, di) => {
                        const dotDelay = rowDelay + 8 + di * 5;
                        const grow = interpolate(frame - dotDelay, [0, 10], [0, 1], { ...clampOpts });
                        const cx = AXIS_X + secondToX(Math.min(sec, SECONDS_MAX));
                        const r = (row.alert ? 7 : 5.5) * grow;
                        return (
                          <circle
                            key={di}
                            cx={cx}
                            cy={y}
                            r={r}
                            fill={baseTone}
                            opacity={0.92}
                          />
                        );
                      })}

                      {/* Serif-italic margin annotation, far right */}
                      {row.note && (
                        <text
                          x={AXIS_X + AXIS_W + 22}
                          y={y + 6}
                          fontFamily={SERIF}
                          fontStyle="italic"
                          fontSize={19}
                          fill={row.alert ? C.alert : C.inkMuted}
                          opacity={interpolate(frame - (rowDelay + 30), [0, 14], [0, 1], clampOpts)}
                        >
                          {row.note}
                        </text>
                      )}
                    </g>
                  );
                })}
              </>
            );
          })()}
        </svg>

        <RuleLine frame={frame} delay={300} color={C.hairline} style={{ marginTop: 8 }} />
        <div
          style={{
            fontFamily: MONO,
            fontSize: 16,
            color: C.inkMuted,
            marginTop: 16,
            letterSpacing: 1,
            opacity: interpolate(frame - 320, [0, 14], [0, 1], clampOpts),
          }}
        >
          fleet <span style={{ color: C.ink }}>22</span> &nbsp;·&nbsp; clustered{" "}
          <span style={{ color: C.alert }}>6</span> &nbsp;·&nbsp; window{" "}
          <span style={{ color: C.ink }}>≤ 1.0s</span>
        </div>
      </div>
    </Scene>
  );
}
