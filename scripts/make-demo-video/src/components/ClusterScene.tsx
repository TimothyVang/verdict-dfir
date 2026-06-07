import React from "react";
import { AbsoluteFill, interpolate, spring, useCurrentFrame, useVideoConfig } from "remotion";
import { Watermark } from "./shared/Watermark";

const MONO = "'JetBrains Mono', 'Courier New', monospace";

const ROWS = [
  { label: "Autoruns (Run key)", color: "#e74c3c", dots: [2, 2, 2, 2, 2, 2] },   // 6 hosts same second
  { label: "rubyw.exe",          color: "#f39c12", dots: [1, 5, 9, 14] },          // 4 scattered
  { label: "svchost32.exe",      color: "#9b59b6", dots: [3, 3, 3, 11] },
  { label: "cmd.exe (elevated)", color: "#8b949e", dots: [1, 6, 12, 17, 20] },
];

const TIME_LABELS = ["T+0s", "T+5s", "T+10s", "T+15s", "T+20s", "T+30s", "T+60s"];
const GRID_W = 1200;
const COL_W = GRID_W / (TIME_LABELS.length - 1);
const ROW_H = 90;

function timeToX(t: number): number {
  return (t / 30) * GRID_W;
}

export function ClusterScene() {
  const frame = useCurrentFrame();
  const { fps, durationInFrames } = useVideoConfig();
  const fadeOut = interpolate(frame, [durationInFrames - 15, durationInFrames], [1, 0], {
    extrapolateLeft: "clamp", extrapolateRight: "clamp",
  });

  const titleOp = interpolate(frame, [0, 16], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });

  // Annotation: Autoruns cluster at frame 50
  const annotOp = interpolate(frame - 50, [0, 14], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  const annotS = spring({ frame: frame - 50, fps, config: { damping: 12, stiffness: 100 } });

  return (
    <AbsoluteFill style={{ backgroundColor: "#0d1117", opacity: fadeOut }}>
      <div style={{
        position: "absolute", inset: 0, opacity: 0.04,
        backgroundImage: "linear-gradient(#fff 1px, transparent 1px), linear-gradient(90deg, #fff 1px, transparent 1px)",
        backgroundSize: "60px 60px",
      }} />

      {/* Title */}
      <div style={{ position: "absolute", top: 52, left: 140, right: 140, opacity: titleOp }}>
        <div style={{ fontFamily: MONO, fontSize: 52, fontWeight: 800, color: "#e6edf3" }}>
          Cross-Host APT Signal
        </div>
        <div style={{ fontFamily: MONO, fontSize: 20, color: "#8b949e", marginTop: 6 }}>
          Temporal clustering — 22 hosts × artifact timeline
        </div>
      </div>

      {/* Timeline grid */}
      <div style={{ position: "absolute", top: 185, left: 100, right: 100 }}>
        <svg width="1720" height={ROWS.length * ROW_H + 60}>
          {/* Time axis */}
          {TIME_LABELS.map((label, i) => (
            <g key={label}>
              <line x1={160 + i * COL_W} y1={0} x2={160 + i * COL_W} y2={ROWS.length * ROW_H + 10}
                stroke="#30363d" strokeWidth="1" strokeDasharray="4 4"/>
              <text x={160 + i * COL_W} y={ROWS.length * ROW_H + 30}
                textAnchor="middle" fontFamily={MONO} fontSize="13" fill="#8b949e">
                {label}
              </text>
            </g>
          ))}

          {/* Rows */}
          {ROWS.map((row, ri) => {
            const y = ri * ROW_H + ROW_H / 2;
            const rowDelay = 15 + ri * 10;
            const rowOp = interpolate(frame - rowDelay, [0, 12], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
            return (
              <g key={row.label} opacity={rowOp}>
                {/* Row label */}
                <text x={150} y={y + 5} textAnchor="end"
                  fontFamily={MONO} fontSize="14" fontWeight="700" fill={row.color}>
                  {row.label}
                </text>
                {/* Row baseline */}
                <line x1={160} y1={y} x2={1640} y2={y} stroke={`${row.color}22`} strokeWidth="1"/>
                {/* Dots */}
                {row.dots.map((t, di) => {
                  const dotDelay = rowDelay + di * 5;
                  const dotS = spring({ frame: frame - dotDelay, fps, config: { damping: 12, stiffness: 150 } });
                  const dotOp = interpolate(frame - dotDelay, [0, 8], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
                  const cx = 160 + timeToX(t);
                  const hostLabel = `H-${String((ri * 3 + di + 1)).padStart(3, "0")}`;
                  return (
                    <g key={di} opacity={dotOp}>
                      <circle cx={cx} cy={y} r={dotS * 8} fill={row.color} opacity="0.85"/>
                      <text x={cx + 11} y={y - 10} fontFamily={MONO} fontSize="9" fill={row.color} opacity="0.7">
                        {hostLabel}
                      </text>
                    </g>
                  );
                })}
              </g>
            );
          })}
        </svg>
      </div>

      {/* Autoruns cluster annotation */}
      <div style={{
        position: "absolute", top: 220, left: 240,
        opacity: annotOp,
        transform: `scale(${0.7 + annotS * 0.3})`,
      }}>
        <div style={{
          background: "rgba(231,76,60,0.12)",
          border: "1.5px solid #e74c3c",
          borderRadius: 8,
          padding: "12px 18px",
          fontFamily: MONO, fontSize: 14, color: "#e74c3c",
        }}>
          6 hosts, same second (T+0s)<br/>
          <span style={{ color: "#8b949e", fontSize: 12 }}>→ PsExec sweep or SCCM push</span><br/>
          <span style={{ color: "#f39c12", fontSize: 12, fontWeight: 700 }}>HYPOTHESIS: T1569.002</span>
        </div>
      </div>

      {/* rubyw annotation */}
      {frame > 60 && (
        <div style={{
          position: "absolute", top: 330, left: 480,
          opacity: interpolate(frame - 60, [0, 14], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" }),
          transform: `scale(${0.7 + spring({ frame: frame - 60, fps, config: { damping: 12, stiffness: 100 } }) * 0.3})`,
        }}>
          <div style={{
            background: "rgba(243,156,18,0.12)",
            border: "1.5px solid #f39c12",
            borderRadius: 8,
            padding: "12px 18px",
            fontFamily: MONO, fontSize: 14, color: "#f39c12",
          }}>
            4 hosts, rubyw.exe scattered<br/>
            <span style={{ color: "#8b949e", fontSize: 12 }}>→ Ruby not in enterprise baseline</span><br/>
            <span style={{ color: "#3498db", fontSize: 12, fontWeight: 700 }}>HYPOTHESIS: T1059.007</span>
          </div>
        </div>
      )}

      <Watermark />
    </AbsoluteFill>
  );
}
