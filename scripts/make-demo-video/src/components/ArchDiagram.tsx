import React from "react";
import { AbsoluteFill, interpolate, spring, useCurrentFrame, useVideoConfig } from "remotion";
import { spread } from "./shared/pacing";
import { Watermark } from "./shared/Watermark";

const MONO = "'JetBrains Mono', 'Courier New', monospace";

const LAYERS = [
  { label: "Evidence Vault",         sub: "read-only · SHA-256 at case_open",  color: "#8b949e", x: 960, y: 170 },
  { label: "SIFT Tools (subprocess)",sub: "Volatility · Hayabusa · Chainsaw · YARA",  color: "#f39c12", x: 960, y: 290 },
  { label: "19 Rust DFIR Tools",     sub: "findevil-mcp · typed IO · hash every output", color: "#3498db", x: 640, y: 420 },
  { label: "12 Python Crypto Tools", sub: "findevil-agent-mcp · ACH · sigstore · memory", color: "#9b59b6", x: 1280, y: 420 },
  { label: "VERDICT Orchestrator",   sub: "Claude Code · Pool A + Pool B · judge · correlate", color: "#e74c3c", x: 960, y: 570 },
];

export function ArchDiagram() {
  const frame = useCurrentFrame();
  const { fps, durationInFrames } = useVideoConfig();
  const fadeOut = interpolate(frame, [durationInFrames - 15, durationInFrames], [1, 0], {
    extrapolateLeft: "clamp", extrapolateRight: "clamp",
  });

  // Title
  const titleOp = interpolate(frame, [0, 16], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });

  // Spread the box + arrow build across the beat instead of finishing in ~2s.
  const sd = (d: number) => spread(d, 10, 66, durationInFrames, 24, 200);
  // Each box's reveal frame; arrows fire just AFTER their target box lands so a
  // connector never points into empty space mid-build.
  const boxDelay = (i: number) => sd(10 + i * 14);

  return (
    <AbsoluteFill style={{ backgroundColor: "#0d1117", opacity: fadeOut }}>
      <div style={{
        position: "absolute", inset: 0, opacity: 0.04,
        backgroundImage: "linear-gradient(#fff 1px, transparent 1px), linear-gradient(90deg, #fff 1px, transparent 1px)",
        backgroundSize: "60px 60px",
      }} />

      {/* Title */}
      <div style={{
        position: "absolute", top: 60, left: 0, right: 0, textAlign: "center",
        opacity: titleOp,
      }}>
        <div style={{ fontFamily: MONO, fontSize: 48, fontWeight: 800, color: "#e6edf3", letterSpacing: 4 }}>
          Architecture
        </div>
        <div style={{ fontFamily: MONO, fontSize: 20, color: "#8b949e", marginTop: 8 }}>
          Five trust boundaries — every output hashed
        </div>
      </div>

      {/* SVG diagram */}
      <svg style={{ position: "absolute", inset: 0 }} width="1920" height="1080">
        {/* Arrows between layers. y1 sits at each source box's BOTTOM edge
            (boxes span [y, y+90]) so the dashed line never crosses the box's
            own subtitle text. */}
        {/* Vault (bottom 260) → SIFT (top 290) — fires after SIFT (box 1) */}
        <Arrow x1={960} y1={262} x2={960} y2={286} frame={frame} fps={fps} delay={boxDelay(1) + 8} color="#8b949e"/>
        {/* SIFT (bottom 380) → Rust MCP (top 420) — after Rust (box 2) */}
        <Arrow x1={900} y1={384} x2={720} y2={414} frame={frame} fps={fps} delay={boxDelay(2) + 8} color="#f39c12"/>
        {/* SIFT (bottom 380) → Python MCP (top 420) — after Python (box 3) */}
        <Arrow x1={1020} y1={384} x2={1200} y2={414} frame={frame} fps={fps} delay={boxDelay(3) + 8} color="#f39c12"/>
        {/* Rust (bottom 510) → Orchestrator (top 570) — after Orchestrator (box 4) */}
        <Arrow x1={700} y1={514} x2={880} y2={566} frame={frame} fps={fps} delay={boxDelay(4) + 8} color="#3498db"/>
        {/* Python (bottom 510) → Orchestrator (top 570) — after Orchestrator (box 4) */}
        <Arrow x1={1220} y1={514} x2={1040} y2={566} frame={frame} fps={fps} delay={boxDelay(4) + 12} color="#9b59b6"/>

        {/* Layer boxes */}
        {LAYERS.map((layer, i) => {
          const delay = boxDelay(i);
          const s = spring({ frame: frame - delay, fps, config: { damping: 13, stiffness: 90 } });
          const op = interpolate(frame - delay, [0, 12], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
          const W = i === 4 ? 540 : 380;
          const H = 90;
          return (
            <g key={layer.label} style={{ opacity: op, transform: `scale(${0.6 + s * 0.4})`, transformOrigin: `${layer.x}px ${layer.y + H / 2}px` }}>
              <rect x={layer.x - W / 2} y={layer.y} width={W} height={H} rx={10}
                fill={`${layer.color}18`} stroke={layer.color} strokeWidth="1.5"/>
              <text x={layer.x} y={layer.y + 32} textAnchor="middle"
                fontFamily={MONO} fontSize="18" fontWeight="700" fill={layer.color}>
                {layer.label}
              </text>
              <text x={layer.x} y={layer.y + 60} textAnchor="middle"
                fontFamily={MONO} fontSize="13" fill="#8b949e">
                {layer.sub}
              </text>
            </g>
          );
        })}
      </svg>

      <Watermark />
    </AbsoluteFill>
  );
}

function Arrow({ x1, y1, x2, y2, frame, fps, delay, color }: {
  x1: number; y1: number; x2: number; y2: number;
  frame: number; fps: number; delay: number; color: string;
}) {
  const op = interpolate(frame - delay, [0, 10], [0, 0.7], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  const dx = x2 - x1;
  const dy = y2 - y1;
  const len = Math.sqrt(dx * dx + dy * dy);
  const progress = interpolate(frame - delay, [0, 16], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  const ex = x1 + dx * progress;
  const ey = y1 + dy * progress;
  void len;
  return (
    <g opacity={op}>
      <line x1={x1} y1={y1} x2={ex} y2={ey} stroke={color} strokeWidth="1.5" strokeDasharray="6 4"/>
      {progress > 0.85 && (
        <polygon
          points={`${x2},${y2} ${x2 - 6},${y2 - 12} ${x2 + 6},${y2 - 12}`}
          fill={color}
          transform={`rotate(${Math.atan2(dy, dx) * 180 / Math.PI - 90}, ${x2}, ${y2})`}
        />
      )}
    </g>
  );
}
