import React from "react";
import { AbsoluteFill, interpolate, spring, useCurrentFrame, useVideoConfig } from "remotion";
import { Watermark } from "./shared/Watermark";

const MONO = "'JetBrains Mono', 'Courier New', monospace";

const HOSTS = Array.from({ length: 22 }, (_, i) => ({
  id: i + 1,
  name: `HOST-${String(i + 1).padStart(3, "0")}`,
  status: i < 18 ? "done" : i < 20 ? "running" : "queued",
  findings: [3, 1, 0, 2, 1, 4, 0, 1, 2, 0, 3, 1, 0, 1, 2, 0, 1, 3, 0, 0, 0, 0][i] ?? 0,
}));

const STATUS_COLOR: Record<string, string> = {
  done: "#2ecc71",
  running: "#f39c12",
  queued: "#30363d",
};

export function FleetScene() {
  const frame = useCurrentFrame();
  const { fps, durationInFrames } = useVideoConfig();
  const fadeOut = interpolate(frame, [durationInFrames - 15, durationInFrames], [1, 0], {
    extrapolateLeft: "clamp", extrapolateRight: "clamp",
  });

  const titleOp = interpolate(frame, [0, 16], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });

  // Progress bar at bottom
  const doneCount = HOSTS.filter((h) => {
    const delay = 20 + h.id * 4;
    return h.status === "done" && frame > delay;
  }).length;
  const progressWidth = (doneCount / 22) * 100;

  // Fleet rollup slides in at frame 95
  const rollupOp = interpolate(frame - 95, [0, 16], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  const rollupX = interpolate(frame - 95, [0, 16], [60, 0], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });

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
          22-Host Fleet Investigation
        </div>
        <div style={{ fontFamily: MONO, fontSize: 20, color: "#8b949e", marginTop: 6 }}>
          84 GB of memory images — one command — crash-resilient progress
        </div>
      </div>

      {/* Host grid */}
      <div style={{
        position: "absolute", top: 185, left: 140, right: 540,
        display: "grid",
        gridTemplateColumns: "repeat(6, 1fr)",
        gap: 14,
      }}>
        {HOSTS.map((host) => {
          const delay = 20 + host.id * 4;
          const s = spring({ frame: frame - delay, fps, config: { damping: 14, stiffness: 110 } });
          const op = interpolate(frame - delay, [0, 10], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
          const color = STATUS_COLOR[host.status];
          return (
            <div key={host.id} style={{
              opacity: op,
              transform: `scale(${0.6 + s * 0.4})`,
              background: `${color}12`,
              border: `1px solid ${color}55`,
              borderRadius: 8,
              padding: "12px 10px",
              textAlign: "center",
            }}>
              <div style={{ fontFamily: MONO, fontSize: 12, color, fontWeight: 700 }}>{host.name}</div>
              {host.status === "done" && host.findings > 0 && (
                <div style={{ fontFamily: MONO, fontSize: 11, color: "#e74c3c", marginTop: 4 }}>
                  {host.findings}F
                </div>
              )}
              {host.status === "done" && host.findings === 0 && (
                <div style={{ fontFamily: MONO, fontSize: 11, color: "#2ecc71", marginTop: 4 }}>clean</div>
              )}
              {host.status === "running" && (
                <div style={{ fontFamily: MONO, fontSize: 11, color: "#f39c12", marginTop: 4 }}>…</div>
              )}
            </div>
          );
        })}
      </div>

      {/* Progress bar */}
      <div style={{ position: "absolute", top: 680, left: 140, right: 540 }}>
        <div style={{ fontFamily: MONO, fontSize: 14, color: "#8b949e", marginBottom: 8 }}>
          {doneCount}/22 complete — progress persisted to Postgres checkpoint
        </div>
        <div style={{ height: 8, background: "#161b22", borderRadius: 4 }}>
          <div style={{ height: "100%", width: `${progressWidth}%`, background: "#2ecc71", borderRadius: 4, transition: "width 0.1s" }} />
        </div>
      </div>

      {/* Fleet rollup */}
      <div style={{
        position: "absolute", top: 185, right: 60, width: 420,
        opacity: rollupOp,
        transform: `translateX(${rollupX}px)`,
        background: "#161b22",
        border: "1px solid #30363d",
        borderRadius: 12,
        padding: 24,
        fontFamily: MONO, fontSize: 14, lineHeight: 1.9,
      }}>
        <div style={{ fontSize: 16, fontWeight: 700, color: "#e6edf3", marginBottom: 16 }}>Fleet Rollup</div>
        <div style={{ color: "#8b949e" }}>Hosts investigated: <span style={{ color: "#e6edf3" }}>22</span></div>
        <div style={{ color: "#8b949e" }}>Total findings:     <span style={{ color: "#e74c3c" }}>24</span></div>
        <div style={{ color: "#8b949e" }}>CONFIRMED:          <span style={{ color: "#2ecc71" }}>11</span></div>
        <div style={{ color: "#8b949e" }}>INFERRED:           <span style={{ color: "#f39c12" }}>8</span></div>
        <div style={{ color: "#8b949e" }}>HYPOTHESIS:         <span style={{ color: "#3498db" }}>5</span></div>
        <div style={{ borderTop: "1px solid #30363d", marginTop: 12, paddingTop: 12 }}>
          <div style={{ color: "#8b949e" }}>Hosts with IOC:     <span style={{ color: "#e74c3c" }}>9</span></div>
          <div style={{ color: "#8b949e" }}>Clean:              <span style={{ color: "#2ecc71" }}>13</span></div>
        </div>
        <div style={{ marginTop: 16, background: "#0d1117", borderRadius: 6, padding: "10px 14px" }}>
          <div style={{ color: "#9b59b6", fontSize: 12 }}>manifest_verify: ✓ signed</div>
          <div style={{ color: "#9b59b6", fontSize: 12 }}>sigstore Rekor: ✓ recorded</div>
        </div>
      </div>

      <Watermark />
    </AbsoluteFill>
  );
}
