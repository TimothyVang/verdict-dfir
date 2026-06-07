import React from "react";
import { AbsoluteFill, interpolate, spring, useCurrentFrame, useVideoConfig } from "remotion";

const MONO = "'JetBrains Mono', 'Courier New', monospace";

export function OutroScene() {
  const frame = useCurrentFrame();
  const { fps, durationInFrames } = useVideoConfig();

  const fadeOut = interpolate(frame, [durationInFrames - 15, durationInFrames], [1, 0], {
    extrapolateLeft: "clamp", extrapolateRight: "clamp",
  });

  // Logo mark scale-in
  const logoS = spring({ frame: frame - 5, fps, config: { damping: 11, stiffness: 80 } });
  const logoOp = interpolate(frame - 5, [0, 14], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });

  // Wordmark
  const wordOp = interpolate(frame - 20, [0, 16], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  const wordY = interpolate(frame - 20, [0, 16], [20, 0], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });

  // Detail lines
  const details = [
    { text: "github.com/TimothyVang/sans-hackathon", color: "#3498db", delay: 36 },
    { text: "License: Apache-2.0", color: "#8b949e", delay: 44 },
    { text: "Build: ✓ green", color: "#2ecc71", delay: 52 },
    { text: "SANS Find Evil! 2026", color: "#9b59b6", delay: 60 },
  ];

  return (
    <AbsoluteFill style={{ backgroundColor: "#0d1117", opacity: fadeOut }}>
      {/* Radial glow */}
      <div style={{
        position: "absolute", inset: 0,
        background: "radial-gradient(ellipse at 50% 45%, rgba(155,89,182,0.14) 0%, transparent 65%)",
      }} />

      {/* Grid */}
      <div style={{
        position: "absolute", inset: 0, opacity: 0.04,
        backgroundImage: "linear-gradient(#fff 1px, transparent 1px), linear-gradient(90deg, #fff 1px, transparent 1px)",
        backgroundSize: "60px 60px",
      }} />

      <div style={{
        position: "absolute", inset: 0,
        display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: 0,
      }}>
        {/* Logo mark */}
        <div style={{ opacity: logoOp, transform: `scale(${logoS})`, marginBottom: 28 }}>
          <svg width="96" height="96" viewBox="0 0 80 80" xmlns="http://www.w3.org/2000/svg">
            <circle cx="40" cy="40" r="38" fill="#161b22" stroke="#9b59b6" strokeWidth="2"/>
            <rect x="14" y="18" width="38" height="17" rx="4" fill="#9b59b6"/>
            <rect x="22" y="18" width="38" height="6" rx="3" fill="#b17fd4" opacity="0.4"/>
            <rect x="31" y="29" width="5" height="30" rx="2.5" fill="#30363d" transform="rotate(-30 33 44)"/>
            <ellipse cx="20" cy="58" rx="8" ry="5" fill="none" stroke="#8b949e" strokeWidth="2.5"/>
            <ellipse cx="36" cy="58" rx="8" ry="5" fill="none" stroke="#8b949e" strokeWidth="2.5"/>
            <circle cx="56" cy="58" r="8" fill="#2ecc71" opacity="0.9"/>
            <polyline points="52,58 55,61 61,54" fill="none" stroke="#0d1117" strokeWidth="2"
              strokeLinecap="round" strokeLinejoin="round"/>
          </svg>
        </div>

        {/* VERDICT wordmark */}
        <div style={{
          opacity: wordOp,
          transform: `translateY(${wordY}px)`,
          fontFamily: MONO, fontSize: 88, fontWeight: 800,
          color: "#e6edf3", letterSpacing: 10,
          marginBottom: 8,
        }}>
          VERDICT
        </div>

        {/* Tagline */}
        <div style={{
          opacity: wordOp,
          fontFamily: MONO, fontSize: 22, fontWeight: 400,
          color: "#8b949e", letterSpacing: 4,
          marginBottom: 44,
        }}>
          DFIR at machine speed.
        </div>

        {/* Detail lines */}
        <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 10 }}>
          {details.map(({ text, color, delay }) => {
            const op = interpolate(frame - delay, [0, 12], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
            return (
              <div key={text} style={{ opacity: op, fontFamily: MONO, fontSize: 18, color, letterSpacing: 1 }}>
                {text}
              </div>
            );
          })}
        </div>
      </div>

      {/* Bottom accent */}
      <div style={{ position: "absolute", bottom: 0, left: 0, right: 0, height: 4, background: "#9b59b6", opacity: 0.8 }} />
    </AbsoluteFill>
  );
}
