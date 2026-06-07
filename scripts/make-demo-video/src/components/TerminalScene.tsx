import React from "react";
import { AbsoluteFill, interpolate, useCurrentFrame, useVideoConfig } from "remotion";
import { ChipBadge } from "./shared/ChipBadge";
import { Watermark } from "./shared/Watermark";

const MONO = "'JetBrains Mono', 'Courier New', monospace";

const TERMINAL_LINES = [
  { text: "$ bash scripts/find-evil-auto evidence/nist-hacking-case.E01", color: "#e6edf3", delay: 5 },
  { text: "[case_open] SHA-256: 3a4f9c... verified", color: "#2ecc71", delay: 20 },
  { text: "[vol_pslist]  scanning active process list...", color: "#8b949e", delay: 34 },
  { text: "[vol_pslist]  32 processes found", color: "#8b949e", delay: 46 },
  { text: "[vol_psscan]  signature-scanning EPROCESS pool...", color: "#8b949e", delay: 58 },
  { text: "[vol_psscan]  35 processes found — 3 DIVERGE from pslist", color: "#e74c3c", delay: 72 },
  { text: "[vol_psxview] cross-referencing 6 views...", color: "#8b949e", delay: 84 },
  { text: "", color: "#8b949e", delay: 94 },
  { text: "  FINDING: DKOM detected — pid 1492 (svchost.exe)", color: "#f39c12", delay: 98 },
  { text: "  confidence: INFERRED  (pslist+psscan diverge, psxview hidden)", color: "#f39c12", delay: 106 },
  { text: "  mitre: T1014 Rootkit", color: "#9b59b6", delay: 114 },
  { text: "  tool_call_id: tci_psscan_00a7f3", color: "#3498db", delay: 120 },
  { text: "", color: "#8b949e", delay: 126 },
  { text: "[audit_append] record hash: e3b0c4... → prev: 9b57a2...", color: "#30363d", delay: 130 },
];

interface TerminalSceneProps {
  title: string;
  subtitle: string;
  accentColor: string;
}

export function TerminalScene({ title, subtitle, accentColor }: TerminalSceneProps) {
  const frame = useCurrentFrame();
  const { durationInFrames } = useVideoConfig();

  const fadeOut = interpolate(frame, [durationInFrames - 15, durationInFrames], [1, 0], {
    extrapolateLeft: "clamp", extrapolateRight: "clamp",
  });
  const titleOp = interpolate(frame, [0, 18], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });

  // Cursor blink
  const cursorVisible = Math.floor(frame / 15) % 2 === 0;

  // Which lines are visible
  const lastVisibleDelay = Math.max(...TERMINAL_LINES.filter((l) => l.delay <= frame).map((l) => l.delay));
  const isTyping = frame < lastVisibleDelay + 30;

  return (
    <AbsoluteFill style={{ backgroundColor: "#0d1117", opacity: fadeOut }}>
      <div style={{
        position: "absolute", inset: 0, opacity: 0.04,
        backgroundImage: "linear-gradient(#fff 1px, transparent 1px), linear-gradient(90deg, #fff 1px, transparent 1px)",
        backgroundSize: "60px 60px",
      }} />

      {/* Header */}
      <div style={{
        position: "absolute", top: 60, left: 140, right: 140, opacity: titleOp,
        display: "flex", justifyContent: "space-between", alignItems: "flex-end",
      }}>
        <div>
          <div style={{ fontFamily: MONO, fontSize: 52, fontWeight: 800, color: "#e6edf3", letterSpacing: 2 }}>
            {title}
          </div>
          <div style={{ fontFamily: MONO, fontSize: 20, color: "#8b949e", marginTop: 4 }}>
            {subtitle}
          </div>
        </div>
        <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
          <ChipBadge label="INFERRED" variant="INFERRED" fontSize={16} />
          <ChipBadge label="T1014 Rootkit" variant="MITRE" fontSize={16} />
        </div>
      </div>

      {/* Terminal window */}
      <div style={{
        position: "absolute", top: 180, left: 140, right: 140, bottom: 80,
        background: "#0d1117",
        border: "1px solid #30363d",
        borderRadius: 12,
        overflow: "hidden",
      }}>
        {/* Chrome bar */}
        <div style={{
          padding: "12px 18px",
          background: "#161b22",
          borderBottom: "1px solid #30363d",
          display: "flex", alignItems: "center", gap: 8,
        }}>
          <div style={{ width: 12, height: 12, borderRadius: "50%", background: "#e74c3c" }} />
          <div style={{ width: 12, height: 12, borderRadius: "50%", background: "#f39c12" }} />
          <div style={{ width: 12, height: 12, borderRadius: "50%", background: "#2ecc71" }} />
          <span style={{ marginLeft: 12, fontFamily: MONO, fontSize: 13, color: "#8b949e" }}>
            find-evil-auto — bash
          </span>
        </div>
        {/* Content */}
        <div style={{ padding: "20px 24px", fontFamily: MONO, fontSize: 16, lineHeight: 1.7 }}>
          {TERMINAL_LINES.map((line, i) => {
            if (frame < line.delay) return null;
            const isLast = i === TERMINAL_LINES.length - 1 || frame < TERMINAL_LINES[i + 1].delay;
            return (
              <div key={i} style={{ color: line.color, minHeight: line.text ? "auto" : 8 }}>
                {line.text}
                {isLast && isTyping && (
                  <span style={{ opacity: cursorVisible ? 1 : 0, color: accentColor }}>█</span>
                )}
              </div>
            );
          })}
        </div>
      </div>

      <Watermark />
    </AbsoluteFill>
  );
}
