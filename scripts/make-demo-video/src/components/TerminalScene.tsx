import React from "react";
import { AbsoluteFill, interpolate, useCurrentFrame, useVideoConfig } from "remotion";
import { ChipBadge } from "./shared/ChipBadge";
import { Watermark } from "./shared/Watermark";

const MONO = "'JetBrains Mono', 'Courier New', monospace";

const TERMINAL_LINES = [
  { text: "$ bash scripts/find-evil-auto evidence/nist-hacking-case.E01", color: "#e6edf3", delay: 5 },
  { text: "[case_open] SHA-256: 3a4f9c8b2d1e07f6a3c091be48d25f4e verified", color: "#2ecc71", delay: 20 },
  { text: "[vol_pslist]  scanning active process list...", color: "#8b949e", delay: 34 },
  { text: "[vol_pslist]  32 processes found", color: "#8b949e", delay: 44 },
  { text: "[vol_psscan]  signature-scanning EPROCESS pool...", color: "#8b949e", delay: 54 },
  { text: "[vol_psscan]  35 processes found — 3 DIVERGE from pslist !", color: "#e74c3c", delay: 66 },
  { text: "[vol_psxview] cross-referencing 6 process views...", color: "#8b949e", delay: 76 },
  { text: "", color: "#8b949e", delay: 84 },
  { text: "  PID    NAME              PPID   OFFSET       STATUS", color: "#30363d", delay: 86 },
  { text: "  ----   ----------------  ----   ----------   ----------------------", color: "#30363d", delay: 88 },
  { text: "  1492   svchost.exe        604   0x8212a020   pslist ONLY", color: "#f39c12", delay: 92 },
  { text: "  1492   svchost.exe        604   0x83f4e060   psscan ONLY  ← DKOM", color: "#e74c3c", delay: 98 },
  { text: "  3044   explorer.exe      1232   0x81f8d040   psscan ONLY  ← hidden", color: "#e74c3c", delay: 104 },
  { text: "", color: "#8b949e", delay: 110 },
  { text: "  FINDING: DKOM — PID 1492 + 3044 hidden from active list", color: "#f39c12", delay: 114 },
  { text: "  confidence: INFERRED   mitre: T1014 Rootkit", color: "#f39c12", delay: 120 },
  { text: "  tool_call_id: tci_psscan_00a7f3c841e609", color: "#3498db", delay: 126 },
  { text: "[verify_finding] replaying tci_psscan_00a7f3c841e609...", color: "#8b949e", delay: 132 },
  { text: "[verify_finding] hash match ✓  INFERRED → CONFIRMED", color: "#2ecc71", delay: 142 },
  { text: "[audit_append]   e3b0c44298fc1c14 → prev: 9b57a2f3c841e609", color: "#30363d", delay: 150 },
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
