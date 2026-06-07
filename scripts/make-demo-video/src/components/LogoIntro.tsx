import React from "react";
import { AbsoluteFill, interpolate, spring, useCurrentFrame, useVideoConfig } from "remotion";
import { Watermark } from "./shared/Watermark";

const MONO = "'JetBrains Mono', 'Courier New', monospace";
const CMD = "> find-evil";

export function LogoIntro() {
  const frame = useCurrentFrame();
  const { fps, durationInFrames } = useVideoConfig();

  // Typewriter: type CMD chars 0..CMD.length over frames 10..10+CMD.length*3
  const CHAR_START = 10;
  const CHARS_PER_FRAME = 1 / 3;
  const charsVisible = Math.min(CMD.length, Math.floor((Math.max(0, frame - CHAR_START)) * CHARS_PER_FRAME));
  const cursorBlink = Math.floor((frame - CHAR_START) / 14) % 2 === 0;

  // Wordmark fades in after CMD is done typing
  const wordmarkDelay = CHAR_START + CMD.length / CHARS_PER_FRAME + 8;
  const wordmarkOpacity = interpolate(frame, [wordmarkDelay, wordmarkDelay + 18], [0, 1], {
    extrapolateLeft: "clamp", extrapolateRight: "clamp",
  });
  const wordmarkY = interpolate(frame, [wordmarkDelay, wordmarkDelay + 18], [30, 0], {
    extrapolateLeft: "clamp", extrapolateRight: "clamp",
  });

  // Tagline after wordmark
  const taglineDelay = wordmarkDelay + 22;
  const taglineOpacity = interpolate(frame, [taglineDelay, taglineDelay + 15], [0, 1], {
    extrapolateLeft: "clamp", extrapolateRight: "clamp",
  });

  // Chips after tagline
  const chipsDelay = taglineDelay + 20;

  // Gavel logo mark scale-in
  const gavelS = spring({ frame: frame - 5, fps, config: { damping: 12, stiffness: 80 } });

  // Master fade out
  const fadeOut = interpolate(frame, [durationInFrames - 15, durationInFrames], [1, 0], {
    extrapolateLeft: "clamp", extrapolateRight: "clamp",
  });

  const chips = [
    { label: "CONFIRMED",  color: "#2ecc71", delay: chipsDelay },
    { label: "INFERRED",   color: "#f39c12", delay: chipsDelay + 8 },
    { label: "HYPOTHESIS", color: "#3498db", delay: chipsDelay + 16 },
  ];

  return (
    <AbsoluteFill style={{ backgroundColor: "#0d1117", opacity: fadeOut }}>
      {/* Radial purple glow */}
      <div style={{
        position: "absolute", inset: 0,
        background: "radial-gradient(ellipse at 50% 45%, rgba(155,89,182,0.18) 0%, transparent 65%)",
      }} />

      {/* Grid overlay */}
      <div style={{
        position: "absolute", inset: 0, opacity: 0.04,
        backgroundImage: "linear-gradient(#fff 1px, transparent 1px), linear-gradient(90deg, #fff 1px, transparent 1px)",
        backgroundSize: "60px 60px",
      }} />

      {/* Center content */}
      <div style={{
        position: "absolute", inset: 0,
        display: "flex", flexDirection: "column",
        alignItems: "center", justifyContent: "center", gap: 0,
      }}>
        {/* Gavel mark */}
        <div style={{ transform: `scale(${gavelS})`, marginBottom: 32 }}>
          <svg width="88" height="88" viewBox="0 0 80 80" xmlns="http://www.w3.org/2000/svg">
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

        {/* Terminal prompt typewriter */}
        <div style={{
          fontFamily: MONO, fontSize: 44, color: "#9b59b6",
          marginBottom: 16, minHeight: 56, display: "flex", alignItems: "center",
        }}>
          <span>{CMD.slice(0, charsVisible)}</span>
          {charsVisible < CMD.length && (
            <span style={{ opacity: cursorBlink ? 1 : 0 }}>█</span>
          )}
          {charsVisible >= CMD.length && (
            <span style={{ opacity: cursorBlink ? 1 : 0, color: "#e6edf3" }}>█</span>
          )}
        </div>

        {/* VERDICT wordmark */}
        <div style={{
          opacity: wordmarkOpacity,
          transform: `translateY(${wordmarkY}px)`,
          fontFamily: MONO, fontSize: 96, fontWeight: 800,
          color: "#e6edf3", letterSpacing: 10,
          marginBottom: 12,
        }}>
          VERDICT
        </div>

        {/* Tagline */}
        <div style={{
          opacity: taglineOpacity,
          fontFamily: MONO, fontSize: 24, fontWeight: 400,
          color: "#8b949e", letterSpacing: 4,
          marginBottom: 40,
        }}>
          DFIR at machine speed.
        </div>

        {/* Confidence chips */}
        <div style={{ display: "flex", gap: 16 }}>
          {chips.map(({ label, color, delay }) => {
            const chipOpacity = interpolate(frame, [delay, delay + 12], [0, 1], {
              extrapolateLeft: "clamp", extrapolateRight: "clamp",
            });
            const chipS = spring({ frame: frame - delay, fps, config: { damping: 14, stiffness: 120 } });
            return (
              <div key={label} style={{
                opacity: chipOpacity,
                transform: `scale(${0.5 + chipS * 0.5})`,
                background: `${color}22`,
                border: `1px solid ${color}99`,
                borderRadius: 6,
                padding: "6px 20px",
                fontFamily: MONO,
                fontSize: 16,
                fontWeight: 700,
                color,
                letterSpacing: 1,
              }}>
                {label}
              </div>
            );
          })}
        </div>
      </div>

      <Watermark />
    </AbsoluteFill>
  );
}
