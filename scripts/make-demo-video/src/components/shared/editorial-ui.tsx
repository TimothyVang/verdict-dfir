import React from "react";
import { Easing, interpolate, spring, useCurrentFrame, useVideoConfig } from "remotion";
import { C, CONFIDENCE_TONE, EASE_OUT, GROTESK, SERIF } from "./editorial";

const easeOut = Easing.bezier(EASE_OUT[0], EASE_OUT[1], EASE_OUT[2], EASE_OUT[3]);
const clampOpts = { extrapolateLeft: "clamp", extrapolateRight: "clamp" } as const;

// Kicker — small uppercase grotesque label that sits above a headline.
export function Kicker({ children, frame, delay = 0, color = C.accent, style }: {
  children: React.ReactNode; frame: number; delay?: number; color?: string; style?: React.CSSProperties;
}) {
  const op = interpolate(frame - delay, [0, 10], [0, 1], clampOpts);
  return (
    <div style={{ opacity: op, fontFamily: GROTESK, fontSize: 18, fontWeight: 600, letterSpacing: 5, textTransform: "uppercase", color, ...style }}>
      {children}
    </div>
  );
}

// RuleLine — editorial hairline that can draw in from the left.
export function RuleLine({ frame = 0, delay = 0, width = "100%", color = C.hairline, thickness = 1, style }: {
  frame?: number; delay?: number; width?: number | string; color?: string; thickness?: number; style?: React.CSSProperties;
}) {
  const p = interpolate(frame - delay, [0, 16], [0, 1], { ...clampOpts, easing: easeOut });
  return <div style={{ height: thickness, width, background: color, transform: `scaleX(${p})`, transformOrigin: "left", ...style }} />;
}

// KineticHeadline — heavy editorial sans headline that wipes up into view behind
// its own top edge (clip-path reveal) with a small rise. The v2 signature move.
export function KineticHeadline({ text, frame, delay = 0, size = 96, color = C.ink, italic = false, weight = 700, style }: {
  text: string; frame: number; delay?: number; size?: number; color?: string; italic?: boolean; weight?: number; style?: React.CSSProperties;
}) {
  const p = interpolate(frame - delay, [0, 22], [0, 1], { ...clampOpts, easing: easeOut });
  const ty = interpolate(p, [0, 1], [22, 0]);
  return (
    <div style={{ overflow: "hidden", paddingBottom: 6 }}>
      <div style={{
        fontFamily: SERIF, fontWeight: weight, fontStyle: italic ? "italic" : "normal",
        fontSize: size, lineHeight: 1.02, letterSpacing: -1, color,
        clipPath: `inset(0 0 ${(1 - p) * 100}% 0)`, transform: `translateY(${ty}px)`, ...style,
      }}>
        {text}
      </div>
    </div>
  );
}

// PullQuote — oversized editorial quote for a beat's key claim.
export function PullQuote({ children, frame, delay = 0, size = 60, color = C.ink, style }: {
  children: React.ReactNode; frame: number; delay?: number; size?: number; color?: string; style?: React.CSSProperties;
}) {
  const op = interpolate(frame - delay, [0, 16], [0, 1], { ...clampOpts, easing: easeOut });
  const ty = interpolate(frame - delay, [0, 18], [14, 0], clampOpts);
  return (
    <div style={{ opacity: op, transform: `translateY(${ty}px)`, fontFamily: SERIF, fontSize: size, fontWeight: 600, lineHeight: 1.12, letterSpacing: -0.5, color, ...style }}>
      {children}
    </div>
  );
}

// RedactionReveal — text under a redaction bar that slides away to expose it.
export function RedactionReveal({ children, frame, delay = 0, color = C.ink, style }: {
  children: React.ReactNode; frame: number; delay?: number; color?: string; style?: React.CSSProperties;
}) {
  const p = interpolate(frame - delay, [0, 18], [0, 1], { ...clampOpts, easing: easeOut });
  return (
    <span style={{ position: "relative", display: "inline-block", ...style }}>
      <span>{children}</span>
      <span aria-hidden style={{ position: "absolute", inset: "-2px -6px", background: color, clipPath: `inset(0 0 0 ${p * 100}%)` }} />
    </span>
  );
}

// EvidenceTag — a tied evidence label, e.g. "T1014 · CONFIRMED". Tier-toned.
export function EvidenceTag({ label, tier, frame, delay = 0, style }: {
  label: string; tier?: string; frame: number; delay?: number; style?: React.CSSProperties;
}) {
  const op = interpolate(frame - delay, [0, 10], [0, 1], clampOpts);
  const tone = tier ? CONFIDENCE_TONE[tier] ?? C.ink : C.ink;
  return (
    <span style={{ opacity: op, display: "inline-flex", alignItems: "center", gap: 10, fontFamily: GROTESK, fontSize: 16, fontWeight: 600, letterSpacing: 3, textTransform: "uppercase", color: tone, border: `1px solid ${tone}66`, padding: "6px 14px", ...style }}>
      <span style={{ width: 6, height: 6, borderRadius: "50%", background: tone }} />
      {label}{tier && tier.toUpperCase() !== String(label).toUpperCase() ? ` · ${tier}` : ""}
    </span>
  );
}

// Stamp — letterpress stamp/seal that hits the page (spring impact), rotated.
export function Stamp({ label, frame, delay = 0, color = C.alert, rotate = -7, size = 40, style }: {
  label: string; frame: number; delay?: number; color?: string; rotate?: number; size?: number; style?: React.CSSProperties;
}) {
  const { fps } = useVideoConfig();
  const s = spring({ frame: frame - delay, fps, config: { damping: 9, stiffness: 130 } });
  const op = interpolate(frame - delay, [0, 5], [0, 1], clampOpts);
  return (
    <div style={{
      opacity: op * 0.92, transform: `rotate(${rotate}deg) scale(${0.55 + s * 0.45})`,
      border: `3px solid ${color}`, color, fontFamily: GROTESK, fontWeight: 700, fontSize: size,
      letterSpacing: 4, textTransform: "uppercase", padding: "6px 18px", display: "inline-block", ...style,
    }}>
      {label}
    </div>
  );
}

// FrameTick — convenience to read the current frame in scene bodies.
export function useFrame() {
  return useCurrentFrame();
}
