"use client";

import React from "react";

// ---------------------------------------------------------------------------
// VERDICT design system — single source of truth for every polished dashboard
// panel. Ported 1:1 from scripts/make-demo-video/src/ (Remotion scenes) into a
// Remotion-free, self-contained client module. Inline styles only, matching the
// video components. GitHub-dark neutral scaffold + 5 semantic accents.
// ---------------------------------------------------------------------------

/** Color tokens. Neutral scaffold = GitHub dark; 5 semantic accents carry meaning. */
export const VERDICT = {
  bg: "#0d1117",
  surface: "#161b22",
  surfaceInset: "#0d1117",
  border: "#30363d",
  borderSubtle: "#1e2530",
  text: "#e6edf3",
  muted: "#8b949e",
  mutedDark: "#6e7681",
  faint: "#30363d",
  // Semantic accents (never use decoratively against their meaning):
  confirmed: "#2ecc71", // green  = CONFIRMED / verified / clean / pass
  inferred: "#f39c12", // amber  = INFERRED / warning / running
  hypothesis: "#3498db", // blue   = HYPOTHESIS / info / FRE-note
  accentPurple: "#9b59b6", // purple = brand / crypto / Merkle / MITRE
  accentPurpleLight: "#b17fd4",
  alertRed: "#e74c3c", // red    = ERROR / contradiction / alert / flagged
  // Per-beat section-accent extras (only place these appear):
  beatTeal: "#1abc9c",
  beatOrange: "#e67e22",
  beatSlate: "#2c3e50",
  white: "#ffffff",
  gridLine: "rgba(255,255,255,0.04)",
} as const;

/** The single font stack used across the ENTIRE UI, wordmark included.
 *  `--font-jbm` is the next/font-hosted JetBrains Mono (see app/layout.tsx);
 *  falls back to a system mono if the variable is absent. */
export const MONO =
  "var(--font-jbm), 'JetBrains Mono', 'Courier New', monospace";

/** Border-radius scale: pills/rows 6, tiles/insets/notes 8, cards/panels 10-12. */
export const RADIUS = { pill: 6, tile: 8, card: 12 } as const;

export type Confidence = "CONFIRMED" | "INFERRED" | "HYPOTHESIS";
export type ChipVariant = Confidence | "MITRE" | "ERROR";

interface ChipColors {
  bg: string;
  border: string;
  text: string;
}

/** Chip taxonomy: 15% alpha fill, solid full-accent border, full-accent text. */
export const CHIP_COLORS: Record<ChipVariant, ChipColors> = {
  CONFIRMED: { bg: "rgba(46,204,113,0.15)", border: VERDICT.confirmed, text: VERDICT.confirmed },
  INFERRED: { bg: "rgba(243,156,18,0.15)", border: VERDICT.inferred, text: VERDICT.inferred },
  HYPOTHESIS: { bg: "rgba(52,152,219,0.15)", border: VERDICT.hypothesis, text: VERDICT.hypothesis },
  MITRE: { bg: "rgba(155,89,182,0.15)", border: VERDICT.accentPurple, text: VERDICT.accentPurple },
  ERROR: { bg: "rgba(231,76,60,0.15)", border: VERDICT.alertRed, text: VERDICT.alertRed },
};

/** Confidence-label color map (used outside chips too: audit rows, terminal text). */
export const CONFIDENCE_COLOR: Record<string, string> = {
  CONFIRMED: VERDICT.confirmed,
  INFERRED: VERDICT.inferred,
  HYPOTHESIS: VERDICT.hypothesis,
};

/** Resolve a confidence string to its semantic color, falling back to muted. */
export function confidenceColor(confidence?: string): string {
  if (!confidence) return VERDICT.muted;
  return CONFIDENCE_COLOR[confidence] ?? VERDICT.muted;
}

// ---------------------------------------------------------------------------
// GridOverlay — the faint 60px white grid present on EVERY scene.
// ---------------------------------------------------------------------------

interface GridOverlayProps {
  /** 0.04 default (content scenes); 0.03 on generic title cards. */
  opacity?: number;
}

export function GridOverlay({ opacity = 0.04 }: GridOverlayProps) {
  return (
    <div
      aria-hidden
      style={{
        position: "absolute",
        inset: 0,
        pointerEvents: "none",
        opacity,
        backgroundImage:
          "linear-gradient(#fff 1px, transparent 1px), linear-gradient(90deg, #fff 1px, transparent 1px)",
        backgroundSize: "60px 60px",
      }}
    />
  );
}

// ---------------------------------------------------------------------------
// RadialGlow — purple hero glow (intro/outro/landing surfaces only).
// ---------------------------------------------------------------------------

interface RadialGlowProps {
  /** 0.18 intro, 0.14 outro. */
  alpha?: number;
  /** "50% 45%" hero default. */
  position?: string;
}

export function RadialGlow({ alpha = 0.14, position = "50% 45%" }: RadialGlowProps) {
  return (
    <div
      aria-hidden
      style={{
        position: "absolute",
        inset: 0,
        pointerEvents: "none",
        background: `radial-gradient(ellipse at ${position}, rgba(155,89,182,${alpha}) 0%, transparent 65%)`,
      }}
    />
  );
}

// ---------------------------------------------------------------------------
// ConfidenceChip / MitreChip — the most reused components.
// ---------------------------------------------------------------------------

interface ChipBaseProps {
  fontSize?: number;
  style?: React.CSSProperties;
}

function ChipBase({
  variant,
  label,
  fontSize = 18,
  style,
}: ChipBaseProps & { variant: ChipVariant; label: string }) {
  const colors = CHIP_COLORS[variant] ?? CHIP_COLORS.CONFIRMED;
  return (
    <span
      style={{
        display: "inline-block",
        background: colors.bg,
        border: `1px solid ${colors.border}`,
        borderRadius: RADIUS.pill,
        padding: "4px 14px",
        fontSize,
        fontWeight: 700,
        fontFamily: MONO,
        color: colors.text,
        letterSpacing: 1,
        ...style,
      }}
    >
      {label}
    </span>
  );
}

interface ConfidenceChipProps extends ChipBaseProps {
  confidence?: Confidence;
  /** Override the visible text; defaults to the confidence keyword itself. */
  label?: string;
}

/** CONFIRMED (green) / INFERRED (amber) / HYPOTHESIS (blue) outlined chip. */
export function ConfidenceChip({ confidence = "CONFIRMED", label, fontSize, style }: ConfidenceChipProps) {
  return <ChipBase variant={confidence} label={label ?? confidence} fontSize={fontSize} style={style} />;
}

interface MitreChipProps extends ChipBaseProps {
  /** e.g. "T1014 Rootkit" or "MITRE T1547.001". */
  technique: string;
}

/** MITRE technique chip (purple), label form "T1014 Rootkit". */
export function MitreChip({ technique, fontSize, style }: MitreChipProps) {
  return <ChipBase variant="MITRE" label={technique} fontSize={fontSize} style={style} />;
}

interface ErrorChipProps extends ChipBaseProps {
  label: string;
}

/** ERROR / contradiction / alert chip (red). */
export function ErrorChip({ label, fontSize, style }: ErrorChipProps) {
  return <ChipBase variant="ERROR" label={label} fontSize={fontSize} style={style} />;
}

// ---------------------------------------------------------------------------
// Surface — the neutral panel/card wrapper.
// ---------------------------------------------------------------------------

type SurfaceTone = "neutral" | "inset";

interface SurfaceProps {
  children: React.ReactNode;
  /** "neutral" = #161b22 panel; "inset" = #0d1117 code/quote block. */
  tone?: SurfaceTone;
  padding?: number | string;
  radius?: number;
  /** Override the border color (e.g. a semantic accent for a tinted card). */
  borderColor?: string;
  style?: React.CSSProperties;
}

/** Card/panel wrapper. Background/border/radius/padding from the design system. */
export function Surface({
  children,
  tone = "neutral",
  padding = 24,
  radius = RADIUS.card,
  borderColor = VERDICT.border,
  style,
}: SurfaceProps) {
  const background = tone === "inset" ? VERDICT.surfaceInset : VERDICT.surface;
  return (
    <div
      style={{
        background,
        border: `1px solid ${borderColor}`,
        borderRadius: radius,
        padding,
        fontFamily: MONO,
        color: VERDICT.text,
        boxSizing: "border-box",
        ...style,
      }}
    >
      {children}
    </div>
  );
}

// ---------------------------------------------------------------------------
// TintedCard — semantic accent card (purple=crypto, green=verified, etc.).
// ---------------------------------------------------------------------------

interface TintedCardProps {
  children: React.ReactNode;
  /** Semantic accent color; fill = 10% alpha, border = soft 0.55 by default. */
  accent: string;
  padding?: number | string;
  radius?: number;
  /** true = soft 1.5px {accent}55 border; false = strong solid 1.5px border. */
  soft?: boolean;
  style?: React.CSSProperties;
}

/** Semantic tinted card: faint accent fill + accent border. Color encodes meaning. */
export function TintedCard({ children, accent, padding = 20, radius = RADIUS.card, soft = true, style }: TintedCardProps) {
  return (
    <div
      style={{
        background: `${accent}1a`,
        border: `1.5px solid ${soft ? `${accent}8c` : accent}`,
        borderRadius: radius,
        padding,
        fontFamily: MONO,
        color: VERDICT.text,
        boxSizing: "border-box",
        ...style,
      }}
    >
      {children}
    </div>
  );
}

// ---------------------------------------------------------------------------
// PanelTitle — the scene/card H1 + muted subtitle pair.
// ---------------------------------------------------------------------------

interface PanelTitleProps {
  title: string;
  subtitle?: string;
  /** H1 size. cardHeading 16-22, sceneTitle 48-52. */
  size?: number;
  /** H1 letter-spacing (sceneTitle uses 2, archTitle 4, default 0). */
  letterSpacing?: number;
  style?: React.CSSProperties;
}

/** Title block: weight-800 H1 in text color with a muted subtitle 6-8px below. */
export function PanelTitle({ title, subtitle, size = 22, letterSpacing = 0, style }: PanelTitleProps) {
  return (
    <div style={{ fontFamily: MONO, ...style }}>
      <div style={{ fontSize: size, fontWeight: 800, color: VERDICT.text, letterSpacing, lineHeight: 1.15 }}>
        {title}
      </div>
      {subtitle && (
        <div style={{ fontSize: 20, fontWeight: 400, color: VERDICT.muted, marginTop: 6 }}>{subtitle}</div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// MonoLine — a single mono text row helper.
// ---------------------------------------------------------------------------

interface MonoLineProps {
  children: React.ReactNode;
  color?: string;
  fontSize?: number;
  fontWeight?: number;
  letterSpacing?: number;
  lineHeight?: number;
  style?: React.CSSProperties;
}

/** A single mono text row (terminal lines, list rows, meta rows). */
export function MonoLine({
  children,
  color = VERDICT.text,
  fontSize = 16,
  fontWeight = 400,
  letterSpacing = 0,
  lineHeight = 1.7,
  style,
}: MonoLineProps) {
  return (
    <div style={{ fontFamily: MONO, color, fontSize, fontWeight, letterSpacing, lineHeight, ...style }}>
      {children}
    </div>
  );
}

// ---------------------------------------------------------------------------
// HashBead — the signature hash-chain pill: kind  prev → hash  CONFIRMED.
// ---------------------------------------------------------------------------

interface HashBeadProps {
  /** Current record hash (mono, 11px #8b949e). */
  hash: string;
  /** Previous record hash (mono, 11px #30363d). */
  prevHash: string;
  /** Audit record kind, rendered in purple (#9b59b6). */
  kind?: string;
  /** Right-aligned confidence label, colored by semantic map. */
  confidence?: string;
  /** Purple-tinted highlight (terminal manifest_finalize record). */
  highlight?: boolean;
  /** Dim to 0.35 opacity. */
  dim?: boolean;
  style?: React.CSSProperties;
}

/** Small mono hash-chain pill row: `kind  prev: <hash> → <hash>  CONFIDENCE`. */
export function HashBead({ hash, prevHash, kind, confidence, highlight, dim, style }: HashBeadProps) {
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: 12,
        padding: "8px 16px",
        borderRadius: RADIUS.pill,
        background: highlight ? "rgba(155,89,182,0.12)" : "rgba(22,27,34,0.8)",
        border: highlight ? "1px solid rgba(155,89,182,0.5)" : `1px solid ${VERDICT.border}`,
        opacity: dim ? 0.35 : 1,
        fontFamily: MONO,
        fontSize: 14,
        ...style,
      }}
    >
      {kind && <span style={{ color: VERDICT.accentPurple, minWidth: 160 }}>{kind}</span>}
      <span style={{ color: VERDICT.faint, fontSize: 11 }}>prev:</span>
      <span style={{ color: VERDICT.faint, fontSize: 11 }}>{prevHash}</span>
      <span style={{ color: VERDICT.faint, fontSize: 11 }}>→</span>
      <span style={{ color: VERDICT.muted, fontSize: 11 }}>{hash}</span>
      {confidence && (
        <span style={{ marginLeft: "auto", color: confidenceColor(confidence), fontWeight: 700, fontSize: 12 }}>
          {confidence}
        </span>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// BrandMark — circular gavel + scales + sigstore-check logo (from OutroScene).
// ---------------------------------------------------------------------------

interface BrandMarkProps {
  /** Rendered pixel size (square). viewBox stays 0 0 80 80. */
  size?: number;
  /** Show the "VERDICT" wordmark beside the mark. */
  withWordmark?: boolean;
  /** Show the "DFIR at machine speed." tagline under the wordmark. */
  withTagline?: boolean;
  /** Lay the mark + wordmark vertically (hero) instead of inline. */
  vertical?: boolean;
  style?: React.CSSProperties;
}

/** Inline-SVG gavel + scales + sigstore green-check brand mark, ported from OutroScene. */
export function BrandMark({
  size = 96,
  withWordmark = false,
  withTagline = false,
  vertical = false,
  style,
}: BrandMarkProps) {
  const wordmarkSize = Math.max(18, Math.round(size * 0.45));
  return (
    <div
      style={{
        display: "flex",
        flexDirection: vertical ? "column" : "row",
        alignItems: "center",
        gap: vertical ? 12 : 14,
        ...style,
      }}
    >
      <svg width={size} height={size} viewBox="0 0 80 80" xmlns="http://www.w3.org/2000/svg" aria-label="VERDICT logo">
        <circle cx="40" cy="40" r="38" fill="#161b22" stroke="#9b59b6" strokeWidth="2" />
        <rect x="14" y="18" width="38" height="17" rx="4" fill="#9b59b6" />
        <rect x="22" y="18" width="38" height="6" rx="3" fill="#b17fd4" opacity="0.4" />
        <rect x="31" y="29" width="5" height="30" rx="2.5" fill="#30363d" transform="rotate(-30 33 44)" />
        <ellipse cx="20" cy="58" rx="8" ry="5" fill="none" stroke="#8b949e" strokeWidth="2.5" />
        <ellipse cx="36" cy="58" rx="8" ry="5" fill="none" stroke="#8b949e" strokeWidth="2.5" />
        <circle cx="56" cy="58" r="8" fill="#2ecc71" opacity="0.9" />
        <polyline
          points="52,58 55,61 61,54"
          fill="none"
          stroke="#0d1117"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      </svg>
      {withWordmark && (
        <div style={{ display: "flex", flexDirection: "column", alignItems: vertical ? "center" : "flex-start" }}>
          <span style={{ fontFamily: MONO, fontSize: wordmarkSize, fontWeight: 800, color: VERDICT.text, letterSpacing: 10 }}>
            VERDICT
          </span>
          {withTagline && (
            <span
              style={{
                fontFamily: MONO,
                fontSize: Math.max(14, Math.round(wordmarkSize * 0.25)),
                fontWeight: 400,
                color: VERDICT.muted,
                letterSpacing: 4,
                marginTop: 8,
              }}
            >
              DFIR at machine speed.
            </span>
          )}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Watermark — bottom-right gavel + VERDICT mark on all content scenes.
// ---------------------------------------------------------------------------

/** Faint bottom-right brand watermark (opacity 0.22) for content scenes. */
export function Watermark() {
  return (
    <div
      aria-hidden
      style={{
        position: "absolute",
        bottom: 32,
        right: 48,
        display: "flex",
        alignItems: "center",
        gap: 10,
        opacity: 0.22,
        pointerEvents: "none",
      }}
    >
      <BrandMark size={28} />
      <span style={{ fontFamily: MONO, fontSize: 15, color: VERDICT.text, fontWeight: 700, letterSpacing: 3 }}>
        VERDICT
      </span>
    </div>
  );
}