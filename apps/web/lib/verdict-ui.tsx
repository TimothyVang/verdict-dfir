"use client";

import React from "react";

// ---------------------------------------------------------------------------
// VERDICT v2 brand system — single source of truth for every polished dashboard
// panel. Mirrors the brand bible at
// VERDICT_DFIR_SVG_Assets_v2/verdict-brand-board-reconstructed.png and the
// Remotion tokens in scripts/make-demo-video/src/components/shared/editorial.ts.
// ---------------------------------------------------------------------------

/** Color tokens — v2 editorial evidence palette. Use one semantic accent per
 *  composition: Seafoam=verified, Coral=rejected, Butter=review, Cobalt/Lilac=brand. */
export const VERDICT = {
  bg: "#101426", // Midnight Ink
  surface: "#12131A", // Near Black raised panel
  surfaceInset: "#0C1020", // darker code/quote block
  border: "#27304A", // editorial hairline on dark fields
  borderSubtle: "#1B2136", // fainter hairline
  text: "#F5F1E8", // Paper Cream ink
  muted: "#B8A8FF", // Soft Lilac captions / furniture
  mutedDark: "#7F789C", // subdued secondary text
  faint: "#27304A",
  // Semantic accents (never use decoratively against their meaning):
  confirmed: "#73D9C2", // Seafoam = VERIFIED / replay matched / pass
  inferred: "#FFD76A", // Butter Yellow = review / note / attention
  hypothesis: "#4D5DFF", // Electric Cobalt = hypothesis / info / brand-active
  accentPurple: "#4D5DFF", // legacy key: Electric Cobalt brand accent
  accentPurpleLight: "#B8A8FF", // Soft Lilac secondary brand accent
  alertRed: "#FF6257", // Signal Coral = rejected / contradiction / failure
  // Per-beat section-accent extras (only place these appear):
  beatTeal: "#73D9C2",
  beatOrange: "#FFD76A",
  beatSlate: "#B8A8FF",
  white: "#F5F1E8",
  gridLine: "rgba(245,241,232,0.04)",
} as const;

/** The single font stack used across the ENTIRE UI, wordmark included.
 *  `--font-jbm` is the next/font-hosted JetBrains Mono (see app/layout.tsx);
 *  falls back to a system mono if the variable is absent. */
export const MONO =
  "var(--font-jbm), 'JetBrains Mono', 'Courier New', monospace";

/** Legacy SERIF alias kept for call-site compatibility. In v2 it resolves to the
 *  heavy editorial sans, not a serif, matching the brand board. */
export const SERIF =
  "var(--font-archivo), 'Archivo', Impact, system-ui, sans-serif";

/** Editorial grotesque (Archivo) — kickers, labels, nav, furniture, section
 *  headings, chips. The "furniture" voice between serif headlines and mono data. */
export const GROTESK =
  "var(--font-archivo), 'Archivo', system-ui, -apple-system, sans-serif";

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
  CONFIRMED: { bg: "rgba(115,217,194,0.15)", border: VERDICT.confirmed, text: VERDICT.confirmed },
  INFERRED: { bg: "rgba(255,215,106,0.15)", border: VERDICT.inferred, text: VERDICT.inferred },
  HYPOTHESIS: { bg: "rgba(77,93,255,0.15)", border: VERDICT.hypothesis, text: VERDICT.accentPurpleLight },
  MITRE: { bg: "rgba(77,93,255,0.15)", border: VERDICT.accentPurple, text: VERDICT.accentPurpleLight },
  ERROR: { bg: "rgba(255,98,87,0.15)", border: VERDICT.alertRed, text: VERDICT.alertRed },
};

/** Confidence-label color map (used outside chips too: audit rows, terminal text). */
export const CONFIDENCE_COLOR: Record<string, string> = {
  CONFIRMED: VERDICT.confirmed,
  INFERRED: VERDICT.inferred,
  HYPOTHESIS: VERDICT.accentPurpleLight,
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
          "linear-gradient(rgba(245,241,232,0.65) 1px, transparent 1px), linear-gradient(90deg, rgba(245,241,232,0.65) 1px, transparent 1px)",
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
          background: `radial-gradient(ellipse at ${position}, rgba(77,93,255,${alpha}) 0%, rgba(184,168,255,${alpha * 0.45}) 35%, transparent 65%)`,
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

/** Title block: heavy editorial H1 in ink with a muted MONO subtitle 6-8px below.
 *  Title uses Archivo display; subtitle stays JetBrains Mono (it's metadata). */
export function PanelTitle({ title, subtitle, size = 28, letterSpacing = -0.5, style }: PanelTitleProps) {
  return (
    <div style={style}>
      <div style={{ fontFamily: SERIF, fontSize: size, fontWeight: 600, color: VERDICT.text, letterSpacing, lineHeight: 1.1 }}>
        {title}
      </div>
      {subtitle && (
        <div style={{ fontFamily: MONO, fontSize: 16, fontWeight: 400, color: VERDICT.muted, marginTop: 8, letterSpacing: 0.5 }}>
          {subtitle}
        </div>
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
  /** Audit record kind, rendered in Electric Cobalt. */
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
        background: highlight ? "rgba(77,93,255,0.12)" : "rgba(18,19,26,0.84)",
        border: highlight ? "1px solid rgba(77,93,255,0.5)" : `1px solid ${VERDICT.border}`,
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
// BrandMark — v2 evidence-path V: cobalt and lilac branches converge into one
// decision node. Keep in sync with VERDICT_DFIR_SVG_Assets_v2/svg_assets.
// ---------------------------------------------------------------------------

interface BrandMarkProps {
  /** Rendered pixel size (square). viewBox stays 0 0 80 80. */
  size?: number;
  /** Show the "VERDICT" wordmark beside the mark. */
  withWordmark?: boolean;
  /** Show the brand-bible tagline under the wordmark. */
  withTagline?: boolean;
  /** Lay the mark + wordmark vertically (hero) instead of inline. */
  vertical?: boolean;
  style?: React.CSSProperties;
}

/** Inline SVG evidence-path V mark, sized to fit the existing square slot. */
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
      <svg width={size} height={size} viewBox="0 0 120 136" xmlns="http://www.w3.org/2000/svg" aria-label="VERDICT logo">
        <path d="M17 18 L31 12 L63 91 L50 103 Z" fill={VERDICT.accentPurple} />
        <path d="M103 18 L89 12 L57 91 L70 103 Z" fill={VERDICT.accentPurpleLight} />
        <circle cx="24" cy="18" r="14" fill={VERDICT.accentPurple} />
        <circle cx="24" cy="18" r="7" fill={VERDICT.text} />
        <circle cx="96" cy="18" r="14" fill={VERDICT.accentPurpleLight} />
        <circle cx="96" cy="18" r="7" fill={VERDICT.text} />
        <circle cx="60" cy="96" r="15" fill={VERDICT.text} />
        <circle cx="60" cy="96" r="10" fill={VERDICT.bg} />
        <rect x="56" y="108" width="8" height="28" rx="4" fill={VERDICT.bg} />
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
              Evidence, not assumption.
            </span>
          )}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Watermark — bottom-right check-as-V + VERDICT mark on all content scenes.
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

// ===========================================================================
// EDITORIAL KIT — DOM/CSS ports of the demo's editorial-ui primitives
// (scripts/make-demo-video/src/components/shared/editorial-ui.tsx). Remotion's
// frame-driven animation is replaced by static styling + the global
// `.verdict-reveal` CSS class (see globals.css), which is reduced-motion gated.
// ===========================================================================

interface KickerProps {
  children: React.ReactNode;
  /** Default brand purple; pass confidenceColor(tier) for a semantic kicker. */
  color?: string;
  style?: React.CSSProperties;
}

/** Small uppercase grotesque label that sits above a headline. */
export function Kicker({ children, color = VERDICT.accentPurple, style }: KickerProps) {
  return (
    <div
      style={{
        fontFamily: GROTESK,
        fontSize: 13,
        fontWeight: 600,
        letterSpacing: 5,
        textTransform: "uppercase",
        color,
        ...style,
      }}
    >
      {children}
    </div>
  );
}

interface RuleLineProps {
  color?: string;
  thickness?: number;
  width?: number | string;
  style?: React.CSSProperties;
}

/** Editorial hairline rule. */
export function RuleLine({ color = VERDICT.border, thickness = 1, width = "100%", style }: RuleLineProps) {
  return <div aria-hidden style={{ width, height: thickness, background: color, ...style }} />;
}

interface SerifHeadlineProps {
  children: React.ReactNode;
  /** Display sizes only (>=22px). */
  size?: number;
  color?: string;
  italic?: boolean;
  weight?: number;
  style?: React.CSSProperties;
}

/** Heavy editorial sans headline (mastheads/H1). Static port of KineticHeadline. */
export function SerifHeadline({ children, size = 40, color = VERDICT.text, italic = false, weight = 600, style }: SerifHeadlineProps) {
  return (
    <div
      style={{
        fontFamily: SERIF,
        fontSize: size,
        fontWeight: weight,
        fontStyle: italic ? "italic" : "normal",
        color,
        lineHeight: 1.04,
        letterSpacing: -0.5,
        ...style,
      }}
    >
      {children}
    </div>
  );
}

interface PullQuoteProps {
  children: React.ReactNode;
  size?: number;
  color?: string;
  style?: React.CSSProperties;
}

/** Serif pull-quote / lede. */
export function PullQuote({ children, size = 30, color = VERDICT.text, style }: PullQuoteProps) {
  return (
    <blockquote style={{ fontFamily: SERIF, fontSize: size, fontWeight: 600, color, lineHeight: 1.15, margin: 0, ...style }}>
      {children}
    </blockquote>
  );
}

interface EvidenceTagProps {
  label: string;
  /** CONFIRMED/INFERRED/HYPOTHESIS → semantic tone; omit for ink. */
  tier?: Confidence | string;
  fontSize?: number;
  style?: React.CSSProperties;
}

/** Editorial outline chip: a dot + uppercase grotesque label in a thin tone
 *  border (the case-file form, distinct from the filled ConfidenceChip pill). */
export function EvidenceTag({ label, tier, fontSize = 13, style }: EvidenceTagProps) {
  const tone = tier ? CONFIDENCE_COLOR[tier] ?? VERDICT.text : VERDICT.text;
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 8,
        fontFamily: GROTESK,
        fontSize,
        fontWeight: 600,
        letterSpacing: 2.5,
        textTransform: "uppercase",
        color: tone,
        border: `1px solid ${tone}66`,
        borderRadius: 4,
        padding: "5px 12px",
        ...style,
      }}
    >
      <span aria-hidden style={{ width: 6, height: 6, borderRadius: "50%", background: tone }} />
      {label}
    </span>
  );
}

interface StampProps {
  label: string;
  color?: string;
  rotate?: number;
  fontSize?: number;
  style?: React.CSSProperties;
}

/** Letterpress stamp (rotated outline). Default alert red; pass confirmed/etc. */
export function Stamp({ label, color = VERDICT.alertRed, rotate = -7, fontSize = 18, style }: StampProps) {
  return (
    <span
      style={{
        display: "inline-block",
        fontFamily: GROTESK,
        fontSize,
        fontWeight: 700,
        letterSpacing: 4,
        textTransform: "uppercase",
        color,
        border: `3px solid ${color}`,
        borderRadius: 6,
        padding: "6px 16px",
        transform: `rotate(${rotate}deg)`,
        ...style,
      }}
    >
      {label}
    </span>
  );
}

interface SectionHeadingProps {
  children: React.ReactNode;
  /** Optional right-aligned mono meta (e.g. an event count). */
  right?: React.ReactNode;
  style?: React.CSSProperties;
}

/** Grotesque uppercase section label + hairline beneath. Replaces bare <h2>. */
export function SectionHeading({ children, right, style }: SectionHeadingProps) {
  return (
    <div style={{ marginBottom: 14, ...style }}>
      <div style={{ display: "flex", alignItems: "baseline", justifyContent: "space-between", marginBottom: 8 }}>
        <span style={{ fontFamily: GROTESK, fontSize: 13, fontWeight: 600, letterSpacing: 3, textTransform: "uppercase", color: VERDICT.muted }}>
          {children}
        </span>
        {right != null && <span style={{ fontFamily: MONO, fontSize: 12, color: VERDICT.mutedDark }}>{right}</span>}
      </div>
      <RuleLine />
    </div>
  );
}

// --- Atmosphere overlays (fixed, static, GPU-cheap) ------------------------

// A single static SVG-noise tile (feTurbulence, desaturated). NOT frame-animated
// — it composites once and never repaints on SSE re-renders. # and % encoded.
const GRAIN_DATA_URI =
  "data:image/svg+xml,%3Csvg%20xmlns='http://www.w3.org/2000/svg'%20width='300'%20height='300'%3E%3Cfilter%20id='n'%3E%3CfeTurbulence%20type='fractalNoise'%20baseFrequency='0.85'%20numOctaves='2'%20stitchTiles='stitch'/%3E%3CfeColorMatrix%20type='saturate'%20values='0'/%3E%3C/filter%3E%3Crect%20width='100%25'%20height='100%25'%20filter='url(%23n)'/%3E%3C/svg%3E";

/** Fixed film-grain overlay (mix-blend overlay). pointerEvents none. */
export function Grain({ opacity = 0.05 }: { opacity?: number }) {
  return (
    <div
      aria-hidden
      style={{
        position: "fixed",
        inset: 0,
        zIndex: 60,
        pointerEvents: "none",
        opacity,
        mixBlendMode: "overlay",
        backgroundImage: `url("${GRAIN_DATA_URI}")`,
        backgroundSize: "300px 300px",
      }}
    />
  );
}

/** Fixed vignette overlay darkening toward the paper edge. pointerEvents none. */
export function Vignette({ strength = 0.55 }: { strength?: number }) {
  return (
    <div
      aria-hidden
      style={{
        position: "fixed",
        inset: 0,
        zIndex: 55,
        pointerEvents: "none",
        background: `radial-gradient(ellipse 92% 86% at 50% 42%, transparent 42%, ${VERDICT.bg} 100%)`,
        opacity: strength,
      }}
    />
  );
}

// --- Case-file running furniture (in-flow header/footer bands) --------------

/** Running case-file header band (top of every page). */
export function CaseFurnitureHeader() {
  const label = {
    fontFamily: GROTESK,
    fontSize: 12,
    fontWeight: 600,
    letterSpacing: 3,
    textTransform: "uppercase" as const,
    color: VERDICT.muted,
  };
  return (
    <div style={{ padding: "14px 32px 0", position: "relative", zIndex: 1 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", maxWidth: 1600, margin: "0 auto", ...label }}>
        <span>VERDICT — Truth in the Trace</span>
        <span style={{ letterSpacing: 4 }}>Show Me the Evidence</span>
      </div>
      <div style={{ maxWidth: 1600, margin: "10px auto 0", height: 1, background: VERDICT.border }} />
    </div>
  );
}

/** Running case-file footer band (bottom of every page). */
export function CaseFurnitureFooter() {
  const label = {
    fontFamily: GROTESK,
    fontSize: 12,
    fontWeight: 600,
    letterSpacing: 3,
    textTransform: "uppercase" as const,
    color: VERDICT.mutedDark,
  };
  return (
    <div style={{ padding: "0 32px 20px", marginTop: 48, position: "relative", zIndex: 1 }}>
      <div style={{ maxWidth: 1600, margin: "0 auto 10px", height: 1, background: VERDICT.border }} />
      <div style={{ display: "flex", justifyContent: "space-between", maxWidth: 1600, margin: "0 auto", ...label }}>
        <span>Evidence over assumption</span>
        <span>Reproducible · transparent · defensible</span>
      </div>
    </div>
  );
}
