// VERDICT v2 demo-video design tokens.
// Mirrors VERDICT_DFIR_SVG_Assets_v2/verdict-brand-board-reconstructed.png:
// Midnight Ink, Paper Cream, Electric Cobalt, Soft Lilac, Seafoam, Signal Coral,
// and Butter Yellow. Semantic colors carry meaning and should not be decorative.
export { SERIF, GROTESK, MONO } from "../../fonts";

export const C = {
  paper: "#101426", // Midnight Ink
  paperEdge: "#080b18", // vignette darkening
  surface: "#12131A", // Near Black raised exhibit panel
  ink: "#F5F1E8", // Paper Cream text
  inkMuted: "#B8A8FF", // Soft Lilac captions, furniture
  inkFaint: "#7F789C", // subdued secondary text
  hairline: "#27304A", // editorial rules
  accent: "#4D5DFF", // Electric Cobalt brand
  alert: "#FF6257", // Signal Coral — rejected / flagged
  // confidence tiers (semantic):
  confirmed: "#73D9C2",
  inferred: "#FFD76A",
  hypothesis: "#4D5DFF",
} as const;

export const CONFIDENCE_TONE: Record<string, string> = {
  CONFIRMED: C.confirmed,
  INFERRED: C.inferred,
  HYPOTHESIS: C.hypothesis,
};

// Editorial easing — a confident ease-out for reveals, an ease-in-out for drift.
export const EASE_OUT = [0.16, 1, 0.3, 1] as const;
export const EASE_IO = [0.65, 0, 0.35, 1] as const;

// Layout — 1920×1080 canvas.
export const MARGIN = 130; // generous editorial side margin
export const CANVAS_W = 1920;
export const CANVAS_H = 1080;
