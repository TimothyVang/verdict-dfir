// Editorial / forensic-dossier design tokens for the demo video.
// Warm near-black "paper", cream "ink", ONE brand accent + ONE alert accent,
// and the three confidence tiers as desaturated letterpress tones (meaning
// only — never decorative). Replaces the old GitHub-dark + rainbow palette.
export { SERIF, GROTESK, MONO } from "../../fonts";

export const C = {
  paper: "#0e0c10", // warm near-black page
  paperEdge: "#060507", // vignette darkening
  surface: "#161318", // raised exhibit panel
  ink: "#ece6da", // warm cream text (not pure white)
  inkMuted: "#8c8576", // captions, furniture
  inkFaint: "#544f48", // hairline-adjacent text
  hairline: "#2b2620", // editorial rules
  accent: "#9b59b6", // brand purple — sparing
  alert: "#d6452f", // redaction / the "evil" found
  // confidence tiers (semantic, desaturated):
  confirmed: "#7fae6e",
  inferred: "#c79a4a",
  hypothesis: "#6f93b8",
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
