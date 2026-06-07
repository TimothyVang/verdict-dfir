// Reveal-pacing helper.
//
// The scenes were authored with small design-time reveal delays (a handful of
// frames apart), so every beat finished animating in its first few seconds and
// then held a frozen frame for the rest of its runtime. `spread` remaps a raw
// delay onto the beat's full frame budget: [startFrame, durationInFrames -
// holdFrames]. Content now reveals across the whole narration instead of
// freezing at ~25%, leaving only a short hold before the cross-fade.

export function spread(
  rawDelay: number,
  rawMin: number,
  rawMax: number,
  durationInFrames: number,
  startFrame = 24,
  holdFrames = 200,
): number {
  if (rawMax <= rawMin) return startFrame;
  const end = Math.max(startFrame + 1, durationInFrames - holdFrames);
  const t = (rawDelay - rawMin) / (rawMax - rawMin);
  return startFrame + t * (end - startFrame);
}
