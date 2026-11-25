import React from "react";
import { useCurrentFrame } from "remotion";
import { C } from "./editorial";

// Film grain — animated fractal-noise overlay that replaces the old tech-grid.
// The seed shifts every couple of frames so the grain shimmers like real film.
export function Grain({ opacity = 0.07 }: { opacity?: number }) {
  const frame = useCurrentFrame();
  const seed = frame % 6;
  const id = `grain-${seed}`;
  return (
    <svg
      aria-hidden
      style={{
        position: "absolute",
        inset: 0,
        width: "100%",
        height: "100%",
        pointerEvents: "none",
        opacity,
        mixBlendMode: "overlay",
      }}
    >
      <filter id={id}>
        <feTurbulence
          type="fractalNoise"
          baseFrequency="0.85"
          numOctaves={2}
          seed={seed}
          stitchTiles="stitch"
        />
        <feColorMatrix type="saturate" values="0" />
      </filter>
      <rect width="100%" height="100%" filter={`url(#${id})`} />
    </svg>
  );
}

// Soft vignette — darkens the edges so the frame reads as a lit page, not a flat slab.
export function Vignette({ strength = 0.55 }: { strength?: number }) {
  return (
    <div
      aria-hidden
      style={{
        position: "absolute",
        inset: 0,
        pointerEvents: "none",
        background: `radial-gradient(ellipse 85% 80% at 50% 42%, transparent 38%, ${C.paperEdge} 100%)`,
        opacity: strength,
      }}
    />
  );
}
