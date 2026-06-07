import React from "react";
import { AbsoluteFill, interpolate, useCurrentFrame, useVideoConfig } from "remotion";
import { C, GROTESK, MARGIN } from "./editorial";
import { Grain, Vignette } from "./Grain";

// CameraDrift — wraps the scene body in a slow, continuous translate+scale so
// the frame breathes (parallax life) instead of sitting dead-still. ~1.5% over
// the whole beat. The opposite of the old "everything pops in place" feel.
function CameraDrift({ children, amount = 1.5 }: { children: React.ReactNode; amount?: number }) {
  const frame = useCurrentFrame();
  const { durationInFrames } = useVideoConfig();
  const p = durationInFrames > 0 ? frame / durationInFrames : 0;
  const scale = 1 + (amount / 100) * p;
  const tx = interpolate(p, [0, 1], [amount * 3, -amount * 3]);
  const ty = interpolate(p, [0, 1], [amount * 1.5, -amount * 1.5]);
  return (
    <AbsoluteFill style={{ transform: `scale(${scale}) translate(${tx}px, ${ty}px)`, transformOrigin: "50% 50%" }}>
      {children}
    </AbsoluteFill>
  );
}

// CaseFurniture — running magazine header/footer (case no. + section + page).
// Replaces the bottom-right watermark with real editorial furniture.
function CaseFurniture({ page, total, caption }: { page: number; total: number; caption: string }) {
  const label = {
    fontFamily: GROTESK,
    fontSize: 17,
    fontWeight: 600,
    letterSpacing: 3,
    textTransform: "uppercase" as const,
    color: C.inkMuted,
  };
  return (
    <>
      <div style={{ position: "absolute", top: 54, left: MARGIN, right: MARGIN, display: "flex", justifyContent: "space-between", alignItems: "baseline", ...label }}>
        <span>Verdict — Case №1492</span>
        <span style={{ fontSize: 15, letterSpacing: 4 }}>A Forensic Case File</span>
      </div>
      <div style={{ position: "absolute", top: 86, left: MARGIN, right: MARGIN, height: 1, background: C.hairline }} />
      <div style={{ position: "absolute", bottom: 54, left: MARGIN, right: MARGIN, height: 1, background: C.hairline }} />
      <div style={{ position: "absolute", bottom: 30, left: MARGIN, right: MARGIN, display: "flex", justifyContent: "space-between", ...label, fontSize: 15, letterSpacing: 2 }}>
        <span>{caption}</span>
        <span>{String(page).padStart(2, "0")} / {String(total).padStart(2, "0")}</span>
      </div>
    </>
  );
}

interface SceneProps {
  page: number;
  caption: string;
  children: React.ReactNode;
  total?: number;
  drift?: boolean;
  furniture?: boolean;
}

// Scene — the shared shell every beat sits in: warm paper, grain, vignette,
// camera drift, and the running furniture. Scenes only supply their body.
export function Scene({ page, caption, children, total = 10, drift = true, furniture = true }: SceneProps) {
  const body = (
    <>
      {children}
      {furniture && <CaseFurniture page={page} total={total} caption={caption} />}
    </>
  );
  return (
    <AbsoluteFill style={{ backgroundColor: C.paper, color: C.ink }}>
      {drift ? <CameraDrift>{body}</CameraDrift> : body}
      <Vignette />
      <Grain />
    </AbsoluteFill>
  );
}
