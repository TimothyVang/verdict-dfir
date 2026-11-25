import React from "react";
import { VERDICT, MONO, Grain, Vignette, CaseFurnitureHeader, CaseFurnitureFooter } from "@/lib/verdict-ui";

/**
 * CaseShell — the editorial "forensic case file" frame every route sits in.
 * Warm-paper background, fixed film-grain + vignette atmosphere overlays, and a
 * running case-file header/footer. Mirrors the demo's Scene.tsx furniture
 * (scripts/make-demo-video/src/components/shared/Scene.tsx) for the live app.
 *
 * Atmosphere overlays are static and pointer-events:none, so they never
 * interfere with the dashboard's interactivity or repaint on SSE updates.
 */
export default function CaseShell({ children }: { children: React.ReactNode }) {
  return (
    <div
      style={{
        position: "relative",
        minHeight: "100vh",
        display: "flex",
        flexDirection: "column",
        background: VERDICT.bg,
        color: VERDICT.text,
        fontFamily: MONO,
      }}
    >
      <Vignette />
      <Grain />
      <CaseFurnitureHeader />
      <div style={{ position: "relative", zIndex: 1, flex: 1 }}>{children}</div>
      <CaseFurnitureFooter />
    </div>
  );
}
