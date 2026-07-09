import React from "react";
import { AbsoluteFill, Img, staticFile } from "remotion";
import { BODY, CONDENSED, GROTESK, HAND, MONO } from "../fonts";

// Brand-system proof v3 — Paper-Cream "annotated case file" editorial page.
// Applies the independent critic panel's fixes vs v2:
//   1. Headline in Archivo NARROW Bold (condensed, weight 700) — matches the
//      board's bold-condensed "TRUTH IN THE TRACE." specimen (v2 used ArchivoBlack,
//      too heavy and too wide).
//   2. Data block is near-black, stacked key:value, 4 lines (v2 was muted-gray,
//      inline, 3 fields — it dropped `result: match`).
//   3. ONE semantic accent per composition (brand rule): Seafoam is the only
//      semantic color (verify state + evidence-path check); Cobalt/Lilac are brand
//      furniture. No coral/butter/off-palette-blue rainbow chip legend.
//   4. No thumbnail-frame (that's a video-thumbnail device) — editorial panel
//      dividers like the brand board, and the real wordmark as masthead.
//   5. Stronger (still restrained) paper grain across the cream field.
// Tactile marks are the actual VERDICT_DFIR_SVG_Assets_v2 vector assets.

const CREAM = "#F5F1E8";
const INK = "#101426"; // Midnight Ink — headline
const NEAR_BLACK = "#12131A"; // Near Black — body/data on light
const PAPER_MUTED = "#6B6459";
const HAIRLINE = "#CFC9BD";
const COBALT = "#4D5DFF";

const PAPER_GRAIN =
  "data:image/svg+xml,%3Csvg%20xmlns='http://www.w3.org/2000/svg'%20width='200'%20height='200'%3E%3Cfilter%20id='n'%3E%3CfeTurbulence%20type='fractalNoise'%20baseFrequency='1.1'%20numOctaves='2'%20stitchTiles='stitch'/%3E%3CfeColorMatrix%20type='saturate'%20values='0'/%3E%3C/filter%3E%3Crect%20width='100%25'%20height='100%25'%20filter='url(%23n)'/%3E%3C/svg%3E";

const L = 104; // left margin
const R = 104; // right margin

export function BrandProof() {
  return (
    <AbsoluteFill style={{ backgroundColor: CREAM }}>
      {/* Restrained paper grain */}
      <div
        aria-hidden
        style={{
          position: "absolute",
          inset: 0,
          backgroundImage: `url("${PAPER_GRAIN}")`,
          backgroundSize: "200px 200px",
          opacity: 0.12,
          mixBlendMode: "soft-light",
          pointerEvents: "none",
        }}
      />

      {/* Masthead — real wordmark (left) + case slug and the single semantic
          VERIFIED accent (right). */}
      <div style={{ position: "absolute", left: L, right: R, top: 64, display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
        <Img src={staticFile("brand/verdict-wordmark.svg")} style={{ height: 58 }} />
        <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: 14 }}>
          <div style={{ fontFamily: GROTESK, fontSize: 18, fontWeight: 700, letterSpacing: 3, textTransform: "uppercase", color: PAPER_MUTED }}>
            Case File · № 2024-0412
          </div>
          <Img src={staticFile("brand/verdict-badge-verified.svg")} style={{ height: 40 }} />
        </div>
      </div>

      {/* Panel divider under masthead */}
      <div style={{ position: "absolute", left: L, right: R, top: 156, height: 2, background: HAIRLINE }} />

      {/* Kicker (single brand accent) + UPPERCASE condensed headline */}
      <div style={{ position: "absolute", left: L, top: 196 }}>
        <div style={{ fontFamily: GROTESK, fontSize: 19, fontWeight: 700, letterSpacing: 5, textTransform: "uppercase", color: COBALT }}>
          Digital Forensics · Incident Response
        </div>
        <div style={{ fontFamily: CONDENSED, fontSize: 176, fontWeight: 700, lineHeight: 0.86, letterSpacing: 1, color: INK, marginTop: 10, textTransform: "uppercase", transform: "scaleX(1.13)", transformOrigin: "left top" }}>
          Truth in
          <br />
          the trace.
        </div>
      </div>

      {/* Panel divider under headline */}
      <div style={{ position: "absolute", left: L, right: R, top: 556, height: 2, background: HAIRLINE }} />

      {/* Vertical column divider */}
      <div style={{ position: "absolute", left: 928, top: 596, width: 1, height: 372, background: HAIRLINE }} />

      {/* Left column — lead paragraph (Inter), evidence-path, near-black stacked data */}
      <div style={{ position: "absolute", left: L, top: 600, width: 760 }}>
        <div style={{ fontFamily: BODY, fontSize: 30, lineHeight: 1.5, color: NEAR_BLACK, fontWeight: 400, maxWidth: 700 }}>
          We test findings the way the evidence was created. Reproducible.
          Transparent. Defensible.
        </div>
        <Img src={staticFile("brand/verdict-evidence-path.svg")} style={{ width: 560, marginTop: 34, display: "block" }} />
        <div style={{ fontFamily: MONO, fontSize: 20, lineHeight: 1.65, color: NEAR_BLACK, marginTop: 30, whiteSpace: "pre" }}>
          {"case_id: 2024-0412\nartifact: tool_call.exe\nresult: match\nverdict: verified"}
        </div>
      </div>

      {/* Right column — the tactile paper-note sticker + one handwritten margin note */}
      <div style={{ position: "absolute", left: 992, top: 592 }}>
        <Img src={staticFile("brand/verdict-sticker-dont-trust.svg")} style={{ width: 424, display: "block", transform: "rotate(-3deg)" }} />
        <div style={{ fontFamily: HAND, fontSize: 46, color: COBALT, transform: "rotate(-4deg)", marginTop: 20, marginLeft: 30 }}>
          show me the evidence
        </div>
      </div>
    </AbsoluteFill>
  );
}
