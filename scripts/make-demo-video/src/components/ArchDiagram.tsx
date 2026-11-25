import React from "react";
import { interpolate, useCurrentFrame, useVideoConfig } from "remotion";
import { C, MARGIN, MONO, SERIF } from "./shared/editorial";
import { Scene } from "./shared/Scene";
import { Kicker, KineticHeadline, PullQuote, RuleLine } from "./shared/editorial-ui";
import { spread } from "./shared/pacing";

// Beat 2 — "The chain of trust." The architecture as an editorial numbered
// flow rather than boxes-and-arrows: the five trust boundaries run 01–05 down
// an asymmetric column, each a heavy editorial label with a mono sub-line, hairlines
// between, and two margin annotations. The data (the five layers + their
// sublabels) is preserved verbatim from the old box diagram.

interface Boundary {
  no: string;
  label: string;
  sub: string;
  note?: string;
}

const BOUNDARIES: Boundary[] = [
  { no: "01", label: "Evidence Vault", sub: "read-only · SHA-256 at case_open", note: "nothing is trusted before it is hashed" },
  { no: "02", label: "SIFT Tools, subprocess", sub: "Volatility · Hayabusa · Chainsaw · YARA" },
  { no: "03", label: "32 Rust DFIR Tools", sub: "findevil-mcp · typed IO · hash every output", note: "no execute_shell — the surface stays narrow" },
  { no: "04", label: "13 Python Crypto Tools", sub: "findevil-agent-mcp · ACH · signer · memory" },
  { no: "05", label: "VERDICT Orchestrator", sub: "Claude Code · Pool A + Pool B · judge · correlate" },
];

export function ArchDiagram() {
  const frame = useCurrentFrame();
  const { durationInFrames } = useVideoConfig();
  const clampOpts = { extrapolateLeft: "clamp", extrapolateRight: "clamp" } as const;

  // Spread the entry reveals across the whole beat so the column builds across
  // the narration rather than freezing at ~25%.
  const sd = (raw: number) => spread(raw, 0, 100, durationInFrames, 24, 200);

  return (
    <Scene page={2} caption="Architecture">
      {/* Masthead — kicker + headline, left gutter, with intentional space */}
      <div style={{ position: "absolute", left: MARGIN, top: 168, width: 980 }}>
        <Kicker frame={frame} delay={sd(2)} color={C.accent}>
          System · five boundaries
        </Kicker>
        <div style={{ marginTop: 16 }}>
          <KineticHeadline text="The chain" frame={frame} delay={sd(6)} size={108} />
          <KineticHeadline text="of trust." frame={frame} delay={sd(12)} size={108} italic />
        </div>
        <div style={{ marginTop: 30 }}>
          <RuleLine frame={frame} delay={sd(20)} width={150} color={C.accent} thickness={2} />
        </div>
      </div>

      {/* Right-rail pull-quote — the thesis, set against the numbered list */}
      <div style={{ position: "absolute", right: MARGIN, top: 196, width: 500 }}>
        <PullQuote frame={frame} delay={sd(28)} size={33} color={C.inkMuted} style={{ lineHeight: 1.22 }}>
          Five boundaries, read top&nbsp;to&nbsp;bottom. Evidence crosses each one
          only by passing through a typed tool that hashes its own&nbsp;output.
        </PullQuote>
        <div style={{ marginTop: 26 }}>
          <RuleLine frame={frame} delay={sd(40)} width={120} color={C.hairline} />
        </div>
        <div
          style={{
            marginTop: 16,
            fontFamily: MONO,
            fontSize: 14,
            letterSpacing: 1,
            color: C.inkFaint,
            opacity: interpolate(frame - sd(44), [0, 14], [0, 1], clampOpts),
          }}
        >
          chain verifiable offline · 45 typed tools
        </div>
      </div>

      {/* The numbered flow — asymmetric column down the left two-thirds */}
      <div style={{ position: "absolute", left: MARGIN, top: 472, width: 1120 }}>
        {BOUNDARIES.map((b, i) => {
          const d = sd(46 + i * 8);
          const op = interpolate(frame - d, [0, 14], [0, 1], clampOpts);
          const tx = interpolate(frame - d, [0, 18], [22, 0], clampOpts);
          const isLast = i === BOUNDARIES.length - 1;
          const labelColor = isLast ? C.accent : C.ink;
          return (
            <div key={b.no} style={{ opacity: op, transform: `translateX(${tx}px)` }}>
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "118px 1fr 320px",
                  alignItems: "baseline",
                  columnGap: 30,
                  padding: "20px 0",
                }}
              >
                {/* The ordinal — large, faint, mono */}
                <span
                  style={{
                    fontFamily: MONO,
                    fontSize: 38,
                    fontWeight: 700,
                    color: C.inkFaint,
                    letterSpacing: 1,
                  }}
                >
                  {b.no}
                </span>

                {/* The boundary name — v2 editorial voice */}
                <span
                  style={{
                    fontFamily: SERIF,
                    fontSize: 42,
                    fontWeight: 600,
                    lineHeight: 1.04,
                    letterSpacing: -0.5,
                    color: labelColor,
                  }}
                >
                  {b.label}
                </span>

                {/* The mechanism — mono sub-line, right-aligned data column */}
                <span
                  style={{
                    fontFamily: MONO,
                    fontSize: 16,
                    lineHeight: 1.5,
                    color: C.inkMuted,
                    letterSpacing: 0.5,
                  }}
                >
                  {b.sub}
                </span>
              </div>

              {/* Hairline between entries (draws in just after the row lands) */}
              {!isLast && (
                <RuleLine frame={frame} delay={d + 6} color={C.hairline} />
              )}

              {/* Margin annotation in the negative space to the far right */}
              {b.note && (
                <div
                  style={{
                    position: "absolute",
                    left: 1160,
                    marginTop: -64,
                    width: 300,
                    fontFamily: SERIF,
                    fontStyle: "italic",
                    fontSize: 19,
                    lineHeight: 1.3,
                    color: C.inkMuted,
                    opacity: interpolate(frame - (d + 16), [0, 16], [0, 1], clampOpts),
                  }}
                >
                  <span style={{ color: C.accent }}>— </span>
                  {b.note}
                </div>
              )}
            </div>
          );
        })}

        {/* Closing rule + read-direction note under the column */}
        <div style={{ marginTop: 6 }}>
          <RuleLine frame={frame} delay={sd(92)} color={C.hairline} thickness={2} />
        </div>
        <div
          style={{
            marginTop: 18,
            display: "flex",
            justifyContent: "space-between",
            alignItems: "baseline",
            opacity: interpolate(frame - sd(96), [0, 16], [0, 1], clampOpts),
          }}
        >
          <span style={{ fontFamily: MONO, fontSize: 15, letterSpacing: 3, textTransform: "uppercase", color: C.inkMuted }}>
            Evidence in
          </span>
          <span style={{ fontFamily: MONO, fontSize: 15, letterSpacing: 3, textTransform: "uppercase", color: C.confirmed }}>
            Signed verdict out
          </span>
        </div>
      </div>
    </Scene>
  );
}
