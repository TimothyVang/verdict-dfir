import React from "react";
import { interpolate, useCurrentFrame, useVideoConfig } from "remotion";
import { C, GROTESK, MARGIN, MONO, SERIF } from "./shared/editorial";
import { Kicker, KineticHeadline, RuleLine, Stamp } from "./shared/editorial-ui";
import { Scene } from "./shared/Scene";

// Beat 9 (colophon) — "Case closed." The closing page set as a magazine
// colophon: a Case Closed stamp hit over the disposition, the VERDICT logotype
// small in the v2 heavy editorial sans, and the credits run as a left-aligned
// grotesque/mono
// colophon block under a RuleLine. No centered metadata stack, no tech-grid.

// Real credit lines preserved from the prior scene — set as label/value pairs
// so they read as a printed colophon, not a list of links.
interface Credit { label: string; value: string; mono?: boolean; tone?: string }
const CREDITS: Credit[] = [
  { label: "Source", value: "github.com/TimothyVang/verdict-dfir", mono: true },
  { label: "License", value: "Apache-2.0" },
  { label: "Continuous integration", value: "L0 · L1 · L2 · L3 — all green", tone: C.confirmed },
  { label: "Tool surface", value: "32 Rust · 13 Python", mono: true },
];

export function OutroScene() {
  const frame = useCurrentFrame();
  const { durationInFrames } = useVideoConfig();
  const clampOpts = { extrapolateLeft: "clamp", extrapolateRight: "clamp" } as const;

  const fadeOut = interpolate(frame, [durationInFrames - 18, durationInFrames], [1, 0], clampOpts);

  return (
    <div style={{ opacity: fadeOut, width: "100%", height: "100%" }}>
      <Scene page={10} caption="Colophon">
        {/* Left column — the imprint: stamp + logotype + creed */}
        <div style={{ position: "absolute", left: MARGIN, top: 232, width: 760 }}>
          <Kicker frame={frame} delay={6} color={C.accent}>End of File</Kicker>

          <div style={{ marginTop: 24, marginBottom: 30 }}>
            <Stamp label="Case Closed" frame={frame} delay={14} color={C.alert} rotate={-6} size={34} />
          </div>

          {/* The VERDICT logotype — v2 heavy editorial sans with its creed beneath. */}
          <div style={{ marginTop: 8 }}>
            <KineticHeadline text="Verdict" frame={frame} delay={26} size={108} weight={900} />
          </div>
          <div
            style={{
              marginTop: 14,
              opacity: interpolate(frame - 48, [0, 16], [0, 1], clampOpts),
              fontFamily: SERIF,
              fontSize: 32,
              fontWeight: 700,
              color: C.inkMuted,
              letterSpacing: -0.3,
            }}
          >
            Evidence, not assumption.
          </div>

          {/* The creed, set as small caps grotesque furniture. */}
          <div style={{ marginTop: 40, display: "flex", alignItems: "center", gap: 18 }}>
            <RuleLine frame={frame} delay={58} width={48} color={C.accent} thickness={2} />
            <span
              style={{
                opacity: interpolate(frame - 64, [0, 14], [0, 1], clampOpts),
                fontFamily: GROTESK,
                fontSize: 19,
                fontWeight: 600,
                letterSpacing: 6,
                textTransform: "uppercase",
                color: C.ink,
              }}
            >
              Trace it · Test it · Trust it
            </span>
          </div>
        </div>

        {/* Right column — the colophon block, left-aligned label/value pairs. */}
        <div style={{ position: "absolute", right: MARGIN, top: 252, width: 660 }}>
          <div
            style={{
              fontFamily: MONO,
              fontSize: 14,
              letterSpacing: 3,
              textTransform: "uppercase",
              color: C.inkMuted,
              marginBottom: 16,
              opacity: interpolate(frame - 40, [0, 12], [0, 1], clampOpts),
            }}
          >
            Colophon
          </div>
          <RuleLine frame={frame} delay={46} color={C.hairline} />

          <div style={{ marginTop: 8 }}>
            {CREDITS.map((c, i) => {
              const d = 60 + i * 14;
              const op = interpolate(frame - d, [0, 14], [0, 1], clampOpts);
              const tx = interpolate(frame - d, [0, 16], [12, 0], clampOpts);
              return (
                <div key={c.label} style={{ opacity: op, transform: `translateX(${tx}px)` }}>
                  <div
                    style={{
                      display: "grid",
                      gridTemplateColumns: "210px 1fr",
                      alignItems: "baseline",
                      gap: 24,
                      padding: "20px 0",
                    }}
                  >
                    <span
                      style={{
                        fontFamily: GROTESK,
                        fontSize: 15,
                        fontWeight: 600,
                        letterSpacing: 3,
                        textTransform: "uppercase",
                        color: C.inkFaint,
                      }}
                    >
                      {c.label}
                    </span>
                    <span
                      style={{
                        fontFamily: c.mono ? MONO : SERIF,
                        fontSize: c.mono ? 21 : 28,
                        fontWeight: c.mono ? 400 : 600,
                        color: c.tone ?? C.ink,
                        letterSpacing: c.mono ? 0 : -0.4,
                      }}
                    >
                      {c.value}
                    </span>
                  </div>
                  {i < CREDITS.length - 1 && <div style={{ height: 1, background: C.hairline, opacity: 0.5 }} />}
                </div>
              );
            })}
          </div>

          <RuleLine frame={frame} delay={132} color={C.hairline} />

          {/* Printer's mark — the signed merkle root, the last line of the file. */}
          <div
            style={{
              marginTop: 22,
              opacity: interpolate(frame - 150, [0, 16], [0, 1], clampOpts),
              fontFamily: MONO,
              fontSize: 14,
              color: C.inkMuted,
              lineHeight: 1.8,
            }}
          >
            Signed · manifest · merkle d1e4bc7a906f2c38
            <br />
            <span style={{ color: C.confirmed }}>chain OK</span> — verifiable offline, years from now
          </div>
        </div>
      </Scene>
    </div>
  );
}
