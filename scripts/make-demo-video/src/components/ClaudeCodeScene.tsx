import React from "react";
import { interpolate, useCurrentFrame, useVideoConfig } from "remotion";
import { C, MARGIN, MONO } from "./shared/editorial";
import { Scene } from "./shared/Scene";
import { Kicker, KineticHeadline, PullQuote, RuleLine } from "./shared/editorial-ui";
import { ExhibitVideo } from "./shared/ExhibitVideo";
import { spread } from "./shared/pacing";

// Beat 2 — "It starts in Claude Code." The entry point shown as a GENUINE
// terminal capture in the right two-thirds (real `claude` → investigate the
// evidence, the agent log streaming for real), with the editorial masthead
// (kicker + kinetic headline + pull-quote) in the left gutter. The terminal is
// real screen recording — record it per CAPTURE.md; until then the slot shows
// an on-brand "awaiting capture" placeholder so the film still renders.

const clampOpts = { extrapolateLeft: "clamp", extrapolateRight: "clamp" } as const;

// The reveal schedule spans the whole beat; raw 0..88 mirrors the old log so the
// masthead and caption keep their timing.
const RAW_MIN = 0;
const RAW_MAX = 88;

// Exhibit window geometry — the right two-thirds.
const TERM_LEFT = 812;
const TERM_TOP = 250;
const TERM_W = 978;
const TERM_H = 560;

export function ClaudeCodeScene() {
  const frame = useCurrentFrame();
  const { durationInFrames } = useVideoConfig();

  // Schedule every reveal across the full beat (hold ~200f before cross-fade).
  const sd = (raw: number) => spread(raw, RAW_MIN, RAW_MAX, durationInFrames, 24, 200);

  return (
    <Scene page={2} caption="How to run it" total={10}>
      {/* Left gutter — the editorial masthead */}
      <div style={{ position: "absolute", left: MARGIN, top: 196, width: 600 }}>
        <Kicker frame={frame} delay={sd(2)} color={C.accent}>
          Exhibit B · The Entry Point
        </Kicker>

        <div style={{ marginTop: 18 }}>
          <KineticHeadline text="One line." frame={frame} delay={sd(6)} size={104} italic />
          <KineticHeadline text="That’s it." frame={frame} delay={sd(12)} size={104} italic />
        </div>

        <div style={{ marginTop: 34, marginBottom: 34 }}>
          <RuleLine frame={frame} delay={sd(22)} width={150} color={C.accent} thickness={2} />
        </div>

        <PullQuote
          frame={frame}
          delay={sd(34)}
          size={36}
          color={C.inkMuted}
          style={{ lineHeight: 1.24, maxWidth: 560 }}
        >
          VERDICT runs inside{" "}
          <span style={{ color: C.ink }}>Claude&nbsp;Code</span> — open it, point it
          at the evidence, and watch.
        </PullQuote>

        <div
          style={{
            marginTop: 30,
            fontFamily: MONO,
            fontSize: 15,
            letterSpacing: 1,
            color: C.inkFaint,
            opacity: interpolate(frame - sd(40), [0, 14], [0, 1], clampOpts),
          }}
        >
          one command · supervisor + two pools · signed run
        </div>
      </div>

      {/* Right — the genuine terminal capture, framed as an exhibit. The raw
          asciinema take runs fast; 0.3× stretches it to ~9s of motion so the
          verifier reject → re-dispatch → recover sequence is followable, then
          the clip holds on the recovery frame while the narration lands. */}
      <ExhibitVideo
        src="ui/terminal-investigation.mp4"
        label="claude · VERDICT DFIR agent"
        x={TERM_LEFT}
        y={TERM_TOP}
        w={TERM_W}
        h={TERM_H}
        objectFit="contain"
        playbackRate={0.3}
      />

      {/* exhibit caption under the terminal panel */}
      <div
        style={{
          position: "absolute",
          left: TERM_LEFT,
          top: TERM_TOP + TERM_H + 22,
          width: TERM_W,
          display: "flex",
          justifyContent: "space-between",
          alignItems: "baseline",
          fontFamily: MONO,
          fontSize: 14,
          letterSpacing: 3,
          textTransform: "uppercase",
          color: C.inkMuted,
          opacity: interpolate(frame - sd(80), [0, 16], [0, 1], clampOpts),
        }}
      >
        <span>Exhibit B-1 — Live Session</span>
        <span style={{ color: C.confirmed }}>Signed verdict out</span>
      </div>
    </Scene>
  );
}
