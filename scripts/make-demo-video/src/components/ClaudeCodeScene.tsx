import React from "react";
import { interpolate, useCurrentFrame, useVideoConfig } from "remotion";
import { C, MARGIN, MONO } from "./shared/editorial";
import { Scene } from "./shared/Scene";
import { Kicker, KineticHeadline, PullQuote, RuleLine } from "./shared/editorial-ui";
import { spread } from "./shared/pacing";

// Beat 2 — "It starts in Claude Code." The entry point shown as an animated
// terminal sitting in the right two-thirds of the page, with the editorial
// masthead (kicker + kinetic headline + pull-quote) in the left gutter. The
// hero line — `> investigate /evidence/…` — typewrites char-by-char and lands
// early; the streamed agent log then fills in line-by-line across the whole
// beat via spread(), so the terminal keeps building instead of freezing.

const clampOpts = { extrapolateLeft: "clamp", extrapolateRight: "clamp" } as const;

// The hero command, typed out character by character.
const HERO_CMD = "> investigate /evidence/base-DC-memory.img";

type LineKind = "prompt" | "banner" | "hero" | "stream";

interface TermLine {
  kind: LineKind;
  // raw value used to drive the spread() schedule (monotonic up the log)
  raw: number;
  text: string;
  color: string;
  // optional tail rendered in a different tone (e.g. "sigstore ✓")
  tail?: string;
  tailColor?: string;
}

const LINES: TermLine[] = [
  { kind: "prompt", raw: 0, text: "$ claude", color: C.inkMuted },
  { kind: "banner", raw: 6, text: "✻ Claude Code — VERDICT DFIR agent", color: C.accent },
  { kind: "hero", raw: 14, text: HERO_CMD, color: C.ink },
  {
    kind: "stream",
    raw: 40,
    text: "· case_open      sha256 9d7a… · evidence locked, read-only",
    color: C.inkMuted,
  },
  {
    kind: "stream",
    raw: 52,
    text: "· fork  Pool A (persistence)  +  Pool B (exfil)",
    color: C.inkMuted,
  },
  {
    kind: "stream",
    raw: 64,
    text: "· vol_pslist · vol_psscan · prefetch_parse · evtx_query …",
    color: C.inkMuted,
  },
  {
    kind: "stream",
    raw: 76,
    text: "· 14 findings drafted · verifying against tool output",
    color: C.inkMuted,
  },
  {
    kind: "stream",
    raw: 88,
    text: "· manifest sealed · ",
    color: C.inkMuted,
    tail: "sigstore ✓",
    tailColor: C.confirmed,
  },
];

const RAW_MIN = 0;
const RAW_MAX = 88;

// Visual constants for the terminal panel.
const TERM_LEFT = 812;
const TERM_TOP = 250;
const TERM_W = 978;
const TERM_H = 560;
const TERM_PAD = 32;
const LINE_FONT = 24;
const LINE_HEIGHT = 1.62;
const CURSOR_BLINK = 15; // frames per visibility toggle

export function ClaudeCodeScene() {
  const frame = useCurrentFrame();
  const { durationInFrames } = useVideoConfig();

  // Schedule every reveal across the full beat (hold ~200f before cross-fade).
  const sd = (raw: number) => spread(raw, RAW_MIN, RAW_MAX, durationInFrames, 24, 200);

  // The hero line's own schedule: it starts when the hero line reveals and
  // typewrites over ~36 frames so it lands early (~frame 60–180 region).
  const heroStart = sd(14);
  const heroTypeFrames = 36;
  const heroChars = Math.round(
    interpolate(frame - heroStart, [0, heroTypeFrames], [0, HERO_CMD.length], clampOpts),
  );
  const heroDone = heroChars >= HERO_CMD.length;

  // Identify the latest line that has begun revealing, so the blinking cursor
  // can sit at the end of the most recent line.
  let latestIndex = 0;
  for (let i = 0; i < LINES.length; i++) {
    if (frame >= sd(LINES[i].raw)) latestIndex = i;
  }
  const cursorVisible = Math.floor(frame / CURSOR_BLINK) % 2 === 0;

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

      {/* Right — the animated terminal panel */}
      <div
        style={{
          position: "absolute",
          left: TERM_LEFT,
          top: TERM_TOP,
          width: TERM_W,
          height: TERM_H,
          borderRadius: 10,
          background: C.surface,
          border: `1px solid ${C.hairline}`,
          overflow: "hidden",
          opacity: interpolate(frame - sd(0), [0, 16], [0, 1], clampOpts),
        }}
      >
        {/* faint top bar with three dots */}
        <div
          style={{
            height: 44,
            borderBottom: `1px solid ${C.hairline}`,
            display: "flex",
            alignItems: "center",
            paddingLeft: 20,
            gap: 9,
          }}
        >
          {[C.inkFaint, C.inkFaint, C.inkFaint].map((dot, i) => (
            <span
              key={i}
              style={{
                width: 11,
                height: 11,
                borderRadius: "50%",
                background: dot,
                opacity: 0.7,
              }}
            />
          ))}
          <span
            style={{
              marginLeft: 18,
              fontFamily: MONO,
              fontSize: 14,
              letterSpacing: 2,
              textTransform: "uppercase",
              color: C.inkFaint,
            }}
          >
            verdict — claude code
          </span>
        </div>

        {/* terminal body */}
        <div
          style={{
            padding: TERM_PAD,
            fontFamily: MONO,
            fontSize: LINE_FONT,
            lineHeight: LINE_HEIGHT,
            letterSpacing: 0.3,
          }}
        >
          {LINES.map((line, i) => {
            const start = sd(line.raw);
            if (frame < start) return null;

            const op = interpolate(frame - start, [0, 10], [0, 1], clampOpts);
            const tx = interpolate(frame - start, [0, 12], [10, 0], clampOpts);
            const isLatest = i === latestIndex;

            // Hero line typewrites; all others render in full once revealed.
            const isHero = line.kind === "hero";
            const shown = isHero ? HERO_CMD.slice(0, heroChars) : line.text;
            const lineSettled = isHero ? heroDone : true;

            // The cursor sits after the latest revealed line (and, for the hero
            // line, blinks only after it has finished typing).
            const showCursor = isLatest && cursorVisible && lineSettled;

            return (
              <div
                key={i}
                style={{
                  opacity: op,
                  transform: `translateX(${tx}px)`,
                  color: line.color,
                  whiteSpace: "pre",
                  marginBottom: line.kind === "hero" ? 14 : 2,
                  fontWeight: isHero ? 700 : 400,
                }}
              >
                {shown}
                {line.tail && lineSettled && (
                  <span style={{ color: line.tailColor ?? line.color }}>{line.tail}</span>
                )}
                {showCursor && (
                  <span
                    style={{
                      display: "inline-block",
                      width: "0.6em",
                      height: "1.05em",
                      marginLeft: 4,
                      background: isHero ? C.ink : C.confirmed,
                      transform: "translateY(0.18em)",
                    }}
                  />
                )}
              </div>
            );
          })}
        </div>
      </div>

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
