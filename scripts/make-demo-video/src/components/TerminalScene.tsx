import React from "react";
import { interpolate, useCurrentFrame } from "remotion";
import { C, MARGIN, MONO } from "./shared/editorial";
import { Scene } from "./shared/Scene";
import { EvidenceTag, Kicker, KineticHeadline, PullQuote, RuleLine } from "./shared/editorial-ui";
import { ExhibitVideo } from "./shared/ExhibitVideo";

// Beat 3 (marquee) — "The host that lied." The left column carries the
// editorial story (the pslist/psscan divergence, the DKOM read); the right is a
// GENUINE terminal capture of the clean live investigation — case_open, the
// tool stream, normal verifier replay, judging, and the final verdict. Optional
// fault-injection harness clips are appendix footage, not this primary exhibit.
// The substance is real screen recording, framed as Exhibit A-1. Record it per
// CAPTURE.md.

const clampOpts = { extrapolateLeft: "clamp", extrapolateRight: "clamp" } as const;

// Exhibit window geometry — right of the story column.
const WIN_X = 950;
const WIN_Y = 214;
const WIN_W = 840;
const WIN_H = 652;

export function TerminalScene() {
  const frame = useCurrentFrame();

  return (
    <Scene page={3} caption="Single-host · memory">
      {/* Left column — the story */}
      <div style={{ position: "absolute", left: MARGIN, top: 210, width: 700 }}>
        <Kicker frame={frame} delay={10} color={C.accent}>
          Exhibit A · Memory Image
        </Kicker>
        <div style={{ marginTop: 16 }}>
          <KineticHeadline text="The host" frame={frame} delay={20} size={100} />
          <KineticHeadline text="that lied." frame={frame} delay={32} size={100} italic />
        </div>
        <div style={{ marginTop: 30, marginBottom: 26 }}>
          <RuleLine frame={frame} delay={44} width={120} color={C.alert} thickness={2} />
        </div>
        <PullQuote frame={frame} delay={300} size={34} color={C.ink} style={{ maxWidth: 640 }}>
          Two processes the active list swears aren&rsquo;t there — recovered intact from pool
          memory. That divergence is the textbook&nbsp;DKOM signature.
        </PullQuote>
        <div style={{ marginTop: 34, display: "flex", alignItems: "center", gap: 18 }}>
          <EvidenceTag label="T1014 Rootkit" tier="CONFIRMED" frame={frame} delay={620} />
          <span style={{ fontFamily: MONO, fontSize: 14, color: C.inkFaint }}>
            verify_finding · replay match
          </span>
        </div>
      </div>

      {/* Right — the live terminal capture, framed as an exhibit */}
      <div
        style={{
          position: "absolute",
          left: WIN_X,
          top: WIN_Y - 34,
          fontFamily: MONO,
          fontSize: 14,
          letterSpacing: 3,
          textTransform: "uppercase",
          color: C.inkMuted,
          opacity: interpolate(frame - 16, [0, 14], [0, 1], clampOpts),
        }}
      >
        Exhibit A-1 — live capture
      </div>
      <ExhibitVideo
        src="ui/terminal-investigation.mp4"
        label="claude · investigate evidence/"
        x={WIN_X}
        y={WIN_Y}
        w={WIN_W}
        h={WIN_H}
        objectFit="contain"
      />
    </Scene>
  );
}
