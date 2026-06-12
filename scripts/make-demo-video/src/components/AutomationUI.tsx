import React from "react";
import { interpolate, useCurrentFrame, useVideoConfig } from "remotion";
import { C, GROTESK, MARGIN, MONO } from "./shared/editorial";
import { Scene } from "./shared/Scene";
import { Kicker, KineticHeadline, PullQuote, RuleLine } from "./shared/editorial-ui";
import { spread } from "./shared/pacing";

// Beat 8 — "Your team takes over." The agent/analyst RESPONSIBILITY BOUNDARY:
// VERDICT runs the mechanical forensic pipeline and stops at a signed case; the
// human analysts triage and decide. This is the "orchestrator that reduces
// friction, not an autonomous responder" narrative. (Post-verdict n8n automation
// is demoted for release, so it is intentionally NOT shown here.)

const clampOpts = { extrapolateLeft: "clamp", extrapolateRight: "clamp" } as const;

// What the agent did (all done) vs. what the humans own (their call).
const AGENT_STEPS = ["opens the case", "runs the typed tools", "verifies every finding", "signs the manifest"];
const HUMAN_STEPS = ["triage the verdict", "decide the response", "take action"];

export function AutomationUI() {
  const frame = useCurrentFrame();
  const { durationInFrames } = useVideoConfig();
  const sd = (raw: number) => spread(raw, 0, 100, durationInFrames, 24, 200);
  const fade = (at: number, len = 16) => interpolate(frame - sd(at), [0, len], [0, 1], clampOpts);
  const rowAt = (i: number) => sd(46 + i * 9);

  return (
    <Scene page={8} caption="Handoff" total={10}>
      {/* ── LEFT COLUMN — the story ─────────────────────────────────────── */}
      <div style={{ position: "absolute", left: MARGIN, top: 172, width: 470 }}>
        <Kicker frame={frame} delay={sd(2)} color={C.accent}>
          Exhibit H · Handoff
        </Kicker>
        <div style={{ marginTop: 16 }}>
          <KineticHeadline text="Your team" frame={frame} delay={sd(6)} size={100} />
          <KineticHeadline text="takes over." frame={frame} delay={sd(12)} size={100} italic />
        </div>
        <div style={{ marginTop: 28, marginBottom: 32 }}>
          <RuleLine frame={frame} delay={sd(20)} width={150} color={C.accent} thickness={2} />
        </div>

        <PullQuote frame={frame} delay={sd(28)} size={38} color={C.ink} style={{ maxWidth: 460 }}>
          The machine does the{" "}
          <span style={{ color: C.accent }}>legwork.</span> People make the calls.
        </PullQuote>

        <div
          style={{
            marginTop: 42,
            fontFamily: GROTESK,
            fontSize: 16,
            fontWeight: 600,
            letterSpacing: 2,
            textTransform: "uppercase",
            color: C.inkFaint,
            opacity: fade(60),
          }}
        >
          an orchestrator that reduces friction — not an autonomous responder
        </div>
      </div>

      {/* ── MAIN — the agent / analyst responsibility boundary ──────────── */}
      <div style={{ position: "absolute", left: 632, top: 196, width: 1158 }}>
        <div
          style={{
            fontFamily: MONO,
            fontSize: 13,
            letterSpacing: 3,
            textTransform: "uppercase",
            color: C.inkMuted,
            marginBottom: 18,
            opacity: fade(18, 14),
          }}
        >
          Exhibit H-1 — where the agent stops
        </div>

        <div style={{ display: "flex", alignItems: "stretch", gap: 26 }}>
          {/* Agent column — everything done */}
          <Column
            title="VERDICT · the agent"
            steps={AGENT_STEPS}
            done
            frame={frame}
            rowAt={rowAt}
            headerOpacity={fade(24, 14)}
          />

          {/* Handoff arrow */}
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              fontFamily: GROTESK,
              fontSize: 56,
              fontWeight: 800,
              color: C.accent,
              opacity: fade(70),
            }}
          >
            →
          </div>

          {/* Analyst column — their call */}
          <Column
            title="your analysts · the humans"
            steps={HUMAN_STEPS}
            done={false}
            frame={frame}
            rowAt={(i: number) => rowAt(i + 5)}
            headerOpacity={fade(64, 14)}
          />
        </div>
      </div>
    </Scene>
  );
}

function Column({
  title,
  steps,
  done,
  frame,
  rowAt,
  headerOpacity,
}: {
  title: string;
  steps: string[];
  done: boolean;
  frame: number;
  rowAt: (i: number) => number;
  headerOpacity: number;
}) {
  return (
    <div style={{ flex: 1 }}>
      <div
        style={{
          fontFamily: MONO,
          fontSize: 15,
          letterSpacing: 1,
          textTransform: "uppercase",
          color: done ? C.confirmed : C.inkMuted,
          marginBottom: 14,
          opacity: headerOpacity,
        }}
      >
        {title}
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
        {steps.map((label, i) => {
          const on = frame >= rowAt(i);
          const op = interpolate(frame - rowAt(i), [0, 10], [0, 1], clampOpts);
          const tone = on ? (done ? C.confirmed : C.ink) : C.inkMuted;
          return (
            <div
              key={label}
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                padding: "14px 18px",
                background: C.surface,
                border: `1px solid ${on ? (done ? `${C.confirmed}66` : `${C.ink}33`) : C.hairline}`,
                borderRadius: 8,
              }}
            >
              <span style={{ fontFamily: MONO, fontSize: 17, letterSpacing: 0.3, color: tone }}>{label}</span>
              <span
                style={{
                  fontFamily: MONO,
                  fontSize: 17,
                  fontWeight: 700,
                  color: on ? (done ? C.confirmed : C.inkMuted) : C.inkFaint,
                  opacity: on ? op : 0.4,
                }}
              >
                {done ? "✓" : "·"}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
