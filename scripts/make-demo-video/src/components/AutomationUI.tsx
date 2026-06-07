import React from "react";
import { Img, interpolate, spring, staticFile, useCurrentFrame, useVideoConfig } from "remotion";
import { C, GROTESK, MARGIN, MONO } from "./shared/editorial";
import { Scene } from "./shared/Scene";
import { Kicker, KineticHeadline, PullQuote, RuleLine } from "./shared/editorial-ui";
import { spread } from "./shared/pacing";

// Beat 8 — "Then it acts." VERDICT's post-verdict automation, shown as the REAL
// n8n canvas (captured from the running instance: the live
// `findevil-finding-to-action` workflow) framed in a browser window, with an
// animated status strip whose rows tick to ✓ across the beat. The automation is
// framed as optional and outside the evidence chain.

const clampOpts = { extrapolateLeft: "clamp", extrapolateRight: "clamp" } as const;

// Status strip rows — mirror the real workflow's nodes; tick in sequence.
const STATUS_ROWS = ["webhook trigger", "route → actions", "slack alert", "write ticket"];

export function AutomationUI() {
  const frame = useCurrentFrame();
  const { durationInFrames, fps } = useVideoConfig();

  // Reveal pacing across the WHOLE beat.
  const sd = (raw: number) => spread(raw, 0, 100, durationInFrames, 24, 200);

  // Browser window reveal.
  const frameIn = spring({ frame: frame - sd(24), fps, config: { damping: 18, stiffness: 90 } });
  const winOpacity = interpolate(frame - sd(24), [0, 16], [0, 1], clampOpts);
  const winScale = 0.97 + frameIn * 0.03;

  // Each status row ticks as the beat progresses (staggered).
  const rowFrame = (i: number) => sd(50 + i * 11);

  return (
    <Scene page={8} caption="Automation" total={10}>
      {/* ── LEFT COLUMN — the story ─────────────────────────────────────── */}
      <div style={{ position: "absolute", left: MARGIN, top: 172, width: 470 }}>
        <Kicker frame={frame} delay={sd(2)} color={C.accent}>
          Exhibit H · Handoff
        </Kicker>
        <div style={{ marginTop: 16 }}>
          <KineticHeadline text="Then it" frame={frame} delay={sd(6)} size={100} />
          <KineticHeadline text="acts." frame={frame} delay={sd(12)} size={100} italic />
        </div>
        <div style={{ marginTop: 28, marginBottom: 32 }}>
          <RuleLine frame={frame} delay={sd(20)} width={150} color={C.accent} thickness={2} />
        </div>

        <PullQuote frame={frame} delay={sd(28)} size={38} color={C.ink} style={{ maxWidth: 460 }}>
          The verdict is signed — now <span style={{ color: C.accent }}>route&nbsp;it.</span>{" "}
          Slack, tickets, your other&nbsp;defenses.
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
            opacity: interpolate(frame - sd(60), [0, 16], [0, 1], clampOpts),
          }}
        >
          n8n · MIT · optional — never part of the evidence chain
        </div>
      </div>

      {/* ── MAIN — the REAL n8n canvas in a browser frame ───────────────── */}
      <div style={{ position: "absolute", left: 632, top: 196, width: 1158 }}>
        <div
          style={{
            fontFamily: MONO,
            fontSize: 13,
            letterSpacing: 3,
            textTransform: "uppercase",
            color: C.inkMuted,
            marginBottom: 12,
            opacity: interpolate(frame - sd(20), [0, 14], [0, 1], clampOpts),
          }}
        >
          Exhibit H-1 — Post-Verdict Workflow · live in n8n
        </div>

        <div
          style={{
            opacity: winOpacity,
            transform: `scale(${winScale})`,
            transformOrigin: "50% 0%",
            borderRadius: 12,
            overflow: "hidden",
            border: `1px solid ${C.hairline}`,
            background: C.surface,
            boxShadow: "0 30px 80px rgba(0,0,0,0.45)",
          }}
        >
          {/* title bar */}
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 8,
              padding: "11px 16px",
              borderBottom: `1px solid ${C.hairline}`,
              background: C.paperEdge,
            }}
          >
            <span style={{ width: 11, height: 11, borderRadius: "50%", background: "#e0443e", display: "inline-block" }} />
            <span style={{ width: 11, height: 11, borderRadius: "50%", background: "#dea123", display: "inline-block" }} />
            <span style={{ width: 11, height: 11, borderRadius: "50%", background: "#1aab29", display: "inline-block" }} />
            <span style={{ marginLeft: 14, fontFamily: MONO, fontSize: 14, color: C.inkMuted, letterSpacing: 0.5 }}>
              n8n · localhost:5678 · findevil-finding-to-action
            </span>
          </div>
          {/* the real captured canvas */}
          <Img
            src={staticFile("ui/n8n-canvas.png")}
            style={{ display: "block", width: "100%", height: "auto" }}
          />
        </div>

        {/* ── STATUS STRIP — ticks across the beat ───────────────────────── */}
        <div
          style={{
            display: "flex",
            gap: 14,
            marginTop: 20,
            opacity: interpolate(frame - sd(44), [0, 16], [0, 1], clampOpts),
          }}
        >
          {STATUS_ROWS.map((label, i) => {
            const done = frame >= rowFrame(i);
            const tickOp = interpolate(frame - rowFrame(i), [0, 10], [0, 1], clampOpts);
            const tone = done ? C.confirmed : C.inkMuted;
            return (
              <div
                key={label}
                style={{
                  flex: 1,
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  padding: "12px 16px",
                  background: C.surface,
                  border: `1px solid ${done ? `${C.confirmed}66` : C.hairline}`,
                  borderRadius: 8,
                }}
              >
                <span style={{ fontFamily: MONO, fontSize: 15, letterSpacing: 0.3, color: tone }}>
                  {label}
                </span>
                <span
                  style={{
                    fontFamily: MONO,
                    fontSize: 16,
                    fontWeight: 700,
                    color: done ? C.confirmed : C.inkFaint,
                    opacity: done ? tickOp : 0.5,
                  }}
                >
                  {done ? "✓" : "·"}
                </span>
              </div>
            );
          })}
        </div>
      </div>
    </Scene>
  );
}
