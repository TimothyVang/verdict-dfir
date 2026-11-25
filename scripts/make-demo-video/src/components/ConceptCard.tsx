import React from "react";
import { interpolate, useCurrentFrame, useVideoConfig } from "remotion";
import { type Beat } from "../beats/beats-data";
import { C, MARGIN, MONO, SERIF } from "./shared/editorial";
import { Kicker, KineticHeadline, RuleLine } from "./shared/editorial-ui";
import { Scene } from "./shared/Scene";

// ConceptCard — a data-driven editorial page for the additional videos
// (explainer, quickstart, contributor call). It renders straight from the beat
// fields (kicker / headline / body / points / command) inside the shared Scene
// shell, so a whole video can be authored as data with no new React per beat.

const clamp = { extrapolateLeft: "clamp", extrapolateRight: "clamp" } as const;

interface Props {
  beat: Beat;
  totalBeats: number;
}

export function ConceptCard({ beat, totalBeats }: Props) {
  const frame = useCurrentFrame();
  const { durationInFrames } = useVideoConfig();
  const fadeOut = interpolate(frame, [durationInFrames - 16, durationInFrames], [1, 0], clamp);
  const accent = beat.accentColor || C.accent;

  return (
    <div style={{ opacity: fadeOut, width: "100%", height: "100%" }}>
      <Scene page={beat.number} total={totalBeats} caption={beat.caption ?? beat.rubric}>
        <div style={{ position: "absolute", left: MARGIN, top: 196, width: 1920 - MARGIN * 2 }}>
          {beat.kicker && (
            <Kicker frame={frame} delay={6} color={accent}>
              {beat.kicker}
            </Kicker>
          )}

          <div style={{ marginTop: 22 }}>
            <KineticHeadline
              text={beat.headline ?? beat.title}
              frame={frame}
              delay={14}
              size={82}
              weight={900}
            />
          </div>

          {beat.body && (
            <div
              style={{
                marginTop: 30,
                maxWidth: 1200,
                fontFamily: SERIF,
                fontSize: 38,
                fontWeight: 400,
                lineHeight: 1.42,
                color: C.inkMuted,
                opacity: interpolate(frame - 40, [0, 16], [0, 1], clamp),
              }}
            >
              {beat.body}
            </div>
          )}

          {beat.points && beat.points.length > 0 && (
            <div style={{ marginTop: 40, display: "flex", flexDirection: "column", gap: 22 }}>
              {beat.points.map((point, i) => {
                const d = 56 + i * 14;
                const op = interpolate(frame - d, [0, 14], [0, 1], clamp);
                const tx = interpolate(frame - d, [0, 16], [16, 0], clamp);
                return (
                  <div
                    key={point}
                    style={{
                      opacity: op,
                      transform: `translateX(${tx}px)`,
                      display: "flex",
                      alignItems: "baseline",
                      gap: 22,
                    }}
                  >
                    <span
                      style={{
                        width: 10,
                        height: 10,
                        borderRadius: "50%",
                        background: accent,
                        flexShrink: 0,
                        transform: "translateY(-4px)",
                      }}
                    />
                    <span
                      style={{
                        fontFamily: SERIF,
                        fontSize: 34,
                        fontWeight: 600,
                        lineHeight: 1.25,
                        letterSpacing: -0.3,
                        color: C.ink,
                      }}
                    >
                      {point}
                    </span>
                  </div>
                );
              })}
            </div>
          )}

          {beat.command && (
            <div
              style={{
                marginTop: 44,
                opacity: interpolate(frame - 70, [0, 16], [0, 1], clamp),
                maxWidth: 1200,
              }}
            >
              <RuleLine frame={frame} delay={70} color={C.hairline} />
              <div
                style={{
                  marginTop: 18,
                  fontFamily: MONO,
                  fontSize: 30,
                  lineHeight: 1.7,
                  color: C.confirmed,
                  whiteSpace: "pre-wrap",
                }}
              >
                {beat.command}
              </div>
            </div>
          )}
        </div>
      </Scene>
    </div>
  );
}
