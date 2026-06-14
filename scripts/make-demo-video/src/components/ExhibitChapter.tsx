import React from "react";
import { interpolate, useCurrentFrame, useVideoConfig } from "remotion";
import { type Beat } from "../beats/beats-data";
import { C, GROTESK, MARGIN, SERIF } from "./shared/editorial";
import { Kicker, KineticHeadline } from "./shared/editorial-ui";
import { ExhibitVideo } from "./shared/ExhibitVideo";
import { Scene } from "./shared/Scene";

// ExhibitChapter — a deep-dive page: an editorial left column (kicker, headline,
// body, supporting points) beside a real captured clip framed as a forensic
// EXHIBIT. Drives entirely from `beat.exhibit` + the text fields, so the whole
// feature-deep-dive video is authored as data. Footage that is not yet on disk
// renders the on-brand "AWAITING CAPTURE" placeholder (see ExhibitVideo.tsx).

const clamp = { extrapolateLeft: "clamp", extrapolateRight: "clamp" } as const;

// Exhibit window geometry — sits inside the Scene furniture rules (top ~86,
// bottom ~1026) on the right half of the 1920×1080 canvas.
const EX_X = 880;
const EX_Y = 214;
const EX_W = 910;
const EX_H = 632;

interface Props {
  beat: Beat;
  totalBeats: number;
}

export function ExhibitChapter({ beat, totalBeats }: Props) {
  const frame = useCurrentFrame();
  const { durationInFrames } = useVideoConfig();
  const fadeOut = interpolate(frame, [durationInFrames - 16, durationInFrames], [1, 0], clamp);
  const accent = beat.accentColor || C.accent;
  const ex = beat.exhibit;

  return (
    <div style={{ opacity: fadeOut, width: "100%", height: "100%" }}>
      <Scene page={beat.number} total={totalBeats} caption={beat.caption ?? beat.rubric}>
        {/* Left column — the editorial copy */}
        <div style={{ position: "absolute", left: MARGIN, top: 232, width: 660 }}>
          {beat.kicker && (
            <Kicker frame={frame} delay={6} color={accent}>
              {beat.kicker}
            </Kicker>
          )}

          <div style={{ marginTop: 20 }}>
            <KineticHeadline
              text={beat.headline ?? beat.title}
              frame={frame}
              delay={14}
              size={62}
              weight={900}
            />
          </div>

          {beat.body && (
            <div
              style={{
                marginTop: 26,
                fontFamily: SERIF,
                fontSize: 31,
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
            <div style={{ marginTop: 34, display: "flex", flexDirection: "column", gap: 18 }}>
              {beat.points.map((point, i) => {
                const d = 56 + i * 14;
                const op = interpolate(frame - d, [0, 14], [0, 1], clamp);
                return (
                  <div
                    key={point}
                    style={{ opacity: op, display: "flex", alignItems: "baseline", gap: 16 }}
                  >
                    <span
                      style={{
                        fontFamily: GROTESK,
                        fontSize: 16,
                        fontWeight: 700,
                        color: accent,
                        transform: "translateY(-2px)",
                      }}
                    >
                      {String(i + 1).padStart(2, "0")}
                    </span>
                    <span
                      style={{
                        fontFamily: SERIF,
                        fontSize: 27,
                        fontWeight: 600,
                        lineHeight: 1.28,
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
        </div>

        {/* Right column — the real captured exhibit */}
        {ex && (
          <ExhibitVideo
            src={ex.src}
            label={ex.label}
            x={EX_X}
            y={EX_Y}
            w={EX_W}
            h={EX_H}
            objectFit={ex.objectFit ?? "contain"}
            playbackRate={ex.playbackRate ?? 1}
            startFrom={ex.startFrom ?? 0}
          />
        )}
      </Scene>
    </div>
  );
}
