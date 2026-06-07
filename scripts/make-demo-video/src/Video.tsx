import React from "react";
import { AbsoluteFill, Series } from "remotion";
import { BeatScene } from "./beats/Beat";
import { BEATS, FPS } from "./beats/beats-data";

// Audio files are written to src/audio/ by make-demo-video-prep.py.
// Remotion's staticFile() resolves relative to the project's public/ or src/ dir.
// We reference them unconditionally; Remotion skips missing static files gracefully.
function audioFileForBeat(beatNumber: number): string {
  return `audio/beat_${String(beatNumber).padStart(2, "0")}.mp3`;
}

export function FindEvilDemo() {
  return (
    <AbsoluteFill style={{ backgroundColor: "#0d1117" }}>
      <Series>
        {BEATS.map((beat) => (
          <Series.Sequence
            key={beat.number}
            durationInFrames={(beat.endS - beat.startS) * FPS}
          >
            <BeatScene
              beat={beat}
              totalBeats={BEATS.length}
              audioFile={audioFileForBeat(beat.number)}
            />
          </Series.Sequence>
        ))}
      </Series>
    </AbsoluteFill>
  );
}
