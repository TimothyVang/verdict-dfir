import React from "react";
import { AbsoluteFill, Series } from "remotion";
import { BeatScene } from "./beats/Beat";
import { type Beat, BEATS, FPS } from "./beats/beats-data";

// Audio files are written by the Piper/ElevenLabs TTS scripts. Each video keeps
// its narration in its own subdirectory so the films don't collide:
//   FindEvilDemo  → public/audio/beat_NN.mp3        (audioPrefix omitted)
//   the others    → public/audio/<prefix>/beat_NN.mp3
// Remotion's staticFile() serves files from public/ at render time.
function audioFileForBeat(beatNumber: number, audioPrefix?: string): string {
  const name = `beat_${String(beatNumber).padStart(2, "0")}.mp3`;
  return audioPrefix ? `audio/${audioPrefix}/${name}` : `audio/${name}`;
}

interface FilmProps {
  beats: Beat[];
  audioPrefix?: string;
}

// FilmFromBeats — the shared player: a Series of beats with per-beat narration.
// Every video (the showcase and the additional explainer/deep-dive/quickstart/
// contributor films) is just this wrapper over a different beats array.
export function FilmFromBeats({ beats, audioPrefix }: FilmProps) {
  return (
    <AbsoluteFill style={{ backgroundColor: "#0d1117" }}>
      <Series>
        {beats.map((beat) => (
          <Series.Sequence
            key={beat.number}
            durationInFrames={(beat.endS - beat.startS) * FPS}
          >
            <BeatScene
              beat={beat}
              totalBeats={beats.length}
              audioFile={audioFileForBeat(beat.number, audioPrefix)}
            />
          </Series.Sequence>
        ))}
      </Series>
    </AbsoluteFill>
  );
}

export function FindEvilDemo() {
  return <FilmFromBeats beats={BEATS} />;
}
