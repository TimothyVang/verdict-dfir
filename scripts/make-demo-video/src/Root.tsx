import React from "react";
import { Composition, registerRoot } from "remotion";
import { FindEvilDemo } from "./Video";
import { ArchPoster } from "./components/ArchPoster";
import { BEATS, FPS, HEIGHT, TOTAL_FRAMES, WIDTH } from "./beats/beats-data";

function RemotionRoot() {
  return (
    <>
      {/* Full 5-minute video */}
      <Composition
        id="FindEvilDemo"
        component={FindEvilDemo}
        durationInFrames={TOTAL_FRAMES}
        fps={FPS}
        width={WIDTH}
        height={HEIGHT}
      />

      {/* Standalone architecture poster — rendered as a still (PNG) for the
          Devpost gallery. `npx remotion still src/Root.tsx ArchPoster out.png` */}
      <Composition
        id="ArchPoster"
        component={ArchPoster}
        durationInFrames={1}
        fps={30}
        width={1920}
        height={1480}
      />

      {/* One composition per beat for iterating during development */}
      {BEATS.map((beat) => (
        <Composition
          key={beat.number}
          id={`Beat${String(beat.number).padStart(2, "0")}`}
          component={FindEvilDemo}
          durationInFrames={(beat.endS - beat.startS) * FPS}
          fps={FPS}
          width={WIDTH}
          height={HEIGHT}
        />
      ))}
    </>
  );
}

registerRoot(RemotionRoot);
