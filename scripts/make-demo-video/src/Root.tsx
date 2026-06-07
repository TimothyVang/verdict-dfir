import React from "react";
import { Composition, registerRoot } from "remotion";
import { FindEvilDemo } from "./Video";
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
