import React from "react";
import { Composition, registerRoot } from "remotion";
import { FilmFromBeats, FindEvilDemo } from "./Video";
import { ArchPoster } from "./components/ArchPoster";
import { BEATS, FPS, HEIGHT, TOTAL_FRAMES, WIDTH, type Beat } from "./beats/beats-data";
import { EXPLAINER_BEATS } from "./beats/explainer-beats";
import { DEEPDIVE_BEATS } from "./beats/deepdive-beats";
import { QUICKSTART_BEATS } from "./beats/quickstart-beats";
import { CONTRIBUTOR_BEATS } from "./beats/contributor-beats";

// Frames for a beats array = last beat's end second × fps.
function framesFor(beats: Beat[]): number {
  return beats[beats.length - 1].endS * FPS;
}

// Each additional video is the shared FilmFromBeats player over its own beats
// array + its own audio subdirectory (public/audio/<prefix>/).
const EducationalExplainer = () => <FilmFromBeats beats={EXPLAINER_BEATS} audioPrefix="explainer" />;
const FeatureDeepDives = () => <FilmFromBeats beats={DEEPDIVE_BEATS} audioPrefix="deepdive" />;
const Quickstart = () => <FilmFromBeats beats={QUICKSTART_BEATS} audioPrefix="quickstart" />;
const ContributorCall = () => <FilmFromBeats beats={CONTRIBUTOR_BEATS} audioPrefix="contributor" />;

function RemotionRoot() {
  return (
    <>
      {/* Full ~4.5-minute showcase */}
      <Composition
        id="FindEvilDemo"
        component={FindEvilDemo}
        durationInFrames={TOTAL_FRAMES}
        fps={FPS}
        width={WIDTH}
        height={HEIGHT}
      />

      {/* Additional videos — educate, deep-dive, quickstart, recruit. */}
      <Composition
        id="EducationalExplainer"
        component={EducationalExplainer}
        durationInFrames={framesFor(EXPLAINER_BEATS)}
        fps={FPS}
        width={WIDTH}
        height={HEIGHT}
      />
      <Composition
        id="FeatureDeepDives"
        component={FeatureDeepDives}
        durationInFrames={framesFor(DEEPDIVE_BEATS)}
        fps={FPS}
        width={WIDTH}
        height={HEIGHT}
      />
      <Composition
        id="Quickstart"
        component={Quickstart}
        durationInFrames={framesFor(QUICKSTART_BEATS)}
        fps={FPS}
        width={WIDTH}
        height={HEIGHT}
      />
      <Composition
        id="ContributorCall"
        component={ContributorCall}
        durationInFrames={framesFor(CONTRIBUTOR_BEATS)}
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
