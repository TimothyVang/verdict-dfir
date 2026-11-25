import React from "react";
import {
  AbsoluteFill,
  Audio,
  interpolate,
  spring,
  staticFile,
  useCurrentFrame,
  useVideoConfig,
} from "remotion";
import { type Beat } from "./beats-data";
import { LogoIntro } from "../components/LogoIntro";
import { ClaudeCodeScene } from "../components/ClaudeCodeScene";
import { CaseProgression } from "../components/CaseProgression";
import { ToolGrid } from "../components/ToolGrid";
import { ContradictionScene } from "../components/ContradictionScene";
import { DashboardUI } from "../components/DashboardUI";
import { HashChainScene } from "../components/HashChainScene";
import { AutomationUI } from "../components/AutomationUI";
import { FleetScene } from "../components/FleetScene";
import { OutroScene } from "../components/OutroScene";
import { ArchDiagram } from "../components/ArchDiagram";
import { ConceptCard } from "../components/ConceptCard";
import { ExhibitChapter } from "../components/ExhibitChapter";

const CHAR_DELAY = 1.5; // frames per character for typewriter fallback

function useSpring(frame: number, delay: number = 0) {
  const { fps } = useVideoConfig();
  return spring({ frame: frame - delay, fps, config: { damping: 14, stiffness: 100 } });
}

function TitleLine({ text, frame, delay }: { text: string; frame: number; delay: number }) {
  const opacity = interpolate(frame - delay, [0, 12], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  const translateY = interpolate(frame - delay, [0, 18], [40, 0], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  return (
    <div style={{ opacity, transform: `translateY(${translateY}px)` }}>
      {text}
    </div>
  );
}

function RubricBadge({ text, frame, accentColor }: { text: string; frame: number; accentColor: string }) {
  const s = useSpring(frame, 18);
  const opacity = interpolate(frame - 18, [0, 10], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  const translateX = interpolate(frame - 18, [0, 20], [60, 0], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  if (!text) return null;
  return (
    <div style={{
      opacity,
      transform: `translateX(${translateX}px) scale(${0.6 + s * 0.4})`,
      backgroundColor: accentColor,
      color: "#fff",
      borderRadius: 8,
      padding: "10px 28px",
      fontSize: 30,
      fontWeight: 700,
      letterSpacing: 1,
      marginBottom: 40,
      display: "inline-block",
    }}>
      {text}
    </div>
  );
}

function TypewriterText({ text, frame, startFrame }: { text: string; frame: number; startFrame: number }) {
  const elapsed = Math.max(0, frame - startFrame);
  const visibleChars = Math.floor(elapsed / CHAR_DELAY);
  const displayed = text.slice(0, visibleChars);
  const opacity = interpolate(startFrame, [startFrame - 5, startFrame], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  return (
    <div style={{ opacity, minHeight: 160 }}>
      {displayed}
      {visibleChars < text.length && (
        <span style={{ opacity: Math.floor(elapsed / 15) % 2 === 0 ? 1 : 0 }}>|</span>
      )}
    </div>
  );
}

function BeatNumber({ num, accentColor, frame }: { num: number; accentColor: string; frame: number }) {
  const s = useSpring(frame, 0);
  const opacity = interpolate(frame, [0, 8], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  return (
    <div style={{
      opacity,
      transform: `scale(${0.5 + s * 0.5})`,
      color: accentColor,
      fontSize: 22,
      fontWeight: 800,
      letterSpacing: 6,
      textTransform: "uppercase",
      marginBottom: 16,
    }}>
      Beat {String(num).padStart(2, "0")}
    </div>
  );
}

function BackgroundGradient({ accentColor, frame }: { accentColor: string; frame: number }) {
  const opacity = interpolate(frame, [0, 30], [0, 0.12], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  return (
    <div style={{
      position: "absolute", inset: 0,
      background: `radial-gradient(ellipse at 70% 30%, ${accentColor} 0%, transparent 70%)`,
      opacity,
    }} />
  );
}

function ProgressBar({ beat, totalBeats, accentColor }: { beat: number; totalBeats: number; accentColor: string }) {
  return (
    <div style={{ position: "absolute", bottom: 0, left: 0, right: 0, height: 4, backgroundColor: "#1e2530" }}>
      <div style={{ height: "100%", width: `${(beat / totalBeats) * 100}%`, backgroundColor: accentColor }} />
    </div>
  );
}

// Generic fallback title card — used when no purpose-built component exists
function TitleCard({ beat, totalBeats }: { beat: Beat; totalBeats: number }) {
  const frame = useCurrentFrame();
  const { durationInFrames } = useVideoConfig();
  const fadeIn = interpolate(frame, [0, 20], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  const fadeOut = interpolate(frame, [durationInFrames - 15, durationInFrames], [1, 0], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  const masterOpacity = Math.min(fadeIn, fadeOut);

  return (
    <AbsoluteFill style={{ backgroundColor: "#0d1117", fontFamily: "'JetBrains Mono', 'Segoe UI', system-ui, sans-serif", opacity: masterOpacity }}>
      <BackgroundGradient accentColor={beat.accentColor} frame={frame} />
      <div style={{ position: "absolute", inset: 0, opacity: 0.03, backgroundImage: "linear-gradient(#fff 1px, transparent 1px), linear-gradient(90deg, #fff 1px, transparent 1px)", backgroundSize: "60px 60px" }} />
      <div style={{ position: "absolute", inset: 0, display: "flex", flexDirection: "column", justifyContent: "center", padding: "0 140px" }}>
        <BeatNumber num={beat.number} accentColor={beat.accentColor} frame={frame} />
        <div style={{ fontSize: 72, fontWeight: 800, color: "#e6edf3", lineHeight: 1.15, marginBottom: 32 }}>
          <TitleLine text={beat.title} frame={frame} delay={6} />
        </div>
        <RubricBadge text={beat.rubric} frame={frame} accentColor={beat.accentColor} />
        <div style={{ fontSize: 34, color: "#8b949e", lineHeight: 1.6, maxWidth: 1400, fontWeight: 400 }}>
          <TypewriterText text={beat.narration} frame={frame} startFrame={30} />
        </div>
      </div>
      <div style={{ position: "absolute", bottom: 24, left: 140, right: 140, display: "flex", justifyContent: "space-between", alignItems: "center", color: "#30363d", fontSize: 22 }}>
        <span>VERDICT</span>
        <span style={{ color: beat.accentColor }}>{beat.startS}s – {beat.endS}s</span>
      </div>
      <ProgressBar beat={beat.number} totalBeats={totalBeats} accentColor={beat.accentColor} />
    </AbsoluteFill>
  );
}

interface BeatProps {
  beat: Beat;
  totalBeats: number;
  audioFile: string | null;
}

// Dispatch to purpose-built components. The additional videos (explainer,
// deep-dives, quickstart, contributor call) set `beat.scene` and are dispatched
// by name. The original FindEvilDemo beats leave `scene` unset and fall through
// to the number-based dispatch below — behaviour is unchanged for that film.
function BeatContent({ beat, totalBeats }: { beat: Beat; totalBeats: number }) {
  if (beat.scene) {
    switch (beat.scene) {
      case "concept": return <ConceptCard beat={beat} totalBeats={totalBeats} />;
      case "exhibit": return <ExhibitChapter beat={beat} totalBeats={totalBeats} />;
      case "tools": return <ToolGrid />;
      case "arch": return <ArchDiagram />;
      case "outro": return <OutroScene />;
      case "logo": return <LogoIntro />;
      case "title":
      default: return <TitleCard beat={beat} totalBeats={totalBeats} />;
    }
  }
  switch (beat.number) {
    case 1: return <LogoIntro />;
    case 2: return <ClaudeCodeScene />;
    case 3: return <CaseProgression />;
    case 4: return <ToolGrid />;
    case 5: return <ContradictionScene />;
    case 6: return <DashboardUI />;
    case 7: return <HashChainScene />;
    case 8: return <AutomationUI />;
    case 9: return <FleetScene />;
    case 10: return <OutroScene />;
    default: return <TitleCard beat={beat} totalBeats={totalBeats} />;
  }
}

export function BeatScene({ beat, totalBeats, audioFile }: BeatProps) {
  return (
    <>
      <BeatContent beat={beat} totalBeats={totalBeats} />
      {audioFile && (
        <Audio src={staticFile(audioFile)} volume={1} />
      )}
    </>
  );
}
