import React from "react";
import {
  interpolate,
  OffthreadVideo,
  spring,
  staticFile,
  useCurrentFrame,
  useVideoConfig,
} from "remotion";
import { C, GROTESK, MONO } from "./editorial";

// ExhibitVideo — the one place real captured footage enters the film. It frames
// a genuine screen recording (the live terminal, the dashboard, the offline
// manifest_verify) inside the same editorial "window" treatment the dashboard
// beat already uses, so a real capture reads as a forensic EXHIBIT, not a raw
// screen grab. The substance on screen is genuine capture — the frame around it
// is the only thing the film draws.
//
// Footage that does not exist yet renders as an on-brand "AWAITING CAPTURE"
// placeholder instead of crashing the render: a file is only played once its
// basename is added to CAPTURED below (drop the .mp4 into public/ui/ AND list
// it here). That keeps `npm run studio` / `render` working at every step of the
// recording process — see scripts/make-demo-video/CAPTURE.md.

// Basenames (under public/ui/) of captures that actually exist on disk. Add a
// filename here the moment you drop its .mp4 in, and the placeholder flips to
// the real footage. dashboard-live.mp4 ships in the repo; the rest are recorded
// per CAPTURE.md.
export const CAPTURED: ReadonlySet<string> = new Set<string>([
  "dashboard-live.mp4",
  // Primary terminal cut: a genuine asciinema capture of a clean investigation
  // run with no fault injection. Optional harness recovery footage uses a
  // separate appendix clip and must not replace this primary asset.
  "terminal-investigation.mp4",
  // Real offline tamper demo (CAPTURE.md Slot 3): trace-finding passes on the
  // committed run, one hex char is flipped in a /tmp copy, the verifier fails
  // naming the exact broken record (seq 97 prev_hash break).
  "manifest-tamper.mp4",
  // Organic cross-pool contradiction (no injection): a real SRL-2018 run where
  // Pool A and Pool B disagree, detect_contradictions surfaces each clash, and
  // the credibility-weighted judge reconciles it (auto_higher_credibility).
  "F-contradiction.mp4",
  // Live interactive Claude Code TUI: a genuinely broken artifact — a truncated
  // registry hive (registry_query: "hive truncated, header too small") — drives a
  // named course_correction (narrow, continue other lanes), then a heartbeat
  // escalation to an honest partial / INDETERMINATE verdict. Organic self-correction
  // captured on the real TUI, fault_injection=0 (matches deepdive Beat 4).
  "self-correction.mp4",
]);

const clampOpts = { extrapolateLeft: "clamp", extrapolateRight: "clamp" } as const;

const TITLEBAR_H = 40;

function basename(src: string): string {
  const parts = src.split("/");
  return parts[parts.length - 1] ?? src;
}

interface ExhibitVideoProps {
  /** staticFile-relative path, e.g. "ui/terminal-investigation.mp4". */
  src: string;
  /** Mono label shown in the window title bar (the "address"). */
  label: string;
  /** Window geometry on the 1920×1080 canvas (top-left anchored). */
  x: number;
  y: number;
  w: number;
  h: number;
  /** "contain" keeps terminal text un-cropped; "cover" fills (dashboards). */
  objectFit?: "cover" | "contain";
  /** Playback speed — speed a long real run up to fit a short beat. */
  playbackRate?: number;
  /** Frame to start the source at (trim a slow head). */
  startFrom?: number;
}

export function ExhibitVideo({
  src,
  label,
  x,
  y,
  w,
  h,
  objectFit = "cover",
  playbackRate = 1,
  startFrom = 0,
}: ExhibitVideoProps) {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  // Match the dashboard beat's spring-in so every exhibit lands the same way.
  const winSpring = spring({ frame, fps, config: { damping: 18, stiffness: 110 } });
  const winOp = interpolate(frame, [0, 20], [0, 1], clampOpts);
  const winScale = 0.965 + winSpring * 0.035;
  const winRise = (1 - winSpring) * 18;

  const isCaptured = CAPTURED.has(basename(src));

  return (
    <div
      style={{
        position: "absolute",
        left: x,
        top: y,
        width: w,
        height: h,
        opacity: winOp,
        transform: `translateY(${winRise}px) scale(${winScale})`,
        transformOrigin: "60% 40%",
        border: `1px solid ${C.hairline}`,
        borderRadius: 10,
        overflow: "hidden",
        background: C.surface,
        boxShadow: `0 30px 80px ${C.paperEdge}aa`,
      }}
    >
      {/* slim title bar — three muted dots + a mono "address" */}
      <div
        style={{
          height: TITLEBAR_H,
          display: "flex",
          alignItems: "center",
          gap: 16,
          padding: "0 18px",
          borderBottom: `1px solid ${C.hairline}`,
          background: C.paper,
        }}
      >
        <div style={{ display: "flex", gap: 8 }}>
          {[0, 1, 2].map((i) => (
            <span
              key={i}
              style={{ width: 9, height: 9, borderRadius: "50%", background: C.inkFaint }}
            />
          ))}
        </div>
        <span style={{ fontFamily: MONO, fontSize: 13, letterSpacing: 1, color: C.inkFaint }}>
          {label}
        </span>
      </div>

      <div style={{ position: "relative", width: "100%", height: h - TITLEBAR_H, background: C.paper }}>
        {isCaptured ? (
          <OffthreadVideo
            src={staticFile(src)}
            muted
            playbackRate={playbackRate}
            startFrom={startFrom}
            style={{ width: "100%", height: "100%", objectFit }}
          />
        ) : (
          <AwaitingCapture filename={basename(src)} frame={frame} />
        )}
      </div>
    </div>
  );
}

// On-brand placeholder so the timeline renders before footage is recorded. A
// faint scanline sweeps so the slot reads as "waiting", not broken.
function AwaitingCapture({ filename, frame }: { filename: string; frame: number }) {
  const sweep = (frame * 2) % 100;
  return (
    <div
      style={{
        width: "100%",
        height: "100%",
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        gap: 14,
        position: "relative",
        overflow: "hidden",
      }}
    >
      <div
        style={{
          position: "absolute",
          left: 0,
          right: 0,
          top: `${sweep}%`,
          height: 2,
          background: `${C.accent}33`,
        }}
      />
      <div
        style={{
          fontFamily: GROTESK,
          fontSize: 17,
          fontWeight: 600,
          letterSpacing: 4,
          textTransform: "uppercase",
          color: C.inkMuted,
        }}
      >
        Exhibit · Awaiting capture
      </div>
      <div style={{ fontFamily: MONO, fontSize: 15, color: C.inkFaint, letterSpacing: 1 }}>
        public/ui/{filename}
      </div>
      <div style={{ fontFamily: MONO, fontSize: 12, color: C.inkFaint, letterSpacing: 1, opacity: 0.7 }}>
        record per CAPTURE.md → add to CAPTURED
      </div>
    </div>
  );
}
