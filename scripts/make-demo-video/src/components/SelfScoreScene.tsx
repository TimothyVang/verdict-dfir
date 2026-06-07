import React from "react";
import { AbsoluteFill, interpolate, spring, useCurrentFrame, useVideoConfig } from "remotion";
import { Watermark } from "./shared/Watermark";

const MONO = "'JetBrains Mono', 'Courier New', monospace";

const JQ_LINES = [
  { text: '{ "kind": "judge_selfscore",',              color: "#9b59b6" },
  { text: '  "criterion": "Evidence Coverage",',        color: "#e6edf3" },
  { text: '  "score": 4, "max": 5,',                    color: "#2ecc71" },
  { text: '  "ts": "2026-06-07T14:28:40Z",',            color: "#30363d" },
  { text: '  "prev_hash": "4a7d1e9c03b2f581",',         color: "#30363d" },
  { text: '  "notes": "All 4 artifact classes exercised" }', color: "#8b949e" },
  { text: '{ "kind": "judge_selfscore",',              color: "#9b59b6" },
  { text: '  "criterion": "Finding Quality",',          color: "#e6edf3" },
  { text: '  "score": 5, "max": 5,',                    color: "#2ecc71" },
  { text: '  "prev_hash": "e3b0c44298fc1c14",',         color: "#30363d" },
  { text: '  "notes": "DKOM CONFIRMED via >=2 artifact classes" }', color: "#8b949e" },
  { text: '{ "kind": "judge_selfscore",',              color: "#9b59b6" },
  { text: '  "criterion": "Chain-of-Custody",',         color: "#e6edf3" },
  { text: '  "score": 5, "max": 5,',                    color: "#2ecc71" },
  { text: '  "ts": "2026-06-07T14:28:44Z",',            color: "#30363d" },
  { text: '  "prev_hash": "8c3f0bde7a214e90",',         color: "#30363d" },
  { text: '  "notes": "sigstore Rekor, offline verifiable" }', color: "#8b949e" },
];

const SCORES = [
  { criterion: "Evidence Coverage",  score: 4, max: 5, color: "#2ecc71" },
  { criterion: "Finding Quality",    score: 5, max: 5, color: "#2ecc71" },
  { criterion: "Chain-of-Custody",   score: 5, max: 5, color: "#9b59b6" },
  { criterion: "Accuracy",           score: 4, max: 5, color: "#2ecc71" },
  { criterion: "Reporting",          score: 4, max: 5, color: "#f39c12" },
  { criterion: "Innovation",         score: 5, max: 5, color: "#3498db" },
];

export function SelfScoreScene() {
  const frame = useCurrentFrame();
  const { fps, durationInFrames } = useVideoConfig();
  const fadeOut = interpolate(frame, [durationInFrames - 15, durationInFrames], [1, 0], {
    extrapolateLeft: "clamp", extrapolateRight: "clamp",
  });

  const titleOp = interpolate(frame, [0, 16], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });

  // Right panel slides in at frame 30
  const rightOp = interpolate(frame - 30, [0, 16], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  const rightX = interpolate(frame - 30, [0, 16], [80, 0], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });

  // Total badge at frame 80
  const totalOp = interpolate(frame - 80, [0, 14], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  const totalS = spring({ frame: frame - 80, fps, config: { damping: 10, stiffness: 100 } });

  return (
    <AbsoluteFill style={{ backgroundColor: "#0d1117", opacity: fadeOut }}>
      <div style={{
        position: "absolute", inset: 0, opacity: 0.04,
        backgroundImage: "linear-gradient(#fff 1px, transparent 1px), linear-gradient(90deg, #fff 1px, transparent 1px)",
        backgroundSize: "60px 60px",
      }} />

      {/* Title */}
      <div style={{ position: "absolute", top: 52, left: 140, right: 140, opacity: titleOp }}>
        <div style={{ fontFamily: MONO, fontSize: 52, fontWeight: 800, color: "#e6edf3" }}>
          Tiebreaker — Self-Score Chip
        </div>
        <div style={{ fontFamily: MONO, fontSize: 20, color: "#8b949e", marginTop: 6 }}>
          Agent self-scores against SANS rubric — signed in the Merkle tree before manifest_finalize
        </div>
      </div>

      {/* Left: jq output */}
      <div style={{
        position: "absolute", top: 185, left: 100, width: 820,
        background: "#0d1117", border: "1px solid #30363d", borderRadius: 12, overflow: "hidden",
      }}>
        {/* Chrome */}
        <div style={{ padding: "10px 16px", background: "#161b22", borderBottom: "1px solid #30363d", display: "flex", alignItems: "center", gap: 8 }}>
          <div style={{ width: 10, height: 10, borderRadius: "50%", background: "#e74c3c" }} />
          <div style={{ width: 10, height: 10, borderRadius: "50%", background: "#f39c12" }} />
          <div style={{ width: 10, height: 10, borderRadius: "50%", background: "#2ecc71" }} />
          <span style={{ marginLeft: 12, fontFamily: MONO, fontSize: 12, color: "#8b949e" }}>
            jq .[] audit.jsonl | grep judge_selfscore
          </span>
        </div>
        <div style={{ padding: "18px 20px", fontFamily: MONO, fontSize: 13, lineHeight: 1.8 }}>
          {JQ_LINES.map((line, i) => {
            const delay = 10 + i * 7;
            const op = interpolate(frame - delay, [0, 8], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
            return (
              <div key={i} style={{ opacity: op, color: line.color }}>{line.text}</div>
            );
          })}
        </div>
      </div>

      {/* Right: score table */}
      <div style={{
        position: "absolute", top: 185, right: 60, width: 680,
        opacity: rightOp, transform: `translateX(${rightX}px)`,
      }}>
        <div style={{
          background: "#161b22", border: "1px solid #30363d", borderRadius: 12, padding: 24,
          fontFamily: MONO,
        }}>
          <div style={{ fontSize: 16, fontWeight: 700, color: "#e6edf3", marginBottom: 20 }}>
            SANS Rubric Self-Assessment
          </div>
          {SCORES.map((s, i) => {
            const barDelay = 35 + i * 8;
            const barW = interpolate(frame - barDelay, [0, 20], [0, (s.score / s.max) * 100], {
              extrapolateLeft: "clamp", extrapolateRight: "clamp",
            });
            const barOp = interpolate(frame - barDelay, [0, 10], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
            return (
              <div key={s.criterion} style={{ marginBottom: 18, opacity: barOp }}>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6 }}>
                  <span style={{ fontSize: 14, color: "#8b949e" }}>{s.criterion}</span>
                  <span style={{ fontSize: 14, fontWeight: 700, color: s.color }}>{s.score}/{s.max}</span>
                </div>
                <div style={{ height: 6, background: "#0d1117", borderRadius: 3 }}>
                  <div style={{ height: "100%", width: `${barW}%`, background: s.color, borderRadius: 3 }} />
                </div>
              </div>
            );
          })}

          {/* Total */}
          <div style={{
            marginTop: 24, borderTop: "1px solid #30363d", paddingTop: 20,
            display: "flex", justifyContent: "space-between", alignItems: "center",
            opacity: totalOp, transform: `scale(${0.7 + totalS * 0.3})`,
          }}>
            <span style={{ fontFamily: MONO, fontSize: 18, color: "#e6edf3", fontWeight: 700 }}>Total</span>
            <span style={{ fontFamily: MONO, fontSize: 28, fontWeight: 800, color: "#2ecc71" }}>27/30</span>
          </div>
        </div>

        <div style={{
          marginTop: 16,
          background: "rgba(155,89,182,0.08)", border: "1px solid #9b59b644",
          borderRadius: 8, padding: "12px 18px",
          fontFamily: MONO, fontSize: 13, color: "#9b59b6", lineHeight: 1.7,
        }}>
          Score is signed in Merkle tree at manifest_finalize.<br/>
          Judges cannot be presented a revised score post-run.
        </div>
      </div>

      <Watermark />
    </AbsoluteFill>
  );
}
