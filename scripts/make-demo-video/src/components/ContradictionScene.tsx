import React from "react";
import { AbsoluteFill, interpolate, spring, useCurrentFrame, useVideoConfig } from "remotion";
import { ChipBadge } from "./shared/ChipBadge";
import { Watermark } from "./shared/Watermark";

const MONO = "'JetBrains Mono', 'Courier New', monospace";

const POOL_A = {
  label: "Pool A",
  color: "#3498db",
  title: "Persistence-biased",
  finding: "HYPOTHESIS: Attacker dropped persistence via Autoruns registry key HKLM\\...\\Run\\svchost32",
  confidence: "INFERRED",
  mitre: "T1547.001",
  notes: ["prefetch_parse: svchost32.exe pf found", "registry_query: key present", "amcache: entry exists"],
};

const POOL_B = {
  label: "Pool B",
  color: "#9b59b6",
  title: "Exfil-biased",
  finding: "HYPOTHESIS: svchost32 is a legitimate Windows component installed by update KB5023696",
  confidence: "HYPOTHESIS",
  mitre: null,
  notes: ["hayabusa_scan: no sigma hits on svchost32", "mft_timeline: created alongside OS files", "no network IOC found"],
};

export function ContradictionScene() {
  const frame = useCurrentFrame();
  const { fps, durationInFrames } = useVideoConfig();
  const fadeOut = interpolate(frame, [durationInFrames - 15, durationInFrames], [1, 0], {
    extrapolateLeft: "clamp", extrapolateRight: "clamp",
  });

  const titleOp = interpolate(frame, [0, 16], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });

  // Pool A slides in from left at frame 15
  const poolAX = interpolate(frame - 15, [0, 20], [-500, 0], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  const poolAOp = interpolate(frame - 15, [0, 14], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });

  // Pool B slides in from right at frame 22
  const poolBX = interpolate(frame - 22, [0, 20], [500, 0], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  const poolBOp = interpolate(frame - 22, [0, 14], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });

  // Contradiction record pulses in at frame 50
  const contPulse = spring({ frame: frame - 50, fps, config: { damping: 10, stiffness: 120 } });
  const contOp = interpolate(frame - 50, [0, 12], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });

  // Judge merges at frame 80
  const judgeOp = interpolate(frame - 80, [0, 16], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  const judgeScale = spring({ frame: frame - 80, fps, config: { damping: 14, stiffness: 100 } });

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
          Analysis of Competing Hypotheses
        </div>
        <div style={{ fontFamily: MONO, fontSize: 20, color: "#8b949e", marginTop: 6 }}>
          Two pools — same evidence, opposing priors — disagree before reconciliation
        </div>
      </div>

      {/* Two columns */}
      <div style={{ position: "absolute", top: 180, left: 60, right: 60, display: "flex", gap: 24 }}>
        {/* Pool A card */}
        <div style={{ flex: 1, opacity: poolAOp, transform: `translateX(${poolAX}px)` }}>
          <PoolCard pool={POOL_A} />
        </div>

        {/* Middle — contradiction + judge */}
        <div style={{ width: 220, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: 24, paddingTop: 40 }}>
          {/* Contradiction badge */}
          <div style={{
            opacity: contOp,
            transform: `scale(${0.5 + contPulse * 0.5})`,
            background: "rgba(231,76,60,0.15)",
            border: "2px solid #e74c3c",
            borderRadius: 10,
            padding: "14px 18px",
            textAlign: "center",
          }}>
            <div style={{ fontFamily: MONO, fontSize: 13, fontWeight: 700, color: "#e74c3c", letterSpacing: 1 }}>
              kind=contradiction
            </div>
            <div style={{ fontFamily: MONO, fontSize: 11, color: "#8b949e", marginTop: 4 }}>
              detect_contradictions
            </div>
          </div>

          {/* Arrow down */}
          {frame > 65 && (
            <div style={{ color: "#30363d", fontSize: 28 }}>↓</div>
          )}

          {/* Judge verdict */}
          {frame > 80 && (
            <div style={{
              opacity: judgeOp,
              transform: `scale(${0.6 + judgeScale * 0.4})`,
              background: "rgba(46,204,113,0.12)",
              border: "1.5px solid #2ecc71",
              borderRadius: 10,
              padding: "14px 18px",
              textAlign: "center",
            }}>
              <div style={{ fontFamily: MONO, fontSize: 13, fontWeight: 700, color: "#2ecc71", letterSpacing: 1 }}>
                judge_findings
              </div>
              <div style={{ fontFamily: MONO, fontSize: 11, color: "#8b949e", marginTop: 4 }}>
                credibility-weighted
              </div>
            </div>
          )}
        </div>

        {/* Pool B card */}
        <div style={{ flex: 1, opacity: poolBOp, transform: `translateX(${poolBX}px)` }}>
          <PoolCard pool={POOL_B} />
        </div>
      </div>

      <Watermark />
    </AbsoluteFill>
  );
}

function PoolCard({ pool }: { pool: typeof POOL_A }) {
  return (
    <div style={{
      background: `${pool.color}0d`,
      border: `1.5px solid ${pool.color}55`,
      borderRadius: 12,
      padding: 28,
    }}>
      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 16, alignItems: "center" }}>
        <span style={{ fontFamily: MONO, fontSize: 22, fontWeight: 800, color: pool.color }}>{pool.label}</span>
        <ChipBadge label={pool.confidence as "CONFIRMED" | "INFERRED" | "HYPOTHESIS"} variant={pool.confidence as "CONFIRMED" | "INFERRED" | "HYPOTHESIS"} fontSize={14} />
      </div>
      <div style={{ fontFamily: MONO, fontSize: 13, color: "#8b949e", marginBottom: 16 }}>{pool.title}</div>
      <div style={{
        fontFamily: MONO, fontSize: 16, color: "#e6edf3",
        background: "#161b22", borderRadius: 8, padding: "14px 18px",
        marginBottom: 20, lineHeight: 1.6,
      }}>
        {pool.finding}
      </div>
      {pool.mitre && (
        <div style={{ marginBottom: 14 }}>
          <ChipBadge label={`MITRE ${pool.mitre}`} variant="MITRE" fontSize={13} />
        </div>
      )}
      <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
        {pool.notes.map((note, i) => (
          <div key={i} style={{ fontFamily: MONO, fontSize: 13, color: "#30363d" }}>
            › {note}
          </div>
        ))}
      </div>
    </div>
  );
}
