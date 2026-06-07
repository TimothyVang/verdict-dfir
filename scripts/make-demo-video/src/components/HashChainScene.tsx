import React from "react";
import { AbsoluteFill, interpolate, spring, useCurrentFrame, useVideoConfig } from "remotion";
import { AuditLine } from "./shared/AuditLine";
import { Watermark } from "./shared/Watermark";

const MONO = "'JetBrains Mono', 'Courier New', monospace";

const AUDIT_RECORDS = [
  { kind: "case_open",        hash: "9b57a2f3c841e609", prevHash: "0000000000000000", confidence: undefined },
  { kind: "tool_call",        hash: "e3b0c44298fc1c14", prevHash: "9b57a2f3c841e609", confidence: undefined },
  { kind: "finding",          hash: "4a7d1e9c03b2f581", prevHash: "e3b0c44298fc1c14", confidence: "INFERRED"  },
  { kind: "verify_finding",   hash: "8c3f0bde7a214e90", prevHash: "4a7d1e9c03b2f581", confidence: "CONFIRMED" },
  { kind: "judge_selfscore",  hash: "2f6a8d01c943b7e5", prevHash: "8c3f0bde7a214e90", confidence: undefined  },
  { kind: "manifest_finalize",hash: "d1e4bc7a906f2c38", prevHash: "2f6a8d01c943b7e5", confidence: undefined  },
];

export function HashChainScene() {
  const frame = useCurrentFrame();
  const { fps, durationInFrames } = useVideoConfig();
  const fadeOut = interpolate(frame, [durationInFrames - 15, durationInFrames], [1, 0], {
    extrapolateLeft: "clamp", extrapolateRight: "clamp",
  });

  const titleOp = interpolate(frame, [0, 16], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });

  // Merkle root appears at frame 65
  const merkleOp = interpolate(frame - 65, [0, 14], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  const merkleS = spring({ frame: frame - 65, fps, config: { damping: 12, stiffness: 100 } });

  // Sigstore badge appears at frame 90
  const sigOp = interpolate(frame - 90, [0, 16], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  const sigS = spring({ frame: frame - 90, fps, config: { damping: 12, stiffness: 90 } });

  // FRE label at frame 110
  const freOp = interpolate(frame - 110, [0, 14], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });

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
          Cryptographic Chain-of-Custody
        </div>
        <div style={{ fontFamily: MONO, fontSize: 20, color: "#8b949e", marginTop: 6 }}>
          3 tiers: audit prev_hash → rs_merkle → sigstore Rekor
        </div>
      </div>

      {/* Audit records column */}
      <div style={{ position: "absolute", top: 180, left: 140, width: 820, display: "flex", flexDirection: "column", gap: 10 }}>
        {AUDIT_RECORDS.map((rec, i) => {
          const delay = 15 + i * 12;
          const op = interpolate(frame - delay, [0, 10], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
          return (
            <div key={i} style={{ opacity: op }}>
              <AuditLine
                kind={rec.kind}
                hash={rec.hash}
                prevHash={rec.prevHash}
                confidence={rec.confidence}
                highlight={rec.kind === "manifest_finalize"}
              />
              {i < AUDIT_RECORDS.length - 1 && frame > delay + 8 && (
                <div style={{ marginLeft: 24, color: "#30363d", fontSize: 14, fontFamily: MONO }}>↓ links to next</div>
              )}
            </div>
          );
        })}
      </div>

      {/* Right column: Merkle + Sigstore */}
      <div style={{ position: "absolute", top: 180, right: 100, width: 640, display: "flex", flexDirection: "column", gap: 24 }}>
        {/* Merkle root box */}
        <div style={{
          opacity: merkleOp,
          transform: `scale(${0.7 + merkleS * 0.3})`,
          background: "rgba(155,89,182,0.12)",
          border: "1.5px solid #9b59b6",
          borderRadius: 12,
          padding: "24px 28px",
        }}>
          <div style={{ fontFamily: MONO, fontSize: 16, fontWeight: 700, color: "#9b59b6", marginBottom: 10 }}>
            rs_merkle root
          </div>
          <div style={{ fontFamily: MONO, fontSize: 13, color: "#8b949e", lineHeight: 1.8 }}>
            <div>root: <span style={{ color: "#e6edf3" }}>f7a3c9e2b1d04...</span></div>
            <div>leaves: <span style={{ color: "#e6edf3" }}>6 audit records</span></div>
            <div>algorithm: <span style={{ color: "#e6edf3" }}>SHA-256</span></div>
          </div>
        </div>

        {/* Sigstore badge */}
        <div style={{
          opacity: sigOp,
          transform: `scale(${0.7 + sigS * 0.3})`,
          background: "rgba(46,204,113,0.10)",
          border: "1.5px solid #2ecc71",
          borderRadius: 12,
          padding: "24px 28px",
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 10 }}>
            <div style={{ width: 20, height: 20, borderRadius: "50%", background: "#2ecc71", display: "flex", alignItems: "center", justifyContent: "center" }}>
              <span style={{ color: "#0d1117", fontSize: 12, fontWeight: 800 }}>✓</span>
            </div>
            <div style={{ fontFamily: MONO, fontSize: 16, fontWeight: 700, color: "#2ecc71" }}>
              Signed via sigstore Rekor
            </div>
          </div>
          <div style={{ fontFamily: MONO, fontSize: 13, color: "#8b949e", lineHeight: 1.8 }}>
            <div>log_id: <span style={{ color: "#e6edf3" }}>rekor.sigstore.dev</span></div>
            <div>entry_id: <span style={{ color: "#e6edf3" }}>24922385...</span></div>
            <div>verifiable: <span style={{ color: "#2ecc71" }}>offline, forever</span></div>
          </div>
        </div>

        {/* FRE 902(14) note */}
        <div style={{
          opacity: freOp,
          background: "rgba(52,152,219,0.08)",
          border: "1px solid #3498db44",
          borderRadius: 8,
          padding: "16px 20px",
          fontFamily: MONO, fontSize: 14, color: "#3498db", lineHeight: 1.7,
        }}>
          FRE 902(14) — self-authenticating electronic evidence.<br/>
          A court can verify this manifest from the sigstore Rekor<br/>
          transparency log — no expert witness required.
        </div>

        {/* manifest_verify CLI block */}
        <div style={{
          opacity: freOp,
          background: "#0d1117",
          border: "1px solid #30363d",
          borderRadius: 8,
          padding: "12px 18px",
          fontFamily: MONO, fontSize: 12, lineHeight: 1.9,
        }}>
          <div style={{ color: "#e6edf3" }}>
            $ uv run python -m findevil_agent_mcp.server manifest_verify
          </div>
          <div style={{ color: "#2ecc71" }}>chain:        OK</div>
          <div style={{ color: "#2ecc71" }}>merkle_root:  d1e4bc7a906f2c38</div>
          <div style={{ color: "#2ecc71" }}>sigstore:     VERIFIED (rekor.sigstore.dev/24922385)</div>
          <div style={{ color: "#8b949e" }}>records:      6  ·  findings: 2  ·  CONFIRMED: 1</div>
        </div>
      </div>

      <Watermark />
    </AbsoluteFill>
  );
}
