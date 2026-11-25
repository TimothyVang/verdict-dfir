import React from "react";
import { C } from "./editorial";

interface AuditLineProps {
  kind: string;
  hash: string;
  prevHash: string;
  confidence?: string;
  dim?: boolean;
  highlight?: boolean;
}

export function AuditLine({ kind, hash, prevHash, confidence, dim, highlight }: AuditLineProps) {
  const confidenceColors: Record<string, string> = {
    CONFIRMED: C.confirmed,
    INFERRED: C.inferred,
    HYPOTHESIS: C.hypothesis,
  };
  const color = confidence ? confidenceColors[confidence] ?? C.inkMuted : C.inkMuted;

  return (
    <div style={{
      display: "flex",
      alignItems: "center",
      gap: 12,
      padding: "8px 16px",
      borderRadius: 6,
      background: highlight ? "rgba(77,93,255,0.12)" : "rgba(18,19,26,0.84)",
      border: highlight ? "1px solid rgba(77,93,255,0.5)" : `1px solid ${C.hairline}`,
      opacity: dim ? 0.35 : 1,
      fontFamily: "'JetBrains Mono', 'Courier New', monospace",
      fontSize: 14,
    }}>
      <span style={{ color: C.accent, minWidth: 160 }}>{kind}</span>
      <span style={{ color: C.inkFaint, fontSize: 11 }}>prev:</span>
      <span style={{ color: C.inkFaint, fontFamily: "monospace", fontSize: 11 }}>{prevHash}</span>
      <span style={{ color: C.inkFaint, fontSize: 11 }}>→</span>
      <span style={{ color: C.inkMuted, fontFamily: "monospace", fontSize: 11 }}>{hash}</span>
      {confidence && (
        <span style={{ marginLeft: "auto", color, fontWeight: 700, fontSize: 12 }}>{confidence}</span>
      )}
    </div>
  );
}
