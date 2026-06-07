import React from "react";

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
    CONFIRMED:  "#2ecc71",
    INFERRED:   "#f39c12",
    HYPOTHESIS: "#3498db",
  };
  const color = confidence ? confidenceColors[confidence] ?? "#8b949e" : "#8b949e";

  return (
    <div style={{
      display: "flex",
      alignItems: "center",
      gap: 12,
      padding: "8px 16px",
      borderRadius: 6,
      background: highlight ? "rgba(155,89,182,0.12)" : "rgba(22,27,34,0.8)",
      border: highlight ? "1px solid rgba(155,89,182,0.5)" : "1px solid #30363d",
      opacity: dim ? 0.35 : 1,
      fontFamily: "'JetBrains Mono', 'Courier New', monospace",
      fontSize: 14,
    }}>
      <span style={{ color: "#9b59b6", minWidth: 160 }}>{kind}</span>
      <span style={{ color: "#6e7681", fontSize: 11 }}>prev:</span>
      <span style={{ color: "#6e7681", fontFamily: "monospace", fontSize: 11 }}>{prevHash}</span>
      <span style={{ color: "#6e7681", fontSize: 11 }}>→</span>
      <span style={{ color: "#8b949e", fontFamily: "monospace", fontSize: 11 }}>{hash}</span>
      {confidence && (
        <span style={{ marginLeft: "auto", color, fontWeight: 700, fontSize: 12 }}>{confidence}</span>
      )}
    </div>
  );
}
