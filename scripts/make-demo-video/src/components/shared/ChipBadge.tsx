import React from "react";

const CHIP_COLORS: Record<string, { bg: string; border: string; text: string }> = {
  CONFIRMED:  { bg: "rgba(46,204,113,0.15)", border: "#2ecc71", text: "#2ecc71" },
  INFERRED:   { bg: "rgba(243,156,18,0.15)", border: "#f39c12", text: "#f39c12" },
  HYPOTHESIS: { bg: "rgba(52,152,219,0.15)", border: "#3498db", text: "#3498db" },
  MITRE:      { bg: "rgba(155,89,182,0.15)", border: "#9b59b6", text: "#9b59b6" },
  ERROR:      { bg: "rgba(231,76,60,0.15)",  border: "#e74c3c", text: "#e74c3c" },
};

interface ChipBadgeProps {
  label: string;
  variant?: "CONFIRMED" | "INFERRED" | "HYPOTHESIS" | "MITRE" | "ERROR";
  fontSize?: number;
  style?: React.CSSProperties;
}

export function ChipBadge({ label, variant = "CONFIRMED", fontSize = 18, style }: ChipBadgeProps) {
  const colors = CHIP_COLORS[variant] ?? CHIP_COLORS.CONFIRMED;
  return (
    <span style={{
      display: "inline-block",
      background: colors.bg,
      border: `1px solid ${colors.border}`,
      borderRadius: 6,
      padding: `4px 14px`,
      fontSize,
      fontWeight: 700,
      fontFamily: "'JetBrains Mono', 'Courier New', monospace",
      color: colors.text,
      letterSpacing: 1,
      ...style,
    }}>
      {label}
    </span>
  );
}
