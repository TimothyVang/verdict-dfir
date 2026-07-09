import React from "react";
import { C } from "./editorial";

const CHIP_COLORS: Record<string, { bg: string; border: string; text: string }> = {
  CONFIRMED:  { bg: "rgba(115,217,194,0.15)", border: C.confirmed, text: C.confirmed },
  INFERRED:   { bg: "rgba(255,215,106,0.15)", border: C.inferred, text: C.inferred },
  HYPOTHESIS: { bg: "rgba(77,93,255,0.15)", border: C.hypothesis, text: C.hypothesis },
  MITRE:      { bg: "rgba(77,93,255,0.15)", border: C.accent, text: C.accent },
  ERROR:      { bg: "rgba(255,98,87,0.15)",  border: C.alert, text: C.alert },
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
