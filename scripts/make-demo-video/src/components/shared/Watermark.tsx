import React from "react";

export function Watermark() {
  return (
    <div style={{
      position: "absolute",
      bottom: 32,
      right: 48,
      display: "flex",
      alignItems: "center",
      gap: 10,
      opacity: 0.22,
    }}>
      <svg width="28" height="28" viewBox="0 0 80 80" xmlns="http://www.w3.org/2000/svg">
        <circle cx="40" cy="40" r="38" fill="#0d1117" stroke="#9b59b6" strokeWidth="2"/>
        <rect x="14" y="18" width="38" height="17" rx="4" fill="#9b59b6"/>
        <rect x="31" y="29" width="5" height="30" rx="2.5" fill="#30363d" transform="rotate(-30 33 44)"/>
        <ellipse cx="20" cy="58" rx="8" ry="5" fill="none" stroke="#8b949e" strokeWidth="2.5"/>
        <ellipse cx="36" cy="58" rx="8" ry="5" fill="none" stroke="#8b949e" strokeWidth="2.5"/>
        <circle cx="56" cy="58" r="8" fill="#2ecc71" opacity="0.9"/>
        <polyline points="52,58 55,61 61,54" fill="none" stroke="#0d1117" strokeWidth="2"
          strokeLinecap="round" strokeLinejoin="round"/>
      </svg>
      <span style={{
        fontFamily: "'JetBrains Mono', 'Courier New', monospace",
        fontSize: 15,
        color: "#e6edf3",
        fontWeight: 700,
        letterSpacing: 3,
      }}>
        VERDICT
      </span>
    </div>
  );
}
