// Shared chrome for the five role sprites. Each per-role sprite
// component renders a thin wrapper around <RoleSpriteCard> that
// supplies its own role label + testid.
//
// PHASE 5 PLACEHOLDER: this is intentionally low-fidelity NES.css
// chrome. The Claude Design pass will replace the inner JSX
// (<RoleSpriteCard>'s body) with real sprite art; the props,
// state-derivation, and parent page do NOT change when that swap
// happens.

import type { SpriteState } from "@/lib/sprite-state";

export interface RoleSpriteProps {
  state: SpriteState;
}

const STATE_COLORS: Record<SpriteState, string> = {
  idle: "#9ca3af", // gray-400 — quiet
  working: "#22c55e", // green-500 — active tool call
  waiting: "#eab308", // yellow-500 — handoff received, hasn't started
  verdict: "#3b82f6", // blue-500 — emitted a result
};

const STATE_LABELS: Record<SpriteState, string> = {
  idle: "idle",
  working: "working",
  waiting: "waiting",
  verdict: "verdict",
};

interface RoleSpriteCardProps {
  roleLabel: string;
  testId: string;
  state: SpriteState;
}

export function RoleSpriteCard({
  roleLabel,
  testId,
  state,
}: RoleSpriteCardProps) {
  const dotColor = STATE_COLORS[state];
  return (
    <div
      className="nes-container with-title is-rounded"
      data-testid={testId}
      data-state={state}
    >
      <p className="title">{roleLabel}</p>
      <div className="flex items-center gap-3">
        <span
          aria-label={`${roleLabel} ${STATE_LABELS[state]}`}
          style={{
            display: "inline-block",
            width: "0.9rem",
            height: "0.9rem",
            borderRadius: "9999px",
            background: dotColor,
            boxShadow: `0 0 6px ${dotColor}`,
            flexShrink: 0,
          }}
        />
        <span className="text-sm">{STATE_LABELS[state]}</span>
      </div>
    </div>
  );
}
