// Correlator — enforces the SOUL.md ≥2 artifact-class rule. See
// agent-config/AGENTS.md. Phase 5 placeholder visual; design pass
// replaces the JSX inside <RoleSpriteCard> without touching this
// file's props.

import { RoleSpriteCard, type RoleSpriteProps } from "./RoleSpriteCommon";

export function CorrelatorSprite({ state }: RoleSpriteProps) {
  return (
    <RoleSpriteCard
      roleLabel="Correlator"
      testId="correlator-sprite"
      state={state}
    />
  );
}
