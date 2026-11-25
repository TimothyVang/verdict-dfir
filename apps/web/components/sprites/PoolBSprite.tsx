// Pool B — exfiltration-biased agent. See agent-config/AGENTS.md.
// Phase 5 placeholder visual; design pass replaces the JSX inside
// <RoleSpriteCard> without touching this file's props.

import { RoleSpriteCard, type RoleSpriteProps } from "./RoleSpriteCommon";

export function PoolBSprite({ state }: RoleSpriteProps) {
  return (
    <RoleSpriteCard
      roleLabel="Pool B — exfiltration"
      testId="pool_b-sprite"
      state={state}
    />
  );
}
