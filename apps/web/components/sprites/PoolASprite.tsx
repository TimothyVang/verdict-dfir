// Pool A — persistence-biased agent. See agent-config/AGENTS.md.
// Phase 5 placeholder visual; design pass replaces the JSX inside
// <RoleSpriteCard> without touching this file's props.

import { RoleSpriteCard, type RoleSpriteProps } from "./RoleSpriteCommon";

export function PoolASprite({ state }: RoleSpriteProps) {
  return (
    <RoleSpriteCard
      roleLabel="Pool A — persistence"
      testId="pool_a-sprite"
      state={state}
    />
  );
}
