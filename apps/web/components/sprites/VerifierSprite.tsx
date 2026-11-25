// Verifier — re-runs each Finding's cited tool_call_id. See
// agent-config/AGENTS.md. Phase 5 placeholder visual; design pass
// replaces the JSX inside <RoleSpriteCard> without touching this
// file's props.

import { RoleSpriteCard, type RoleSpriteProps } from "./RoleSpriteCommon";

export function VerifierSprite({ state }: RoleSpriteProps) {
  return (
    <RoleSpriteCard
      roleLabel="Verifier"
      testId="verifier-sprite"
      state={state}
    />
  );
}
