// Judge — credibility-weighted merge of Pool A + Pool B findings.
// See agent-config/AGENTS.md. Phase 5 placeholder visual; design
// pass replaces the JSX inside <RoleSpriteCard> without touching
// this file's props.

import { RoleSpriteCard, type RoleSpriteProps } from "./RoleSpriteCommon";

export function JudgeSprite({ state }: RoleSpriteProps) {
  return (
    <RoleSpriteCard
      roleLabel="Judge"
      testId="judge-sprite"
      state={state}
    />
  );
}
