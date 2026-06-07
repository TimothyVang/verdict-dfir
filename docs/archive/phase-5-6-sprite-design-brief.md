# Phase 5/6 sprite + chrome design brief

**For:** Claude Design prototyping session (or human designer adopting the same constraints).
**Project:** Find Evil! — SANS Find Evil! 2026 hackathon submission.
**Branch:** `master` (do not branch for design work; deliverables are PNGs + small CSS overrides, swapped into existing components).
**Deadline:** 2026-06-15 (deliverables ideally land 2 weeks earlier so we can re-record the demo video against final art).
**Status when this brief was written:** all five sprite components and the dashboard page are scaffolded with placeholder visuals; the engineering contract (props, state machine, file paths) is locked.

> **Archive note (non-authoritative).** This parked brief predates the self-score change. `judge_selfscore` is no longer emitted into the investigation pipeline and the dashboard no longer renders it — the SANS-rubric self-assessment now lives only in the standalone pre-submission grader `scripts/self-score.py` (writes `<case>/self-score.json`; does not touch the sealed audit chain). Where the AuditBeadString palette and `kind` references below mention `judge_selfscore`, treat them as historical: that bead kind no longer appears in a live audit stream. The Pool A/B `judge_findings` MERGE agent (the "Judge" sprite) is unrelated and unaffected. CLAUDE.md is authoritative.

---

## 1. What's being designed

Five **always-on pixel-art role sprites** plus three **dashboard chrome components** for the live audit dashboard at `apps/web/`. The dashboard tails a running investigation's `audit.jsonl` over Server-Sent Events and renders the agent army at work, in the spirit of NES-era management/strategy games (NES.css is the chosen aesthetic library — already wired in).

**The sprites are characters, not status icons.** Each one represents a real agent role from `agent-config/AGENTS.md`. A SANS judge watching the demo should feel they're watching a small turn-based RPG party investigate a memory image, with the audit chain visible as a string of beads beneath them.

### The five sprites

| Sprite | Role narrative | Visual cue ideas (suggestive, not prescriptive) |
|---|---|---|
| **Pool A — persistence-biased** | The "registry archaeologist." Hunts Run keys, Services, Scheduled Tasks, Amcache, Prefetch. Slow, methodical. | Cloak / robe; magnifying glass over a registry hive; earth-tone palette |
| **Pool B — exfil-biased** | The "network watcher." Hunts beacons, DNS oddities, anomalous outbound connections, RDP/SMB lateral movement. Quick, suspicious. | Hood / scarf obscuring face; spyglass aimed outward; cool-blue palette |
| **Verifier** | The "skeptic." Re-runs every cited `tool_call_id` to confirm Pool A/B's findings reproduce. Stops anything not backed by evidence. | Owl, librarian, or judge-in-training; checklist + stamp; muted gray-purple |
| **Judge** | The "magistrate." Receives Pool A + Pool B findings (post-verifier), surfaces contradictions, applies credibility-weighted merge. | Crowned figure on a small dais; scales of justice; gold accent over neutral robe |
| **Correlator** | The "two-witnesses-or-it-didn't-happen" enforcer. Demands ≥2 artifact classes for any execution claim (SOUL.md hard rule). | Twin figures or one figure holding two scrolls; chain-link motif; warm-red accent |

The supervisor role (Claude Code itself) is deliberately **off-screen**. Don't design a supervisor sprite.

### The three chrome components

| Component | Function | Where on the page |
|---|---|---|
| **AuditBeadString** | One bead per `audit_append` event, threaded left-to-right in chronological order. Color encodes the `kind` field (`tool_call_start`, `finding_approved`, `acp_handoff`, `judge_selfscore`, etc.). Hovering a bead reveals seq + ts + line_hash. | Horizontal strip beneath the sprite grid, full width |
| **HashChainBadge** | Single shield/seal indicating whether the audit chain currently verifies. Green = `prev_hash` chain intact + Merkle root matches. Red = tampered or broken. | Top-right of the dashboard header |
| **FindingChip** | Compact card showing one Finding: confidence tier (`CONFIRMED` / `INFERRED` / `HYPOTHESIS`), MITRE technique if present, summary, `tool_call_id` evidence pointer. | Stacked in a panel below the AuditBeadString as findings emerge |

---

## 2. Hard constraints (the engineering contract — do not violate)

The placeholders shipped in PR #15 deliberately froze everything below the visual layer. The design pass replaces **only** the inner JSX of each component's render body and supplies image assets. Anything in this section is non-negotiable without a spec amendment.

### 2.1 Sprite component contract

Every sprite component (`apps/web/components/sprites/{PoolA,PoolB,Verifier,Judge,Correlator}Sprite.tsx`) accepts exactly one prop:

```tsx
interface RoleSpriteProps {
  state: "idle" | "working" | "waiting" | "verdict";
}
```

| State | Meaning (driven by audit-chain events) | Frame intent |
|---|---|---|
| `idle` | No tool call active for this role; not awaiting a handoff. | Resting pose. Subtle breathing/idle bob is fine; not required. |
| `working` | A `tool_call_start` event for this role is the most recent unfinished tool call. | Active work pose — looking at evidence, gesturing, casting. |
| `waiting` | Received an `acp_handoff` but hasn't started yet (e.g. judge waiting for verifier output). | Anticipatory pose — alert, head turned, but not engaged. |
| `verdict` | Just emitted a Finding (Pool A/B) or just completed a handoff to the next role (verifier → judge → correlator). | Brief flourish — raised arm, exclamation, banner — that decays back to idle after ~1500ms. |

The decay timer for `verdict` is the parent's responsibility, not the sprite's. The sprite renders the state it's given.

State derivation lives in `apps/web/lib/sprite-state.ts` (`deriveRoleStates`). **Don't propose changes there**; if the state vocabulary feels wrong, raise it as a question in the deliverables instead of editing.

### 2.2 NES.css is the aesthetic anchor (for the `/` dashboard only)

The placeholders use `<div className="nes-container with-title is-rounded">` wrappers. Final art must remain visually coherent with the NES.css component library already on the page (input box, buttons, badges all use NES.css). The sprite art itself can be richer than NES.css's flat 8-bit palette — borrowed motifs from 16-bit JRPGs are welcome — but the surrounding chrome shouldn't look out of place next to a `.nes-btn`.

**Iter 8 / NES.css-derived component vocabulary** to use on the
dashboard at `/` (canonical reference: showcase at
`https://nostalgic-css.github.io/NES.css/`):

- Containers: `.nes-container.with-title.is-rounded` for sprite
  cards + sub-panels (already in placeholder)
- Buttons: `.nes-btn` with variants `is-primary` / `is-success` /
  `is-warning` / `is-error` (5-color palette; use
  `is-success` sparingly — reserve for judge-relevant moments
  like CONFIRMED finding emission)
- Inputs: `.nes-input` for the case-path field
- Progress bars: `.nes-progress` with `is-success` / `is-primary`
  / `is-warning` / `is-error` — applicable for the verdict-flourish
  decay or HashChainBadge breakdown
- Badges/icons: `.nes-avatar` / `.nes-icon` family for tiny
  status indicators
- Dialog balloons: `.nes-balloon` (with `from-left` / `from-right`
  variants) for agent-annotation popups when the analyst hovers
  a sprite during an active step

**Iter 3 / forensics-redirect cross-reference**: NES.css is the
aesthetic for `/` only. The Judge Mode route at `/judge` adopts
a forensic-tool aesthetic (Velociraptor + Timesketch references)
distinct from `/` — see Judge Mode spec §0.1 for the full split.
Sprite art designed under this brief lands on `/` and DOES NOT
appear on the Judge Mode pages.

### 2.3 Frame format and asset path

- **PNG sprite sheets, 32×32 px per frame, 4 frames horizontal**: `idle | working | waiting | verdict`. One sheet per role. (A3 spec §2.1 line 92.)
- **Path**: `apps/web/public/sprites/{pool_a,pool_b,verifier,judge,correlator}.png`.
- **Pixel-perfect rendering**: scale 4× on screen via CSS `image-rendering: pixelated`. Don't pre-scale the PNGs.
- **Background-position cycling** for `verdict`-frame decay is fine; CSS animation > JS timing where possible.

Optional 8× variant for the `verdict` flourish (a brief "burst" frame at higher pixel density) is acceptable if it pays off narratively, but not required.

### 2.4 Audit-chain semantics (for AuditBeadString)

Each bead corresponds to one line in `audit.jsonl`. The line schema (canonical, do not redesign):

```json
{
  "seq": 7,
  "ts": "2026-04-26T14:23:01.524Z",
  "kind": "tool_call_start",
  "payload": { "...kind-specific..." },
  "prev_hash": "a8f2...",
  "line_hash": "b1c4..."
}
```

Color the bead by `kind`. Suggested palette (negotiable; the suggestion locks ordering by importance, not the hex values):

| `kind` | Suggested color family | Why |
|---|---|---|
| `tool_call_start` / `tool_call_end` | Cool gray-blue | Highest volume — backbone events, should not visually dominate |
| `finding_draft` / `finding_approved` | Warm yellow / gold | The "actual content" — should pop |
| `acp_handoff` | Magenta / purple | Inter-agent communication — distinct from tool events |
| `judge_selfscore` | Deep red | Rubric-self-grade records, rare, high signal |
| `chain_update` / `manifest_finalize` | Forest green | Cryptographic attestation events — reassuring |
| Anything else | Neutral mid-gray | Fallback |

Hover-reveal: `seq=<n> · <kind> · <ts> · hash=<line_hash[:8]>`. Click-to-copy the line_hash if the design treatment supports it.

### 2.5 HashChainBadge semantics

The badge is bound to the verification result of `verifyAuditChain(events)` from `apps/web/lib/audit-tail.ts` (already shipped — do not redesign the verification logic).

- **Green seal**: `prev_hash` chain intact end-to-end and matches the published Merkle root.
- **Red seal**: any link broken. The badge surfaces the seq number of the first broken link via tooltip.

The badge is the single most important rubric-criterion-#5 visual. It should look like something a federal court clerk would stamp on a document — solemn, unambiguous, rather than playful — even though the rest of the page is whimsical. This visual contrast is intentional: the cryptographic chain is the load-bearing legal claim (FRE 902(14)).

### 2.6 FindingChip semantics

Renders a Finding from the audit stream. Required fields visible without expansion:

- **Confidence tier** (CONFIRMED / INFERRED / HYPOTHESIS) — prominent, three distinct treatments. CONFIRMED gets a "verified" mark; INFERRED gets a "two-supporting-evidence" mark; HYPOTHESIS gets a "tentative" mark (lighter weight, italic, etc.).
- **MITRE technique** (e.g. `T1014`, `T1055`) — small badge, monospace.
- **One-line summary** (`payload.summary`).
- **Pool origin** (`A` / `B` / `merged`) — small icon matching the pool sprite's color.
- **Evidence pointer** — link/tooltip showing `tool_call_id` count + first one's id.

Expandable detail (on click) is welcome but not required. Strict horizontal layout preferred so chips stack cleanly in the panel.

### 2.7 What you cannot redefine

- The state vocabulary (`idle`/`working`/`waiting`/`verdict`).
- The role names or count (5 roles, mapping 1:1 to `agent-config/AGENTS.md`).
- The audit JSONL schema (immutable; tests assert it).
- The SSE-not-WebSocket transport (set in stone by PR #7; documented in CLAUDE.md "Spec/code divergences" §7).
- The component file paths and prop names (assert on a smoke test that imports them).

---

## 3. Reference inputs (already in the repo)

Available locally for inspiration; **none of these ship in the submission** (they live under `git-hub-references/` which is `.gitignore`'d).

| Reference | What to look at | Why |
|---|---|---|
| `git-hub-references/pixel-agents/` | Sprite-style dashboard component patterns; their state-to-frame mapping | A3 §1 names this as the visual-language reference |
| `git-hub-references/openclaw/` (where applicable) | Hallucination-containment UI affordances | The Verifier sprite's "skeptic" framing borrows this |
| NES.css docs at `https://nostalgic-css.github.io/NES.css/` | Component vocabulary already on the page | Whatever you design must coexist with these |
| Anthropic Claude Design at `https://www.anthropic.com/news/claude-design-anthropic-labs` | The prototyping toolchain itself | A3 §1.2 names this as the design-pass tool |

In-repo prior art that already establishes the project's tone:

- `docs/reports/2026-04-26-srl2018-dc-investigation.md` — analyst-facing investigation report. Note the cryptographic-attestation framing; the badge should match this seriousness.
- `docs/cryptographic-attestation.md` — five-link chain explanation. The HashChainBadge is essentially the visual surface of this document.
- `docs/false-positives.md` — the "verifier as skeptic" framing comes from here.
- `agent-config/AGENTS.md` — the canonical role definitions; the narrative descriptions in §1 above are derived from this.

---

## 4. Deliverables

Land these as one PR (suggested branch name: design-phase-5-6-sprites):

### 4.1 Sprite PNGs (5 files)

- `apps/web/public/sprites/pool_a.png` — 4 frames × 32×32, total 128×32
- `apps/web/public/sprites/pool_b.png` — same
- `apps/web/public/sprites/verifier.png` — same
- `apps/web/public/sprites/judge.png` — same
- `apps/web/public/sprites/correlator.png` — same

### 4.2 Sprite component swap-ins (5 files)

Edit only the `<RoleSpriteCard>` body in each of:
- `apps/web/components/sprites/PoolASprite.tsx`
- `apps/web/components/sprites/PoolBSprite.tsx`
- `apps/web/components/sprites/VerifierSprite.tsx`
- `apps/web/components/sprites/JudgeSprite.tsx`
- `apps/web/components/sprites/CorrelatorSprite.tsx`

The shared chrome (`apps/web/components/sprites/RoleSpriteCommon.tsx`) can be edited if needed — but keep `RoleSpriteProps` and the `data-state` / `data-testid` attributes intact (tests assert on them).

### 4.3 New chrome components (3 files)

- `apps/web/components/AuditBeadString.tsx` — props: `events: AuditLine[]`. Renders horizontally; color-by-kind per §2.4.
- `apps/web/components/HashChainBadge.tsx` — props: `events: AuditLine[]`. Calls `verifyAuditChain` from `apps/web/lib/audit-tail.ts`. Renders green/red per §2.5.
- `apps/web/components/FindingChip.tsx` — props: `finding: FindingPayload` (type derived from `apps/web/lib/events.ts`). Renders per §2.6.

### 4.4 Page integration (1 file)

`apps/web/app/page.tsx` already has slots for these (see the "Sprite grid" comment block); add the AuditBeadString below the grid, the HashChainBadge to the header, a `<FindingChip />` panel beneath the bead string. Keep the existing connect/disconnect controls and the `/debug` link.

### 4.5 Visual style guide (1 file)

A new `phase-5-6-style-guide.md` alongside this brief in the same directory — short reference doc capturing:
- Final palette (hex values)
- Typography scale used (NES.css sets the floor; if anything was added)
- Animation timings actually shipped
- Any motifs/glyphs introduced (so future expansions reuse them)

This doc lives forever; the brief itself is consumed once.

---

## 5. Success criteria (CI-checkable + judge-checkable)

The design pass is complete when **all** of:

- [ ] `pnpm --filter @findevil/web test` passes (8 existing Vitest tests must stay green; tests assert `data-testid` and `data-state` attributes).
- [ ] `pnpm --filter @findevil/web build` succeeds.
- [ ] `pnpm --filter @findevil/web typecheck` clean.
- [ ] `pnpm --filter @findevil/web dev` boots; visiting `http://localhost:3000/?case=<absolute-path-to-a-real-case-dir>` renders all 5 sprites animating against a real `audit.jsonl` stream.
- [ ] Connecting to a tampered case dir (one byte flipped in `audit.jsonl`) flips the HashChainBadge to red within one tick.
- [ ] At least one frame from each sprite's `verdict` state is visible during a 30-second replay of `tmp/auto-runs/auto-<some-uuid>/audit.jsonl` from a recent investigation.
- [ ] No new top-level dependencies in `apps/web/package.json` beyond what's already there. (NES.css + Tailwind v4 + React 19 + Vitest is the package floor — designers can add image-optimization helpers if needed but the base stays.)
- [ ] The `/debug` route still works (raw events viewer must remain accessible — design must not consume the entire page real estate).

Additionally, judge-checkable but not CI-locked:

- [ ] A non-DFIR-savvy viewer watching the demo video (`docs/demo-script-a2.md` Beat 4 in particular) can identify which sprite is currently working without reading the labels — narrative legibility is the soft target.
- [ ] The HashChainBadge looks legally serious; it should be the one visual element that doesn't feel "playful," matching the FRE 902(14) framing.

---

## 6. Open questions to resolve in the design pass

These are intentional gaps the brief leaves open. The pass should resolve them and document the choices in the Phase 5/6 style guide (§4.5):

1. **Aspect ratio handling**: portrait vs square framing for the sprite cards. Current placeholder is square via NES.css default.
2. **Verdict-flourish duration**: 1500ms is the placeholder spec; if 800ms or 2200ms reads better, change it (and update the `apps/web/lib/sprite-state.ts` decay constant to match).
3. **Bead string horizontal scroll**: at high event volume (>500 events) the string overflows. Acceptable resolutions: virtualize, fade out the head, paginate by phase. Pick one.
4. **Color-blind accessibility for kind palette**: the suggested palette in §2.4 is not colorblind-safe. Augment with shape/pattern variation per `kind` — beads as circles/squares/diamonds rather than circles-only.
5. **Dark mode**: NES.css ships a `.nes-balloon.is-dark` variant but not a global dark mode. Decide whether to commit to one mode or both.

---

## 7. Out of scope (deliberately, do not propose)

- Reorganizing the dashboard layout beyond §4.4. The two-column-then-stacked sprite grid is locked.
- Adding new states beyond the four in §2.1.
- A supervisor sprite (Claude Code is off-screen, by design — A3 §2.1 line 100).
- Adjusting the audit JSONL schema or audit-line transport (SSE, not WebSocket — see CLAUDE.md "Spec/code divergences" §7).
- Building MCP App widgets (`apps/mcp-widgets/` — deferred per A2 §2.1, A3 does not promote it back).
- Mobile responsiveness below 800px viewport. Demo video is 1080p; mobile is a bonus, not a requirement.
- Integrating with the build swarm or sandbox layers — those are invisible to judges.

---

## 8. How this brief fits the rest of the project

This document is the **handoff** between engineering and design. The placeholder layer (PR #15, commit `ab2edd0`) was structured precisely so this swap-in is mechanical: image assets + JSX body changes + three new components, with the engineering contract already locked.

When the design pass is complete:

1. Re-record demo video Beat 4 ("the agent army at work") against the final art.
2. Update `apps/web/README.md` Status block: change "5 sprite components — pending Claude Design pass (Phase 5)" → ✓ shipped; same for Phase 6 chrome.
3. Drop the placeholder footer note in `apps/web/app/page.tsx`: "Sprites are placeholder NES.css visuals; final art lands with the Claude Design pass (A3 §1.2)."

The submission timeline (deadline 2026-06-15) leaves comfortable runway. Earlier is better — re-recording the demo video is the only downstream task, and the script (`docs/demo-script-a2.md`) is already locked, so post-design work is just one recording session plus minor doc updates.
