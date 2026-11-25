# VERDICT Brand

VERDICT's visual source of truth is the v2 asset package in
`VERDICT_DFIR_SVG_Assets_v2/`.

Use these files before inventing new visuals:

| File | Purpose |
|---|---|
| `VERDICT_DFIR_SVG_Assets_v2/verdict-brand-board-reconstructed.png` | Canonical brand bible image. |
| `VERDICT_DFIR_SVG_Assets_v2/BRAND_DESIGN_PROMPT.md` | Voice, positioning, and visual rules. |
| `VERDICT_DFIR_SVG_Assets_v2/USAGE_GUIDE.md` | Logo, semantic color, and portability guidance. |
| `VERDICT_DFIR_SVG_Assets_v2/SVG_ASSET_LIST.md` | Production SVG inventory. |
| `VERDICT_DFIR_SVG_Assets_v2/QA_REPORT.md` | Asset QA notes and rendering checks. |

## Palette

| Token | Hex | Use |
|---|---:|---|
| Midnight Ink | `#101426` | Primary dark background. |
| Near Black | `#12131A` | Raised dark surfaces. |
| Paper Cream | `#F5F1E8` | Primary text and light marks. |
| Electric Cobalt | `#4D5DFF` | Brand, active state, hypothesis/info. |
| Soft Lilac | `#B8A8FF` | Secondary brand, captions, subtle UI furniture. |
| Seafoam | `#73D9C2` | Verified, replay matched, pass. |
| Signal Coral | `#FF6257` | Rejected, contradiction, failed, flagged. |
| Butter Yellow | `#FFD76A` | Review, warning, attention, indeterminate. |

Semantic colors carry meaning. Do not use Seafoam, Coral, or Butter as purely
decorative accents in investigation UI, reports, or video.

## Voice

Canonical phrases:

- Show Me the Evidence
- Evidence over assumption
- Don't trust the model. Reproduce the finding.
- Trace it. Test it. Trust it.

Avoid copy that implies stronger forensic conclusions than the evidence supports.
Visual polish must not upgrade confidence, create Findings, or weaken the scoped
meaning of `SUSPICIOUS`, `INDETERMINATE`, or `NO_EVIL`.

## Implementation Surfaces

- Web dashboard tokens: `apps/web/lib/verdict-ui.tsx` and `apps/web/app/globals.css`.
- Report tokens: `scripts/_report_style.css` and `_DEFAULT_CSS` in `scripts/render_report.py`.
- Report figure palette: `scripts/render_report.py` and `scripts/render_fleet_report.py`.
- Remotion/video tokens: `scripts/make-demo-video/src/components/shared/editorial.ts`.
- Logo assets: `assets/logo/`, `apps/web/public/`, and `scripts/make-demo-video/src/assets/`.

When changing any visual surface, update the shared token source first and then
patch call sites only when they hard-code semantic colors or obsolete copy.
