# Demo video — real-footage capture guide

The submission requires a **live screen recording**, not an animated recreation. This Remotion
film embeds genuine screen captures as "exhibits" (the `ExhibitVideo` component) inside the
editorial frame. This guide is the shot-list: what to record, the exact command, the target
file, and how to wire it in.

> **Why this exists:** the judging audit flagged the prior cut as "a simulated animated terminal
> pane" — the substance was redrawn, not recorded. Every slot below replaces a recreation with a
> genuine capture. The frame/typography/narration around the footage is the only thing the film
> draws.

## How the slots work

`src/components/shared/ExhibitVideo.tsx` plays a file from `public/ui/` **only if its basename is
listed in the `CAPTURED` set** at the top of that file. Until then it renders an on-brand
"AWAITING CAPTURE" placeholder, so `pnpm studio` and `pnpm render` keep working at every step.

To light up a slot:

1. Record the clip (below), export to **1920×1080 (or the panel aspect), H.264 .mp4**.
2. Drop it in `scripts/make-demo-video/public/ui/<name>.mp4`.
3. Add `"<name>.mp4"` to the `CAPTURED` set in `ExhibitVideo.tsx`.
4. `pnpm studio` to preview; re-time `playbackRate` / `startFrom` on the `<ExhibitVideo>` if the
   real clip is longer than the beat.

## Recording setup (once)

- **Resolution:** record the terminal/browser at 1920×1080 (or 16:9). Big font (terminal 16–18pt)
  so text is legible at video scale.
- **Tooling:**
  - *Terminal shots* → **`asciinema` + `agg`** (verified on this machine). asciinema records the
    real session as text and `agg` renders it to crisp video at any size — sharper than a pixel
    grab. Install the converter once: `cargo install --git https://github.com/asciinema/agg agg`.
  - *Browser/dashboard shots* → a real screen recorder. On this Wayland box the no-install option
    is GNOME's recorder (`Ctrl+Alt+Shift+R`; lift the cap with
    `gsettings set org.gnome.settings-daemon.plugins.media-keys max-screencast-length 0`), or
    install **OBS** (`flatpak install flathub com.obsproject.Studio`) if you want to narrate live.
  - *Pure ffmpeg grab* (XWayland `:0`): `ffmpeg -video_size 1920x1080 -framerate 30 -f x11grab -i :0.0+0,0 -c:v libx264 -crf 18 -pix_fmt yuv420p grab.mp4`.
- **Pacing aid:** `FIND_EVIL_PACE=0.15` spaces the audit/stage output so the stream builds
  visibly instead of dumping instantly (no effect on the result). Use it for the terminal + the
  dashboard takes.

---

## Slot 1 — `ui/terminal-investigation.mp4` (Beat 2: "It starts in Claude Code")

**The flagship shot.** A real terminal running the investigation end-to-end, **including the live
self-correction** (the verifier catching a bad replay and re-dispatching). This single capture
covers the audit's "live terminal" + "live self-correction" asks.

```bash
# From the repo root. FIND_EVIL_FAULT_INJECT makes the verifier reject one
# replay so the re-dispatch loop fires ON CAMERA — then recovers, verdict
# unchanged. The injection is labeled fault_injection in the chain (honest).
FIND_EVIL_PACE=0.15 \
FIND_EVIL_FAULT_INJECT="verifier_reject_once:prefetch-cain-exe" \
  python3 scripts/find_evil_auto.py evidence/SCHARDT.dd \
  --local --unattended --case-id demo-self-correction
```

**What's on screen, in order:** `case_open` + the SHA-256, the tool stream
(`vol_*` / `prefetch_parse` / `registry_query` / `evtx_query`), then the verify phase printing the
self-correction **to stdout** (the engine now prints these — no audit-log spelunking needed):

```
verify_finding rejected f-A-… — re-dispatching once (fresh replay)
verify_finding recovered f-A-… on re-dispatch ✓
```

…and the final `verdict = SUSPICIOUS`.

**Verified recipe (asciinema → agg → mp4), this machine:** record the run *inside* asciinema's
`-c`, then render. No GUI needed; text stays razor-sharp.

```bash
# 1. record the real run as an asciicast (the -c command runs in a pty)
asciinema rec --overwrite \
  -c "FIND_EVIL_PACE=0.08 FIND_EVIL_FAULT_INJECT=verifier_reject_once:prefetch-cain-exe \
      python3 scripts/find_evil_auto.py evidence/SCHARDT.dd --local --unattended --no-parallel \
      --case-id demo-self-correction" \
  /tmp/self-correction.cast

# 2. render to video (speed up a long run to fit the ~22s beat)
agg --font-size 26 --theme asciinema --speed 1.6 /tmp/self-correction.cast /tmp/self-correction.gif
ffmpeg -y -i /tmp/self-correction.gif -movflags +faststart -pix_fmt yuv420p \
  -vf "scale=trunc(iw/2)*2:trunc(ih/2)*2" \
  scripts/make-demo-video/public/ui/terminal-investigation.mp4

# 3. add "terminal-investigation.mp4" to CAPTURED in ExhibitVideo.tsx, then `pnpm render`
```

`evidence/attack-samples` (EVTX) is a faster swap-in if you want a ~30s run instead of the
minutes-long NIST disk case — use `verifier_reject_once:audit-log-cleared` for that fixture. A
quick reference clip recorded exactly this way verified the pipeline end-to-end (the recovery is
legible at video scale). Trim or raise `--speed` / the `<ExhibitVideo playbackRate>` to fit the
beat budget (≈ 22s).

## Slot 2 — `ui/dashboard-live.mp4` (Beat 6: "Watch it work") — already present, re-capture for richness

A real capture ships (`public/ui/dashboard-live.mp4`, 11s). The audit called it "static" — if it
reads flat, re-record a livelier take: run a case with `FIND_EVIL_LOCAL=1` so the dashboard at
`http://localhost:3000` streams, and capture findings landing + the pipeline rail lighting up +
hovering a finding to show its `tool_call_id` chip. Same filename → no code change.

```bash
# Terminal A: bring the dashboard up (see docs/using/running-verdict.md), then
# Terminal B: run a case in local mode and screen-capture the browser.
FIND_EVIL_PACE=0.2 scripts/verdict evidence/SCHARDT.dd
```

## Slot 3 (optional) — `ui/manifest-tamper.mp4` (chain-of-custody proof)

A real `manifest_verify` run: `overall=true` on the committed sample run, then flip one byte and
watch it fail. Strongest possible proof for the audit-trail criterion. Not yet wired into a beat
— add an `<ExhibitVideo src="ui/manifest-tamper.mp4" …>` to `HashChainScene.tsx` if you want it,
or keep it as B-roll.

```bash
# Pass: committed run verifies offline (zero deps).
scripts/trace-finding docs/sample-run/fault-injection-redispatch

# Fail: tamper one byte, re-verify → precise chain-break diagnostic, overall=false.
cp -r docs/sample-run/fault-injection-redispatch /tmp/tamper-demo
# edit one hex char in /tmp/tamper-demo/audit.jsonl, then:
scripts/trace-finding /tmp/tamper-demo   # exits non-zero, names the broken seq
```

---

## Render

```bash
cd scripts/make-demo-video
pnpm install          # first time
pnpm studio           # live preview while you drop footage in
pnpm render           # writes ../../docs/find-evil-demo.mp4
```

Then host the mp4 (YouTube/Vimeo/Youku) and record the URL in
`SUBMISSION_COMPLIANCE.md` §6 and the Devpost submission field.

## Honesty note

The fault injection in Slot 1 is deliberate and **declared in the audit chain** (a
`fault_injection` record precedes the rejection) and on screen via the engine's stderr banner.
The recovery itself is the production code path — the same re-dispatch fires on any real transient
replay failure. The committed reference run is `docs/sample-run/fault-injection-redispatch/`.
