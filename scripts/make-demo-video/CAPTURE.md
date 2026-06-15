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

**The primary clean shot.** A real terminal running the investigation end-to-end with no fault
injection. This capture covers the audit's "live terminal" ask and shows the normal typed tool
stream, verification, judging, and final verdict. The forced self-correction take belongs in the
optional harness appendix.

```bash
# From the repo root. Do not set FIND_EVIL_FAULT_INJECT for the primary capture.
FIND_EVIL_PACE=0.15 \
  python3 scripts/find_evil_auto.py evidence/SCHARDT.dd \
  --local --unattended --case-id demo-clean-primary
```

**What's on screen, in order:** `case_open` + the SHA-256, the typed tool stream
(`vol_*` / `prefetch_parse` / `registry_query` / `evtx_query`), normal verification and judging,
and the final `verdict = SUSPICIOUS`.

**Verified recipe (asciinema → agg → mp4), this machine:** record the run *inside* asciinema's
`-c`, then render. No GUI needed; text stays razor-sharp.

```bash
# 1. record the real run as an asciicast (the -c command runs in a pty)
asciinema rec --overwrite \
  -c "FIND_EVIL_PACE=0.08 \
      python3 scripts/find_evil_auto.py evidence/SCHARDT.dd --local --unattended --no-parallel \
      --case-id demo-clean-primary" \
  /tmp/clean-primary.cast

# 2. render to video (speed up a long run to fit the ~22s beat)
agg --font-size 26 --theme asciinema --speed 1.6 /tmp/clean-primary.cast /tmp/clean-primary.gif
ffmpeg -y -i /tmp/clean-primary.gif -movflags +faststart -pix_fmt yuv420p \
  -vf "scale=trunc(iw/2)*2:trunc(ih/2)*2" \
  scripts/make-demo-video/public/ui/terminal-investigation.mp4

# 3. add "terminal-investigation.mp4" to CAPTURED in ExhibitVideo.tsx, then `pnpm render`
```

`evidence/attack-samples` (EVTX) is a faster swap-in if you want a ~30s clean run instead of the
minutes-long NIST disk case. Do not use fault injection for the primary
`terminal-investigation.mp4`. Trim or raise `--speed` / the `<ExhibitVideo playbackRate>` to fit
the beat budget (≈ 22s).

## Optional appendix — `ui/harness-self-correction.mp4` (fault-injection harness demo)

This clip is optional harness/demo evidence only. It deliberately sets
`FIND_EVIL_FAULT_INJECT` to make the verifier reject one replay so the re-dispatch loop fires on
camera, then recovers with the verdict unchanged. The injected run demonstrates the recovery
harness/code path; it is not organic self-correction evidence and should never replace the clean
primary capture.

```bash
FIND_EVIL_PACE=0.15 \
FIND_EVIL_FAULT_INJECT="verifier_reject_once:prefetch-cain-exe" \
  python3 scripts/find_evil_auto.py evidence/SCHARDT.dd \
  --local --unattended --case-id demo-harness-self-correction
```

For the faster EVTX fixture, use `verifier_reject_once:audit-log-cleared` only for this optional
harness appendix clip. The expected visible recovery lines are:

```
verify_finding rejected f-A-… — re-dispatching once (fresh replay)
verify_finding recovered f-A-… on re-dispatch ✓
```

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

A real `manifest_verify` run: `overall=true` on a completed case directory, then flip one byte and
watch it fail. Strongest possible proof for the audit-trail criterion. Not yet wired into a beat
— add an `<ExhibitVideo src="ui/manifest-tamper.mp4" …>` to `HashChainScene.tsx` if you want it,
or keep it as B-roll.

```bash
# Pass: completed run verifies offline (zero deps).
scripts/trace-finding tmp/auto-runs/<case-id>

# Fail: tamper one byte, re-verify → precise chain-break diagnostic, overall=false.
cp -r tmp/auto-runs/<case-id> /tmp/tamper-demo
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

Then host the mp4 and record the URL in the release notes or submission field.

## Optional harness appendix note

Only the appendix self-correction clip uses fault injection. The primary Slot 1 capture should be
recorded without `FIND_EVIL_FAULT_INJECT`. When used, the injected appendix run is deliberate and
declared in the audit chain via a `fault_injection` record before the rejection, and on screen via
the engine's stderr banner. The recovery itself exercises the production re-dispatch path that also
fires on real transient replay failures.
