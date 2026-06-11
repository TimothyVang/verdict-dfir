# 5-Minute Demo Script (Amendment A2)

> **Status: SUPERSEDED.** The narration canon is now
> `scripts/make-demo-video/src/beats/beats-data.ts` (the rendered Remotion
> film) with shot recipes in `scripts/make-demo-video/CAPTURE.md`. This
> document is kept for its capture recipes and pre-flight checklist only —
> do not record from these beats.
>
> Original status: draft. Recorded under Amendment A2 — Claude Code is the
> primary interface. The pre-A2 demo flow in `BUILD_PLAN_v2.md §9` was
> built around the Next.js SPA which is deferred to bonus polish.

This is the demo-video script for the Devpost submission. Hard cap
5:00 (Devpost rejects longer). Each beat has the spoken narration,
the on-screen content, and the capability it demonstrates. Words are
written to be read aloud at ~150 wpm.

---

## Pre-flight checklist

Before recording:

1. **Clean `tmp/auto-runs/` and `tmp/fleet-runs/` of older runs** so
   the latest fleet-run timestamp is the one the demo references.
   `find-evil-auto` is non-destructive; the per-case dirs accumulate.
2. **Pre-warm the Volatility symbol cache** by running one investigation
   end-to-end (`bash scripts/find-evil-auto <small-mem-image>
   --unattended`). First-run vol3 takes 2-3 minutes for symbol download;
   subsequent runs are <30s. Don't make a judge wait for symbol downloads.
3. **Open three terminal tabs** in advance: one with `claude`
   running (the official Claude Code CLI; opens in cwd), one with
   `bash scripts/find-evil-auto <evidence>`, one ready to drive
   `manifest_verify` via the MCP smoke harness. Tab-switching
   mid-take wastes seconds.
4. **Pre-render `FLEET_REPORT.pdf`** from a recent fleet run and have
   it open in a PDF viewer offscreen. The video shows it; we don't
   wait for matplotlib + pandoc + Chrome to render in 5 minutes.
5. **Disable notifications.** Slack/email/Discord pop-ups during
   recording are an instant retake.
6. **Test audio levels.** Voice-over recordings get rejected if the
   mic clips. Aim for -12 to -6 dBFS.

---

## Beat map

| # | Time      | Length | Beat                          | Focus                        |
|---|-----------|--------|-------------------------------|------------------------------|
| 1 | 0:00–0:25 | 0:25   | Cold open + problem framing   | Stakes                       |
| 2 | 0:25–0:50 | 0:25   | Architecture                  | Constraints / guardrails     |
| 3 | 0:50–1:35 | 0:45   | Single-host investigation     | Epistemic discipline         |
| 4 | 1:35–2:35 | 1:00   | Live ACH disagreement         | Competing hypotheses         |
| 5 | 2:35–3:10 | 0:35   | Crypto chain-of-custody       | Verifiable evidence          |
| 6 | 3:10–4:00 | 0:50   | 22-host fleet investigation   | Breadth / depth              |
| 7 | 4:00–4:30 | 0:30   | Cross-host APT signal         | Cross-host correlation       |
| 8 | 4:30–4:50 | 0:20   | Signed verdict                | Sealed, verifiable output    |
| 9 | 4:50–5:00 | 0:10   | Outro — repo URL + license    | —                            |

---

## Beat 1 — Cold open (0:00–0:25)

**On-screen:** A single screenshot of the SANS Find Evil! 2026
landing page with the deadline (2026-06-15) circled in red. Cut to
black at 0:08, then fade into the project title card: *"Find Evil:
A Cryptographically-Verifiable DFIR Agent"*.

**Voice-over:**

> Modern attackers move at machine speed — the median ransomware
> dwell time is now measured in hours, not days. The SANS Find Evil!
> hackathon asks one question: can an agent reproduce a forensic
> investigator's work, fast enough to keep up — and prove what it
> did. Our submission says yes, and gives the analyst a sigstore-
> backed signature on every finding, verifiable offline.

**Notes:**
- Deliver this dry, not breathless. The cryptographic-attestation
  claim is the differentiator; lead with it, but don't oversell.

---

## Beat 2 — Architecture (0:25–0:50)

**On-screen:** `docs/architecture.md` rendered in a markdown
preview, scrolled to the trust-boundary diagram. Cursor highlights
each of the five boundaries as the narrator names them.

**Voice-over:**

> Five trust boundaries. Evidence vault — read-only. SIFT tools as
> subprocesses, never linked, so we stay license-clean for AGPL
> code. Two MCP servers — Rust for forensic tools, Python for the
> crypto chain. Claude Code as the orchestrator. Every Finding
> cites a tool-call ID; every tool call hashes its output. There
> is no `execute_shell` tool — by design.

**Notes:**
- "By design" is the key phrase — architectural guardrails matter
  more than feature surface (per Spec #2 and SOUL.md).

---

## Beat 3 — Single-host investigation (0:50–1:35)

**On-screen:** Terminal showing
`bash scripts/find-evil-auto <evidence>/base-dc-memory.img --unattended`.
Streaming output scrolls. At 1:10, switch to side-by-side: terminal
on left, real-time `tail -f audit.jsonl` on right showing each
hash-chained record landing.

**Voice-over:**

> One command. The agent opens the case, hashes the
> image, walks the active process list with Volatility's pslist,
> then signature-scans EPROCESS pool memory with psscan — and the
> two disagree. That divergence *can* be a DKOM rootkit signature —
> but on this image the agent spots the acquisition-smear tells
> (core OS singletons recovered only by psscan, duplicate `System`
> EPROCESS — which a rootkit can't produce) and labels it a
> `HYPOTHESIS`, **not** a confirmed rootkit, refusing to assert
> T1014 without a second artifact class. It does **not** over-claim
> `CONFIRMED`. That epistemic discipline is non-negotiable.

**Notes:**
- The "INFERRED, not CONFIRMED" line is what proves we're not
  hallucinating verdict tiers. Leave a 1-second pause after it.

---

## Beat 4 — Live ACH disagreement (1:35–2:35)

**On-screen:** Terminal showing the audit JSONL streaming. At ~1:50,
zoom in on a `kind: "contradiction"` record. The record shows two
Findings — one from Pool A (persistence-biased), one from Pool B
(exfil-biased) — with conflicting `mitre_technique` labels on the
same `_EPROCESS` block. At 2:10, the `judge_findings` record fires:
credibility-weighted merge selects Pool A's framing.

**Voice-over:**

> Heuer's Analysis of Competing Hypotheses, applied at agent
> architecture. Two pools investigate the same evidence with
> opposing priors. They will disagree — and that disagreement is
> not a bug. We surface it before reconciliation, named, in the
> audit trail. The judge merges with credibility weighting. The
> analyst sees both arguments and the reconciliation. No
> consensus-seeking single agent can give them that.

**Notes:**
- This shows autonomous reasoning + self-correction. Make the
  contradiction record visible on screen for ≥3 seconds.
- **Reproducible live self-correction (recipe).** To capture the
  verifier catching a failure and recovering ON CAMERA — not as an
  animation — run the case with the audit-labeled fault hook:

  ```bash
  FIND_EVIL_FAULT_INJECT="verifier_reject_once:prefetch-cain-exe" \
    python3 scripts/find_evil_auto.py evidence/SCHARDT.dd \
    --local --unattended --no-parallel --case-id demo-self-correction
  ```

  The chain then shows, live and in order: `fault_injection` (the
  injection declares itself), the verifier rejecting the corrupted
  replay, `verifier_redispatch`, and the fresh attempt approving —
  verdict unchanged. `grep -E 'fault_injection|verifier_redispatch'`
  over `tail -f audit.jsonl` makes the sequence pop on screen. The
  committed reference run is `docs/sample-run/fault-injection-redispatch/`.

---

## Beat 5 — Crypto chain-of-custody (2:35–3:10)

**On-screen:** Terminal showing `manifest_finalize` running, output
shows the Merkle root. Cut to a second terminal driving
`manifest_verify` against the same case dir, output shows
`overall=True, audit_chain_ok=True, merkle_root_ok=True,
signature_present=True`. Then on-screen: a one-byte tamper of
the Merkle root in `run.manifest.json`, re-run `manifest_verify`,
output flips to `overall=False` with a precise diagnostic naming
the field that diverged.

**Voice-over:**

> Every audit record, every tool output, every Finding — all
> hash-chained. At investigation end, we Merkle-tree the chain
> and sign the root with sigstore, whose Rekor transparency log
> records the signature as an independent third party. This
> supports a FRE 902(14) self-authenticating-evidence claim.
> A judge — a literal judge in a literal court — can verify
> this submission's integrity from the manifest alone, three
> years from now, without trusting us. Tamper a single byte and
> the verifier names the byte that moved.

**Notes:**
- "FRE 902(14)" is the legal cite for self-authenticating
  electronic evidence — pronounce it "Federal Rule of Evidence
  nine-oh-two-fourteen". Drop the cite confidently; do not
  apologize for the legal jargon.
- The live tamper-and-fail demo is the load-bearing replacement
  for the pre-A5 Bitcoin-block visual. It shows the chain works,
  not just that we claim it does.

---

## Beat 6 — 22-host fleet investigation (3:10–4:00)

**On-screen:** Terminal showing
`python scripts/fleet_investigate.py && python scripts/fleet_correlate.py
&& python scripts/render_fleet_report.py`. (Pre-recorded, sped up
4× — the actual fleet run takes ~30 minutes; viewer sees the
sped-up summary scroll.) At 3:30, switch to the rendered
`FLEET_REPORT.pdf`, scrolled to the verdict-distribution chart.

**Voice-over:**

> Single-host is the demo; fleet investigation is the use case.
> Twenty-two memory images, eighty-four gigabytes total,
> investigated end-to-end with one command. The orchestrator
> persists progress after every host so a crash doesn't cost you
> the run. Every host gets its own signed manifest; the fleet
> rollup adds cross-host correlation on top.

**Notes:**
- The "84 GB" and "22 hosts" numbers reference the real
  SRL-2018 SANS HACKATHON-2026 corpus. Verify they match the
  current fleet directory before recording.

---

## Beat 7 — Cross-host APT signal (4:00–4:30)

**On-screen:** `FLEET_REPORT.pdf` scrolled to the temporal-clusters
figure. Highlight Cluster 1 — six hosts running `Autorunsc.exe` at
the *exact same second*. Then scroll to the cross-host process
table; highlight `rubyw.exe` on 4 hosts.

**Voice-over:**

> This is what makes fleet correlation worth the cost. Six hosts
> ran Autoruns at the exact same second — that is not natural
> system behavior, that is a PsExec sweep or an SCCM push. Four
> different hosts ran rubyw — Ruby for Windows isn't enterprise
> tooling. These are correlations no single-host investigation
> would surface. The agent didn't decide they were attack
> signatures — it surfaced them as `HYPOTHESIS` and named the
> threshold. The analyst confirms.

**Notes:**
- The "agent surfaces, analyst confirms" framing matches Rob
  Lee's stated preference (memory:
  `project_judging_signals.md`). Do *not* say "the agent
  responded to the attack" — that's the autonomous-responder
  framing he explicitly disprefers.

---

## Beat 8 — Signed verdict (4:30–4:50)

**On-screen:** Split-screen. Left: terminal showing the tail end of
the `scripts/verdict <evidence>` run — the signed `verdict.json`
landing in the case dir, with its `verdict`, `confidence`, and the
sigstore-signed `run.manifest.json` written alongside. Right:
terminal driving `manifest_verify` against that same case dir,
output `overall=True, audit_chain_ok=True, merkle_root_ok=True,
signature_present=True`. The cursor highlights the `verdict` and
`merkle_root` fields in `verdict.json`.

**Voice-over:**

> Cut evidence in, get a signed verdict out — one command. The
> `verdict` command runs the whole pipeline and seals the result:
> a `verdict.json` carrying the call and its confidence, rooted in
> the same Merkle tree and covered by the same sigstore signature
> as every Finding behind it. Anyone can re-run `manifest_verify`
> offline and confirm nothing moved. The verdict isn't a claim you
> have to trust — it's a sealed artifact you can check.

**Notes:**
- This is the payoff beat — the single signed output the whole
  pipeline exists to produce. Don't oversell; deliver as a
  closing flourish.
- The signed `verdict.json` + `run.manifest.json` are produced by
  `scripts/verdict <evidence>` (which drives the headless engine
  and the crypto chain). If you need to re-record this beat, point
  `manifest_verify` at any case dir a `verdict` run produced — they
  all carry the signed manifest and verdict.

---

## Beat 9 — Outro (4:50–5:00)

**On-screen:** Title card: repo URL, license (Apache-2.0), commit
SHA, build status badge. Hold for 7 seconds, then fade to black.

**Voice-over:**

> Source is open. License is Apache-2.0. Build is green. Cut
> evidence in. Get a signed verdict out. Thank you.

---

## Recording mechanics

- **Resolution:** 1920×1080. Devpost recompresses; lower-res
  source loses crispness on the small-text terminal panes.
- **Capture tool:** OBS Studio, x264 software encode at CRF 18.
  No GPU encode (NVENC artifacts on small text).
- **Audio:** voice-over recorded separately to a clean track,
  then mixed in DaVinci Resolve. Live narration during screen
  capture introduces breath and click noise.
- **Final export:** H.264 MP4, 8 Mbps target, AAC 192 kbps audio.
  Devpost limits files to 100 MB; this hits ~70 MB at 5:00.
- **Sanity check before upload:** play the final file at 0.5×
  speed and verify nothing is illegible. Judges aren't going to
  pause on every frame; they will if anything looks like it
  matters and they can't read it.

---

## What this script *deliberately does not show*

- **The Next.js SPA.** Deferred to bonus polish under A2; not on
  the critical path. If the SPA ships before recording, add it
  as a 15-second cutaway in Beat 6.
- **L0-L3 sandbox layers.** They gate CI; they're not a user-
  facing feature. Mention in Devpost, not video.
- **Apologies for missing features.** Don't list what we didn't
  build. Show what we did.
